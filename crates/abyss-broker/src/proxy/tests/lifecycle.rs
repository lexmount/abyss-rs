//! Autonomous completion, draining, request cancellation and stale-run regressions.

use std::sync::Arc;

use tokio::{
    sync::{oneshot, watch},
    task::AbortHandle,
    time::{Duration, timeout},
};
use uuid::Uuid;

use super::{test_plan, test_proxy_service};
use crate::{
    error::BrokerError,
    ingress::{Ingress, IngressError, IngressRuntimeStatus, PlatformFlow, StartedIngress},
    proxy::{
        ProxyLifecycle, ProxyRuntimeState, ProxyService, StartedProxyRuntime, StoppedProxyRuntime,
        lifecycle::{WorkerExit, WorkerSupervisor},
    },
};

struct RunControl {
    completed: watch::Receiver<WorkerExit>,
    abort: AbortHandle,
}

impl RunControl {
    async fn finished(self) -> WorkerExit {
        timeout(Duration::from_secs(2), WorkerExit::wait(self.completed))
            .await
            .expect("supervisor must publish completion")
            .expect("completion channel must remain available")
    }
}

async fn install<I: Ingress + 'static>(service: &ProxyService, ingress: I) -> RunControl {
    let mut state = service.state.lock().await;
    let run_id = Uuid::new_v4();
    let task = StoppedProxyRuntime::spawn_started(
        StartedIngress::new(
            ingress,
            IngressRuntimeStatus::ExplicitHttp {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
            },
        ),
        service.worker_services.clone(),
        Arc::downgrade(&service.state),
        run_id,
    );
    let control = RunControl {
        completed: task.completed.clone(),
        abort: task.abort_handle.clone(),
    };
    *state = ProxyRuntimeState::Started(StartedProxyRuntime {
        process_id: std::process::id(),
        requested_plan: test_plan(),
        run_id,
        task,
    });
    drop(state);
    control
}

async fn assert_stopped_without_control_request(service: &ProxyService) {
    assert!(
        matches!(&*service.state.lock().await, ProxyRuntimeState::Stopped(_)),
        "supervision must update state without start/stop/status calls"
    );
}

#[tokio::test]
async fn failed_worker_updates_state_without_status_calls_and_can_restart() {
    let service = test_proxy_service().await;
    service.start(test_plan()).await.unwrap();
    let control = {
        let state = service.state.lock().await;
        let ProxyRuntimeState::Started(runtime) = &*state else {
            panic!("proxy must be started");
        };
        let control = RunControl {
            completed: runtime.task.completed.clone(),
            abort: runtime.task.abort_handle.clone(),
        };
        drop(state);
        control
    };
    control.abort.abort();
    assert!(control.finished().await.into_result().is_err());
    assert_stopped_without_control_request(&service).await;
    assert_eq!(
        service.start(test_plan()).await.unwrap().lifecycle(),
        ProxyLifecycle::Running
    );
    service.stop().await.unwrap();
}

struct PanicIngress;

impl Ingress for PanicIngress {
    type Accepted = PlatformFlow;

    async fn accept(&mut self) -> Result<Self::Accepted, IngressError> {
        panic!("injected ingress panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_panic_is_observed_and_publishes_stopped() {
    let service = test_proxy_service().await;
    let control = install(&service, PanicIngress).await;
    let WorkerExit::Finished(Err(error)) = control.finished().await else {
        panic!("panic must remain available to completion observers");
    };
    assert!(error.is_panic());
    assert_stopped_without_control_request(&service).await;
}

struct BlockingShutdown {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

impl Ingress for BlockingShutdown {
    type Accepted = PlatformFlow;

    async fn accept(&mut self) -> Result<Self::Accepted, IngressError> {
        std::future::pending().await
    }

    async fn shutdown(self) {
        self.entered.send(()).unwrap();
        self.release.await.unwrap();
    }
}

async fn blocking_run(
    service: &ProxyService,
) -> (RunControl, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, waiting) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let control = install(
        service,
        BlockingShutdown {
            entered,
            release: released,
        },
    )
    .await;
    (control, waiting, release)
}

#[tokio::test]
async fn status_remains_readable_and_restart_waits_for_shutdown() {
    let service = test_proxy_service().await;
    let (_control, entered, release) = blocking_run(&service).await;
    let stopping_service = service.clone();
    let stopping = tokio::spawn(async move { stopping_service.stop().await });
    entered.await.unwrap();
    let status = timeout(Duration::from_secs(1), service.status())
        .await
        .unwrap();
    assert_eq!(
        status.lifecycle(),
        ProxyLifecycle::Running,
        "draining retains its running snapshot"
    );
    let starting_service = service.clone();
    let mut starting = tokio::spawn(async move { starting_service.start(test_plan()).await });
    assert!(
        timeout(Duration::from_millis(30), &mut starting)
            .await
            .is_err(),
        "start must wait for the old ingress to release its resources"
    );
    release.send(()).unwrap();
    let stopped = timeout(Duration::from_secs(1), stopping)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stopped.lifecycle(), ProxyLifecycle::Stopped);
    assert_eq!(
        timeout(Duration::from_secs(1), starting)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .lifecycle(),
        ProxyLifecycle::Running
    );
    service.stop().await.unwrap();
}

#[tokio::test]
async fn cancelled_stop_keeps_supervision_and_restart_serialized() {
    let service = test_proxy_service().await;
    let (_control, entered, release) = blocking_run(&service).await;
    let stopping_service = service.clone();
    let stopping = tokio::spawn(async move { stopping_service.stop().await });
    entered.await.unwrap();
    stopping.abort();
    assert!(stopping.await.unwrap_err().is_cancelled());
    let starting_service = service.clone();
    let mut starting = tokio::spawn(async move { starting_service.start(test_plan()).await });
    assert!(
        timeout(Duration::from_millis(30), &mut starting)
            .await
            .is_err()
    );
    assert_eq!(service.status().await.lifecycle(), ProxyLifecycle::Running);
    release.send(()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), starting)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .lifecycle(),
        ProxyLifecycle::Running
    );
    service.stop().await.unwrap();
}

#[tokio::test]
async fn explicit_stop_preserves_worker_failure_after_publishing_stopped() {
    let service = test_proxy_service().await;
    let (control, entered, release) = blocking_run(&service).await;
    let stopping_service = service.clone();
    let stopping = tokio::spawn(async move { stopping_service.stop().await });
    entered.await.unwrap();
    control.abort.abort();
    let result = timeout(Duration::from_secs(1), stopping)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(BrokerError::Task { source, .. }) if source.is_cancelled()));
    assert_stopped_without_control_request(&service).await;
    drop(release);
}

#[tokio::test]
async fn stale_completion_cannot_stop_a_newer_run() {
    let service = test_proxy_service().await;
    service.start(test_plan()).await.unwrap();
    let (sender, completed) = watch::channel(WorkerExit::Pending);
    let (release, released) = oneshot::channel();
    let worker = tokio::spawn(async move { released.await.unwrap() });
    let supervisor = tokio::spawn(
        WorkerSupervisor::new(Arc::downgrade(&service.state), Uuid::new_v4(), sender).run(worker),
    );
    release.send(()).unwrap();
    WorkerExit::wait(completed)
        .await
        .unwrap()
        .into_result()
        .unwrap();
    supervisor.await.unwrap();
    assert_eq!(service.status().await.lifecycle(), ProxyLifecycle::Running);
    service.stop().await.unwrap();
}

#[tokio::test]
async fn supervision_does_not_retain_the_last_service_handle() {
    let service = test_proxy_service().await;
    service.start(test_plan()).await.unwrap();
    let weak = Arc::downgrade(&service.state);
    let completed = {
        let state = service.state.lock().await;
        let ProxyRuntimeState::Started(runtime) = &*state else {
            panic!("started runtime");
        };
        let completed = runtime.task.completed.clone();
        drop(state);
        completed
    };
    drop(service);
    assert!(
        weak.upgrade().is_none(),
        "supervisor must not keep the state and shutdown sender alive"
    );
    timeout(Duration::from_secs(1), WorkerExit::wait(completed))
        .await
        .unwrap()
        .unwrap()
        .into_result()
        .unwrap();
}

#[cfg(target_os = "linux")]
struct ClosedTunIngress;

#[cfg(target_os = "linux")]
impl Ingress for ClosedTunIngress {
    type Accepted = PlatformFlow;

    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Self::Accepted, IngressError>> + Send {
        std::future::ready(Err(crate::ingress::linux::TunIngressError::Stopped.into()))
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn closed_tun_channel_publishes_normal_worker_exit_without_status_calls() {
    let service = test_proxy_service().await;
    let control = install(&service, ClosedTunIngress).await;
    control.finished().await.into_result().unwrap();
    assert_stopped_without_control_request(&service).await;
}
