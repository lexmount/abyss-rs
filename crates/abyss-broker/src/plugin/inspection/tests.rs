//! Pending-decision cleanup and connection membership invariants.

use super::*;
use crate::plugin::InspectionPlan;

fn context() -> Arc<InspectionRequest> {
    let message: abyss_plugin_protocol::message::BrokerMessage =
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/broker-plugin-protocol/v1/fixtures/inspect-request.json"
        )))
        .unwrap();
    let abyss_plugin_protocol::message::BrokerMessage::InspectRequest { context } = message else {
        panic!("inspection fixture");
    };
    Arc::new(InspectionRequest::new(context).unwrap())
}

#[tokio::test(start_paused = true)]
async fn timeout_and_cancellation_remove_waiters_and_late_replies_are_ignored() {
    let registry = Arc::new(InspectionRegistry::default());
    let (registration, mut requests) = registry.register("test".to_owned());
    let session = registration.session.clone();
    let pending = tokio::spawn(async move {
        session
            .inspect(context(), Instant::now() + DECISION_TIMEOUT)
            .await
    });
    let request = requests.recv().await.unwrap();
    tokio::time::advance(DECISION_TIMEOUT).await;
    assert!(
        pending.await.unwrap().is_err(),
        "silent selected plugin must fail the request"
    );
    assert!(
        registration.session.pending.lock().is_empty(),
        "timeout must remove its waiter"
    );
    registration.session.reply(InspectResponse {
        request_id: request.request_id.clone(),
        decision: InspectionDecision::Allow,
    });
    let session = registration.session.clone();
    let pending = tokio::spawn(async move {
        session
            .inspect(context(), Instant::now() + DECISION_TIMEOUT)
            .await
    });
    let _request = requests.recv().await.unwrap();
    pending.abort();
    assert!(
        pending.await.unwrap_err().is_cancelled(),
        "request task must be cancelled"
    );
    assert!(
        registration.session.pending.lock().is_empty(),
        "cancelled requests must not leave pending state"
    );
}

#[tokio::test]
async fn selected_disconnect_fails_current_request_and_future_requests_use_current_membership() {
    let registry = Arc::new(InspectionRegistry::default());
    let participants = registry.subscribe();
    assert!(
        participants.borrow().is_empty(),
        "no plugins means ordinary streaming"
    );
    let (first, mut requests) = registry.register("test".to_owned());
    let (second, _requests) = registry.register("test".to_owned());
    let plan = InspectionPlan {
        sessions: participants.borrow().clone(),
        available: true,
    };
    let snapshot: Vec<_> = plan
        .participants()
        .map(|participant| registry.select(&participant).unwrap())
        .collect();
    assert!(
        Arc::ptr_eq(&snapshot[0], &first.session),
        "registration order must be stable"
    );
    assert!(
        Arc::ptr_eq(&snapshot[1], &second.session),
        "all selected connections must participate"
    );
    let session = snapshot[0].clone();
    let pending = tokio::spawn(async move {
        session
            .inspect(context(), Instant::now() + DECISION_TIMEOUT)
            .await
    });
    let _request = requests.recv().await.unwrap();
    drop(first);
    assert!(
        pending.await.unwrap().is_err(),
        "selected disconnect must fail its waiter"
    );
    assert_eq!(participants.borrow().len(), 1);
    assert!(
        registry
            .select(&plan.participants().next().unwrap())
            .is_err(),
        "a disconnected identity cannot be replaced"
    );
    assert!(
        snapshot[0]
            .inspect(context(), Instant::now() + DECISION_TIMEOUT)
            .await
            .is_err(),
        "old snapshots must retain closed session identity"
    );
    drop(second);
    assert!(
        participants.borrow().is_empty(),
        "future requests must return to streaming after last disconnect"
    );
}

#[tokio::test]
async fn caller_cancellation_cancels_server_task_and_session_waiter() {
    let registry = Arc::new(InspectionRegistry::default());
    let (registration, mut requests) = registry.register("test".to_owned());
    let plan = InspectionPlan {
        sessions: registry.subscribe().borrow().clone(),
        available: true,
    };
    let message: BrokerMessage = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/broker-plugin-protocol/v1/fixtures/inspect-request.json"
    )))
    .unwrap();
    let BrokerMessage::InspectRequest { context } = message else {
        panic!("fixture");
    };
    let (reply, response) = oneshot::channel();
    let task = tokio::spawn(
        InspectionTask::new(
            &registry,
            &plan.participants().next().unwrap(),
            context,
            Instant::now() + DECISION_TIMEOUT,
            reply,
        )
        .run(),
    );
    let _request = requests.recv().await.unwrap();
    assert_eq!(registration.session.pending.lock().len(), 1);
    drop(response);
    task.await.unwrap();
    assert!(registration.session.pending.lock().is_empty());
}
