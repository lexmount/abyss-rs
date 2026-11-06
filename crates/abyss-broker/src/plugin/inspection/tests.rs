//! Pending-decision cleanup and connection membership invariants.

use super::*;

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
    let (registration, mut requests) = registry.register();
    let session = registration.session.clone();
    let pending = tokio::spawn(async move { session.inspect(context()).await });
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
        allow: true,
        reason: None,
    });
    let session = registration.session.clone();
    let pending = tokio::spawn(async move { session.inspect(context()).await });
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
    let inspector =
        AgentRequestInspector::new(registry.clone(), HooksRuntimeConfig::default_enabled());
    assert!(
        inspector.plan().is_none(),
        "no plugins means ordinary streaming"
    );
    let (first, mut requests) = registry.register();
    let (second, _requests) = registry.register();
    let snapshot = inspector.plan().unwrap();
    assert!(
        Arc::ptr_eq(&snapshot[0], &first.session),
        "registration order must be stable"
    );
    assert!(
        Arc::ptr_eq(&snapshot[1], &second.session),
        "all selected connections must participate"
    );
    let session = snapshot[0].clone();
    let pending = tokio::spawn(async move { session.inspect(context()).await });
    let _request = requests.recv().await.unwrap();
    drop(first);
    assert!(
        pending.await.unwrap().is_err(),
        "selected disconnect must fail its waiter"
    );
    assert_eq!(inspector.plan().unwrap().len(), 1);
    assert!(
        snapshot[0].inspect(context()).await.is_err(),
        "old snapshots must retain closed session identity"
    );
    drop(second);
    assert!(
        inspector.plan().is_none(),
        "future requests must return to streaming after last disconnect"
    );
}
