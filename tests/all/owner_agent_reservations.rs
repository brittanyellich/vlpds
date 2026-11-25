use crate::common::cluster_node;
use std::sync::Arc;
use std::time::Duration;
use vlpds::xrpc::agent_provisioning::{Journal, SignupOutcome, Status};
use vlpds::xrpc::XResult;

const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const AGENT: &str = "did:plc:cccccccccccccccccccccccc";

#[track_caller]
fn ok<T>(result: XResult<T>) -> T {
    result.unwrap_or_else(|error| panic!("{}: {}", error.error, error.message))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_agent_reservations_are_atomic_and_survive_restart() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let first = cluster_node("agent-reservation-first", store.clone(), 4, |_| {}).await;
    let alice = Journal::new(&first.app, ALICE);
    let bob = Journal::new(&first.app, BOB);

    // Two different reservation IDs contend for Alice's last slot.
    let (a, b) =
        tokio::join!(alice.reserve("one", "first.vlpds.test", 1), alice.reserve("two", "second.vlpds.test", 1),);
    let (id, handle) = match (a, b) {
        (Ok(winner), Err(loser)) => {
            assert_eq!(loser.error, "AgentQuotaExceeded");
            ("one", winner.handle)
        }
        (Err(loser), Ok(winner)) => {
            assert_eq!(loser.error, "AgentQuotaExceeded");
            ("two", winner.handle)
        }
        _ => panic!("expected exactly one reservation"),
    };
    let (same, replay) = tokio::join!(alice.reserve(id, &handle, 1), alice.reserve(id, &handle, 1));
    assert_eq!(ok(same), ok(replay));
    assert_eq!(alice.reserve(id, "different.vlpds.test", 1).await.unwrap_err().error, "AgentProvisioningConflict");
    assert!(ok(bob.get(id).await).is_none());
    ok(bob.reserve(id, "bob-agent.vlpds.test", 1).await);

    // Only the caller winning the state transition may actually create.
    let (claim, parallel) = tokio::join!(alice.claim(id), alice.claim(id));
    let (claim, parallel) = (ok(claim), ok(parallel));
    let attempt = match (claim, parallel) {
        (Some(attempt), None) | (None, Some(attempt)) => attempt,
        _ => panic!("expected a single dispatch claim"),
    };
    assert_eq!(ok(bob.get(id).await).unwrap().status, Status::Reserved);
    assert!(bob.settle(id, attempt, SignupOutcome::Created { did: AGENT.into() }).await.is_err());
    assert_eq!(ok(alice.get(id).await).unwrap().status, Status::InFlight);

    assert!(vlpds::server::shutdown_gracefully(&first.app, Duration::from_secs(5)).await);
    drop(first);
    let reopened = cluster_node("agent-reservation-reopened", store, 4, |_| {}).await;
    let alice = Journal::new(&reopened.app, ALICE);
    let bob = Journal::new(&reopened.app, BOB);

    // A restarted coordinator must reconcile the original attempt rather
    // than dispatch a new signup when PLC or PDS may already have applied it.
    assert_eq!(ok(alice.get(id).await).unwrap().status, Status::InFlight);
    assert_eq!(ok(alice.claim(id).await), None);
    assert_eq!(ok(alice.settle(id, attempt, SignupOutcome::PlcUncertain).await).status, Status::PlcUncertain);
    assert_eq!(ok(alice.claim(id).await), None);
    assert!(alice.settle(id, attempt, SignupOutcome::RejectedBeforeCreation).await.is_err());
    assert_eq!(alice.reserve("new", "new-agent.vlpds.test", 1).await.unwrap_err().error, "AgentQuotaExceeded");

    // Bob's independent operation can retry once a definite pre-creation
    // failure is known. A late report from that old attempt is rejected.
    let before = ok(bob.claim(id).await).unwrap();
    assert_eq!(ok(bob.settle(id, before, SignupOutcome::RejectedBeforeCreation).await).status, Status::Reserved);
    let current = ok(bob.claim(id).await).unwrap();
    assert_ne!(before, current);
    assert!(bob.settle(id, before, SignupOutcome::Created { did: AGENT.into() }).await.is_err());
    let ready = ok(bob.settle(id, current, SignupOutcome::Created { did: AGENT.into() }).await);
    assert_eq!(ready.status, Status::Ready { did: AGENT.into() });
    assert_eq!(ok(bob.settle(id, current, SignupOutcome::Created { did: AGENT.into() }).await), ready);
    assert_eq!(ok(alice.get(id).await).unwrap().status, Status::PlcUncertain);
}
