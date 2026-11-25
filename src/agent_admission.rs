//! Local native wiring candidate. No production route is mounted.
//! Owner consent comes only from the authenticated internal CAS writer.
use crate::xrpc::agent_binding::{PairObservation, PairStatus};
use crate::{
    agent_endorsement::{AGENT, PRINCIPAL},
    xrpc::{authn, App},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
// One fixed pair: bound the entire admission/decision operation, never queue retries.
static ADMISSION_SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));
use std::{
    future::Future,
    sync::LazyLock,
    time::{Duration, SystemTime},
};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Consent {
    pub(crate) version: u8,
    pub(crate) principal: String,
    pub(crate) agent: String,
    pub(crate) caller: String,
    pub(crate) revision: u64,
    pub(crate) consent_granted: bool,
    pub(crate) enabled: bool,
    pub(crate) endorsement_revoked: bool,
    pub(crate) owner_disabled: bool,
}
impl Consent {
    fn allows(&self, caller: &str) -> bool {
        self.version == 1
            && self.principal == PRINCIPAL
            && self.agent == AGENT
            && self.caller == caller
            && self.consent_granted
            && self.enabled
            && !self.endorsement_revoked
            && !self.owner_disabled
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Caller,
    Consent,
    Evidence,
    Changed,
    Busy,
}
fn current_proof(proof: &PairObservation) -> bool {
    proof.agent == AGENT
        && proof.principal == PRINCIPAL
        && matches!(proof.status, PairStatus::Verified { .. })
        && SystemTime::now().duration_since(proof.observed_at).ok().is_some_and(|age| age <= Duration::from_secs(5))
}
async fn gate<T, Read, ReadFuture, Observe, ObserveFuture, Action, ActionFuture>(
    slots: &Semaphore,
    caller: &str,
    mut read: Read,
    observe: Observe,
    action: Action,
) -> Result<T, Refusal>
where
    Read: FnMut() -> ReadFuture,
    ReadFuture: Future<Output = Option<Consent>>,
    Observe: FnOnce() -> ObserveFuture,
    ObserveFuture: Future<Output = PairObservation>,
    Action: FnOnce() -> ActionFuture,
    ActionFuture: Future<Output = T>,
{
    let before = read().await.filter(|c| c.allows(caller)).ok_or(Refusal::Consent)?;
    let _slot = slots.try_acquire().map_err(|_| Refusal::Busy)?;
    let proof = observe().await;
    if !current_proof(&proof) {
        return Err(Refusal::Evidence);
    }
    // Recheck both content and revision after the asynchronous proof lookup.
    let after = read().await.ok_or(Refusal::Changed)?;
    if before != after || !after.allows(caller) {
        return Err(Refusal::Changed);
    }
    if !current_proof(&proof) {
        return Err(Refusal::Evidence);
    }
    // Revocation after this read may race already-admitted work; no cancellation claim.
    Ok(action().await)
}
/// Internal integration seam. `expected_caller` is server configuration, never JSON.
/// Authenticate before reading consent/proof, then gate BOTH cached return and dispatch.
/// This function has no caller-supplied proof/consent parameter and is not mounted.
pub async fn run_if_admitted<T, Action, ActionFuture>(
    app: &App,
    token: &str,
    expected_caller: &str,
    action: Action,
) -> Result<T, Refusal>
where
    Action: FnOnce() -> ActionFuture,
    ActionFuture: Future<Output = T>,
{
    let authenticated =
        authn::verify_agent_contact_jwt(app, token, expected_caller).await.map_err(|_| Refusal::Caller)?;
    gate(
        &ADMISSION_SLOTS,
        &authenticated.iss,
        || async {
            // Repeat token time/key verification before the final policy read too.
            authn::verify_agent_contact_jwt(app, token, expected_caller).await.ok()?;
            crate::agent_enrollment::current(app, PRINCIPAL, AGENT).await
        },
        crate::agent_endorsement_fetch::observe_fixed,
        action,
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    fn consent() -> Consent {
        Consent {
            version: 1,
            principal: PRINCIPAL.into(),
            agent: AGENT.into(),
            caller: "did:plc:fixturecaller".into(),
            revision: 1,
            consent_granted: true,
            enabled: true,
            endorsement_revoked: false,
            owner_disabled: false,
        }
    }
    fn proof(status: PairStatus) -> PairObservation {
        PairObservation { agent: AGENT.into(), principal: PRINCIPAL.into(), observed_at: SystemTime::now(), status }
    }
    fn verified() -> PairStatus {
        PairStatus::Verified {
            commit: vlatproto::cid::Cid::dag_cbor(b"synthetic-commit"),
            record: vlatproto::cid::Cid::dag_cbor(b"synthetic-record"),
        }
    }
    async fn attempt(
        row: Option<Consent>,
        observation: PairObservation,
        changed: Option<Consent>,
        action_count: Arc<AtomicUsize>,
    ) -> Result<&'static str, Refusal> {
        let rows = Arc::new(Mutex::new(row));
        let a = rows.clone();
        let b = rows.clone();
        let slots = Semaphore::new(1);
        gate(
            &slots,
            "did:plc:fixturecaller",
            move || {
                let v = a.lock().unwrap().clone();
                async move { v }
            },
            move || async move {
                *b.lock().unwrap() = changed;
                observation
            },
            move || async move {
                action_count.fetch_add(1, Ordering::SeqCst);
                "cached-or-dispatch"
            },
        )
        .await
    }
    #[tokio::test]
    async fn verified_evidence_alone_never_grants_consent() {
        for row in [
            None,
            Some(Consent { consent_granted: false, ..consent() }),
            Some(Consent { caller: "other".into(), ..consent() }),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            assert_eq!(attempt(row, proof(verified()), Some(consent()), count.clone()).await, Err(Refusal::Consent));
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn current_proof_and_independent_consent_allow_cache_or_dispatch_only_once() {
        let count = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            attempt(Some(consent()), proof(verified()), Some(consent()), count.clone()).await,
            Ok("cached-or-dispatch")
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn every_nonverified_observation_denies_even_a_cached_reply() {
        for status in [
            PairStatus::Unavailable,
            PairStatus::Undeclared,
            PairStatus::SignedAbsent { commit: vlatproto::cid::Cid::dag_cbor(b"absent") },
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            assert_eq!(
                attempt(Some(consent()), proof(status), Some(consent()), count.clone()).await,
                Err(Refusal::Evidence)
            );
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn disable_revoke_owner_shutoff_deletion_and_revision_change_during_proof_deny() {
        for row in [
            None,
            Some(Consent { enabled: false, ..consent() }),
            Some(Consent { endorsement_revoked: true, ..consent() }),
            Some(Consent { owner_disabled: true, ..consent() }),
            Some(Consent { revision: 2, ..consent() }),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            assert_eq!(attempt(Some(consent()), proof(verified()), row, count.clone()).await, Err(Refusal::Changed));
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn wrong_pair_stale_future_observation_and_disabled_initial_state_deny() {
        for p in [
            PairObservation { agent: PRINCIPAL.into(), ..proof(verified()) },
            PairObservation { observed_at: SystemTime::now() - Duration::from_secs(6), ..proof(verified()) },
            PairObservation { observed_at: SystemTime::now() + Duration::from_secs(60), ..proof(verified()) },
        ] {
            assert_eq!(
                attempt(Some(consent()), p, Some(consent()), Arc::new(AtomicUsize::new(0))).await,
                Err(Refusal::Evidence)
            );
        }
        for c in [
            Consent { enabled: false, ..consent() },
            Consent { endorsement_revoked: true, ..consent() },
            Consent { owner_disabled: true, ..consent() },
        ] {
            assert_eq!(
                attempt(Some(c), proof(verified()), Some(consent()), Arc::new(AtomicUsize::new(0))).await,
                Err(Refusal::Consent)
            );
        }
    }
    #[tokio::test]
    async fn slow_final_policy_read_cannot_extend_observation_age() {
        let mut reads = 0;
        let slots = Semaphore::new(1);
        let result: Result<(), Refusal> = gate(
            &slots,
            "did:plc:fixturecaller",
            move || {
                reads += 1;
                let delay = reads == 2;
                async move {
                    if delay {
                        tokio::time::sleep(Duration::from_millis(5100)).await;
                    }
                    Some(consent())
                }
            },
            || async { proof(verified()) },
            || async { panic!("stale proof must not reach cached reply or dispatch") },
        )
        .await;
        assert_eq!(result, Err(Refusal::Evidence));
    }
    #[tokio::test]
    async fn proof_budget_refuses_fanout_and_cancellation_releases_slot() {
        let slots = Arc::new(Semaphore::new(1));
        let entered = Arc::new(tokio::sync::Notify::new());
        let hold = Arc::new(tokio::sync::Notify::new());
        let first_slots = slots.clone();
        let first_entered = entered.clone();
        let first_hold = hold.clone();
        let first = tokio::spawn(async move {
            gate(
                &first_slots,
                "did:plc:fixturecaller",
                || async { Some(consent()) },
                || async move {
                    first_entered.notify_one();
                    first_hold.notified().await;
                    proof(verified())
                },
                || async {},
            )
            .await
        });
        entered.notified().await;
        let denied: Result<(), Refusal> = gate(
            &slots,
            "did:plc:fixturecaller",
            || async { Some(consent()) },
            || async { panic!("No second observer may start") },
            || async { panic!("No second action may start") },
        )
        .await;
        assert_eq!(denied, Err(Refusal::Busy));
        assert_eq!(slots.available_permits(), 0);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(
            gate(
                &slots,
                "did:plc:fixturecaller",
                || async { Some(consent()) },
                || async { proof(verified()) },
                || async {}
            )
            .await,
            Ok(())
        );
    }
}
