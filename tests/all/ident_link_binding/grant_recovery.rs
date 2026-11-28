use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use vlpds::xrpc::{
    agent_dispatch::{resolve, Binding, Grant},
    agent_grant_recovery::{
        runner::{resume_abandoned, CleanupOutcome, IssuedGrant, Lookup, Progress, Provider},
        CleanupTarget, Observation, Recovery, Request, State,
    },
    authn::{authenticate, Credentials},
};

const ISSUER: &str = "https://recovery.example.invalid";
const RESOURCE: &str = "https://recovery.example.invalid/mcp";
const CLIENT: &str = "fixture-client";

fn request(owner: &Account, agent: &Account, digest: u8) -> Request {
    Request {
        issuer: ISSUER.into(),
        resource: RESOURCE.into(),
        client: CLIENT.into(),
        request_digest: [digest; 32],
        binding: Binding {
            agent: agent.did.clone(),
            space: format!("at:space/{}/com.example.mcpchat/recovery", owner.did),
        },
    }
}

fn grant<'a>(owner: &'a Account, id: &'a str) -> Grant<'a> {
    Grant { issuer: ISSUER, resource: RESOURCE, id, owner: &owner.did }
}

fn observe_grant<'a>(owner: &'a Account, id: &'a str, correlation: &'a str) -> Observation<'a> {
    Observation { grant: grant(owner, id), client: CLIENT, correlation }
}

async fn credentials(s: &TestServer, owner: &Account) -> Credentials {
    let (parts, _) = axum::http::Request::builder()
        .header("authorization", format!("Bearer {}", owner.jwt))
        .body(())
        .unwrap()
        .into_parts();
    authenticate(&s.app, &parts).await.unwrap_or_else(|error| panic!("{}", error.message))
}

fn checked<T>(result: vlpds::xrpc::XResult<T>) -> T {
    result.unwrap_or_else(|error| panic!("{}", error.message))
}

/// An issuer call may leave a durable grant behind before its redirect is
/// lost. This fixture preserves its correlation record across the PDS restart.
#[derive(Default)]
pub(super) struct Issuer {
    minted: AtomicUsize,
    grants: parking_lot::Mutex<std::collections::HashMap<String, String>>,
}

impl Issuer {
    async fn issue(&self, recovery: &Recovery<'_>, operation: &str) -> Option<String> {
        let correlation = checked(recovery.claim(operation).await)?;
        let id = format!("grant-{}", self.minted.fetch_add(1, Ordering::Relaxed) + 1);
        self.grants.lock().insert(correlation, id.clone());
        Some(id)
    }

    fn find(&self, correlation: &str) -> Option<String> {
        self.grants.lock().get(correlation).cloned()
    }

    fn remove(&self, correlation: &str) {
        self.grants.lock().remove(correlation);
    }
}

pub(super) async fn before_restart(s: &TestServer, alice: &Account, agent: &Account, bob: &Account) -> Issuer {
    let alice_credentials = credentials(s, alice).await;
    let bob_credentials = credentials(s, bob).await;
    let alice_recovery = checked(Recovery::for_owner(&s.app, &alice_credentials, &alice.did).await);
    let bob_recovery = checked(Recovery::for_owner(&s.app, &bob_credentials, &bob.did).await);
    assert!(Recovery::for_owner(&s.app, &bob_credentials, &alice.did).await.is_err());
    let req = request(alice, agent, 1);
    let (one, two) =
        tokio::join!(alice_recovery.reserve("lost", req.clone()), alice_recovery.reserve("lost", req.clone()));
    let intent = checked(one);
    assert_eq!(intent, checked(two));
    assert!(alice_recovery.reserve("lost", request(alice, agent, 2)).await.is_err());
    assert!(checked(bob_recovery.get("lost").await).is_none());
    assert!(bob_recovery.reserve("lost", req).await.is_err());

    let issuer = Issuer::default();
    let (one, two) = tokio::join!(issuer.issue(&alice_recovery, "lost"), issuer.issue(&alice_recovery, "lost"));
    assert_eq!(one.is_some() as usize + two.is_some() as usize, 1);
    let id = one.or(two).unwrap();
    assert_eq!(id, "grant-1");
    assert_eq!(resolve(&s.app, grant(alice, &id)).await, None);
    let redacted = observe_grant(alice, &id, "other-correlation");
    assert!(alice_recovery.reconcile_lost_redirect("lost", &redacted).await.is_err());
    // Issuer response was lost and lookup is temporarily unavailable.
    // Leave the intent issuing. A new claim must not mint a second grant.
    assert_eq!(issuer.issue(&alice_recovery, "lost").await, None);
    assert_eq!(issuer.minted.load(Ordering::Relaxed), 1);

    let abandoned = checked(alice_recovery.reserve("abandoned", request(alice, agent, 4)).await);
    let abandoned_id = issuer.issue(&alice_recovery, "abandoned").await.unwrap();
    let abandoned_grant = observe_grant(alice, &abandoned_id, &abandoned.correlation);
    checked(alice_recovery.cancel("abandoned").await);
    assert!(alice_recovery.issued("abandoned", &abandoned_grant).await.is_err());
    assert_eq!(resolve(&s.app, grant(alice, &abandoned_id)).await, None);

    let bound = checked(alice_recovery.reserve("delivered", request(alice, agent, 3)).await);
    let id = issuer.issue(&alice_recovery, "delivered").await.unwrap();
    let observed = observe_grant(alice, &id, &bound.correlation);
    let (one, two) =
        tokio::join!(alice_recovery.issued("delivered", &observed), alice_recovery.issued("delivered", &observed));
    assert_eq!(checked(one) as usize + checked(two) as usize, 1);
    assert_eq!(resolve(&s.app, grant(alice, &id)).await, Some(bound.request.binding));
    checked(alice_recovery.cancel("delivered").await);
    assert_eq!(resolve(&s.app, grant(alice, &id)).await, None);
    // The issuer deleted the grant, but its result was lost before we could
    // acknowledge it. The restart must safely retry the same cleanup.
    issuer.remove(&bound.correlation);
    assert!(alice_recovery.acknowledge("delivered", "wrong-grant", CleanupTarget::Issuer).await.is_err());
    checked(alice_recovery.acknowledge("delivered", &id, CleanupTarget::Upstream).await);
    issuer
}

pub(super) async fn after_restart(s: &TestServer, alice: &Account, issuer: Issuer) {
    let credentials = credentials(s, alice).await;
    let recovery = checked(Recovery::for_owner(&s.app, &credentials, &alice.did).await);
    let intent = checked(recovery.get("lost").await).unwrap();
    assert_eq!(intent.state, State::Issuing);
    assert_eq!(issuer.issue(&recovery, "lost").await, None);
    let id = issuer.find(&intent.correlation).unwrap();
    let observation = observe_grant(alice, &id, &intent.correlation);
    checked(recovery.reconcile_lost_redirect("lost", &observation).await);
    checked(recovery.reconcile_lost_redirect("lost", &observation).await);
    assert_eq!(resolve(&s.app, grant(alice, &id)).await, None);
    assert!(recovery.issued("lost", &observation).await.is_err());
    assert_eq!(issuer.issue(&recovery, "lost").await, None);
    issuer.remove(&intent.correlation);
    let (one, two) = tokio::join!(
        recovery.acknowledge("lost", &id, CleanupTarget::Issuer),
        recovery.acknowledge("lost", &id, CleanupTarget::Upstream),
    );
    checked(one);
    checked(two);
    assert_eq!(checked(recovery.get("lost").await).unwrap().state, State::Closed { grant: Some(id) });

    let closed = checked(recovery.reserve("lost", intent.request).await);
    assert!(matches!(closed.state, State::Closed { .. }));
    assert!(checked(recovery.claim("lost").await).is_none());

    let delivered = checked(recovery.get("delivered").await).unwrap();
    assert_eq!(delivered.state, State::Cleanup { grant: "grant-3".into(), issuer_done: false, upstream_done: true });
    assert_eq!(resolve(&s.app, grant(alice, "grant-3")).await, None);
    issuer.remove(&delivered.correlation);
    checked(recovery.acknowledge("delivered", "grant-3", CleanupTarget::Issuer).await);
    checked(recovery.acknowledge("delivered", "grant-3", CleanupTarget::Issuer).await);
    assert_eq!(
        checked(recovery.get("delivered").await).unwrap().state,
        State::Closed { grant: Some("grant-3".into()) }
    );
    let abandoned = checked(recovery.get("abandoned").await).unwrap();
    assert_eq!(abandoned.state, State::Abandoned);
    assert_eq!(issuer.issue(&recovery, "abandoned").await, None);
    let abandoned_id = issuer.find(&abandoned.correlation).unwrap();
    let mut adapter = Adapter {
        owner: alice.did.clone(),
        correlation: abandoned.correlation.clone(),
        grant: abandoned_id.clone(),
        visible: false,
        issuer_calls: AtomicUsize::new(0),
        upstream_calls: AtomicUsize::new(0),
    };
    assert_eq!(checked(resume_abandoned(&recovery, "abandoned", &adapter).await), Progress::WaitingForIssuer);
    assert_eq!(adapter.issuer_calls.load(Ordering::Relaxed), 0);
    assert_eq!(issuer.issue(&recovery, "abandoned").await, None);

    adapter.visible = true;
    let wrong_owner = std::mem::replace(&mut adapter.owner, "did:plc:foreign".into());
    assert!(resume_abandoned(&recovery, "abandoned", &adapter).await.is_err());
    assert_eq!(checked(recovery.get("abandoned").await).unwrap().state, State::Abandoned);
    adapter.owner = wrong_owner;

    assert_eq!(checked(resume_abandoned(&recovery, "abandoned", &adapter).await), Progress::CleanupPending);
    assert_eq!(resolve(&s.app, grant(alice, &abandoned_id)).await, None);
    assert_eq!(
        checked(recovery.get("abandoned").await).unwrap().state,
        State::Cleanup { grant: abandoned_id.clone(), issuer_done: false, upstream_done: true }
    );
    assert_eq!(checked(resume_abandoned(&recovery, "abandoned", &adapter).await), Progress::Closed);
    assert_eq!(checked(resume_abandoned(&recovery, "abandoned", &adapter).await), Progress::Closed);
    assert_eq!(adapter.issuer_calls.load(Ordering::Relaxed), 2);
    assert_eq!(adapter.upstream_calls.load(Ordering::Relaxed), 1);
    assert_eq!(issuer.minted.load(Ordering::Relaxed), 3);
}

struct Adapter {
    owner: String,
    correlation: String,
    grant: String,
    visible: bool,
    issuer_calls: AtomicUsize,
    upstream_calls: AtomicUsize,
}

impl Provider for Adapter {
    async fn lookup(&self, _owner: &str, request: &Request, correlation: &str) -> vlpds::xrpc::XResult<Lookup> {
        assert_eq!(correlation, self.correlation);
        assert_eq!((&*request.issuer, &*request.resource, &*request.client), (ISSUER, RESOURCE, CLIENT));
        Ok(if self.visible {
            Lookup::Found(IssuedGrant {
                owner: self.owner.clone(),
                issuer: ISSUER.into(),
                resource: RESOURCE.into(),
                client: CLIENT.into(),
                correlation: self.correlation.clone(),
                id: self.grant.clone(),
            })
        } else {
            Lookup::Pending
        })
    }

    async fn cleanup(&self, grant: Grant<'_>, target: CleanupTarget) -> CleanupOutcome {
        assert_eq!(
            (grant.owner, grant.issuer, grant.resource, grant.id),
            (&*self.owner, ISSUER, RESOURCE, &*self.grant)
        );
        match target {
            CleanupTarget::Issuer if self.issuer_calls.fetch_add(1, Ordering::Relaxed) == 0 => CleanupOutcome::Retry,
            CleanupTarget::Issuer => CleanupOutcome::Complete,
            CleanupTarget::Upstream => {
                self.upstream_calls.fetch_add(1, Ordering::Relaxed);
                CleanupOutcome::Complete
            }
        }
    }
}
