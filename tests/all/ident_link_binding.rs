//! Pinned ident.link draft with disposable OAuth accounts and mock PLC.

use crate::common::{cluster_node, Auth, TestServer, J};
use crate::oauth::{self, Account, Browser, DpopKey, Flow, Srv, Tokens};
use serde_json::json;
use std::sync::Arc;
use vlatproto::crypto::Keypair;
use vlpds::agent_endorsement::{verify_pair, Outcome, TrustedSnapshot};
use vlpds::plc::{mock::MockPlc, PlcConfig, RotationKey};
use vlpds::xrpc::agent_binding::{observe, PairStatus};

mod grant_recovery;
mod signed_dispatch;

const COLLECTION: &str = "link.ident.endorsement";
const OWNER_SCOPE: &str = "atproto repo:link.ident.endorsement?action=create";
const AGENT_OPERATOR_SCOPE: &str = "atproto identity:*";
const LIST: &str = "vlpds.agent.listAgents";

async fn provision(s: &TestServer, principal: &Account, name: &str) -> Account {
    let handle = format!("{name}.vlpds.test");
    let response = s.xrpc.post(
        "vlpds.agent.provision",
        &json!({"operationId": "setup", "handle": handle, "email": format!("{name}@example.com"), "password": oauth::PASSWORD}),
        &Auth::Bearer(principal.jwt.clone()),
    ).await.ok();
    assert_eq!(response["status"], "ready");
    let did = response["did"].as_str().unwrap().to_owned();
    let login = s.create_session(&handle, oauth::PASSWORD).await.ok();
    assert_eq!(login["did"], did);
    Account { did, handle, jwt: login["accessJwt"].as_str().unwrap().to_owned() }
}

async fn agents(s: &TestServer, principal: &Account) -> J {
    let response = s.xrpc.get(LIST, &[], &Auth::Bearer(principal.jwt.clone())).await;
    assert_eq!(response.header("cache-control").as_deref(), Some("no-store"));
    response.ok()["agents"].clone()
}

fn listed_agent(agent: &Account) -> J {
    json!([{"did": agent.did, "handle": agent.handle}])
}

fn declared_aliases(original: &J, principal: &Account) -> J {
    let mut aliases = original.clone();
    aliases.as_array_mut().unwrap().push(json!(format!("https://ident.link/agent-of/{}", principal.did)));
    aliases
}

async fn verified(s: &TestServer, plc: &MockPlc, owner: &str, agent: &str) -> Result<Outcome, String> {
    let (head_before, _) = s.latest_commit(owner).await;
    let owner_doc = vlpds::plc::format_did_doc(&plc.data(owner).unwrap());
    let agent_doc = vlpds::plc::format_did_doc(&plc.data(agent).unwrap());
    let record = s
        .xrpc
        .get("com.atproto.repo.getRecord", &[("repo", owner), ("collection", COLLECTION), ("rkey", agent)], &Auth::None)
        .await;
    let independent = match record.status {
        200 => Some(&record.json),
        400 | 404 if record.error_name() == Some("RecordNotFound") => None,
        _ => return Err("Independent record read unavailable".into()),
    };
    let car = s
        .xrpc
        .get("com.atproto.sync.getRecord", &[("did", owner), ("collection", COLLECTION), ("rkey", agent)], &Auth::None)
        .await;
    if car.status != 200 {
        return Err("Repository proof unavailable".into());
    }
    let (head_after, _) = s.latest_commit(owner).await;
    let snapshot =
        TrustedSnapshot { agent_document: &agent_doc, principal_document: &owner_doc, head_before, head_after };
    verify_pair(agent, owner, &snapshot, &car.body, independent)
}

async fn endorsement(srv: &Srv, flow: &Flow<'_>, grant: &Tokens, repo: &str, agent: &str) -> oauth::Resp {
    oauth::xrpc_dpop(
        srv,
        flow.key,
        &grant.access,
        "POST",
        "com.atproto.repo.createRecord",
        Some(json!({
            "repo": repo, "collection": COLLECTION, "rkey": agent,
            "record": {"$type": COLLECTION, "agent": agent},
            "validate": false,
        })),
    )
    .await
}

async fn change_aliases(
    s: &TestServer,
    srv: &Srv,
    plc: &MockPlc,
    agent: &Account,
    flow: &Flow<'_>,
    grant: &Tokens,
    aliases: J,
) {
    let before = plc.data(&agent.did).unwrap();
    let requested = oauth::xrpc_dpop(
        srv,
        flow.key,
        &grant.access,
        "POST",
        "com.atproto.identity.requestPlcOperationSignature",
        None,
    )
    .await;
    assert_eq!(requested.status, 200, "{}", requested.body);
    let account = s.get_session(&Auth::Bearer(agent.jwt.clone())).await.ok();
    let email = account["email"].as_str().expect("disposable account has email");
    let token = s.mail_token(email).await.expect("disposable mail spool has confirmation");
    let signed = oauth::xrpc_dpop(
        srv,
        flow.key,
        &grant.access,
        "POST",
        "com.atproto.identity.signPlcOperation",
        Some(json!({
            "token": token,
            "alsoKnownAs": aliases,
            "rotationKeys": before["rotationKeys"],
            "verificationMethods": before["verificationMethods"],
            "services": before["services"],
        })),
    )
    .await;
    assert_eq!(signed.status, 200, "{}", signed.body);
    let op = &signed.body["operation"];
    assert_eq!(op["alsoKnownAs"], aliases);
    for field in ["rotationKeys", "verificationMethods", "services"] {
        assert_eq!(op[field], before[field]);
    }
    assert_eq!(plc.data(&agent.did).unwrap(), before);
    let submitted = oauth::xrpc_dpop(
        srv,
        flow.key,
        &grant.access,
        "POST",
        "com.atproto.identity.submitPlcOperation",
        Some(json!({"operation": op})),
    )
    .await;
    assert_eq!(submitted.status, 200, "{}", submitted.body);
    let after = plc.data(&agent.did).unwrap();
    assert_eq!(after["alsoKnownAs"], aliases);
    for field in ["rotationKeys", "verificationMethods", "services"] {
        assert_eq!(after[field], before[field]);
    }
}

async fn delete_endorsement(s: &TestServer, owner: &Account, agent: &Account) {
    s.xrpc
        .post(
            "com.atproto.repo.deleteRecord",
            &json!({"repo": owner.did, "collection": COLLECTION, "rkey": agent.did}),
            &Auth::Bearer(owner.jwt.clone()),
        )
        .await
        .ok();
}

fn is_verified(result: Result<Outcome, String>) -> bool {
    matches!(result, Ok(Outcome::Verified { .. }))
}

async fn node(
    plc: &MockPlc,
    rotation_key: Arc<Keypair>,
    store: Arc<object_store::memory::InMemory>,
    id: &str,
) -> TestServer {
    let url = plc.url.clone();
    cluster_node(id, store, 4, move |config| {
        config.plc_url = url;
        config.service_did = "did:web:pds.test".into();
        config.spaces = true;
        config.plc = PlcConfig { rotation_key: Some(RotationKey::Key(rotation_key)), ..Default::default() };
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ident_link_binding_requires_both_consents_and_either_party_can_revoke() {
    let plc = MockPlc::start().await;
    let store = Arc::new(object_store::memory::InMemory::new());
    let rotation_key = Arc::new(Keypair::generate());
    let s = node(&plc, rotation_key.clone(), store.clone(), "ident-first").await;
    let srv = Srv {
        app: s.app.clone(),
        base: s.url.clone(),
        http: reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    };
    let alice = oauth::create_account(&srv, "identalice").await;
    let bob = oauth::create_account(&srv, "identbob").await;
    let agent = provision(&s, &alice, "identagent").await;
    let bob_agent = provision(&s, &bob, "identbobagent").await;
    assert_eq!(s.xrpc.get(LIST, &[], &Auth::None).await.status, 401);
    assert_eq!(agents(&s, &alice).await, json!([]));
    assert_eq!(agents(&s, &bob).await, json!([]));
    let alice_key = DpopKey::new();
    let bob_key = DpopKey::new();
    let agent_key = DpopKey::new();
    let alice_flow = Flow::loopback(OWNER_SCOPE, &alice_key);
    let bob_flow = Flow::loopback(OWNER_SCOPE, &bob_key);
    let agent_flow = Flow::loopback(AGENT_OPERATOR_SCOPE, &agent_key);
    let alice_grant = oauth::grant(&srv, &mut Browser::default(), &alice_flow, &alice).await;
    let bob_grant = oauth::grant(&srv, &mut Browser::default(), &bob_flow, &bob).await;
    assert_eq!(alice_grant.scope, OWNER_SCOPE);

    assert!(!is_verified(verified(&s, &plc, &alice.did, &agent.did).await));
    let wrong_repo = endorsement(&srv, &bob_flow, &bob_grant, &alice.did, &agent.did).await;
    assert_eq!(wrong_repo.status, 401, "{}", wrong_repo.body);
    assert_eq!(endorsement(&srv, &alice_flow, &alice_grant, &alice.did, &agent.did).await.status, 200);
    // A principal's create-only grant cannot request the identity email.
    assert_eq!(
        oauth::xrpc_dpop(
            &srv,
            &alice_key,
            &alice_grant.access,
            "POST",
            "com.atproto.identity.requestPlcOperationSignature",
            None,
        )
        .await
        .status,
        403
    );
    assert!(!is_verified(verified(&s, &plc, &alice.did, &agent.did).await));
    assert_eq!(agents(&s, &alice).await, json!([]));

    let agent_grant = oauth::grant(&srv, &mut Browser::default(), &agent_flow, &agent).await;
    assert_eq!(agent_grant.scope, AGENT_OPERATOR_SCOPE);
    let original = plc.data(&agent.did).unwrap()["alsoKnownAs"].clone();
    let aliases = declared_aliases(&original, &alice);
    change_aliases(&s, &srv, &plc, &agent, &agent_flow, &agent_grant, aliases).await;
    assert!(is_verified(verified(&s, &plc, &alice.did, &agent.did).await));

    // The other owner can endorse in its own repo. Its separate signed
    // endorsement cannot substitute for the missing agent declaration.
    assert_eq!(endorsement(&srv, &bob_flow, &bob_grant, &bob.did, &agent.did).await.status, 200);
    assert!(!is_verified(verified(&s, &plc, &bob.did, &agent.did).await));
    assert_eq!(agents(&s, &alice).await, listed_agent(&agent));
    assert_eq!(agents(&s, &bob).await, json!([]));

    // Even a valid public relationship cannot add another owner's
    // provisioned agent to this owner's private list.
    let shared = declared_aliases(&declared_aliases(&original, &alice), &bob);
    change_aliases(&s, &srv, &plc, &agent, &agent_flow, &agent_grant, shared).await;
    assert!(is_verified(verified(&s, &plc, &bob.did, &agent.did).await));
    assert_eq!(agents(&s, &bob).await, json!([]));

    // The second owner starts with a declaration and no endorsement.
    let bob_agent_key = DpopKey::new();
    let bob_agent_flow = Flow::loopback(AGENT_OPERATOR_SCOPE, &bob_agent_key);
    let bob_agent_grant = oauth::grant(&srv, &mut Browser::default(), &bob_agent_flow, &bob_agent).await;
    let bob_original = plc.data(&bob_agent.did).unwrap()["alsoKnownAs"].clone();
    change_aliases(
        &s,
        &srv,
        &plc,
        &bob_agent,
        &bob_agent_flow,
        &bob_agent_grant,
        declared_aliases(&bob_original, &bob),
    )
    .await;
    assert_eq!(agents(&s, &bob).await, json!([]));
    assert_eq!(endorsement(&srv, &bob_flow, &bob_grant, &bob.did, &bob_agent.did).await.status, 200);
    assert_eq!(agents(&s, &bob).await, listed_agent(&bob_agent));
    assert_eq!(agents(&s, &alice).await, listed_agent(&agent));
    let foreign_filter = s.xrpc.get(LIST, &[("did", &bob.did)], &Auth::Bearer(alice.jwt.clone())).await.ok();
    assert_eq!(foreign_filter["agents"], listed_agent(&agent));

    let recovery_issuer = grant_recovery::before_restart(&s, &alice, &agent, &bob).await;

    let bridge = signed_dispatch::Bridge::start(&s, &plc).await;
    let alice_binding = signed_dispatch::Bridge::approve(&s, &alice, &agent, "alice").await;
    let bob_binding = signed_dispatch::Bridge::approve(&s, &bob, &bob_agent, "bob").await;
    signed_dispatch::Bridge::approve(&s, &alice, &agent, "race").await;
    bridge.check_denials(&alice, &bob, &alice_binding).await;
    bridge.revoke_in_flight(&s, &alice, "race").await;
    bridge.check(&bob, "bob", Some(&bob_binding)).await;

    let restore = plc.data(&agent.did).unwrap()["alsoKnownAs"].clone();
    let (server, oauth_server, directory, owner, operator) = (&s, &srv, &plc, &alice, &agent);
    let (owner_flow, owner_grant, operator_flow, operator_grant) =
        (&alice_flow, &alice_grant, &agent_flow, &agent_grant);
    let (undeclared, declared) = (&original, &restore);
    let worker_grants = crate::spaces_mcp_chat::check_verified_bridge(
        &s,
        &plc,
        [(&alice, &agent), (&bob, &bob_agent)],
        |phase| async move {
            match phase.as_str() {
                "remove-endorsement" => delete_endorsement(server, owner, operator).await,
                "restore-endorsement" => {
                    assert_eq!(
                        endorsement(oauth_server, owner_flow, owner_grant, &owner.did, &operator.did).await.status,
                        200
                    );
                }
                "remove-declaration" | "restore-declaration" => {
                    let aliases = if phase == "remove-declaration" { undeclared } else { declared };
                    change_aliases(
                        server,
                        oauth_server,
                        directory,
                        operator,
                        operator_flow,
                        operator_grant,
                        aliases.clone(),
                    )
                    .await;
                }
                _ => panic!("unknown fixture phase"),
            }
        },
    )
    .await;

    // Owner revocation uses the existing full PDS session, separate from the
    // create-only approval. The current signed CAR proves record absence.
    bridge.deny_while_resolving(&alice, "alice", delete_endorsement(&s, &alice, &agent)).await;
    bridge.check(&alice, "alice", None).await;
    bridge.check(&bob, "bob", Some(&bob_binding)).await;
    assert!(matches!(verified(&s, &plc, &alice.did, &agent.did).await, Ok(Outcome::Absent { .. })));
    assert_eq!(agents(&s, &alice).await, json!([]));
    assert_eq!(agents(&s, &bob).await, listed_agent(&bob_agent));

    assert_eq!(endorsement(&srv, &alice_flow, &alice_grant, &alice.did, &agent.did).await.status, 200);
    assert!(is_verified(verified(&s, &plc, &alice.did, &agent.did).await));
    assert_eq!(agents(&s, &alice).await, listed_agent(&agent));
    bridge.check(&alice, "alice", Some(&alice_binding)).await;
    change_aliases(&s, &srv, &plc, &agent, &agent_flow, &agent_grant, original).await;
    bridge.check(&alice, "alice", None).await;
    bridge.check(&bob, "bob", Some(&bob_binding)).await;
    assert!(!is_verified(verified(&s, &plc, &alice.did, &agent.did).await));
    assert_eq!(agents(&s, &alice).await, json!([]));
    assert_eq!(agents(&s, &bob).await, listed_agent(&bob_agent));

    for (flow, grant) in [
        (&alice_flow, &alice_grant),
        (&bob_flow, &bob_grant),
        (&agent_flow, &agent_grant),
        (&bob_agent_flow, &bob_agent_grant),
    ] {
        let refresh = grant.refresh.as_deref().unwrap();
        assert_eq!(
            oauth::as_post(&srv, flow.key, "/oauth/revoke", &[("client_id", &flow.client_id), ("token", refresh)],)
                .await
                .status,
            200
        );
        assert_eq!(oauth::refresh(&srv, flow, refresh, &[]).await.body["error"], "invalid_grant");
    }
    assert_eq!(
        oauth::xrpc_dpop(
            &srv,
            &agent_key,
            &agent_grant.access,
            "POST",
            "com.atproto.identity.requestPlcOperationSignature",
            None,
        )
        .await
        .status,
        401
    );

    assert!(vlpds::server::shutdown_gracefully(&s.app, std::time::Duration::from_secs(5)).await);
    drop((bridge, srv, s));
    let restarted = node(&plc, rotation_key, store, "ident-restarted").await;
    grant_recovery::after_restart(&restarted, &alice, recovery_issuer).await;
    assert_eq!(agents(&restarted, &alice).await, json!([]));
    assert_eq!(agents(&restarted, &bob).await, listed_agent(&bob_agent));
    if let Some([alice_grant, bob_grant]) = worker_grants {
        use vlpds::xrpc::agent_dispatch::resolve;
        let resource = format!("{}/mcp", alice_grant.issuer);
        assert_eq!(resolve(&restarted.app, alice_grant.grant(&resource, &alice.did)).await, None);
        assert_eq!(
            resolve(&restarted.app, bob_grant.grant(&resource, &bob.did)).await.as_ref(),
            Some(&bob_grant.binding)
        );
        assert_eq!(resolve(&restarted.app, bob_grant.grant(&resource, &alice.did)).await, None);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ident_link_existing_dids_verify_without_provisioning_marker() {
    use tokio::sync::Notify;
    use vlpds::xrpc::agent_provisioning::{binding_is_verified, Journal, SignupOutcome};
    use vlpds::xrpc::cas::set_pause_hook;

    let plc = MockPlc::start().await;
    let s = node(&plc, Arc::new(Keypair::generate()), Arc::new(object_store::memory::InMemory::new()), "existing-dids")
        .await;
    let srv = Srv {
        app: s.app.clone(),
        base: s.url.clone(),
        http: reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    };

    // These accounts use regular signup, independently of provisioning.
    let owner = oauth::create_account(&srv, "existingowner").await;
    let agent = oauth::create_account(&srv, "existingagent").await;
    assert_eq!(observe(&s.app, &agent.did, &owner.did).await.status, PairStatus::Undeclared);
    let owner_key = DpopKey::new();
    let agent_key = DpopKey::new();
    let owner_flow = Flow::loopback(OWNER_SCOPE, &owner_key);
    let agent_flow = Flow::loopback(AGENT_OPERATOR_SCOPE, &agent_key);
    let owner_grant = oauth::grant(&srv, &mut Browser::default(), &owner_flow, &owner).await;
    let agent_grant = oauth::grant(&srv, &mut Browser::default(), &agent_flow, &agent).await;
    let original = plc.data(&agent.did).unwrap()["alsoKnownAs"].clone();
    change_aliases(&s, &srv, &plc, &agent, &agent_flow, &agent_grant, declared_aliases(&original, &owner)).await;
    assert!(matches!(observe(&s.app, &agent.did, &owner.did).await.status, PairStatus::SignedAbsent { .. }));
    let published = endorsement(&srv, &owner_flow, &owner_grant, &owner.did, &agent.did).await;
    assert_eq!(published.status, 200);
    let started = std::time::SystemTime::now();
    let observed = observe(&s.app, &agent.did, &owner.did).await;
    assert_eq!((&observed.agent, &observed.principal), (&agent.did, &owner.did));
    assert!(observed.observed_at >= started);
    let PairStatus::Verified { record, .. } = observed.status else {
        panic!("expected signed pair, got {observed:?}");
    };
    assert_eq!(record.to_string(), published.body["cid"].as_str().unwrap());

    // Even a ready reservation cannot bypass the original signup marker.
    let journal = Journal::new(&s.app, &owner.did);
    journal.reserve("existing", &agent.handle, 1).await.map_err(|e| e.message).unwrap();
    let attempt = journal.claim("existing").await.map_err(|e| e.message).unwrap().unwrap();
    journal
        .settle("existing", attempt, SignupOutcome::Created { did: agent.did.clone() })
        .await
        .map_err(|e| e.message)
        .unwrap();
    assert_eq!(agents(&s, &owner).await, json!([]));
    assert!(!binding_is_verified(&s.app, &owner.did, &agent.did).await);

    // A concurrent repo change invalidates a proof that was otherwise valid.
    let reached = Arc::new(Notify::new());
    let proceed = Arc::new(Notify::new());
    let (signal, resume) = (reached.clone(), proceed.clone());
    set_pause_hook(
        &owner.did,
        Some(Arc::new(move |point| {
            let hold = point == "agent_binding_before_final_snapshot";
            let (signal, resume) = (signal.clone(), resume.clone());
            Box::pin(async move {
                if hold {
                    signal.notify_one();
                    resume.notified().await;
                }
            })
        })),
    );
    let (changed, ()) = tokio::join!(observe(&s.app, &agent.did, &owner.did), async {
        tokio::time::timeout(std::time::Duration::from_secs(2), reached.notified()).await.unwrap();
        delete_endorsement(&s, &owner, &agent).await;
        proceed.notify_one();
    });
    set_pause_hook(&owner.did, None);
    assert_eq!(changed.status, PairStatus::Unavailable);
    assert!(matches!(observe(&s.app, &agent.did, &owner.did).await.status, PairStatus::SignedAbsent { .. }));
    plc.set_down(true);
    assert_eq!(observe(&s.app, &agent.did, &owner.did).await.status, PairStatus::Unavailable);
}
