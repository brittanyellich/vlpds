//! In-crate only: actual loopback router + synthetic signed authority + stub bridge.
macro_rules! suite_only {
    ($($i:item)*) => {};
}
#[path = "../tests/all/common/mod.rs"]
pub(crate) mod common;
use crate::{
    agent_a2a::NativeA2a,
    agent_contact_pilot::AGENT_PATH,
    agent_endorsement::{AGENT, PRINCIPAL},
    agent_endorsement_fetch::{
        self,
        fixture_transport::{self, Authority, Mode},
    },
    agent_enrollment::{Action, Operation, OwnerConsentTransport},
    agent_profile_bridge::Bridge,
};
use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use common::{json, TestServer, J};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tower::ServiceExt;
struct StartingChild(Option<Child>);
impl std::ops::Deref for StartingChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.0.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for StartingChild {
    fn deref_mut(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
}
impl StartingChild {
    fn into_child(mut self) -> Child {
        self.0.take().unwrap()
    }
}
impl Drop for StartingChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
struct Stub {
    child: Child,
    counter: Arc<AtomicUsize>,
    reader: Option<std::thread::JoinHandle<()>>,
    origin: String,
}
impl Stub {
    async fn start(key: [u8; 32]) -> Self {
        let mut child = StartingChild(Some(
            Command::new("node")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tools/agent-contact-pilot/production/mounted-bridge-fixture.mjs"
                ))
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_vec(&json!({"key":hex::encode(key)})).unwrap().as_slice())
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (origin, mut reader) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                reader.by_ref().take(4096).read_line(&mut line).unwrap();
                let descriptor: J = serde_json::from_str(&line).unwrap();
                (descriptor["origin"].as_str().unwrap().to_owned(), reader)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let counts = counter.clone();
        let reader = std::thread::spawn(move || loop {
            let mut line = String::new();
            let n = reader.by_ref().take(4096).read_line(&mut line).unwrap();
            if n == 0 {
                break;
            }
            let value: J = serde_json::from_str(&line).unwrap();
            counts.store(value["dispatches"].as_u64().unwrap() as usize, Ordering::SeqCst);
        });
        Self { child: child.into_child(), counter, reader: Some(reader), origin }
    }
    fn close(&mut self) -> bool {
        let _ = self.child.kill();
        let reaped = self.child.wait().is_ok();
        let reader = self.reader.take().is_none_or(|reader| reader.join().is_ok());
        reaped && reader
    }
}
impl Drop for Stub {
    fn drop(&mut self) {
        if self.reader.is_some() {
            let _ = self.close();
        }
    }
}
struct RouteServer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl RouteServer {
    async fn close(&mut self) -> bool {
        let mut task = self.task.take().unwrap();
        if self.stop.take().unwrap().send(()).is_err() {
            task.abort();
            let _ = task.await;
            return false;
        }
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(result) => result.is_ok(),
            Err(_) => {
                task.abort();
                let _ = task.await;
                false
            }
        }
    }
}
impl Drop for RouteServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn scoped_authority(State(authority): State<Arc<Authority>>, request: Request<Body>, next: Next) -> Response {
    fixture_transport::scope(authority, next.run(request)).await
}
fn operation(id: &str, action: Action, revision: u64) -> Operation {
    Operation {
        request_id: id.into(),
        agent: if action == Action::OwnerDisable { None } else { Some(AGENT.into()) },
        action,
        revision,
    }
}
fn rpc(event: &str) -> J {
    json!({"jsonrpc":"2.0","id":event,"method":"SendMessage","params":{"message":{"messageId":event,"role":"ROLE_USER","parts":[{"data":{"skillId":"resolve-identity-test","agentDid":AGENT,"principalDid":PRINCIPAL}}]}}})
}
async fn post(client: &reqwest::Client, origin: &str, token: &str, event: &str) -> (u16, J) {
    let r = client
        .post(format!("{origin}{AGENT_PATH}"))
        .bearer_auth(token)
        .header("a2a-version", "1.0")
        .json(&rpc(event))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}
#[derive(serde::Deserialize)]
struct HttpConsentDecision {
    enabled: bool,
}
async fn apply_http_consent(
    s: &TestServer,
    token: &str,
    operation: &Operation,
) -> crate::xrpc::XResult<HttpConsentDecision> {
    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .post(format!("{}/xrpc/chat.atagents.agent.applyConsent", s.url))
        .bearer_auth(token)
        .json(operation)
        .send()
        .await
        .unwrap();
    let status = response.status();
    if status.is_success() {
        Ok(response.json().await.unwrap())
    } else {
        let error: J = response.json().await.unwrap();
        Err(vlatproto::xrpc::XrpcError {
            status,
            error: error["error"].as_str().unwrap().into(),
            message: error["message"].as_str().unwrap_or("Consent refused").into(),
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mounted_signed_authority_consent_cache_and_single_stub_dispatch() {
    fixture_transport::deny_real_https(mounted_signed_case()).await;
}
async fn mounted_signed_case() {
    assert!(fixture_transport::https_denied());
    assert!(
        tokio::spawn(async { !fixture_transport::https_denied() && fixture_transport::current().is_none() })
            .await
            .unwrap(),
        "Fixture guard must not affect an unrelated parallel task"
    );
    let authority = Authority::new();
    assert!(matches!(
        agent_endorsement_fetch::observe_fixed().await.status,
        crate::xrpc::agent_binding::PairStatus::Unavailable
    ));
    assert_eq!(authority.requests.load(Ordering::SeqCst), 0, "Unscoped requests must not fall back to real HTTPS");
    let key = rand::random::<[u8; 32]>();
    let mut stub = Stub::start(key).await;
    let store = Arc::new(object_store::memory::InMemory::new());
    let s = TestServer::spawn_lone(|c| {
        c.memory_store = Some(store.clone());
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("mountedcaller").await;
    // Disposable fixture metadata and issuer. No control of the real fixed identities.
    for (did, handle) in [(AGENT, "agentfixture.test"), (PRINCIPAL, "ownerfixture.test")] {
        let partition = s.app.partition(did).unwrap_or_else(|_| panic!("Missing fixture partition"));
        let account = crate::state::Account { did: did.into(), handle: handle.into(), ..Default::default() };
        partition.db.put(crate::state::account_key(did), serde_json::to_vec(&account).unwrap()).await.unwrap();
    }
    vlpds::server::shutdown(&s.app).await;
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
        c.agent_owner_consent = Some(
            OwnerConsentTransport::new(PRINCIPAL.into(), vec![(AGENT.into(), caller.did.clone())])
                .unwrap_or_else(|e| panic!("{}", e.message)),
        );
    })
    .await;
    let owner_token = s.app.jwt.access(PRINCIPAL);
    let enable = operation("consent", Action::Enable, 0);
    let foreign_token = s.app.jwt.access(&caller.did);
    let refused = apply_http_consent(&s, &foreign_token, &enable).await.err().expect("Foreign owner refused");
    assert_eq!(refused.status.as_u16(), 401);
    assert_eq!(refused.message, "Active configured owner required");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let cfg = NativeA2a::new(&origin, &caller.did, Bridge::new(&stub.origin, key.to_vec()).unwrap(), true)
        .unwrap()
        .with_local_enrollment_gate_for_fixture()
        .unwrap();
    let router = cfg
        .clone()
        .routes(s.app.clone())
        .layer(axum::middleware::from_fn_with_state(authority.clone(), scoped_authority));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let mut route = RouteServer { stop: Some(stop), task: Some(task) };
    let aud = s.pds_did().await;
    let token = s
        .xrpc
        .get(
            "com.atproto.server.getServiceAuth",
            &[("aud", aud.as_str()), ("lxm", "chat.atagents.agent.contact")],
            &caller.auth(),
        )
        .await
        .ok()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    assert_eq!(post(&client, &origin, &token, "before-consent").await.0, 403);
    assert_eq!(stub.counter.load(Ordering::SeqCst), 0);
    assert!(apply_http_consent(&s, &owner_token, &enable).await.map_err(|e| e.message).unwrap().enabled);
    let (status, first) = post(&client, &origin, &token, "same").await;
    assert_eq!(status, 200, "Synthetic mounted authority response");
    assert_eq!(first["result"]["message"]["parts"][0]["data"]["status"], "verified");
    let reads = authority.requests.load(Ordering::SeqCst);
    let (status, retry) = post(&client, &origin, &token, "same").await;
    assert_eq!(status, 200);
    assert_eq!(first, retry);
    assert!(authority.requests.load(Ordering::SeqCst) > reads, "Retry must recheck proof before cached reply");
    // Independently demonstrate signed absence rather than merely a failed lookup.
    authority.mode(Mode::Absent);
    assert!(matches!(
        fixture_transport::scope(authority.clone(), agent_endorsement_fetch::observe_fixed()).await.status,
        crate::xrpc::agent_binding::PairStatus::SignedAbsent { .. }
    ));
    for (index, mode) in [
        Mode::Absent,
        Mode::Unavailable,
        Mode::Tampered,
        Mode::WrongPair,
        Mode::ChangedHead,
        Mode::BadMedia,
        Mode::Redirect,
        Mode::Oversize,
        Mode::ChangedDid,
        Mode::Encoded,
    ]
    .into_iter()
    .enumerate()
    {
        authority.mode(mode);
        assert_eq!(post(&client, &origin, &token, "same").await.0, 503, "negative mode {index} cached");
        assert_eq!(
            post(&client, &origin, &token, &format!("denied{index}")).await.0,
            503,
            "negative mode {index} fresh"
        );
    }
    authority.mode(Mode::Valid);
    apply_http_consent(&s, &owner_token, &operation("disable", Action::Disable, 1))
        .await
        .map_err(|e| e.message)
        .unwrap();
    let reads = authority.requests.load(Ordering::SeqCst);
    assert_eq!(post(&client, &origin, &token, "same").await.0, 403);
    assert_eq!(post(&client, &origin, &token, "disabled-fresh").await.0, 403);
    assert_eq!(reads, authority.requests.load(Ordering::SeqCst));
    assert!(!apply_http_consent(&s, &owner_token, &enable).await.map_err(|e| e.message).unwrap().enabled);
    apply_http_consent(&s, &owner_token, &operation("fresh-consent", Action::Enable, 2))
        .await
        .map_err(|e| e.message)
        .unwrap();
    let (entered, release) = authority.pause_proof();
    let c = client.clone();
    let u = origin.clone();
    let t = token.clone();
    let pending = tokio::spawn(async move { post(&c, &u, &t, "same").await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await.unwrap();
    apply_http_consent(&s, &owner_token, &operation("race-disable", Action::Disable, 3))
        .await
        .map_err(|e| e.message)
        .unwrap();
    release.notify_one();
    assert_eq!(pending.await.unwrap().0, 503);
    assert_eq!(post(&client, &origin, &token, "same").await.0, 403);
    apply_http_consent(&s, &owner_token, &operation("after-race-consent", Action::Enable, 4))
        .await
        .map_err(|e| e.message)
        .unwrap();
    // The same common 3-second fetch boundary bounds a stalled fixture reply.
    let (_entered, _release) = authority.pause_proof();
    assert_eq!(post(&client, &origin, &token, "same").await.0, 503);
    let reads = authority.requests.load(Ordering::SeqCst);
    authority.mode(Mode::Unavailable);
    assert_eq!(post(&client, &origin, &token, "same").await.0, 503);
    assert!(authority.requests.load(Ordering::SeqCst) > reads, "Timeout must release admission permit");
    authority.mode(Mode::Valid);
    // Aborting a scoped mounted-router future also releases the permit.
    let (entered, _release) = authority.pause_proof();
    let local = cfg.routes(s.app.clone());
    let a = authority.clone();
    let request = Request::builder()
        .method("POST")
        .uri(AGENT_PATH)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("a2a-version", "1.0")
        .body(Body::from(serde_json::to_vec(&rpc("same")).unwrap()))
        .unwrap();
    let aborted = tokio::spawn(fixture_transport::scope(a, local.oneshot(request)));
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await.unwrap();
    aborted.abort();
    assert!(aborted.await.unwrap_err().is_cancelled());
    let reads = authority.requests.load(Ordering::SeqCst);
    authority.mode(Mode::Unavailable);
    assert_eq!(post(&client, &origin, &token, "same").await.0, 503);
    assert!(authority.requests.load(Ordering::SeqCst) > reads);
    authority.mode(Mode::Valid);
    apply_http_consent(&s, &owner_token, &operation("revoke", Action::RevokeEndorsement, 5))
        .await
        .map_err(|e| e.message)
        .unwrap();
    let reads = authority.requests.load(Ordering::SeqCst);
    assert_eq!(post(&client, &origin, &token, "same").await.0, 403);
    assert_eq!(post(&client, &origin, &token, "revoked-fresh").await.0, 403);
    assert_eq!(reads, authority.requests.load(Ordering::SeqCst));
    let refused = apply_http_consent(&s, &owner_token, &operation("no-restore", Action::Enable, 6))
        .await
        .err()
        .expect("Revoked enrollment cannot be restored");
    assert_eq!(refused.status.as_u16(), 400);
    assert_eq!(refused.error, "EnrollmentRefused");
    assert_eq!(refused.message, "Revoked or shut off; no automatic restoration");
    apply_http_consent(&s, &owner_token, &operation("off", Action::OwnerDisable, 6))
        .await
        .map_err(|e| e.message)
        .unwrap();
    assert_eq!(post(&client, &origin, &token, "same").await.0, 403);
    assert_eq!(post(&client, &origin, &token, "owner-off-fresh").await.0, 403);
    assert!(route.close().await, "Owned route server cleanup");
    vlpds::server::shutdown(&s.app).await;
    assert!(stub.close(), "Owned stub process and counter reader cleanup");
    assert_eq!(
        stub.counter.load(Ordering::SeqCst),
        1,
        "Identical retry and every denied case must make exactly one total actual stub dispatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_owner_consent_local_gate_blocks_actual_cached_reply_after_disable() {
    use crate::agent_a2a_store::{finish, reserve, Reservation};
    use axum::{body::Body, http::Request};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use vlpds::{
        agent_a2a::NativeA2a,
        agent_contact_pilot::AGENT_PATH,
        agent_endorsement::{AGENT, PRINCIPAL},
        agent_enrollment::{apply_owner_consent as apply, Action::*, Pair},
        agent_profile_bridge::Bridge,
    };
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("enrollcachecaller").await;
    // Disposable metadata only: no real fixed DID, signing key or account authority.
    for (did, handle) in [(AGENT, "syntheticagent.test"), (PRINCIPAL, "syntheticowner.test")] {
        let partition = s.app.partition(did).unwrap_or_else(|_| panic!("Missing fixture partition"));
        let account = vlpds::state::Account { did: did.into(), handle: handle.into(), ..Default::default() };
        partition.db.put(vlpds::state::account_key(did), serde_json::to_vec(&account).unwrap()).await.unwrap();
    }
    let cfg =
        NativeA2a::new(&s.url, &caller.did, Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(), true).unwrap();
    let legacy = cfg.clone().routes(s.app.clone());
    let gated = cfg.with_local_enrollment_gate_for_fixture().unwrap().routes(s.app.clone());
    let aud = s.pds_did().await;
    let token = s
        .xrpc
        .get(
            "com.atproto.server.getServiceAuth",
            &[("aud", aud.as_str()), ("lxm", "chat.atagents.agent.contact")],
            &caller.auth(),
        )
        .await
        .ok()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let event = "cached-enrollment";
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(
            &json!({"messageId":event,"skillId":"resolve-identity-test","agentDid":AGENT,"principalDid":PRINCIPAL}),
        )
        .unwrap(),
    ));
    let Reservation::Fresh { row, pending } =
        reserve(&s.app, AGENT, &caller.did, event, &digest, 100).await.map_err(|e| e.message).unwrap()
    else {
        panic!("fresh")
    };
    finish(&s.app, AGENT, &row, pending, &json!({"jsonrpc":"2.0","id":"cached","result":{"fixture":"cached-only"}}))
        .await
        .map_err(|e| e.message)
        .unwrap();
    let body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"request","method":"SendMessage","params":{"message":{"messageId":event,"role":"ROLE_USER","parts":[{"data":{"skillId":"resolve-identity-test","agentDid":AGENT,"principalDid":PRINCIPAL}}]}}})).unwrap();
    let request = || {
        Request::builder()
            .method("POST")
            .uri(AGENT_PATH)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("a2a-version", "1.0")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    assert_eq!(legacy.clone().oneshot(request()).await.unwrap().status(), 200);
    assert_eq!(gated.clone().oneshot(request()).await.unwrap().status(), 403);
    // Only this disposable server issues this synthetic principal session; no live identity authority.
    let owner = s.app.jwt.access(PRINCIPAL);
    let pairs = [Pair { agent: AGENT, caller: &caller.did }];
    let enabled = operation("consent", Enable, 0);
    apply(&s.app, &owner, PRINCIPAL, &pairs, &enabled).await.map_err(|e| e.message).unwrap();
    apply(&s.app, &owner, PRINCIPAL, &pairs, &operation("disable", Disable, 1)).await.map_err(|e| e.message).unwrap();
    assert_eq!(gated.clone().oneshot(request()).await.unwrap().status(), 403);
    assert!(!apply(&s.app, &owner, PRINCIPAL, &pairs, &enabled).await.map_err(|e| e.message).unwrap().enabled);
    apply(&s.app, &owner, PRINCIPAL, &pairs, &operation("off", OwnerDisable, 2)).await.map_err(|e| e.message).unwrap();
    assert_eq!(gated.oneshot(request()).await.unwrap().status(), 403);
    assert_eq!(
        legacy.oneshot(request()).await.unwrap().status(),
        200,
        "Local opt-in does not change legacy pilot semantics"
    );
    assert!(NativeA2a::new(
        "https://pds.example.invalid",
        &caller.did,
        Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(),
        false
    )
    .unwrap()
    .with_local_enrollment_gate_for_fixture()
    .is_err());
    vlpds::server::shutdown(&s.app).await;
}
