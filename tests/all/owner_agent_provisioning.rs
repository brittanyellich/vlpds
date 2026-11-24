//! Disposable provisioning lifecycle over the real PDS signup and repo APIs.
//! The journal and its locks model one coordinator; production needs durable
//! reservations, encrypted secrets, and fencing across coordinators.

use crate::common::{Auth, Resp, TestServer, HANDLE_DOMAIN, PASSWORD};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Agent {
    did: String,
    handle: String,
}

#[derive(Debug, PartialEq, Eq)]
enum ProvisionError {
    Unauthorized,
    InvalidRequestId,
    Quota,
    Pds(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Progress {
    Pending,
    Ready(Agent),
}

struct Intent {
    handle: String,
    email: String,
    password: String,
    submitted: bool,
    result: Option<Agent>,
}

impl Intent {
    fn new() -> Self {
        let name = format!("a-{:016x}", rand::random::<u64>());
        Self {
            handle: format!("{name}.{HANDLE_DOMAIN}"),
            email: format!("{name}@example.com"),
            password: format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>()),
            submitted: false,
            result: None,
        }
    }

    fn account(&self, response: &Resp) -> Agent {
        assert_eq!(response.json["handle"], self.handle);
        Agent { did: response.json["did"].as_str().unwrap().to_owned(), handle: self.handle.clone() }
    }

    async fn signup(&mut self, server: &TestServer, invite: Option<&str>) -> Resp {
        // This transition precedes the first request. If its outcome is
        // unknown, a retry reconciles this identity before repeating signup.
        self.submitted = true;
        let mut request = json!({"handle": self.handle, "email": self.email, "password": self.password});
        if let Some(code) = invite {
            request["inviteCode"] = json!(code);
        }
        server.xrpc.post("com.atproto.server.createAccount", &request, &Auth::None).await
    }

    async fn complete(&mut self, server: &TestServer, invite: Option<&str>) -> Result<Agent, ProvisionError> {
        if let Some(agent) = &self.result {
            return Ok(agent.clone());
        }
        if self.submitted {
            let login = server.create_session(&self.handle, &self.password).await;
            if login.is_ok() {
                let agent = self.account(&login);
                self.result = Some(agent.clone());
                return Ok(agent);
            }
            if login.error_name() != Some("AuthenticationRequired") {
                return Err(pds_error(&login));
            }
            // Unproven identity. A repeated signup uses the same reserved
            // handle/email, so PDS uniqueness prevents a second account.
        }
        let response = self.signup(server, invite).await;
        if !response.is_ok() {
            return Err(pds_error(&response));
        }
        let agent = self.account(&response);
        self.result = Some(agent.clone());
        Ok(agent)
    }
}

fn pds_error(response: &Resp) -> ProvisionError {
    ProvisionError::Pds(response.error_name().unwrap_or("UnknownError").to_owned())
}

type Operations = HashMap<String, Arc<Mutex<Intent>>>;
type Journal = Mutex<HashMap<String, Operations>>;

struct Provisioner<'a> {
    server: &'a TestServer,
    journal: &'a Journal,
    quota: usize,
}

impl Provisioner<'_> {
    async fn owner(&self, auth: &Auth) -> Result<String, ProvisionError> {
        // Reuse the existing full-account-session gate in the fixture.
        // A production handler can apply the same gate to its Auth extractor.
        if !self.server.xrpc.get("vlpds.oauth.listSessions", &[], auth).await.is_ok() {
            return Err(ProvisionError::Unauthorized);
        }
        let session = self.server.get_session(auth).await;
        if !session.is_ok() || session.json["active"] != true {
            return Err(ProvisionError::Unauthorized);
        }
        Ok(session.json["did"].as_str().unwrap().to_owned())
    }

    async fn begin(&self, auth: &Auth, request_id: &str) -> Result<Arc<Mutex<Intent>>, ProvisionError> {
        let owner = self.owner(auth).await?;
        if request_id.is_empty() || request_id.len() > 64 || !request_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(ProvisionError::InvalidRequestId);
        }
        let mut journal = self.journal.lock().await;
        let operations = journal.entry(owner).or_default();
        if let Some(existing) = operations.get(request_id) {
            return Ok(existing.clone());
        }
        if operations.len() >= self.quota {
            return Err(ProvisionError::Quota);
        }
        let intent = Arc::new(Mutex::new(Intent::new()));
        operations.insert(request_id.to_owned(), intent.clone());
        Ok(intent)
    }

    async fn provision(&self, auth: &Auth, request_id: &str, invite: Option<&str>) -> Result<Agent, ProvisionError> {
        self.begin(auth, request_id).await?.lock().await.complete(self.server, invite).await
    }

    async fn status(&self, auth: &Auth, request_id: &str) -> Result<Option<Progress>, ProvisionError> {
        let owner = self.owner(auth).await?;
        let intent = self.journal.lock().await.get(&owner).and_then(|ops| ops.get(request_id)).cloned();
        let Some(intent) = intent else {
            return Ok(None);
        };
        let result = intent.lock().await.result.clone();
        Ok(Some(result.map_or(Progress::Pending, Progress::Ready)))
    }

    async fn list(&self, auth: &Auth) -> Result<Vec<Agent>, ProvisionError> {
        let owner = self.owner(auth).await?;
        let operations = self.journal.lock().await.get(&owner).cloned().unwrap_or_default();
        let mut agents = Vec::new();
        for intent in operations.values() {
            if let Some(agent) = &intent.lock().await.result {
                agents.push(agent.clone());
            }
        }
        Ok(agents)
    }
}

async fn invite(server: &TestServer) -> String {
    server.xrpc.post("com.atproto.server.createInviteCode", &json!({"useCount": 1}), &Auth::Admin).await.ok()["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn owner(server: &TestServer, name: &str) -> Auth {
    let signup = server
        .xrpc
        .post(
            "com.atproto.server.createAccount",
            &json!({
                "handle": format!("{name}.{HANDLE_DOMAIN}"),
                "email": format!("{name}@example.com"), "password": PASSWORD, "inviteCode": invite(server).await,
            }),
            &Auth::None,
        )
        .await
        .ok();
    Auth::Bearer(signup["accessJwt"].as_str().unwrap().to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_agent_provisioning_retries_and_isolation() {
    let server = TestServer::spawn_with(|config| config.invite_required = true).await;
    let alice = owner(&server, "agentowneralice").await;
    let bob = owner(&server, "agentownerbob").await;
    let journal = Journal::default();
    let service = Provisioner { server: &server, journal: &journal, quota: 1 };
    assert_eq!(service.provision(&Auth::None, "operation", None).await, Err(ProvisionError::Unauthorized));
    assert_eq!(service.list(&Auth::None).await, Err(ProvisionError::Unauthorized));
    assert_eq!(
        service.provision(&alice, "operation", None).await,
        Err(ProvisionError::Pds("InvalidInviteCode".into()))
    );
    assert_eq!(service.list(&alice).await.unwrap(), []);
    assert_eq!(service.provision(&alice, "overquota", None).await, Err(ProvisionError::Quota));

    let code = invite(&server).await;
    let intent = service.begin(&alice, "operation").await.unwrap();
    // Inject the loss of the successful response before coordinator completion.
    let committed = intent.lock().await.signup(&server, Some(&code)).await.ok();
    assert_eq!(service.list(&alice).await.unwrap(), []);
    assert_eq!(service.list(&bob).await.unwrap(), []);
    assert_eq!(service.status(&alice, "operation").await.unwrap(), Some(Progress::Pending));
    assert_eq!(service.status(&bob, "operation").await.unwrap(), None);

    let reopened = Provisioner { server: &server, journal: &journal, quota: 1 };
    let (first, retry) = tokio::join!(
        reopened.provision(&alice, "operation", Some(&code)),
        reopened.provision(&alice, "operation", Some(&code)),
    );
    let agent = first.unwrap();
    assert_eq!(retry.unwrap(), agent);
    assert_eq!(committed["did"], agent.did);
    assert_eq!(committed["handle"], agent.handle);
    let (_, rev) = server.latest_commit(&agent.did).await;
    assert!(!rev.is_empty());

    let bob_code = invite(&server).await;
    let other = reopened.provision(&bob, "operation", Some(&bob_code)).await.unwrap();
    assert_ne!(agent.did, other.did);
    assert_ne!(agent.handle, other.handle);
    assert_eq!(reopened.status(&alice, "operation").await.unwrap(), Some(Progress::Ready(agent.clone())));
    assert_eq!(reopened.status(&bob, "operation").await.unwrap(), Some(Progress::Ready(other.clone())));
    assert_eq!(reopened.list(&alice).await.unwrap(), [agent]);
    assert_eq!(reopened.list(&bob).await.unwrap(), [other]);
}

const PROVISION: &str = "vlpds.agent.provision";
const STATUS: &str = "vlpds.agent.getProvisioningStatus";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_agent_endpoint_recovers_a_lost_signup_response() {
    use axum::body::Body;
    use axum::http::Request;
    use tokio::sync::Notify;
    use tower::ServiceExt;
    use vlpds::xrpc::cas::set_pause_hook;

    let server = TestServer::spawn_with(|config| config.invite_required = true).await;
    let alice = owner(&server, "endpointalice").await;
    let bob = owner(&server, "endpointbob").await;
    let alice_did = server.get_session(&alice).await.ok()["did"].as_str().unwrap().to_owned();
    let mut input = json!({
        "operationId": "setup",
        "handle": "endpointagent.vlpds.test",
        "email": "endpointagent@example.com",
        "password": PASSWORD,
    });
    let query = [("operationId", "setup")];
    assert_eq!(server.xrpc.post(PROVISION, &input, &Auth::None).await.status, 401);
    assert_eq!(server.xrpc.get(STATUS, &query, &Auth::Admin).await.status, 401);
    server.xrpc.post(PROVISION, &input, &alice).await.err(400, "InvalidInviteCode");
    assert_eq!(server.xrpc.get(STATUS, &query, &alice).await.ok()["status"], "reserved");
    server.xrpc.get(STATUS, &query, &bob).await.err(400, "AgentReservationNotFound");
    input["inviteCode"] = json!(invite(&server).await);

    let reached = Arc::new(Notify::new());
    let signal = reached.clone();
    set_pause_hook(
        &alice_did,
        Some(Arc::new(move |point| {
            let hold = point == "agent_provisioning_before_settlement";
            let signal = signal.clone();
            Box::pin(async move {
                if hold {
                    signal.notify_one();
                    std::future::pending::<()>().await;
                }
            })
        })),
    );
    let Auth::Bearer(owner_access) = &alice else { unreachable!() };
    let request = Request::post(format!("/xrpc/{PROVISION}"))
        .header("Authorization", format!("Bearer {owner_access}"))
        .header("Content-Type", "application/json")
        .body(Body::from(input.to_string()))
        .unwrap();
    let signup = tokio::spawn(vlpds::server::router(&server.app).oneshot(request));
    tokio::time::timeout(std::time::Duration::from_secs(10), reached.notified()).await.unwrap();
    signup.abort();
    assert!(signup.await.unwrap_err().is_cancelled());
    set_pause_hook(&alice_did, None);

    assert_eq!(server.xrpc.get(STATUS, &query, &alice).await.ok()["status"], "pending");
    let committed_did =
        server.app.resolve_handle("endpointagent.vlpds.test").await.map_err(|error| error.message).unwrap().unwrap();
    server.latest_commit(&committed_did).await;
    let (a, b) = tokio::join!(server.xrpc.post(PROVISION, &input, &alice), server.xrpc.post(PROVISION, &input, &alice));
    let recovered = a.ok();
    assert_eq!(recovered, b.ok());
    assert_eq!(recovered["status"], "ready");
    assert_eq!(recovered["did"], committed_did);
    assert_eq!(server.xrpc.get(STATUS, &query, &alice).await.ok(), recovered);

    let mut different = input.clone();
    different["operationId"] = json!("other");
    server.xrpc.post(PROVISION, &different, &alice).await.err(400, "AgentQuotaExceeded");
    server.xrpc.get(STATUS, &query, &bob).await.err(400, "AgentReservationNotFound");

    let bob_did = server.get_session(&bob).await.ok()["did"].as_str().unwrap().to_owned();
    let journal = vlpds::xrpc::agent_provisioning::Journal::new(&server.app, &bob_did);
    journal.reserve("setup", "endpointagent.vlpds.test", 1).await.map_err(|e| e.message).unwrap();
    let attempt = journal.claim("setup").await.map_err(|e| e.message).unwrap().unwrap();
    // The handle resolves to Alice's agent. The private creation marker
    // must prevent Bob's independent operation from adopting it.
    let unmatched = server.xrpc.post(PROVISION, &input, &bob).await.ok();
    assert_eq!(unmatched["status"], "pending");
    assert!(unmatched.get("did").is_none());
    journal
        .settle("setup", attempt, vlpds::xrpc::agent_provisioning::SignupOutcome::PlcUncertain)
        .await
        .map_err(|e| e.message)
        .unwrap();
    let stopped = server.xrpc.post(PROVISION, &input, &bob).await.ok();
    assert_eq!(stopped["status"], "needsReconciliation");
    assert!(stopped.get("did").is_none());
    assert_eq!(server.xrpc.get(STATUS, &query, &alice).await.ok(), recovered);
}
