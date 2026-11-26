use super::{Chat, SpaceClient, J};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde_json::json;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use vlpds::plc::mock::MockPlc;
use vlpds::xrpc::agent_dispatch::{self, Binding, Grant};
use vlpds::xrpc::agent_dispatch_auth::{admit, Authority, MAX_BODY_BYTES, METHOD};

use vlpds::xrpc::agent_chat::{self, VERSION, VERSION_HEADER};

pub(crate) struct Session {
    caller: SpaceClient,
    owner: String,
    binding: Binding,
    conversation: String,
    token: String,
}

impl Session {
    pub(super) fn new(caller: SpaceClient, owner: &str, agent: &str, space: &str, conversation: &str) -> Self {
        Self {
            caller,
            owner: owner.into(),
            binding: Binding { agent: agent.into(), space: space.into() },
            conversation: conversation.into(),
            token: format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>()),
        }
    }

    pub(crate) fn binding(&self) -> Binding {
        self.binding.clone()
    }

    async fn owner_credentials(&self) -> vlpds::xrpc::XResult<vlpds::xrpc::authn::Credentials> {
        let (parts, _) = axum::http::Request::builder()
            .header(header::AUTHORIZATION, format!("Bearer {}", self.caller.session_jwt))
            .body(())
            .unwrap()
            .into_parts();
        vlpds::xrpc::authn::authenticate(&self.caller.srv.app, &parts).await
    }

    pub(crate) async fn dispatch(&self, body: &[u8]) -> Response {
        agent_chat::handle(self, body).await
    }

    fn chat(&self) -> Chat<'_> {
        Chat {
            caller: &self.caller,
            owner: &self.owner,
            agent: &self.binding.agent,
            space: &self.binding.space,
            conversation: &self.conversation,
        }
    }
}

impl agent_chat::ChatSession for Session {
    fn conversation(&self) -> &str {
        &self.conversation
    }

    async fn start(&self) -> agent_chat::ToolResult {
        self.chat().start().await
    }

    async fn send(&self, message_id: &str, text: &str) -> agent_chat::ToolResult {
        self.chat().send(message_id, text).await
    }

    async fn history(&self) -> agent_chat::ToolResult {
        self.chat().history().await
    }
}

impl agent_chat::ScopedSession for Session {
    fn binding(&self) -> &Binding {
        &self.binding
    }
}

pub(super) struct FixtureSigner {
    did: String,
    audience: String,
    jwk: J,
}

impl FixtureSigner {
    pub(super) async fn register(plc: &MockPlc, audience: String) -> Self {
        use p256::elliptic_curve::Generate;
        let key = p256::ecdsa::SigningKey::generate();
        let point = key.verifying_key().to_sec1_point(false);
        let point = point.as_bytes();
        let jwk = json!({
            "kty": "EC", "crv": "P-256",
            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
            "d": B64.encode(key.to_bytes()),
        });
        let rotation = vlatproto::crypto::Keypair::generate();
        let public = p256::PublicKey::from_sec1_bytes(point).unwrap();
        let operation = vlpds::plc::sign(
            json!({
                "type": "plc_operation",
                "rotationKeys": [rotation.did_key()],
                "verificationMethods": {"atproto": vlpds::space::mac::did_key(&public)},
                "alsoKnownAs": ["at://worker-fixture.example.invalid"],
                "services": {},
                "prev": null,
            }),
            &rotation,
        )
        .unwrap();
        let did = vlpds::plc::did_for_genesis(&operation).unwrap();
        assert!(reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}/{did}", plc.url))
            .json(&operation)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        Self { did, audience, jwk }
    }
}

struct Endpoint {
    authority: String,
    sessions: Vec<Session>,
    signer: Option<FixtureSigner>,
    bridge_token: String,
    issuer: OnceLock<String>,
    grants: parking_lot::Mutex<[Option<String>; 2]>,
}

pub(super) struct Server {
    endpoint: Arc<Endpoint>,
    task: JoinHandle<()>,
}

pub(crate) struct WorkerGrant {
    pub issuer: String,
    pub id: String,
    pub binding: Binding,
}

impl WorkerGrant {
    pub(crate) fn grant<'a>(&'a self, resource: &'a str, owner: &'a str) -> Grant<'a> {
        Grant { issuer: &self.issuer, resource, id: &self.id, owner }
    }
}

impl Server {
    pub(super) async fn bind(sessions: Vec<Session>, signer: Option<FixtureSigner>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Arc::new(Endpoint {
            authority: listener.local_addr().unwrap().to_string(),
            sessions,
            signer,
            bridge_token: format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>()),
            issuer: OnceLock::new(),
            grants: parking_lot::Mutex::new([None, None]),
        });
        let app = Router::new()
            .route("/mcp", post(request).get(request))
            .route(&format!("/xrpc/{METHOD}"), post(request))
            .route("/fixture/grant", post(grant_consent))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(endpoint.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { endpoint, task }
    }

    /// Optional local Worker integration using only two disposable owner sessions.
    pub(super) async fn check_oauth_bridge<F, Fut>(&self, foreign_token: &str, on_phase: F) -> bool
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = ()>,
    {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let workerd = std::env::var_os("EXP711_WORKERD");
        let provider = std::env::var_os("EXP711_OAUTH_PROVIDER");
        let (Some(workerd), Some(provider)) = (&workerd, &provider) else {
            assert!(workerd.is_none() && provider.is_none(), "set both framework fixture paths");
            return false;
        };
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/spaces-mcp-auth-fixture/test.mjs");
        let mut child = tokio::process::Command::new("node")
            .arg(script)
            .arg(workerd)
            .arg(provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start local MCP OAuth framework fixture");
        let bindings: Vec<_> = self.endpoint.sessions[..2]
            .iter()
            .map(|session| {
                let mut binding = json!({"conversationId": session.conversation, "authorDid": session.caller.did});
                if self.endpoint.signer.is_none() {
                    binding["token"] = json!(session.token);
                }
                binding
            })
            .collect();
        let signer = self.endpoint.signer.as_ref().map(|signer| {
            json!({
                "iss": signer.did, "aud": signer.audience, "jwk": signer.jwk,
                "method": METHOD,
            })
        });
        let input = json!({
            "backend": self.endpoint.authority, "bindings": bindings, "foreignToken": foreign_token, "signer": signer,
            "verifyBinding": self.endpoint.signer.is_some(),
            "bridgeToken": self.endpoint.signer.is_some().then_some(&self.endpoint.bridge_token),
        });
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(format!("{input}\n").as_bytes()).await.unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let status = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(phase) = line.strip_prefix("EXP711_PHASE ") {
                    assert!(self.endpoint.signer.is_some());
                    if let Some(origin) = phase.strip_prefix("issuer ") {
                        let url = reqwest::Url::parse(origin).unwrap();
                        assert_eq!(url.scheme(), "http");
                        assert_eq!(url.host_str(), Some("127.0.0.1"));
                        assert_eq!(url.origin().ascii_serialization(), origin);
                        self.endpoint.issuer.set(origin.to_owned()).unwrap();
                    } else if phase == "unsigned-probe" {
                        self.assert_unsigned_dispatch_denied().await;
                    } else if phase == "arm-durable-revocation" {
                        self.arm_durable_revocation().await;
                    } else {
                        on_phase(phase.to_owned()).await;
                    }
                    stdin.write_all(b"ok\n").await.unwrap();
                } else {
                    println!("{line}");
                }
            }
            child.wait().await.unwrap()
        })
        .await
        .expect("MCP OAuth bridge timed out");
        assert!(status.success(), "MCP OAuth bridge fixture failed");
        true
    }

    async fn assert_unsigned_dispatch_denied(&self) {
        let grant = self.endpoint.grants.lock()[0].clone().unwrap();
        let response = self
            .client(0)
            .http
            .post(format!("http://{}/xrpc/{METHOD}", self.endpoint.authority))
            .bearer_auth(&self.endpoint.bridge_token)
            .header("x-exp711-user", "owner-a")
            .header("x-exp711-grant", grant)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    pub(super) fn worker_grants(&self) -> [WorkerGrant; 2] {
        let ids = self.endpoint.grants.lock();
        std::array::from_fn(|index| WorkerGrant {
            issuer: self.endpoint.issuer.get().unwrap().clone(),
            id: ids[index].as_ref().unwrap().clone(),
            binding: self.endpoint.sessions[index].binding(),
        })
    }

    pub(super) async fn assert_record_absent(&self, owner: usize, key: &str) {
        let session = &self.endpoint.sessions[owner];
        session
            .caller
            .get(
                "com.atproto.space.getRecord",
                &[
                    ("space", &session.binding.space),
                    ("repo", &session.owner),
                    ("collection", super::MESSAGE),
                    ("rkey", key),
                ],
            )
            .await
            .err(400, "RecordNotFound");
    }

    async fn arm_durable_revocation(&self) {
        let [alice, _] = self.worker_grants();
        let session = &self.endpoint.sessions[0];
        let owner = session.owner.clone();
        let app = session.caller.srv.app.clone();
        let credentials = session.owner_credentials().await.map_err(|e| e.message).unwrap();
        let owner_key = owner.clone();
        vlpds::xrpc::cas::set_pause_hook(
            &owner_key,
            Some(Arc::new(move |point| {
                let hold = point == "agent_dispatch_before_final_read";
                let (app, owner, credentials) = (app.clone(), owner.clone(), credentials.clone());
                let (issuer, id) = (alice.issuer.clone(), alice.id.clone());
                Box::pin(async move {
                    if hold {
                        vlpds::xrpc::cas::set_pause_hook(&owner, None);
                        let resource = format!("{issuer}/mcp");
                        let grant = Grant { issuer: &issuer, resource: &resource, id: &id, owner: &owner };
                        agent_dispatch::revoke(&app, &credentials, grant).await.map_err(|e| e.message).unwrap();
                    }
                })
            })),
        );
    }

    pub(super) fn client(&self, index: usize) -> Client {
        Client {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            url: format!("http://{}/mcp", self.endpoint.authority),
            token: self.endpoint.sessions[index].token.clone(),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn fixture_owner(user_id: &str) -> Option<usize> {
    match user_id {
        "owner-a" => Some(0),
        "owner-b" => Some(1),
        _ => None,
    }
}

fn matches_listener(endpoint: &Endpoint, headers: &HeaderMap) -> bool {
    !headers.contains_key(header::ORIGIN)
        && headers.get(header::HOST).and_then(|h| h.to_str().ok()) == Some(endpoint.authority.as_str())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

async fn grant_consent(State(endpoint): State<Arc<Endpoint>>, headers: HeaderMap, Json(body): Json<J>) -> StatusCode {
    if endpoint.signer.is_none()
        || !matches_listener(&endpoint, &headers)
        || bearer(&headers) != Some(endpoint.bridge_token.as_str())
    {
        return StatusCode::FORBIDDEN;
    }
    let Some(index) = body["userId"].as_str().and_then(fixture_owner) else {
        return StatusCode::FORBIDDEN;
    };
    let (Some(issuer), Some(id), Some(session)) =
        (endpoint.issuer.get(), body["grantId"].as_str(), endpoint.sessions.get(index))
    else {
        return StatusCode::FORBIDDEN;
    };
    let Ok(credentials) = session.owner_credentials().await else {
        return StatusCode::FORBIDDEN;
    };
    let resource = format!("{issuer}/mcp");
    let grant = Grant { issuer, resource: &resource, id, owner: &session.owner };
    match body["operation"].as_str() {
        Some("approve") => {
            if agent_dispatch::approve(&session.caller.srv.app, &credentials, grant, session.binding()).await.is_err() {
                return StatusCode::FORBIDDEN;
            }
            endpoint.grants.lock()[index] = Some(id.to_owned());
        }
        Some("revoke") => {
            if agent_dispatch::revoke(&session.caller.srv.app, &credentials, grant).await.is_err() {
                return StatusCode::FORBIDDEN;
            }
        }
        _ => return StatusCode::BAD_REQUEST,
    }
    StatusCode::NO_CONTENT
}

async fn request(
    State(endpoint): State<Arc<Endpoint>>,
    uri: axum::http::Uri,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Native loopback clients only. A browser Origin or a rebinding Host is refused.
    if !matches_listener(&endpoint, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let token = bearer(&headers);
    let session = if let Some(signer) = &endpoint.signer {
        let (Some(token), Some(issuer), Some(first)) = (token, endpoint.issuer.get(), endpoint.sessions.first()) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if uri.path() != format!("/xrpc/{METHOD}") || uri.query().is_some() || method != Method::POST {
            return StatusCode::FORBIDDEN.into_response();
        }
        let resource = format!("{issuer}/mcp");
        let authority = Authority { signer: &signer.did, issuer, resource: &resource };
        let Ok(binding) = admit(&first.caller.srv.app, &authority, token, &body).await else {
            return StatusCode::FORBIDDEN.into_response();
        };
        endpoint.sessions.iter().find(|session| session.binding() == binding)
    } else {
        if uri.path() != "/mcp" {
            return StatusCode::FORBIDDEN.into_response();
        }
        endpoint.sessions.iter().find(|session| token == Some(session.token.as_str()))
    };
    let Some(session) = session else {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response();
    };

    if headers.get(VERSION_HEADER).is_some_and(|version| version != VERSION) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if method != Method::POST {
        // The JSON transport has no SSE stream.
        return (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response();
    }
    session.dispatch(&body).await
}

pub(super) struct Client {
    http: reqwest::Client,
    url: String,
    token: String,
}

impl Client {
    pub(super) fn post(&self) -> reqwest::RequestBuilder {
        self.http.post(&self.url).bearer_auth(&self.token).header(header::ACCEPT, "application/json, text/event-stream")
    }

    pub(super) async fn initialize(&self) {
        let init = self.rpc(
            "initialize",
            json!({"protocolVersion": VERSION, "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}),
        ).await;
        assert_eq!(init["protocolVersion"], VERSION);
        assert_eq!(init["capabilities"]["tools"], json!({}));
        let response = self
            .post()
            .header(VERSION_HEADER, VERSION)
            .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.bytes().await.unwrap().is_empty());
    }

    pub(super) async fn rpc(&self, method: &str, params: J) -> J {
        let id = rand::random::<u64>().to_string();
        let mut post = self.post();
        if method != "initialize" {
            post = post.header(VERSION_HEADER, VERSION);
        }
        let response =
            post.json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body: J = response.json().await.unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], id);
        assert!(body.get("error").is_none(), "{body}");
        body["result"].clone()
    }

    pub(super) async fn call(&self, name: &str, args: J) -> J {
        self.rpc("tools/call", json!({"name": name, "arguments": args})).await
    }

    pub(super) async fn assert_transport_boundaries(&self) {
        let listing = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        for (request, expected) in [
            (self.http.post(&self.url), StatusCode::UNAUTHORIZED),
            (self.post().header(header::ORIGIN, "https://example.invalid"), StatusCode::FORBIDDEN),
            (self.post().header(header::HOST, "example.invalid"), StatusCode::FORBIDDEN),
            (self.post().header(VERSION_HEADER, "1900-01-01"), StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(request.json(&listing).send().await.unwrap().status(), expected);
        }
        assert_eq!(
            self.http
                .get(&self.url)
                .bearer_auth(&self.token)
                .header(header::ACCEPT, "text/event-stream")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let malformed = self.post().body("{").send().await.unwrap().json::<J>().await.unwrap();
        assert_eq!(malformed["error"]["code"], -32700);
    }
}
