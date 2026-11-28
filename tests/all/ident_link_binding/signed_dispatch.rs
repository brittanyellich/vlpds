use super::*;
use crate::spaces_mcp_chat::{http::Session, owner_session, reopen_owner_session};
use axum::{response::IntoResponse, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::OnceLock;
use tokio::sync::Notify;
use vlatproto::crypto::Purpose;
use vlpds::xrpc::{
    agent_dispatch::{approve, revoke, Binding, Grant},
    agent_dispatch_auth::{MAX_BODY_BYTES, METHOD},
    agent_dispatch_route::Mount,
    authn::authenticate,
    cas::set_pause_hook,
};

const ISSUER: &str = "https://issuer.example.invalid";
const RESOURCE: &str = "https://issuer.example.invalid/mcp";
const BODY: &[u8] = br#"{"name":"chat.retrieve","arguments":{"threadId":"fixture"}}"#;

pub(super) struct Bridge {
    key: Keypair,
    signer: String,
    audience: String,
    url: String,
    client: reqwest::Client,
    chats: Arc<OnceLock<[Session; 2]>>,
}

impl Bridge {
    pub(super) async fn prepare(plc: &MockPlc) -> Self {
        let key = Keypair::generate();
        let operation = vlpds::plc::sign(
            json!({
                "type": "plc_operation",
                "rotationKeys": [key.did_key()],
                "verificationMethods": {"atproto": key.did_key()},
                "alsoKnownAs": ["at://bridge.example.invalid"],
                "services": {},
                "prev": null,
            }),
            &key,
        )
        .unwrap();
        let signer = vlpds::plc::did_for_genesis(&operation).unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        assert!(client
            .post(format!("{}/{signer}", plc.url))
            .json(&operation)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());

        Self { key, signer, audience: String::new(), url: String::new(), client, chats: Arc::default() }
    }

    pub(super) fn mount(&self) -> Mount {
        let chats = Arc::downgrade(&self.chats);
        Mount::new(&self.signer, ISSUER, RESOURCE, move |binding, body| {
            let chats = chats.clone();
            async move {
                if body.as_ref() == BODY {
                    return Json(binding).into_response();
                }
                let chats = chats.upgrade();
                let Some(session) = chats
                    .as_deref()
                    .and_then(OnceLock::get)
                    .and_then(|sessions| sessions.iter().find(|session| session.binding() == binding))
                else {
                    return axum::http::StatusCode::FORBIDDEN.into_response();
                };
                session.dispatch(&body).await
            }
        })
        .unwrap()
    }

    pub(super) async fn check_scoped_restart(
        &mut self,
        plc: &MockPlc,
        rotation: Arc<Keypair>,
        store: Arc<object_store::memory::InMemory>,
        alice: &Account,
        bob: &Account,
    ) {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Weak,
        };
        use vlpds::xrpc::agent_chat::{HISTORY, SEND};

        let calls = Arc::new(AtomicUsize::new(0));
        let opened = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let server = Arc::new(OnceLock::<Weak<TestServer>>::new());
        let bob_access = Arc::new(Account { did: bob.did.clone(), handle: bob.handle.clone(), jwt: bob.jwt.clone() });
        let open = {
            let (server, calls, opened, resume) = (server.clone(), calls.clone(), opened.clone(), resume.clone());
            move |scope: vlpds::xrpc::agent_chat::SessionScope| {
                let (server, calls, bob, opened, resume) =
                    (server.clone(), calls.clone(), bob_access.clone(), opened.clone(), resume.clone());
                async move {
                    let call = calls.fetch_add(1, Ordering::Relaxed);
                    let server = server.get()?.upgrade()?;
                    if scope.owner() != bob.did {
                        return None;
                    }
                    let session = reopen_owner_session(&server, &bob, scope).await;
                    if call == 4 {
                        opened.notify_one();
                        resume.notified().await;
                    }
                    Some(session)
                }
            }
        };
        let mount = Mount::chat(&self.signer, ISSUER, RESOURCE, open).unwrap();
        let restarted = Arc::new(node(plc, rotation, store, "scoped-chat-restarted", Some(mount)).await);
        assert!(server.set(Arc::downgrade(&restarted)).is_ok());
        self.connect(&restarted).await;

        let alice_args = json!({"conversationId": "mountedalice"});
        assert_eq!(self.chat_call(alice, "chat-alice", HISTORY, alice_args.clone()).await.status(), 401);
        assert_eq!(self.chat_call(alice, "chat-bob", HISTORY, alice_args.clone()).await.status(), 401);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let denied = Self::chat_result(self.chat_call(bob, "chat-bob", HISTORY, alice_args).await).await;
        assert_eq!(denied["code"], "conversation_unavailable");
        let message = json!({"conversationId": "mountedbob", "messageId": "restart", "text": "Synthetic restart"});
        let receipt = Self::chat_result(self.chat_call(bob, "chat-bob", SEND, message.clone()).await).await;
        assert_eq!(receipt["authorDid"], bob.did);
        assert_eq!(Self::chat_result(self.chat_call(bob, "chat-bob", SEND, message).await).await, receipt);
        let bob_args = json!({"conversationId": "mountedbob"});
        let history = Self::chat_result(self.chat_call(bob, "chat-bob", HISTORY, bob_args.clone()).await).await;
        let messages = history["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["cid"], receipt["cid"]);

        let raced = json!({"conversationId": "mountedbob", "messageId": "raced", "text": "Revoked during opening"});
        let (response, ()) = tokio::join!(self.chat_call(bob, "chat-bob", SEND, raced), async {
            tokio::time::timeout(std::time::Duration::from_secs(5), opened.notified()).await.unwrap();
            let credentials = owner_credentials(&restarted, bob).await;
            revoke(&restarted.app, &credentials, grant(bob, "chat-bob"))
                .await
                .unwrap_or_else(|e| panic!("{}", e.message));
            resume.notify_one();
        });
        assert_eq!(response.status(), 401);
        assert_eq!(self.chat_call(bob, "chat-bob", HISTORY, bob_args).await.status(), 401);
        assert_eq!(calls.load(Ordering::Relaxed), 5);
    }

    async fn chat_call(&self, owner: &Account, id: &str, name: &str, args: J) -> reqwest::Response {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }))
        .unwrap();
        let mut claims = self.claims(owner, id);
        claims["body_sha256"] = json!(hex::encode(Sha256::digest(&body)));
        let token = Self::sign(&self.key, &claims);
        self.send(&token, &body).await
    }

    async fn chat_result(response: reqwest::Response) -> J {
        assert_eq!(response.headers()["cache-control"], "no-store");
        response.error_for_status().unwrap().json::<J>().await.unwrap()["result"]["structuredContent"].clone()
    }

    pub(super) async fn check_chat(&self, s: &TestServer, pairs: [(&Account, &Account); 2]) {
        use vlpds::xrpc::agent_chat::{HISTORY, SEND, START};

        let [(alice, alice_agent), (bob, bob_agent)] = pairs;
        let alice_chat = owner_session(s, alice, alice_agent, "mountedalice").await;
        let bob_chat = owner_session(s, bob, bob_agent, "mountedbob").await;
        for (owner, id, chat) in [(alice, "chat-alice", &alice_chat), (bob, "chat-bob", &bob_chat)] {
            let credentials = owner_credentials(s, owner).await;
            approve(&s.app, &credentials, grant(owner, id), chat.binding())
                .await
                .unwrap_or_else(|e| panic!("{}", e.message));
        }
        assert!(self.chats.set([alice_chat, bob_chat]).is_ok());

        for (owner, grant, conversation) in [(alice, "chat-alice", "mountedalice"), (bob, "chat-bob", "mountedbob")] {
            assert_eq!(
                Self::chat_result(self.chat_call(owner, grant, START, json!({})).await).await,
                json!({"conversationId": conversation})
            );
        }
        let message =
            json!({"conversationId": "mountedalice", "messageId": "first", "text": "Mounted synthetic message"});
        let receipt = Self::chat_result(self.chat_call(alice, "chat-alice", SEND, message.clone()).await).await;
        assert_eq!(receipt["authorDid"], alice.did);
        assert_eq!(Self::chat_result(self.chat_call(alice, "chat-alice", SEND, message.clone()).await).await, receipt);
        assert_eq!(self.chat_call(bob, "chat-alice", SEND, message.clone()).await.status(), 401);
        let denied = Self::chat_result(self.chat_call(bob, "chat-bob", SEND, message).await).await;
        assert_eq!(denied["code"], "conversation_unavailable");

        let alice_args = json!({"conversationId": "mountedalice"});
        let alice_history =
            Self::chat_result(self.chat_call(alice, "chat-alice", HISTORY, alice_args.clone()).await).await;
        let messages = alice_history["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["cid"], receipt["cid"]);
        let credentials = owner_credentials(s, alice).await;
        revoke(&s.app, &credentials, grant(alice, "chat-alice")).await.unwrap_or_else(|e| panic!("{}", e.message));
        assert_eq!(self.chat_call(alice, "chat-alice", HISTORY, alice_args).await.status(), 401);
        let bob_history =
            Self::chat_result(self.chat_call(bob, "chat-bob", HISTORY, json!({"conversationId": "mountedbob"})).await)
                .await;
        assert_eq!(bob_history["messages"], json!([]));
    }

    pub(super) async fn connect(&mut self, s: &TestServer) {
        self.audience = s.pds_did().await;
        self.url = format!("{}/xrpc/{METHOD}", s.url);
    }

    pub(super) async fn check_default_off(&self, s: &TestServer) {
        let target = format!("{}/xrpc/{METHOD}", s.url);
        for request in [
            self.client.post(&target),
            self.client.post(&target).header("atproto-proxy", "did:web:elsewhere.invalid#service"),
        ] {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 501);
            assert_eq!(response.json::<J>().await.unwrap()["error"], "MethodNotImplemented");
        }
    }

    fn claims(&self, owner: &Account, id: &str) -> J {
        let now = vlatproto::tid::now_micros() / 1_000_000;
        json!({
            "iss": self.signer, "aud": self.audience, "lxm": METHOD,
            "iat": now, "exp": now + 25, "jti": vlpds::space::token::new_jti(),
            "issuer": ISSUER, "resource": RESOURCE, "owner": owner.did, "grant": id,
            "body_sha256": hex::encode(Sha256::digest(BODY)),
        })
    }

    fn sign(key: &Keypair, claims: &J) -> String {
        let header = B64.encode(br#"{"typ":"JWT","alg":"ES256K"}"#);
        let payload = B64.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{header}.{payload}");
        let signature = key.sign_verified(Purpose::ServiceAuth, input.as_bytes()).unwrap();
        format!("{input}.{}", B64.encode(signature))
    }

    async fn send(&self, token: &str, bytes: &[u8]) -> reqwest::Response {
        self.client.post(&self.url).bearer_auth(token).body(bytes.to_vec()).send().await.unwrap()
    }

    pub(super) async fn check(&self, owner: &Account, id: &str, expected: Option<&Binding>) {
        let token = Self::sign(&self.key, &self.claims(owner, id));
        let response = self.send(&token, BODY).await;
        if let Some(expected) = expected {
            assert_eq!(response.error_for_status().unwrap().json::<Binding>().await.unwrap(), *expected);
        } else {
            assert_eq!(response.status(), 401);
        }
    }

    pub(super) async fn check_denials(&self, owner: &Account, other: &Account, binding: &Binding) {
        let token = Self::sign(&self.key, &self.claims(owner, "alice"));
        assert_eq!(self.client.get(&self.url).send().await.unwrap().status(), 400);
        assert_eq!(self.client.post(&self.url).body(vec![0; MAX_BODY_BYTES + 1]).send().await.unwrap().status(), 413);
        assert_eq!(
            self.client
                .post(format!("{}?other=1", self.url))
                .bearer_auth(&token)
                .body(BODY)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            self.client
                .post(&self.url)
                .bearer_auth(&token)
                .header("origin", ISSUER)
                .body(BODY)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(self.send(&token, b"different request").await.status(), 401);
        let response = self.send(&token, BODY).await;
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.json::<Binding>().await.unwrap(), *binding);
        assert_eq!(self.send(&token, BODY).await.status(), 401);
        let other_key = Keypair::generate();
        for (field, value, key) in [
            ("iss", json!(other.did), &other_key),
            ("aud", json!(other.did), &self.key),
            ("lxm", json!("chat.atagents.agent.contact"), &self.key),
            ("issuer", json!("https://other.example.invalid"), &self.key),
            ("resource", json!("https://other.example.invalid/mcp"), &self.key),
            ("exp", json!(1), &self.key),
        ] {
            let mut claims = self.claims(owner, "alice");
            claims[field] = value;
            assert_eq!(self.send(&Self::sign(key, &claims), BODY).await.status(), 401, "{field}");
        }
        let claims = self.claims(owner, "alice");
        assert_eq!(self.send(&Self::sign(&other_key, &claims), BODY).await.status(), 401);
        self.check(other, "alice", None).await;
    }

    pub(super) async fn approve(s: &TestServer, owner: &Account, agent: &Account, id: &str) -> Binding {
        let binding =
            Binding { agent: agent.did.clone(), space: format!("at:space/{}/com.example.mcpchat/test", owner.did) };
        let credentials = owner_credentials(s, owner).await;
        approve(&s.app, &credentials, grant(owner, id), binding.clone())
            .await
            .unwrap_or_else(|e| panic!("{}", e.message));
        binding
    }

    pub(super) async fn revoke_in_flight(&self, s: &TestServer, owner: &Account, id: &str) {
        self.deny_while_resolving(owner, id, async {
            let credentials = owner_credentials(s, owner).await;
            revoke(&s.app, &credentials, grant(owner, id)).await.unwrap_or_else(|e| panic!("{}", e.message));
        })
        .await;
        self.check(owner, id, None).await;
    }

    pub(super) async fn deny_while_resolving(&self, owner: &Account, id: &str, revoke: impl Future<Output = ()>) {
        let reached = Arc::new(Notify::new());
        let proceed = Arc::new(Notify::new());
        let (signal, resume) = (reached.clone(), proceed.clone());
        set_pause_hook(
            &owner.did,
            Some(Arc::new(move |point| {
                let hold = point == "agent_dispatch_before_final_read";
                let (signal, resume) = (signal.clone(), resume.clone());
                Box::pin(async move {
                    if hold {
                        signal.notify_one();
                        resume.notified().await;
                    }
                })
            })),
        );
        let token = Self::sign(&self.key, &self.claims(owner, id));
        let (response, ()) = tokio::join!(self.send(&token, BODY), async {
            tokio::time::timeout(std::time::Duration::from_secs(5), reached.notified()).await.unwrap();
            revoke.await;
            proceed.notify_one();
        });
        set_pause_hook(&owner.did, None);
        assert_eq!(response.status(), 401);
    }
}

fn grant<'a>(owner: &'a Account, id: &'a str) -> Grant<'a> {
    Grant { issuer: ISSUER, resource: RESOURCE, id, owner: &owner.did }
}

async fn owner_credentials(s: &TestServer, owner: &Account) -> vlpds::xrpc::authn::Credentials {
    let (parts, _) = axum::http::Request::builder()
        .header("authorization", format!("Bearer {}", owner.jwt))
        .body(())
        .unwrap()
        .into_parts();
    authenticate(&s.app, &parts).await.unwrap_or_else(|e| panic!("{}", e.message))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_dispatch_authentication_is_behind_global_ip_limit() {
    let mount = Mount::new("did:web:signer.example.invalid", ISSUER, RESOURCE, |_, _| async {
        panic!("unsigned request reached the dispatch consumer")
    })
    .unwrap();
    let s = TestServer::spawn_lone(move |config| {
        config.spaces = true;
        config.rate_limits_enabled = true;
        config.agent_dispatch = Some(mount);
    })
    .await;
    s.xrpc
        .post(
            "vlpds.admin.updateRateLimits",
            &json!({
                "config": {"limiters": {"global-ip": {"points": 1, "windowSecs": 3600}}},
                "ifVersion": 0, "actor": "synthetic-fixture",
            }),
            &Auth::Admin,
        )
        .await
        .ok();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{}/xrpc/{METHOD}", s.url);
    for status in [401, 429] {
        assert_eq!(client.post(&url).send().await.unwrap().status(), status);
    }
}
