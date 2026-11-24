use super::*;
use axum::{body::Bytes, extract::DefaultBodyLimit, http::HeaderMap, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
use std::future::Future;
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use vlatproto::crypto::Purpose;
use vlpds::xrpc::{
    agent_dispatch::{approve, revoke, Binding, Grant},
    agent_dispatch_auth::{admit, Authority, MAX_BODY_BYTES, METHOD},
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
    task: JoinHandle<()>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Bridge {
    pub(super) async fn start(s: &TestServer, plc: &MockPlc) -> Self {
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/xrpc/{METHOD}", listener.local_addr().unwrap());
        let app = s.app.clone();
        let trusted = signer.clone();
        let router = Router::new()
            .route(
                &format!("/xrpc/{METHOD}"),
                post(move |headers: HeaderMap, body: Bytes| {
                    let (app, signer) = (app.clone(), trusted.clone());
                    async move {
                        let token = headers
                            .get("authorization")
                            .and_then(|h| h.to_str().ok())
                            .and_then(|h| h.strip_prefix("Bearer "))
                            .ok_or_else(|| vlatproto::xrpc::XrpcError::auth("Missing dispatch assertion"))?;
                        admit(&app, &Authority { signer: &signer, issuer: ISSUER, resource: RESOURCE }, token, &body)
                            .await
                            .map(Json)
                    }
                }),
            )
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { key, signer, audience: s.pds_did().await, url, client, task }
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
        assert_eq!(self.send(&token, b"different request").await.status(), 401);
        assert_eq!(self.send(&token, BODY).await.json::<Binding>().await.unwrap(), *binding);
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
            Binding { agent: agent.did.clone(), space: format!("at://{}/space/com.example.mcpchat/test", owner.did) };
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
