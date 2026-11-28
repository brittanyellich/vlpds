//! Preview chat over the local PDS Spaces XRPCs.

use super::{
    credentials::{self, MESSAGE, THREAD},
    oauth_client::LoopbackOAuth,
    ChatSession, ScopedSession, SessionScope, ToolResult,
};
use crate::xrpc::{agent_dispatch::Binding, App};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::Generate,
};
use reqwest::{Method, Response};
use serde_json::{json, Value as J};
use zeroize::Zeroizing;

pub struct Session {
    scope: SessionScope,
    oauth: LoopbackOAuth,
    key: SigningKey,
    access: Zeroizing<String>,
    holder: SigningKey,
}

impl ScopedSession for Session {
    fn binding(&self) -> &Binding {
        self.scope.binding()
    }
}

impl Session {
    pub async fn open(app: &App, scope: SessionScope, listener: &str) -> Option<Self> {
        let oauth = LoopbackOAuth::with_listener(&app.public_url, listener).ok()?;
        let (key, tokens) = credentials::refresh(app, &scope, &oauth).await.ok()?;
        Some(Self {
            scope,
            oauth,
            key: SigningKey::from_slice(key.as_slice()).ok()?,
            access: tokens.access,
            holder: SigningKey::generate(),
        })
    }

    async fn credential(&self) -> Option<Zeroizing<String>> {
        let request = self
            .oauth
            .xrpc(Method::GET, "com.atproto.space.getDelegationToken")?
            .query(&[("space", &self.binding().space)]);
        let response = self.oauth.scoped(&self.key, &self.access, request).await?.error_for_status().ok()?;
        let body: J = response.json().await.ok()?;
        let token = body["token"].as_str()?;
        let mut key = vec![0x80, 0x24];
        key.extend_from_slice(self.holder.verifying_key().to_sec1_point(true).as_bytes());
        let response = self.oauth.xrpc(Method::POST, "com.atproto.space.authorizeSpaceSync")?
            .json(&json!({"space": self.binding().space, "credentialKey": format!("did:key:z{}", bs58::encode(key).into_string()), "delegationToken": token}))
            .send().await.ok()?.error_for_status().ok()?;
        let body: J = response.json().await.ok()?;
        Some(Zeroizing::new(body["credential"].as_str()?.to_owned()))
    }

    async fn read(&self, nsid: &str, repo: &str, credential: &str, query: &[(&str, &str)]) -> ToolResult {
        let mut request = self
            .oauth
            .xrpc(Method::GET, nsid)
            .ok_or("storage_error")?
            .query(&[("space", self.binding().space.as_str()), ("repo", repo)])
            .query(query);
        for (name, value) in crate::space::httpsig::headers(credential, repo, |base| {
            let sig: Signature = self.holder.sign(base);
            sig.to_bytes().into()
        }) {
            request = request.header(name, value);
        }
        let mac = if nsid == "com.atproto.space.getRecord" {
            let description: J = self
                .oauth
                .xrpc(Method::GET, "com.atproto.repo.describeRepo")
                .ok_or("storage_error")?
                .query(&[("repo", repo)])
                .send()
                .await
                .map_err(|_| "storage_error")?
                .error_for_status()
                .map_err(|_| "storage_error")?
                .json()
                .await
                .map_err(|_| "storage_error")?;
            let kem = crate::space::mac::kem_key_of(&description["didDoc"]).ok_or("storage_error")?;
            let (share, secret) = crate::space::mac::encapsulate(&kem).map_err(|_| "storage_error")?;
            request = request.header(
                crate::space::mac::ACCEPT_SIGNATURE,
                crate::space::mac::format_request(crate::space::mac::Profile::Record, &share),
            );
            Some((share, Zeroizing::new(secret)))
        } else {
            None
        };
        let response =
            request.send().await.map_err(|_| "storage_error")?.error_for_status().map_err(|_| "storage_error")?;
        let headers = mac.as_ref().map(|_| response.headers().clone());
        let body: J = response.json().await.map_err(|_| "storage_error")?;
        if let Some(((share, secret), headers)) = mac.zip(headers) {
            let header = |name: &str| {
                let values: Vec<_> = headers.get_all(name).iter().filter_map(|value| value.to_str().ok()).collect();
                (!values.is_empty()).then(|| values.join(", "))
            };
            let uri = body["uri"].as_str().ok_or("storage_error")?;
            let cid = body["cid"].as_str().ok_or("storage_error")?;
            crate::space::mac::verify_record(uri, cid, &share, &secret, &header).map_err(|_| "storage_error")?;
        }
        Ok(body)
    }

    async fn thread(&self, credential: &str) -> ToolResult {
        self.read(
            "com.atproto.space.getRecord",
            self.scope.owner(),
            credential,
            &[("collection", THREAD), ("rkey", "self")],
        )
        .await
        .map(|body| body["value"].clone())
        .map_err(|_| "conversation_unavailable")
    }

    async fn active_thread(&self) -> Result<Zeroizing<String>, &'static str> {
        let credential = self.credential().await.ok_or("conversation_unavailable")?;
        if self.thread(&credential).await?["agent"] != self.binding().agent {
            return Err("conversation_unavailable");
        }
        Ok(credential)
    }

    async fn create(&self, collection: &str, rkey: &str, record: &J) -> Result<Response, &'static str> {
        let request = self
            .oauth
            .xrpc(Method::POST, "com.atproto.space.createRecord")
            .ok_or("storage_error")?
            .json(&json!({"space": self.binding().space, "repo": self.scope.owner(), "collection": collection,
                "rkey": rkey, "record": record, "validate": false}));
        self.oauth.scoped(&self.key, &self.access, request).await.ok_or("storage_error")
    }
}

impl ChatSession for Session {
    fn conversation(&self) -> &str {
        self.scope.conversation()
    }

    async fn start(&self) -> ToolResult {
        let record = json!({"$type": THREAD, "agent": self.binding().agent});
        let response = self.create(THREAD, "self", &record).await?;
        if !response.status().is_success() {
            let body: J = response.json().await.map_err(|_| "storage_error")?;
            if body["error"] != "RecordAlreadyExists" {
                return Err("storage_error");
            }
            let credential = self.credential().await.ok_or("conversation_unavailable")?;
            if self.thread(&credential).await? != record {
                return Err("conversation_unavailable");
            }
        }
        Ok(json!({"conversationId": self.conversation()}))
    }

    async fn send(&self, message_id: &str, text: &str) -> ToolResult {
        let credential = self.active_thread().await?;
        let record = json!({"$type": MESSAGE, "text": text});
        let response = self.create(MESSAGE, message_id, &record).await?;
        let status = response.status();
        let body: J = response.json().await.map_err(|_| "storage_error")?;
        let stored = if status.is_success() {
            body
        } else if body["error"] == "RecordAlreadyExists" {
            let existing = self
                .read(
                    "com.atproto.space.getRecord",
                    self.scope.owner(),
                    &credential,
                    &[("collection", MESSAGE), ("rkey", message_id)],
                )
                .await?;
            if existing["value"] != record {
                return Err("idempotency_conflict");
            }
            existing
        } else {
            return Err("storage_error");
        };
        let cid = stored["cid"].as_str().ok_or("storage_error")?;
        Ok(json!({"messageId": message_id, "authorDid": self.scope.owner(), "cid": cid}))
    }

    async fn history(&self) -> ToolResult {
        let credential = self.active_thread().await?;
        let mut messages = Vec::new();
        for repo in [self.scope.owner(), &self.binding().agent] {
            let mut cursor = None::<String>;
            loop {
                let mut query = vec![("collection", MESSAGE), ("limit", "50")];
                if let Some(cursor) = &cursor {
                    query.push(("cursor", cursor));
                }
                let body = self.read("com.atproto.space.listRecords", repo, &credential, &query).await?;
                for record in body["records"].as_array().ok_or("storage_error")? {
                    messages.push(json!({"authorDid": repo, "messageId": record["rkey"], "cid": record["cid"],
                        "text": record["value"]["text"]}));
                }
                let Some(next) = body["cursor"].as_str() else { break };
                if cursor.as_deref() == Some(next) {
                    return Err("storage_error");
                }
                cursor = Some(next.to_owned());
            }
        }
        Ok(json!({"conversationId": self.conversation(), "messages": messages}))
    }
}
