//! Local MCP tool contract fixture. The transport supplies an authenticated
//! session and its approved binding; calls below exercise the real Spaces XRPCs.

use crate::common::spaces::SpaceClient;
use crate::common::{Resp, TestServer, J};
use serde_json::json;
use std::future::Future;
use vlpds::xrpc::agent_chat::{ChatSession, ToolResult, HISTORY, SEND, START};

mod auth;
pub(crate) mod http;

const SPACE_TYPE: &str = "com.example.mcpchat";
const MESSAGE: &str = "com.example.mcpchat.message";
const THREAD: &str = "com.example.mcpchat.thread";
const SCOPE: &str = concat!(
    "space:com.example.mcpchat?authority=*&action=read&action=create&manage=create&manage=update",
    "&collection=com.example.mcpchat.message&collection=com.example.mcpchat.thread",
);

struct Chat<'a> {
    caller: &'a SpaceClient,
    owner: &'a str,
    agent: &'a str,
    space: &'a str,
    conversation: &'a str,
}

impl ChatSession for Chat<'_> {
    fn conversation(&self) -> &str {
        self.conversation
    }

    async fn start(&self) -> ToolResult {
        if self.caller.did != self.owner {
            return Err("conversation_unavailable");
        }
        let record = json!({"$type": THREAD, "agent": self.agent});
        let response = self.create_record(THREAD, "self", &record).await;
        if response.json["error"] == "RecordAlreadyExists" {
            let credential = self.credential().await?;
            if self.thread(&credential).await? != record {
                return Err("conversation_unavailable");
            }
        } else if response.status != 200 {
            return Err("storage_error");
        }
        Ok(json!({"conversationId": self.conversation}))
    }

    async fn send(&self, message_id: &str, text: &str) -> ToolResult {
        self.active_thread().await?;
        self.write_message(message_id, text).await
    }

    async fn history(&self) -> ToolResult {
        let credential = self.active_thread().await?;
        self.read_history(&credential).await
    }
}

impl Chat<'_> {
    async fn active_thread(&self) -> Result<String, &'static str> {
        if self.caller.did != self.owner && self.caller.did != self.agent {
            return Err("conversation_unavailable");
        }
        let credential = self.credential().await?;
        if self.thread(&credential).await?["agent"] != self.agent {
            return Err("conversation_unavailable");
        }
        Ok(credential)
    }

    async fn credential(&self) -> Result<String, &'static str> {
        let delegation = self.caller.delegation_token(self.space).await;
        let token = delegation.json["token"].as_str().ok_or("conversation_unavailable")?;
        let response = self.caller.exchange(&self.caller.srv.base, self.space, token).await;
        response.json["credential"].as_str().map(str::to_owned).ok_or("conversation_unavailable")
    }

    async fn thread(&self, credential: &str) -> ToolResult {
        let query = [("space", self.space), ("repo", self.owner), ("collection", THREAD), ("rkey", "self")];
        let response = self
            .caller
            .signed_get(&self.caller.srv.base, "com.atproto.space.getRecord", &query, credential, self.owner)
            .await;
        if response.status != 200 {
            return Err("conversation_unavailable");
        }
        Ok(response.json["value"].clone())
    }

    async fn create_record(&self, collection: &str, rkey: &str, record: &J) -> Resp {
        // The tool validates its own synthetic schema; skip discovery of its example NSID.
        self.caller
            .post(
                "com.atproto.space.createRecord",
                json!({
                    "space": self.space, "repo": self.caller.did,
                    "collection": collection, "rkey": rkey, "record": record, "validate": false,
                }),
            )
            .await
    }

    async fn write_message(&self, message_id: &str, text: &str) -> ToolResult {
        let record = json!({"$type": MESSAGE, "text": text});
        let response = self.create_record(MESSAGE, message_id, &record).await;
        let stored = match (response.status, response.json["error"].as_str()) {
            (200, _) => response,
            (_, Some("RecordAlreadyExists")) => {
                let existing = self
                    .caller
                    .get(
                        "com.atproto.space.getRecord",
                        &[
                            ("space", self.space),
                            ("repo", &self.caller.did),
                            ("collection", MESSAGE),
                            ("rkey", message_id),
                        ],
                    )
                    .await;
                if existing.status != 200 {
                    return Err("storage_error");
                }
                if existing.json["value"] != record {
                    return Err("idempotency_conflict");
                }
                existing
            }
            _ => return Err("storage_error"),
        };
        Ok(json!({"messageId": message_id, "authorDid": self.caller.did, "cid": stored.json["cid"]}))
    }

    async fn read_history(&self, credential: &str) -> ToolResult {
        let mut messages = Vec::new();
        for repo in [self.owner, self.agent] {
            let mut cursor: Option<String> = None;
            loop {
                let mut query = vec![("space", self.space), ("repo", repo), ("collection", MESSAGE), ("limit", "50")];
                if let Some(cursor) = &cursor {
                    query.push(("cursor", cursor.as_str()));
                }
                let response = self
                    .caller
                    .signed_get(&self.caller.srv.base, "com.atproto.space.listRecords", &query, credential, repo)
                    .await;
                if response.status != 200 {
                    return Err("storage_error");
                }
                let records = response.json["records"].as_array().ok_or("storage_error")?;
                for record in records {
                    messages.push(json!({
                        "authorDid": repo, "messageId": record["rkey"], "cid": record["cid"], "text": record["value"]["text"],
                    }));
                }
                cursor = response.json["cursor"].as_str().map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(json!({"conversationId": self.conversation, "messages": messages}))
    }
}

async fn approved_space(owner: &SpaceClient, agent: &SpaceClient, key: &str) -> String {
    let space = owner.create_space(SPACE_TYPE, key).await;
    owner
        .post(
            "com.atproto.memberspace.putMembers",
            json!({
                "space": space, "members": [{"did": agent.did, "read": true, "write": true}]
            }),
        )
        .await
        .ok();
    space
}

async fn chat_session(
    server: &TestServer,
    caller: &SpaceClient,
    owner: &SpaceClient,
    agent: &SpaceClient,
    space: &str,
    conversation: &str,
) -> http::Session {
    let mut scope =
        format!("space:{SPACE_TYPE}?authority={}&action=read&action=create&collection={MESSAGE}", owner.did);
    if caller.did == owner.did {
        scope.push_str(&format!("&collection={THREAD}"));
    }
    let scoped = SpaceClient::for_account(server, &caller.did, &caller.handle, &caller.session_jwt, &scope).await;
    http::Session::new(scoped, &owner.did, &agent.did, space, conversation)
}

pub(crate) async fn owner_session(
    server: &TestServer,
    owner: &crate::oauth::Account,
    agent: &crate::oauth::Account,
    conversation: &str,
) -> http::Session {
    let owner = SpaceClient::for_account(server, &owner.did, &owner.handle, &owner.jwt, SCOPE).await;
    let agent = SpaceClient::for_account(server, &agent.did, &agent.handle, &agent.jwt, "atproto").await;
    let space = approved_space(&owner, &agent, conversation).await;
    chat_session(server, &owner, &owner, &agent, &space, conversation).await
}

pub(crate) async fn check_verified_bridge<F, Fut>(
    server: &TestServer,
    plc: &vlpds::plc::mock::MockPlc,
    pairs: [(&crate::oauth::Account, &crate::oauth::Account); 2],
    on_phase: F,
) -> Option<[http::WorkerGrant; 2]>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = ()>,
{
    if std::env::var_os("EXP711_WORKERD").is_none() && std::env::var_os("EXP711_OAUTH_PROVIDER").is_none() {
        return None;
    }
    let mut sessions = Vec::new();
    let mut foreign_token = None;
    for ((owner, agent), conversation) in pairs.into_iter().zip(["boundalice", "boundbob"]) {
        let owner = SpaceClient::for_account(server, &owner.did, &owner.handle, &owner.jwt, SCOPE).await;
        let agent = SpaceClient::for_account(server, &agent.did, &agent.handle, &agent.jwt, "atproto").await;
        let space = approved_space(&owner, &agent, conversation).await;
        sessions.push(chat_session(server, &owner, &owner, &agent, &space, conversation).await);
        foreign_token.get_or_insert(owner.access);
    }
    let signer = http::FixtureSigner::register(plc, server.pds_did().await).await;
    let mcp = http::Server::bind(sessions, Some(signer)).await;
    let direct = mcp
        .client(0)
        .post()
        .header("x-exp711-user", "owner-a")
        .header("x-exp711-grant", "client-supplied")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(mcp.check_oauth_bridge(&foreign_token.unwrap(), on_phase).await);
    let grants = mcp.worker_grants();
    // A rejected send must leave no record in the owner's actual Space.
    for id in ["race", "endorsement", "declaration", "crossowner"] {
        mcp.assert_record_absent(0, id).await;
    }
    mcp.assert_record_absent(1, "crossowner").await;
    Some(grants)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_mcp_chat_two_owners() {
    let store = std::sync::Arc::new(crate::common::throttled_store(0));
    let server = TestServer::spawn_with(|config| {
        config.spaces = true;
        config.memory_store = Some(store.clone());
    })
    .await;
    let alice = SpaceClient::new(&server, "mcpalice", SCOPE).await;
    let bob = SpaceClient::new(&server, "mcpbob", SCOPE).await;
    let alice_agent = SpaceClient::new(&server, "mcpagentone", SCOPE).await;
    let bob_agent = SpaceClient::new(&server, "mcpagenttwo", SCOPE).await;

    let alice_space = approved_space(&alice, &alice_agent, "alicechat").await;
    let bob_space = approved_space(&bob, &bob_agent, "bobchat").await;
    let mcp = http::Server::bind(
        vec![
            chat_session(&server, &alice, &alice, &alice_agent, &alice_space, "alicechat").await,
            chat_session(&server, &bob, &bob, &bob_agent, &bob_space, "bobchat").await,
            chat_session(&server, &alice_agent, &alice, &alice_agent, &alice_space, "alicechat").await,
            chat_session(&server, &alice, &alice, &alice_agent, &alice_space, "alicechat").await,
        ],
        None,
    )
    .await;
    let chat = mcp.client(0);
    let bob_chat = mcp.client(1);
    let agent = mcp.client(2);
    chat.assert_transport_boundaries().await;
    for client in [&chat, &bob_chat, &agent] {
        client.initialize().await;
    }

    let listing = chat.rpc("tools/list", json!({})).await;
    let names: Vec<_> = listing["tools"].as_array().unwrap().iter().map(|tool| tool["name"].clone()).collect();
    assert_eq!(names, [START, SEND, HISTORY].map(|name| json!(name)));

    let alice_id = json!({"conversationId": "alicechat"});
    let unavailable = json!({"code": "conversation_unavailable"});
    assert_eq!(chat.call(HISTORY, alice_id.clone()).await["structuredContent"], unavailable);
    let started = chat.call(START, json!({})).await;
    assert_eq!(started["structuredContent"], alice_id);
    assert_eq!(chat.call(START, json!({})).await, started);
    assert_eq!(bob_chat.call(START, json!({})).await["structuredContent"], json!({"conversationId": "bobchat"}));

    let send = json!({"conversationId": "alicechat", "messageId": "first", "text": "Synthetic question"});
    // Let the worker observe the duplicate while the first create is
    // still waiting on its log write.
    store.config_mut(|config| config.wait_put_per_call = std::time::Duration::from_millis(100));
    let (receipt, retry) = tokio::join!(chat.call(SEND, send.clone()), chat.call(SEND, send.clone()));
    store.config_mut(|config| config.wait_put_per_call = std::time::Duration::ZERO);
    assert_eq!(receipt["isError"], false);
    assert_eq!(receipt, retry);
    assert_eq!(receipt["structuredContent"]["authorDid"], alice.did);
    let mut changed = send.clone();
    changed["text"] = json!("different");
    assert_eq!(chat.call(SEND, changed).await["structuredContent"]["code"], "idempotency_conflict");

    let mut spoofed = send.clone();
    spoofed["authorDid"] = json!(bob.did);
    assert_eq!(chat.call(SEND, spoofed).await["structuredContent"]["code"], "invalid_arguments");

    assert_eq!(agent.call(START, json!({})).await["structuredContent"], unavailable);
    let reply = agent
        .call(
            SEND,
            json!({
                "conversationId": "alicechat", "messageId": "first", "text": "Synthetic reply",
            }),
        )
        .await;
    assert_eq!(reply["structuredContent"]["authorDid"], alice_agent.did);

    let fresh = mcp.client(3);
    fresh.initialize().await;
    let resumed = fresh.call(HISTORY, alice_id.clone()).await;
    let messages = resumed["structuredContent"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["text"], "Synthetic question");
    assert_eq!(messages[1]["text"], "Synthetic reply");
    assert_eq!(messages[1]["authorDid"], alice_agent.did);
    assert_eq!(messages[0]["cid"], receipt["structuredContent"]["cid"]);
    assert_eq!(agent.call(HISTORY, alice_id.clone()).await, resumed);

    for (name, args) in [(HISTORY, alice_id), (SEND, send)] {
        let denied = bob_chat.call(name, args).await;
        assert_eq!(denied["isError"], true);
        assert_eq!(denied["structuredContent"], unavailable);
    }
    let denied = bob_chat.call(HISTORY, json!({"conversationId": "bobchat"})).await;
    assert_eq!(denied["structuredContent"]["messages"], json!([]));

    if mcp.check_oauth_bridge(&alice.access, |_| async {}).await {
        // Verify exactly which records reached the real PDS, including the
        // absence of attempted cross-owner and post-revocation writes.
        let alice_history = chat.call(HISTORY, json!({"conversationId": "alicechat"})).await;
        let bob_history = bob_chat.call(HISTORY, json!({"conversationId": "bobchat"})).await;
        let alice_records = alice_history["structuredContent"]["messages"].as_array().unwrap();
        assert_eq!(alice_records.len(), 3);
        assert!(alice_records.iter().any(|entry| {
            entry["messageId"] == "worker" && entry["authorDid"] == alice.did && entry["text"] == "OAuth owner A"
        }));
        let bob_records = bob_history["structuredContent"]["messages"].as_array().unwrap();
        assert_eq!(bob_records.len(), 1);
        assert_eq!(bob_records[0]["messageId"], "worker");
        assert_eq!(bob_records[0]["authorDid"], bob.did);
        assert_eq!(bob_records[0]["text"], "OAuth owner B");
    }

    let token = bob.delegation_token(&alice_space).await.ok()["token"].as_str().unwrap().to_owned();
    bob.exchange(&server.url, &alice_space, &token).await.err(400, "SpaceNotFound");
    bob.post(
        "com.atproto.space.createRecord",
        json!({
            "space": alice_space, "repo": alice.did, "collection": MESSAGE, "rkey": "first",
            "record": {"$type": MESSAGE, "text": "denied"}, "validate": false,
        }),
    )
    .await
    .err(403, "Forbidden");
}
