//! Exercise the upstream OAuth leg using a disposable metadata client, grant
//! approvals, and two successive PDS nodes sharing the same object store.

use super::{J, MESSAGE, SPACE_TYPE};
use crate::common::{cluster_node, TestServer};
use crate::oauth::{self, Account, Browser, DpopKey, Flow, Srv, Tokens};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use std::sync::Arc;

const HOST: &str = "mcp-auth-pds.invalid";
const ISSUER: &str = "http://mcp-auth-pds.invalid";
const MCP_RESOURCE: &str = "http://mcp-chat.invalid/mcp";
const REDIRECT: &str = "https://mcp-bridge.invalid/callback";

async fn pds(id: &str, store: Arc<object_store::memory::InMemory>) -> (TestServer, Srv) {
    let node = cluster_node(id, store, 4, |config| {
        config.public_url = ISSUER.into();
        config.spaces = true;
    })
    .await;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(HOST, node.addr)
        .build()
        .unwrap();
    let client = Srv { app: node.app.clone(), base: ISSUER.into(), http };
    (node, client)
}

async fn private_space(srv: &Srv, owner: &Account) -> String {
    let key = DpopKey::new();
    let scope = format!("atproto space:{SPACE_TYPE}?action=read&manage=create");
    let grant = oauth::grant(srv, &mut Browser::default(), &Flow::loopback(&scope, &key), owner).await;
    let result = oauth::xrpc_dpop(
        srv,
        &key,
        &grant.access,
        "POST",
        "com.atproto.space.createSpace",
        Some(
            json!({"spaceType": SPACE_TYPE, "skey": "approval", "policy": {"$type": "com.atproto.memberspace.policy"}}),
        ),
    )
    .await;
    assert_eq!(result.status, 200, "{}", result.body);
    result.body["space"].as_str().unwrap().to_owned()
}

async fn grant(srv: &Srv, flow: &Flow<'_>, account: &Account) -> Tokens {
    let pkce = oauth::pkce();
    let code = oauth::authorize_interactive(srv, &mut Browser::default(), flow, account, &pkce).await;
    let grant = oauth::tokens(&oauth::exchange(srv, flow, &code, &pkce, &[("resource", MCP_RESOURCE)]).await);
    let scope = grant.scope.split_whitespace().find(|s| s.starts_with("space:")).unwrap();
    assert!(
        scope.contains(&format!("authority={}", account.did))
            || scope.contains(&format!("authority={}", oauth::enc(&account.did)))
    );
    assert!(!scope.contains("manage="));

    // A supplied MCP resource indicator did not change the upstream audience.
    let payload = grant.access.split('.').nth(1).unwrap();
    let claims: J = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["aud"], srv.app.jwt.service_did);
    assert_ne!(claims["aud"], MCP_RESOURCE);
    grant
}

async fn write(srv: &Srv, flow: &Flow<'_>, grant: &Tokens, repo: &str, space: &str, key: &str) -> oauth::Resp {
    oauth::xrpc_dpop(
        srv,
        flow.key,
        &grant.access,
        "POST",
        "com.atproto.space.createRecord",
        Some(json!({
            "repo": repo, "space": space, "collection": MESSAGE, "rkey": key, "validate": false,
            "record": {"$type": MESSAGE, "text": "Synthetic authorization fixture"}
        })),
    )
    .await
}

async fn read(srv: &Srv, flow: &Flow<'_>, grant: &Tokens, repo: &str, space: &str) -> oauth::Resp {
    let method = format!(
        "com.atproto.space.getRecord?repo={}&space={}&collection={MESSAGE}&rkey=first",
        oauth::enc(repo),
        oauth::enc(space),
    );
    oauth::xrpc_dpop(srv, flow.key, &grant.access, "GET", &method, None).await
}

async fn session_id(srv: &Srv, owner: &Account, client_id: &str) -> String {
    let (status, response) = srv.bearer(&owner.jwt, "vlpds.oauth.listSessions", false, None).await;
    assert_eq!(status, 200);
    response["sessions"].as_array().unwrap().iter().find(|s| s["clientId"] == client_id).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn revoke(srv: &Srv, owner: &Account, session: &str) -> (u16, J) {
    srv.bearer(&owner.jwt, "vlpds.oauth.revokeSession", true, Some(json!({"id": session}))).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_mcp_oauth_restart_and_revoke() {
    let store = Arc::new(object_store::memory::InMemory::new());
    let (first, srv) = pds("mcp-auth-first", store.clone()).await;
    let metadata = srv.get_json("/.well-known/oauth-authorization-server").await;
    assert_eq!(metadata["require_pushed_authorization_requests"], true);
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    assert!(metadata.get("registration_endpoint").is_none());
    let resource = srv.get_json("/.well-known/oauth-protected-resource").await;
    assert_eq!(resource["resource"], ISSUER);

    let scope = format!("atproto space:{SPACE_TYPE}?authority=self&action=read&action=create&collection={MESSAGE}");
    let client_id = oauth::serve_metadata(|id| {
        json!({
            "client_id": id, "client_name": "Synthetic MCP bridge", "redirect_uris": [REDIRECT],
            "scope": scope, "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none", "application_type": "web", "dpop_bound_access_tokens": true,
        })
    })
    .await;
    let alice = oauth::create_account(&srv, "mcpgrantone").await;
    let bob = oauth::create_account(&srv, "mcpgranttwo").await;
    let alice_space = private_space(&srv, &alice).await;
    let bob_space = private_space(&srv, &bob).await;
    let alice_key = DpopKey::new();
    let bob_key = DpopKey::new();
    let alice_flow = Flow::new(&client_id, REDIRECT, &scope, &alice_key).with("resource", MCP_RESOURCE);
    let bob_flow = Flow::new(&client_id, REDIRECT, &scope, &bob_key).with("resource", MCP_RESOURCE);
    let alice_grant = grant(&srv, &alice_flow, &alice).await;
    let bob_grant = grant(&srv, &bob_flow, &bob).await;

    assert_eq!(write(&srv, &alice_flow, &alice_grant, &alice.did, &alice_space, "first").await.status, 200);
    assert_eq!(write(&srv, &bob_flow, &bob_grant, &bob.did, &bob_space, "first").await.status, 200);
    let denied = write(&srv, &bob_flow, &bob_grant, &bob.did, &alice_space, "foreign").await;
    assert_eq!((denied.status, &denied.body["error"]), (403, &json!("ScopeMissingError")));
    let alice_session = session_id(&srv, &alice, &client_id).await;
    let denied = revoke(&srv, &bob, &alice_session).await;
    assert_eq!((denied.0, &denied.1["error"]), (400, &json!("SessionNotFound")));

    assert!(vlpds::server::shutdown_gracefully(&first.app, std::time::Duration::from_secs(5)).await);
    drop((first, srv));
    let (_second, srv) = pds("mcp-auth-second", store).await;

    let alice_rt = alice_grant.refresh.as_deref().unwrap();
    let bob_rt = bob_grant.refresh.as_deref().unwrap();
    let wrong_key = oauth::refresh(&srv, &bob_flow, alice_rt, &[]).await;
    assert_eq!(wrong_key.status, 400);
    *alice_key.nonce.lock() = None;
    *bob_key.nonce.lock() = None;
    let alice_reconnected = oauth::tokens(&oauth::refresh(&srv, &alice_flow, alice_rt, &[]).await);
    let bob_reconnected = oauth::tokens(&oauth::refresh(&srv, &bob_flow, bob_rt, &[]).await);
    assert_ne!(alice_reconnected.refresh.as_deref(), Some(alice_rt));
    assert_ne!(bob_reconnected.refresh.as_deref(), Some(bob_rt));
    let alice_record = read(&srv, &alice_flow, &alice_reconnected, &alice.did, &alice_space).await;
    assert_eq!(alice_record.status, 200);
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &bob.did, &bob_space).await.status, 200);
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &alice.did, &alice_space).await.status, 400);

    assert_eq!(revoke(&srv, &alice, &alice_session).await.0, 200);
    assert_eq!(read(&srv, &alice_flow, &alice_reconnected, &alice.did, &alice_space).await.status, 401);
    let revoked = oauth::refresh(&srv, &alice_flow, alice_reconnected.refresh.as_deref().unwrap(), &[]).await;
    assert_eq!((revoked.status, &revoked.body["error"]), (400, &json!("invalid_grant")));
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &bob.did, &bob_space).await.status, 200);

    let reapproved = grant(&srv, &alice_flow, &alice).await;
    let persisted = read(&srv, &alice_flow, &reapproved, &alice.did, &alice_space).await;
    assert_eq!(persisted.status, 200);
    assert_eq!(persisted.body["cid"], alice_record.body["cid"]);
}
