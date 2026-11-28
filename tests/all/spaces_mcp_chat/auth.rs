//! Exercise the upstream OAuth leg using a disposable metadata client, grant
//! approvals, and two successive PDS nodes sharing the same object store.

use super::{J, MESSAGE, SPACE_TYPE};
use crate::common::{cluster_node, TestServer};
use crate::oauth::{self, Account, Browser, DpopKey, Flow, Srv, Tokens};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use std::sync::Arc;
use vlpds::xrpc::{
    agent_chat::rotation::{Grant as UpstreamGrant, Rotation},
    agent_dispatch::Binding,
};

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
    let flow = Flow::loopback(&scope, &key);
    let grant = oauth::grant(srv, &mut Browser::default(), &flow, owner).await;
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

// The fixture keeps the wrapping key separate from the disposable on-disk
// credential envelope. The approved Space is part of the authenticated context.
fn save_session(vault: &vlpds::secrets::LocalKek, path: &std::path::Path, space: &str, key: &DpopKey, grant: &Tokens) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let sealed = seal_session(vault, space, key, grant);
    let pending = path.with_extension("pending");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)
        .and_then(|mut file| {
            file.write_all(&sealed)?;
            file.sync_all()
        })
        .unwrap();
    std::fs::rename(pending, path).unwrap();
    sync_directory(path).unwrap();
}

fn seal_session(vault: &vlpds::secrets::LocalKek, space: &str, key: &DpopKey, grant: &Tokens) -> Vec<u8> {
    let key = key.private_bytes();
    let mut material = zeroize::Zeroizing::new(key.to_vec());
    material.extend_from_slice(grant.refresh.as_deref().unwrap().as_bytes());
    vault.wrap_sync(space.as_bytes(), &material)
}

fn open_session(
    vault: &vlpds::secrets::LocalKek,
    path: &std::path::Path,
    space: &str,
) -> Result<(DpopKey, zeroize::Zeroizing<String>), vlpds::secrets::SecretError> {
    let sealed = std::fs::read(path).map_err(|_| vlpds::secrets::SecretError::Malformed)?;
    unseal_session(vault, space, &sealed)
}

fn unseal_session(
    vault: &vlpds::secrets::LocalKek,
    space: &str,
    sealed: &[u8],
) -> Result<(DpopKey, zeroize::Zeroizing<String>), vlpds::secrets::SecretError> {
    let material = vault.unwrap_sync(space.as_bytes(), sealed)?;
    let (key, refresh) = material.split_at(32);
    Ok((DpopKey::from_private_bytes(key), zeroize::Zeroizing::new(std::str::from_utf8(refresh).unwrap().to_owned())))
}

fn sync_directory(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(path.parent().unwrap())?.sync_all()
}

// Retire the active envelope before contacting the issuer. An outstanding
// rotation survives restart and requires fresh owner authorization.
fn begin_rotation(
    vault: &vlpds::secrets::LocalKek,
    path: &std::path::Path,
    space: &str,
) -> Option<(DpopKey, zeroize::Zeroizing<String>)> {
    let rotating = path.with_extension("rotating");
    if rotating.try_exists().ok()? {
        return None;
    }
    std::fs::rename(path, &rotating).ok()?;
    sync_directory(path).ok()?;
    open_session(vault, &rotating, space).ok()
}

fn finish_rotation(
    vault: &vlpds::secrets::LocalKek,
    path: &std::path::Path,
    space: &str,
    key: &DpopKey,
    grant: &Tokens,
) -> std::io::Result<()> {
    save_session(vault, path, space, key, grant);
    std::fs::remove_file(path.with_extension("rotating"))?;
    sync_directory(path)
}

pub(crate) struct MountedCredentials {
    binding: Binding,
}

struct CredentialDirectory(std::path::PathBuf);

impl CredentialDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(crate::common::unique_name("mcp-credentials"));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for CredentialDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn upstream_grant(srv: &Srv, flow: &Flow<'_>, tokens: &Tokens) -> UpstreamGrant {
    let refresh = vlpds::oauth::store::parse_refresh_token(tokens.refresh.as_deref().unwrap()).unwrap();
    UpstreamGrant { issuer: srv.base.clone(), client: flow.client_id.clone(), id: refresh.session_id }
}

fn local_oauth(server: &TestServer) -> Srv {
    Srv {
        app: server.app.clone(),
        base: server.url.clone(),
        http: reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
    }
}

impl MountedCredentials {
    pub(crate) async fn issue(server: &TestServer, owner: &Account, binding: Binding, conversation: &str) -> Self {
        Self::issue_at(&local_oauth(server), owner, binding, conversation).await
    }

    pub(crate) async fn issue_at(srv: &Srv, owner: &Account, binding: Binding, conversation: &str) -> Self {
        use tower::ServiceExt;
        use vlpds::xrpc::agent_grant_recovery::http::{Mount, PATH};
        assert!(binding.space.ends_with(&format!("/{conversation}")));
        let redirect = "http://127.0.0.1:43811/callback";
        let bridge_token = "disposable-preview-service-token";
        let selected = binding.clone();
        let owner_did = owner.did.clone();
        let router = Mount::new("https://preview.example.invalid", bridge_token, move |did| {
            (did == owner_did).then(|| selected.clone())
        })
        .unwrap()
        .with_enrollment(redirect.into())
        .unwrap()
        .private_router(srv.app.clone());
        let call = |body: J| {
            let request = axum::extract::Request::builder()
                .method("POST")
                .uri(PATH)
                .header("authorization", format!("Bearer {bridge_token}"))
                .header("x-vlpds-owner-session", format!("Bearer {}", owner.jwt))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap();
            router.clone().oneshot(request)
        };
        let started = call(json!({"operation": "enrollment-start"})).await.unwrap();
        assert_eq!(started.status(), 200);
        assert_eq!(started.headers()["cache-control"], "no-store");
        let bytes = axum::body::to_bytes(started.into_body(), 16 * 1024).await.unwrap();
        let authorization: J = serde_json::from_slice(&bytes).unwrap();
        assert!(authorization.get("verifier").is_none());
        let key = DpopKey::new(); // Browser fixture does not hold the enrollment key.
        let flow = Flow::new(authorization["clientId"].as_str().unwrap(), redirect, "", &key);
        let (status, headers, _) = oauth::browser_consent(
            srv,
            &mut Browser::default(),
            &flow,
            owner,
            authorization["requestUri"].as_str().unwrap(),
            &[],
        )
        .await;
        assert_eq!(status, 303);
        let (callback, params) = oauth::location_params(&headers);
        assert_eq!(callback, redirect);
        assert_eq!(params["state"], authorization["state"].as_str().unwrap());
        let finish = |state: &str| {
            call(json!({
                "operation": "enrollment-finish", "state": state, "issuer": params["iss"], "code": params["code"],
            }))
        };
        assert_eq!(finish("invalid-state").await.unwrap().status(), 403);
        assert_eq!(finish(&params["state"]).await.unwrap().status(), 204);
        assert_eq!(finish(&params["state"]).await.unwrap().status(), 403);
        Self { binding }
    }

    pub(crate) async fn open(
        &self,
        server: &TestServer,
        owner: &Account,
        scope: vlpds::xrpc::agent_chat::SessionScope,
    ) -> Option<vlpds::xrpc::agent_chat::runtime::Session> {
        if scope.owner() != owner.did || scope.binding() != &self.binding {
            return None;
        }
        vlpds::xrpc::agent_chat::runtime::Session::open(&server.app, scope, &server.url).await
    }
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

    let scope = format!(
        "atproto space:{SPACE_TYPE}?authority=self&skey=approval&action=read&action=create&collection={MESSAGE}"
    );
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

    let contention_binding = Binding { agent: alice.did.clone(), space: bob_space.clone() };
    let first_provider =
        Rotation::new(&srv.app, &bob.did, &contention_binding).unwrap_or_else(|error| panic!("{}", error.message));
    let second_provider =
        Rotation::new(&srv.app, &bob.did, &contention_binding).unwrap_or_else(|error| panic!("{}", error.message));
    let wrapping_key = vlpds::secrets::KekBytes::random();
    let vault = vlpds::secrets::LocalKek::new(&wrapping_key);
    let old_upstream = upstream_grant(&srv, &bob_flow, &bob_grant);
    let old_envelope = seal_session(&vault, &bob_space, &bob_key, &bob_grant);
    assert!(first_provider
        .install(old_upstream.clone(), old_envelope.clone())
        .await
        .unwrap_or_else(|error| panic!("{}", error.message)));
    let (first_claim, second_claim) = tokio::join!(first_provider.claim(), second_provider.claim());
    let first_claim = first_claim.unwrap_or_else(|error| panic!("{}", error.message));
    let second_claim = second_claim.unwrap_or_else(|error| panic!("{}", error.message));
    assert_ne!(first_claim.is_some(), second_claim.is_some());
    let stale_claim = first_claim.or(second_claim).unwrap();
    assert_eq!(stale_claim.envelope, old_envelope);

    let credentials = CredentialDirectory::new();
    let alice_path = credentials.0.join("alice");
    let bob_path = credentials.0.join("bob");
    save_session(&vault, &alice_path, &alice_space, &alice_key, &alice_grant);
    save_session(&vault, &bob_path, &bob_space, &bob_key, &bob_grant);
    drop((alice_key, bob_key, alice_grant, bob_grant, vault));

    assert!(vlpds::server::shutdown_gracefully(&first.app, std::time::Duration::from_secs(5)).await);
    drop((first, srv));
    let (second, srv) = pds("mcp-auth-second", store.clone()).await;
    let reopened_provider =
        Rotation::new(&srv.app, &bob.did, &contention_binding).unwrap_or_else(|error| panic!("{}", error.message));
    assert!(reopened_provider.claim().await.unwrap_or_else(|error| panic!("{}", error.message)).is_none());
    assert!(!reopened_provider
        .install(old_upstream.clone(), vec![2])
        .await
        .unwrap_or_else(|error| panic!("{}", error.message)));

    let vault = vlpds::secrets::LocalKek::new(&wrapping_key);
    assert!(open_session(&vault, &alice_path, &bob_space).is_err());
    let (alice_key, alice_rt) = open_session(&vault, &alice_path, &alice_space).unwrap();
    let (bob_key, bob_rt) = open_session(&vault, &bob_path, &bob_space).unwrap();
    let alice_flow = Flow::new(&client_id, REDIRECT, &scope, &alice_key).with("resource", MCP_RESOURCE);
    let bob_flow = Flow::new(&client_id, REDIRECT, &scope, &bob_key).with("resource", MCP_RESOURCE);
    let wrong_key = oauth::refresh(&srv, &bob_flow, &alice_rt, &[]).await;
    assert_eq!(wrong_key.status, 400);
    *bob_key.nonce.lock() = None;
    let alice_reconnected = oauth::tokens(&oauth::refresh(&srv, &alice_flow, &alice_rt, &[]).await);
    let bob_reconnected = oauth::tokens(&oauth::refresh(&srv, &bob_flow, &bob_rt, &[]).await);
    assert_ne!(alice_reconnected.refresh.as_deref(), Some(alice_rt.as_str()));
    assert_ne!(bob_reconnected.refresh.as_deref(), Some(bob_rt.as_str()));
    let alice_record = read(&srv, &alice_flow, &alice_reconnected, &alice.did, &alice_space).await;
    assert_eq!(alice_record.status, 200);
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &bob.did, &bob_space).await.status, 200);
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &alice.did, &alice_space).await.status, 400);

    assert_eq!(revoke(&srv, &alice, &alice_session).await.0, 200);
    assert_eq!(read(&srv, &alice_flow, &alice_reconnected, &alice.did, &alice_space).await.status, 401);
    let revoked = oauth::refresh(&srv, &alice_flow, alice_reconnected.refresh.as_deref().unwrap(), &[]).await;
    assert_eq!((revoked.status, &revoked.body["error"]), (400, &json!("invalid_grant")));
    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &bob.did, &bob_space).await.status, 200);

    use vlpds::xrpc::agent_grant_recovery::runner::CleanupOutcome;
    let replacement = grant(&srv, &bob_flow, &bob).await;
    let replacement_grant = upstream_grant(&srv, &bob_flow, &replacement);
    let blocked = reopened_provider.blocked().await.unwrap_or_else(|error| panic!("{}", error.message)).unwrap();
    assert!(reopened_provider
        .replace_blocked(blocked, old_upstream.clone(), vec![2])
        .await
        .unwrap_or_else(|error| panic!("{}", error.message))
        .is_none());
    let blocked = reopened_provider.blocked().await.unwrap_or_else(|error| panic!("{}", error.message)).unwrap();
    let retirement = reopened_provider
        .replace_blocked(blocked, replacement_grant.clone(), seal_session(&vault, &bob_space, &bob_key, &replacement))
        .await
        .unwrap_or_else(|error| panic!("{}", error.message))
        .unwrap();
    assert!(!reopened_provider
        .complete(stale_claim, vec![3])
        .await
        .unwrap_or_else(|error| panic!("{}", error.message)));
    let result = reopened_provider
        .retire(&retirement, |queued| {
            let (bob, old_upstream, replacement_grant) = (&bob, &old_upstream, &replacement_grant);
            async move {
                assert_eq!(queued.owner, bob.did);
                assert_eq!(&queued.grant, old_upstream);
                assert_ne!(&queued.grant, replacement_grant);
                CleanupOutcome::Retry // The issuer is unavailable during this pass.
            }
        })
        .await
        .unwrap_or_else(|error| panic!("{}", error.message));
    assert!(matches!(result, CleanupOutcome::Retry));
    assert!(vlpds::server::shutdown_gracefully(&second.app, std::time::Duration::from_secs(5)).await);
    drop((second, srv));
    let (_third, srv) = pds("mcp-auth-cleanup-restart", store).await;
    *alice_key.nonce.lock() = None;
    *bob_key.nonce.lock() = None;
    let cleanup_provider =
        Rotation::new(&srv.app, &bob.did, &contention_binding).unwrap_or_else(|error| panic!("{}", error.message));
    assert_eq!(
        cleanup_provider.drain_local_retirements(16).await.unwrap_or_else(|error| panic!("{}", error.message)),
        1
    );
    assert_eq!(
        cleanup_provider.drain_local_retirements(16).await.unwrap_or_else(|error| panic!("{}", error.message)),
        0
    );
    assert_eq!(read(&srv, &bob_flow, &replacement, &bob.did, &bob_space).await.status, 200);
    let installed = cleanup_provider.claim().await.unwrap_or_else(|error| panic!("{}", error.message)).unwrap();
    let (key, refresh) = unseal_session(&vault, &bob_space, &installed.envelope).unwrap();
    let replacement_flow = Flow::new(&client_id, REDIRECT, &scope, &key);
    let fresh = oauth::tokens(&oauth::refresh(&srv, &replacement_flow, &refresh, &[]).await);
    assert_eq!(read(&srv, &replacement_flow, &fresh, &bob.did, &bob_space).await.status, 200);
    assert!(cleanup_provider
        .complete(installed, seal_session(&vault, &bob_space, &key, &fresh))
        .await
        .unwrap_or_else(|error| panic!("{}", error.message)));

    assert_eq!(read(&srv, &bob_flow, &bob_reconnected, &bob.did, &bob_space).await.status, 401);

    let reapproved = grant(&srv, &alice_flow, &alice).await;
    let persisted = read(&srv, &alice_flow, &reapproved, &alice.did, &alice_space).await;
    assert_eq!(persisted.status, 200);
    assert_eq!(persisted.body["cid"], alice_record.body["cid"]);

    // Simulate process loss after the issuer accepted the refresh and before
    // the client saved the replacement. A fresh provider sees only the marker.
    let crash_path = credentials.0.join("crash");
    save_session(&vault, &crash_path, &alice_space, &alice_key, &reapproved);
    let (crash_key, old_refresh) = begin_rotation(&vault, &crash_path, &alice_space).unwrap();
    let crash_flow = Flow::new(&client_id, REDIRECT, &scope, &crash_key);
    let upstream = oauth::tokens(&oauth::refresh(&srv, &crash_flow, &old_refresh, &[]).await);
    drop((vault, old_refresh));
    let reopened = vlpds::secrets::LocalKek::new(&wrapping_key);
    assert!(begin_rotation(&reopened, &crash_path, &alice_space).is_none());
    // Blind replay would revoke this upstream session.
    assert_eq!(read(&srv, &crash_flow, &upstream, &alice.did, &alice_space).await.status, 200);
    let recovery_path = credentials.0.join("reconsented");
    let recovered = grant(&srv, &alice_flow, &alice).await;
    save_session(&reopened, &recovery_path, &alice_space, &alice_key, &recovered);
    let (key, token) = begin_rotation(&reopened, &recovery_path, &alice_space).unwrap();
    let flow = Flow::new(&client_id, REDIRECT, &scope, &key);
    let rotated = oauth::tokens(&oauth::refresh(&srv, &flow, &token, &[]).await);
    finish_rotation(&reopened, &recovery_path, &alice_space, &key, &rotated).unwrap();
    let record = read(&srv, &flow, &rotated, &alice.did, &alice_space).await;
    assert_eq!(record.status, 200);
    assert_eq!(record.body["cid"], persisted.body["cid"]);
}
