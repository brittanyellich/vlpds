//! Disposable native CAS fixture, no public account/key/record changes.
macro_rules! suite_only {
    ($($i:item)*) => {};
}
#[path = "all/common/mod.rs"]
mod common;
use common::*;
use vlpds::agent_a2a_store::{finish, reserve, Reservation};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_durable_reservation_cache_isolation_and_ambiguous_failure() {
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let account = s.create_account("nativea2afixture").await;
    let routing = &account.did;
    let (a, b) = tokio::join!(
        reserve(&s.app, routing, "did:fixture:caller", "same", "fixed-digest", 1000),
        reserve(&s.app, routing, "did:fixture:caller", "same", "fixed-digest", 1000)
    );
    let values = [a.map_err(|e| e.message).unwrap(), b.map_err(|e| e.message).unwrap()];
    assert_eq!(values.iter().filter(|v| matches!(v, Reservation::Fresh { .. })).count(), 1);
    let fresh = values.into_iter().find(|v| matches!(v, Reservation::Fresh { .. })).unwrap();
    let Reservation::Fresh { row, pending } = fresh else { unreachable!() };
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:caller", "same", "fixed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Pending
    ));
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:caller", "other", "fixed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Busy
    ));
    let reply = json!({"result":{"message":{"contextId":"stable-context","messageId":"stable-message","parts":[{"data":{"status":"verified"}}]}}});
    finish(&s.app, routing, &row, pending.clone(), &reply).await.map_err(|e| e.message).unwrap();
    assert!(finish(&s.app, routing, &row, pending, &reply).await.is_err());
    let Reservation::Cached(cached) = reserve(&s.app, routing, "did:fixture:caller", "same", "fixed-digest", 1000)
        .await
        .map_err(|e| e.message)
        .unwrap()
    else {
        panic!("cached")
    };
    assert_eq!(cached, reply);
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:caller", "same", "changed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Conflict
    ));
    // A new caller cannot obtain the previous caller's decision, even with same id.
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:other", "same", "fixed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Fresh { .. }
    ));
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:other", "same", "fixed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Pending
    ));
    assert!(matches!(
        reserve(&s.app, routing, "did:fixture:caller", "same", "fixed-digest", 1000)
            .await
            .map_err(|e| e.message)
            .unwrap(),
        Reservation::Cached(_)
    ));
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_service_auth_is_caller_audience_method_and_freshness_bound() {
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("a2aauthcaller").await;
    let other = s.create_account("a2aauthother").await;
    let aud = s.pds_did().await;
    let method = "chat.atagents.agent.contact";
    for (target, lxm, allowed, good) in [
        (&*aud, method, &*caller.did, true),
        (&*aud, method, &*other.did, false),
        (&*aud, "com.atproto.server.describeServer", &*caller.did, false),
        ("did:web:other.invalid", method, &*caller.did, false),
    ] {
        let r = s
            .xrpc
            .get("com.atproto.server.getServiceAuth", &[("aud", target), ("lxm", lxm)], &caller.auth())
            .await
            .ok();
        let token = r["token"].as_str().unwrap();
        let result = vlpds::xrpc::authn::verify_agent_contact_jwt(&s.app, token, allowed).await;
        assert_eq!(result.is_ok(), good);
    }
    // Exercise the lifetime precheck before signature lookup with individually fresh endpoints.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let now = vlatproto::tid::now_micros() / 1_000_000;
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256K"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iat":now-30,"exp":now+60})).unwrap());
    let err = vlpds::xrpc::authn::verify_agent_contact_jwt(&s.app, &format!("{header}.{payload}.invalid"), &caller.did)
        .await
        .err()
        .unwrap();
    assert_eq!(err.message, "contact token freshness refused");
    assert!(vlpds::xrpc::authn::verify_agent_contact_jwt(&s.app, &caller.access, &caller.did).await.is_err());
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_opt_in_http_boundary_is_default_off_and_does_not_trust_forwarded_auth() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use vlpds::{
        agent_a2a::NativeA2a,
        agent_contact_pilot::{AGENT_PATH, CARD_PATH},
        agent_profile_bridge::Bridge,
    };
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("a2aroutecaller").await;
    assert_eq!(s.xrpc.http.get(format!("{}{CARD_PATH}", s.url)).send().await.unwrap().status(), 404);
    let cfg =
        NativeA2a::new(&s.url, &caller.did, Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(), true).unwrap();
    assert!(NativeA2a::new(&s.url, &caller.did, Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(), false)
        .is_err());
    assert!(cfg.validate(false, &s.url).is_err(), "Programmatic config cannot bypass production HTTPS");
    let r = cfg.routes(s.app.clone());
    for headers in [vec![], vec![("x-forwarded-user", caller.did.as_str())], vec![("authorization", "Bearer forged")]] {
        let mut req = Request::builder().method("POST").uri(AGENT_PATH);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        assert_eq!(r.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap().status(), 401);
    }
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
        .to_string();
    let request_body = json!({"jsonrpc":"2.0","id":"authorized","method":"SendMessage","params":{"message":{"messageId":"authorized","role":"ROLE_USER","parts":[{"data":{"agentDid":vlpds::agent_endorsement::AGENT,"principalDid":vlpds::agent_endorsement::PRINCIPAL,"skillId":"resolve-identity-test"}}]}}});
    let req = Request::builder()
        .method("POST")
        .uri(AGENT_PATH)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("a2a-version", "1.0")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    // The authenticated branch is reached, but the fixed live agent is deliberately
    // absent from these disposable repos, so no proof/profile invocation occurs.
    assert_eq!(r.clone().oneshot(req).await.unwrap().status(), 404);
    let req = Request::builder()
        .method("POST")
        .uri(AGENT_PATH)
        .header("authorization", format!("Bearer {token}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(r.clone().oneshot(req).await.unwrap().status(), 401);
    for path in [format!("{CARD_PATH}?x=1"), AGENT_PATH.replace("%3A", "%253A"), "/private/agent-profile/assert".into()]
    {
        assert_eq!(
            r.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap().status(),
            404
        );
    }
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_capacity_can_increase_without_erasing_retry_history() {
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let account = s.create_account("a2acapacityfixture").await;
    let r = &account.did;
    let Reservation::Fresh { row, pending } =
        reserve(&s.app, r, "caller", "one", "digest", 1).await.map_err(|e| e.message).unwrap()
    else {
        panic!("fresh")
    };
    let reply = json!({"contextId":"preserved"});
    finish(&s.app, r, &row, pending, &reply).await.map_err(|e| e.message).unwrap();
    assert!(matches!(
        reserve(&s.app, r, "caller", "two", "digest", 1).await.map_err(|e| e.message).unwrap(),
        Reservation::Full
    ));
    assert!(matches!(
        reserve(&s.app, r, "caller", "two", "digest", 2).await.map_err(|e| e.message).unwrap(),
        Reservation::Fresh { .. }
    ));
    let Reservation::Cached(cached) =
        reserve(&s.app, r, "caller", "one", "digest", 2).await.map_err(|e| e.message).unwrap()
    else {
        panic!("original retry preserved")
    };
    assert_eq!(cached, reply);
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_agent_authentication_is_behind_existing_global_ip_limit() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use vlpds::{agent_a2a::NativeA2a, agent_contact_pilot::AGENT_PATH, agent_profile_bridge::Bridge};
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.rate_limits_enabled = true;
    })
    .await;
    let caller = s.create_account("a2aratefixture").await;
    let cfg =
        NativeA2a::new(&s.url, &caller.did, Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(), true).unwrap();
    s.xrpc.post("vlpds.admin.updateRateLimits",&json!({"config":{"limiters":{"global-ip":{"points":1,"windowSecs":3600}}},"ifVersion":0,"actor":"synthetic-fixture"}),&Auth::Admin).await.ok();
    let r = cfg.routes(s.app.clone());
    for status in [401, 429] {
        let req = Request::builder().method("POST").uri(AGENT_PATH).body(Body::empty()).unwrap();
        assert_eq!(r.clone().oneshot(req).await.unwrap().status(), status);
    }
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_and_completed_decisions_survive_new_pds_instance() {
    let store = std::sync::Arc::new(object_store::memory::InMemory::new());
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    let account = s.create_account("a2arestartfixture").await;
    let r = account.did.clone();
    let Reservation::Fresh { row, pending } =
        reserve(&s.app, &r, "caller", "complete", "digest", 10).await.map_err(|e| e.message).unwrap()
    else {
        panic!("fresh")
    };
    let reply = json!({"contextId":"stable-across-reopen"});
    finish(&s.app, &r, &row, pending, &reply).await.map_err(|e| e.message).unwrap();
    assert!(matches!(
        reserve(&s.app, &r, "caller", "pending", "digest", 10).await.map_err(|e| e.message).unwrap(),
        Reservation::Fresh { .. }
    ));
    vlpds::server::shutdown(&s.app).await;
    let reopened = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    let Reservation::Cached(cached) =
        reserve(&reopened.app, &r, "caller", "complete", "digest", 10).await.map_err(|e| e.message).unwrap()
    else {
        panic!("durable cached decision")
    };
    assert_eq!(cached, reply);
    assert!(matches!(
        reserve(&reopened.app, &r, "caller", "pending", "digest", 10).await.map_err(|e| e.message).unwrap(),
        Reservation::Pending
    ));
    assert!(matches!(
        reserve(&reopened.app, &r, "caller", "new", "digest", 10).await.map_err(|e| e.message).unwrap(),
        Reservation::Busy
    ));
    vlpds::server::shutdown(&reopened.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_jsonrpc_errors_are_correlated_and_version_error_is_typed() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    use vlpds::{
        agent_a2a::NativeA2a,
        agent_contact_pilot::AGENT_PATH,
        agent_endorsement::{AGENT, PRINCIPAL},
        agent_profile_bridge::Bridge,
    };
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("a2aprotocolfixture").await;
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
        .to_string();
    let cfg =
        NativeA2a::new(&s.url, &caller.did, Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(), true).unwrap();
    let r = cfg.routes(s.app.clone());
    let body = json!({"jsonrpc":"2.0","id":"correlated","method":"SendMessage","params":{"message":{"messageId":"event","role":"ROLE_USER","parts":[{"data":{"agentDid":AGENT,"principalDid":PRINCIPAL,"skillId":"resolve-identity-test"}}]}}});
    let mut method = body.clone();
    method["method"] = json!("UnknownMethod");
    let mut params = body.clone();
    params["params"]["contextId"] = json!("not-supported");
    for (value, version, code) in [(body.clone(), "0.3", -32009), (method, "1.0", -32601), (params, "1.0", -32602)] {
        let req = Request::builder()
            .method("POST")
            .uri(AGENT_PATH)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("a2a-version", version)
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap();
        let result = r.clone().oneshot(req).await.unwrap();
        assert_eq!(result.status(), 400);
        let j: J = serde_json::from_slice(&to_bytes(result.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(j["id"], "correlated");
        assert_eq!(j["error"]["code"], code);
        if code == -32009 {
            assert_eq!(j["error"]["data"][0]["reason"], "VERSION_NOT_SUPPORTED");
            assert_eq!(j["error"]["data"][0]["domain"], "a2a-protocol.org");
        }
    }
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_card_retired_pins_survive_reopen_and_production_rejects_unsigned() {
    use vlpds::{agent_a2a::NativeA2a, agent_card, agent_profile_bridge::Bridge};
    let store = std::sync::Arc::new(object_store::memory::InMemory::new());
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    let account = s.create_account("a2acardlatch").await;
    let r = account.did.clone();
    let production = NativeA2a::new(
        "https://pds.crate.social",
        &account.did,
        Bridge::new("http://127.0.0.1:19099", vec![1; 32]).unwrap(),
        false,
    )
    .unwrap();
    assert!(production.validate(false, "https://pds.crate.social").is_err(), "Unsigned production card is a hard gate");
    assert!(!agent_card::is_retired(&s.app, &r, "synthetic-public-pin").await.unwrap());
    agent_card::retire(&s.app, &r, "synthetic-public-pin").await.unwrap();
    agent_card::retire(&s.app, &r, "synthetic-public-pin").await.unwrap();
    assert!(agent_card::is_retired(&s.app, &r, "synthetic-public-pin").await.unwrap());
    vlpds::server::shutdown(&s.app).await;
    let b = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    assert!(agent_card::is_retired(&b.app, &r, "synthetic-public-pin").await.unwrap());
    assert!(!agent_card::is_retired(&b.app, &r, "different-synthetic-pin").await.unwrap());
    vlpds::server::shutdown(&b.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Explicit read-only public Card authority check; synthetic key and disposable PDS storage only"]
async fn synthetic_production_did_card_is_rejected_by_live_key_and_latched() {
    use vlpds::{
        agent_card::{is_retired, SignedCard},
        agent_endorsement::AGENT,
    };
    let v: J = serde_json::from_slice(
        &std::fs::read(std::env::var("VLPDS_AGENT_CARD_VECTOR_PATH").expect("Public synthetic vector path")).unwrap(),
    )
    .unwrap();
    let pin = v["publicPin"].as_str().unwrap().to_string();
    let store = std::sync::Arc::new(object_store::memory::InMemory::new());
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
        c.service_did = "did:web:pds.crate.social".into();
    })
    .await;
    let signed = SignedCard::new(v["signedCard"].clone(), pin.clone()).unwrap();
    let error = signed.checked(&s.app, "https://pds.crate.social").await.unwrap_err();
    assert!(error.contains("changed or removed"), "{error}");
    assert!(is_retired(&s.app, AGENT, &pin).await.unwrap());
    vlpds::server::shutdown(&s.app).await;
    let b = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
        c.service_did = "did:web:pds.crate.social".into();
    })
    .await;
    let fresh = SignedCard::new(v["signedCard"].clone(), pin).unwrap();
    assert!(fresh.checked(&b.app, "https://pds.crate.social").await.unwrap_err().contains("Retired"));
    vlpds::server::shutdown(&b.app).await;
    println!("Synthetic same-production-DID Card rejected against live public key; retirement persisted in disposable PDS; no live key or record writes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn card_readiness_distinguishes_absent_inactive_and_invalid_trust_in_disposable_storage() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    use vlpds::{
        agent_a2a::NativeA2a, agent_contact_pilot::CARD_PATH, agent_endorsement::AGENT, agent_profile_bridge::Bridge,
    };
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let cfg = NativeA2a::new(
        &s.url,
        "did:plc:vsgwub3c3pupqt3yhxfmecma",
        Bridge::new("http://127.0.0.1:19099", vec![7; 32]).unwrap(),
        true,
    )
    .unwrap();
    let router = cfg.routes(s.app.clone());
    let request = || Request::builder().uri(CARD_PATH).body(Body::empty()).unwrap();
    let missing = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(missing.status(), 404);
    let body: J = serde_json::from_slice(&to_bytes(missing.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"], "Agent unavailable");
    // Metadata rows exist only in this in-memory fixture; no signing/account
    // authority is asserted and no live DID/repo/key is modified.
    let p = s.app.partition(AGENT).unwrap_or_else(|_| panic!("Fixture partition missing"));
    for status in [Some("deactivated"), Some("takendown"), Some("suspended"), None] {
        let account = vlpds::state::Account {
            did: AGENT.into(),
            handle: "synthetic.vlpds.test".into(),
            status: status.map(str::to_string),
            ..Default::default()
        };
        p.db.put(vlpds::state::account_key(AGENT), serde_json::to_vec(&account).unwrap()).await.unwrap();
        let response = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), if status.is_none() { 200 } else { 404 });
    }
    // This active fixture has deliberately invalid signed Card bytes. Trust
    // fails locally before any public DID fetch, yielding a distinct503.
    let directory = std::env::temp_dir().join(unique_name("card-readiness"));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let write = |name: &str, bytes: &[u8]| {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(directory.join(name)).unwrap().write_all(bytes).unwrap();
    };
    let key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(key.verifying_key().to_sec1_point(true).as_bytes());
    let pin = format!("z{}", bs58::encode(multikey).into_string());
    write("key", hex::encode([7u8; 32]).as_bytes());
    write("card", b"{}");
    write("config", &serde_json::to_vec(&json!({"enabled":true,"caller_did":"did:plc:vsgwub3c3pupqt3yhxfmecma","bridge_origin":"http://127.0.0.1:19099","bridge_key_file":directory.join("key"),"signed_card_file":directory.join("card"),"card_key_multibase":pin})).unwrap());
    let signed = NativeA2a::load(&directory.join("config"), &s.url, true).unwrap();
    let refused = signed.routes(s.app.clone()).oneshot(request()).await.unwrap();
    assert_eq!(refused.status(), 503);
    let body: J = serde_json::from_slice(&to_bytes(refused.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["error"], "Signed Card trust unavailable");
    std::fs::remove_dir_all(directory).unwrap();
    vlpds::server::shutdown(&s.app).await;
}

#[test]
#[ignore = "Explicit offline verification of the local public signed Card artifact; no resolver/network"]
fn frozen_pilot_card_matches_production_origin_audience_and_signature_offline() {
    let path = std::env::var("VLPDS_FROZEN_CARD_PATH").expect("Public signed artifact path");
    let card: J = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let pin = "zDnaeyNSrMXCKbWdCmMWCcPv8qCCXGzQs3JLwH4KUWcq8ogna";
    vlpds::agent_card::verify(&card, pin, "https://pds.crate.social", "did:web:pds.crate.social").unwrap();
    assert!(vlpds::agent_card::verify(&card, pin, "http://pds.crate.social", "did:web:pds.crate.social").is_err());
    assert!(vlpds::agent_card::verify(&card, pin, "https://pds.crate.social", "did:web:other.invalid").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Explicit public read-only PLC authority check, frozen public Card and disposable active account only"]
async fn frozen_card_get_over_http_with_disposable_active_account_and_public_authority() {
    use vlpds::{agent_a2a::NativeA2a, agent_contact_pilot::CARD_PATH, agent_endorsement::AGENT};
    let directory = std::env::temp_dir().join(unique_name("card-http"));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let write = |name: &str, bytes: &[u8]| {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(directory.join(name)).unwrap().write_all(bytes).unwrap();
    };
    let card = std::fs::read(std::env::var("VLPDS_FROZEN_CARD_PATH").expect("Public signed artifact path")).unwrap();
    write("card", &card);
    write("key", hex::encode([7u8; 32]).as_bytes());
    write("config", &serde_json::to_vec(&json!({"enabled":true,"caller_did":"did:plc:vsgwub3c3pupqt3yhxfmecma","bridge_origin":"http://127.0.0.1:19099","bridge_key_file":directory.join("key"),"signed_card_file":directory.join("card"),"card_key_multibase":"zDnaeyNSrMXCKbWdCmMWCcPv8qCCXGzQs3JLwH4KUWcq8ogna"})).unwrap());
    let cfg = NativeA2a::load(&directory.join("config"), "https://pds.crate.social", false).unwrap();
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.public_url = "https://pds.crate.social".into();
        c.service_did = "did:web:pds.crate.social".into();
        c.agent_a2a = Some(cfg);
    })
    .await;
    let p = s.app.partition(AGENT).unwrap_or_else(|_| panic!("Fixture partition missing"));
    let account =
        vlpds::state::Account { did: AGENT.into(), handle: "synthetic.vlpds.test".into(), ..Default::default() };
    p.db.put(vlpds::state::account_key(AGENT), serde_json::to_vec(&account).unwrap()).await.unwrap();
    // Real native HTTP router + unchanged guarded public resolver; no profile call.
    let response = reqwest::Client::new().get(format!("{}{CARD_PATH}", s.url)).send().await.unwrap();
    let status = response.status();
    let received: J = response.json().await.unwrap();
    vlpds::server::shutdown(&s.app).await;
    std::fs::remove_dir_all(directory).unwrap();
    assert_eq!(status, 200, "Native Card HTTP status; response intentionally not logged");
    assert_eq!(received, serde_json::from_slice::<J>(&card).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Explicit disposable local S3 fixture seed for unchanged release-image Card HTTP test"]
async fn seed_disposable_s3_active_card_account() {
    use vlpds::agent_endorsement::AGENT;
    let endpoint = std::env::var("VLPDS_CARD_FIXTURE_S3").expect("Explicit local S3 emulator");
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.public_url = "https://pds.crate.social".into();
        c.service_did = "did:web:pds.crate.social".into();
        c.prefix = "exp710-card-fixture".into();
        c.s3 = Some(vlsync_store::store::S3Config {
            endpoint,
            bucket: "exp710-fixture".into(),
            access_key: "synthetic".into(),
            secret_key: "synthetic".into(),
            region: "us-east-1".into(),
        });
    })
    .await;
    let p = s.app.partition(AGENT).unwrap_or_else(|_| panic!("Fixture partition missing"));
    let account =
        vlpds::state::Account { did: AGENT.into(), handle: "synthetic.vlpds.test".into(), ..Default::default() };
    p.db.put(vlpds::state::account_key(AGENT), serde_json::to_vec(&account).unwrap()).await.unwrap();
    vlpds::server::shutdown(&s.app).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_enrollment_requires_authenticated_caller_and_private_consent() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use vlpds::agent_admission::{run_if_admitted, Refusal};
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let caller = s.create_account("enrollmentcallerfixture").await;
    let aud = s.pds_did().await;
    let result = s
        .xrpc
        .get(
            "com.atproto.server.getServiceAuth",
            &[("aud", &*aud), ("lxm", "chat.atagents.agent.contact")],
            &caller.auth(),
        )
        .await
        .ok();
    let token = result["token"].as_str().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    for (token, expected) in [("not-a-token", Refusal::Caller), (token, Refusal::Consent)] {
        let calls = count.clone();
        let outcome = run_if_admitted(&s.app, token, &caller.did, move || async move {
            calls.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(outcome, Err(expected));
    }
    // No policy row exists: a valid service JWT cannot cause proof fetch or action.
    assert_eq!(count.load(Ordering::SeqCst), 0);
    vlpds::server::shutdown(&s.app).await;
}

async fn enrollment_owner_token(s: &TestServer, access: &str) -> String {
    let (parts, _) = axum::http::Request::builder()
        .header("authorization", format!("Bearer {access}"))
        .body(())
        .unwrap()
        .into_parts();
    assert!(matches!(
        vlpds::xrpc::authn::authenticate(&s.app, &parts).await.map_err(|e| e.message).unwrap(),
        vlpds::xrpc::authn::Credentials::Session { .. }
    ));
    access.to_owned()
}

fn enrollment_op(
    id: &str,
    agent: Option<&str>,
    action: vlpds::agent_enrollment::Action,
    revision: u64,
) -> vlpds::agent_enrollment::Operation {
    vlpds::agent_enrollment::Operation { request_id: id.into(), agent: agent.map(str::to_owned), action, revision }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_owner_consent_cas_retries_isolation_disable_and_shutdown() {
    use vlpds::agent_enrollment::{apply_owner_consent as apply, Action::*, Pair};
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let owner = s.create_account("enrollownerfixture").await;
    let other = s.create_account("enrollotherfixture").await;
    let agent = s.create_account("enrollagentfixture").await;
    let second = s.create_account("enrollsecondfixture").await;
    let other_agent = s.create_account("enrollforeignfixture").await;
    let credentials = enrollment_owner_token(&s, &owner.access).await;
    let foreign = enrollment_owner_token(&s, &other.access).await;
    let pairs = [Pair { agent: &agent.did, caller: &owner.did }, Pair { agent: &second.did, caller: &owner.did }];
    let b_pairs = [Pair { agent: &other_agent.did, caller: &other.did }];
    let original = enrollment_op("original", Some(&agent.did), Enable, 0);
    let first = apply(&s.app, &credentials, &owner.did, &pairs, &original).await.map_err(|e| e.message).unwrap();
    assert!(first.enabled);
    let replay = apply(&s.app, &credentials, &owner.did, &pairs, &original).await.map_err(|e| e.message).unwrap();
    assert!(replay.replay);
    assert_eq!(first.receipt, replay.receipt);
    assert!(apply(&s.app, &foreign, &owner.did, &pairs, &original).await.is_err());
    let app_password = s.app.jwt.issue_with_jti(&owner.did, "com.atproto.appPassPrivileged", 60, "at+jwt", None);
    assert!(apply(&s.app, &app_password, &owner.did, &pairs, &original).await.is_err());
    assert!(apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("original", Some(&agent.did), Disable, 0))
        .await
        .is_err());
    let foreign_enable = enrollment_op("foreign", Some(&other_agent.did), Enable, 0);
    assert!(
        apply(&s.app, &foreign, &other.did, &b_pairs, &foreign_enable).await.map_err(|e| e.message).unwrap().enabled
    );
    assert!(
        !apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("disable", Some(&agent.did), Disable, 1))
            .await
            .map_err(|e| e.message)
            .unwrap()
            .enabled
    );
    assert!(!apply(&s.app, &credentials, &owner.did, &pairs, &original).await.map_err(|e| e.message).unwrap().enabled);
    assert!(apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("stale", Some(&agent.did), Enable, 1))
        .await
        .is_err());
    assert!(
        apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("fresh", Some(&agent.did), Enable, 2))
            .await
            .map_err(|e| e.message)
            .unwrap()
            .enabled
    );
    apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("revoke", Some(&agent.did), RevokeEndorsement, 3))
        .await
        .map_err(|e| e.message)
        .unwrap();
    assert!(apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("restore", Some(&agent.did), Enable, 4))
        .await
        .is_err());
    let second_enable = enrollment_op("second", Some(&second.did), Enable, 4);
    assert!(
        apply(&s.app, &credentials, &owner.did, &pairs, &second_enable).await.map_err(|e| e.message).unwrap().enabled
    );
    let shutdown = enrollment_op("shutdown", None, OwnerDisable, 5);
    let result = apply(&s.app, &credentials, &owner.did, &pairs, &shutdown).await.map_err(|e| e.message).unwrap();
    assert!(result.owner_disabled);
    assert_eq!(
        apply(&s.app, &credentials, &owner.did, &pairs, &shutdown).await.map_err(|e| e.message).unwrap().receipt,
        result.receipt
    );
    assert!(
        !apply(&s.app, &credentials, &owner.did, &pairs, &second_enable).await.map_err(|e| e.message).unwrap().enabled
    );
    assert!(apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("afteroff", Some(&second.did), Enable, 6))
        .await
        .is_err());
    assert!(
        apply(&s.app, &foreign, &other.did, &b_pairs, &foreign_enable).await.map_err(|e| e.message).unwrap().enabled
    );
    s.xrpc.post("com.atproto.server.deactivateAccount", &json!({}), &owner.auth()).await.ok();
    assert!(
        apply(&s.app, &credentials, &owner.did, &pairs, &original).await.is_err(),
        "Retained session identity cannot bypass inactive owner"
    );
    vlpds::server::shutdown(&s.app).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_owner_consent_disable_fences_inflight_enable_cas() {
    use std::sync::Arc;
    use tokio::sync::Notify;
    use vlpds::{
        agent_enrollment::{apply_owner_consent as apply, Action::*, Pair},
        xrpc::cas::set_pause_hook,
    };
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
    })
    .await;
    let owner = s.create_account("enrollraceowner").await;
    let agent = s.create_account("enrollraceagent").await;
    let credentials = enrollment_owner_token(&s, &owner.access).await;
    let pairs = [Pair { agent: &agent.did, caller: &owner.did }];
    apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("setup", Some(&agent.did), Enable, 0))
        .await
        .map_err(|e| e.message)
        .unwrap();
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let reached_hook = reached.clone();
    let release_hook = release.clone();
    set_pause_hook(
        &owner.did,
        Some(Arc::new(move |point| {
            let reached = reached_hook.clone();
            let release = release_hook.clone();
            let should = point == "agent_enrollment_enable_before_cas";
            Box::pin(async move {
                if should {
                    reached.notify_one();
                    release.notified().await;
                }
            })
        })),
    );
    let app = s.app.clone();
    let creds = credentials.clone();
    let owner_id = owner.did.clone();
    let agent_id = agent.did.clone();
    let delayed = tokio::spawn(async move {
        let pairs = [Pair { agent: &agent_id, caller: &owner_id }];
        apply(&app, &creds, &owner_id, &pairs, &enrollment_op("delayed", Some(&agent_id), Enable, 1)).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), reached.notified()).await.unwrap();
    apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("disable", Some(&agent.did), Disable, 1))
        .await
        .map_err(|e| e.message)
        .unwrap();
    release.notify_one();
    assert!(delayed.await.unwrap().is_err());
    set_pause_hook(&owner.did, None);
    let setup = enrollment_op("setup", Some(&agent.did), Enable, 0);
    assert!(!apply(&s.app, &credentials, &owner.did, &pairs, &setup).await.map_err(|e| e.message).unwrap().enabled);
    vlpds::server::shutdown(&s.app).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_owner_consent_shutdown_survives_capacity_and_reopen() {
    use std::sync::Arc;
    use vlpds::agent_enrollment::{apply_owner_consent as apply, Action::*, Pair};
    let store = Arc::new(object_store::memory::InMemory::new());
    let s = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    let owner = s.create_account("enrollcapacityowner").await;
    let agent = s.create_account("enrollcapacityagent").await;
    let credentials = enrollment_owner_token(&s, &owner.access).await;
    let pairs = [Pair { agent: &agent.did, caller: &owner.did }];
    let initial = enrollment_op("first", Some(&agent.did), Enable, 0);
    apply(&s.app, &credentials, &owner.did, &pairs, &initial).await.map_err(|e| e.message).unwrap();
    for revision in 1..64 {
        apply(
            &s.app,
            &credentials,
            &owner.did,
            &pairs,
            &enrollment_op(&format!("disable{revision}"), Some(&agent.did), Disable, revision),
        )
        .await
        .map_err(|e| e.message)
        .unwrap();
    }
    assert!(apply(&s.app, &credentials, &owner.did, &pairs, &enrollment_op("full", Some(&agent.did), Enable, 64))
        .await
        .is_err());
    let off = enrollment_op("off", None, OwnerDisable, 64);
    apply(&s.app, &credentials, &owner.did, &[], &off).await.map_err(|e| e.message).unwrap();
    vlpds::server::shutdown(&s.app).await;
    let reopened = TestServer::spawn_lone(|c| {
        c.workers = 1;
        c.shards = 1;
        c.memory_store = Some(store.clone());
    })
    .await;
    let result = apply(&reopened.app, &credentials, &owner.did, &pairs, &initial).await.map_err(|e| e.message).unwrap();
    assert!(result.replay && result.owner_disabled && !result.enabled);
    vlpds::server::shutdown(&reopened.app).await;
}
