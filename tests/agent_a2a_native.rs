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
