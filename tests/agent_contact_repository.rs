//! Repository-backed local discovery, not a production resolver or card signer.
//! The Rust verifier is exercised only on bounded native fixture CARs; the Kody
//! spike's vulnerable JS/Zod parser is neither imported nor exposed here.
macro_rules! suite_only {
    ($($i:item)*) => {};
}
#[path = "all/common/mod.rs"]
mod common;

use base64::Engine;
use common::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use vlpds::agent_contact_pilot::{Mount, AGENT_PATH, CARD_PATH};

const CONTACT: &str = "link.ident.agent";
const ENDORSEMENT: &str = "link.ident.endorsement";
const FIXED_KODY_AGENT: &str = "did:plc:6tlvgafuonoighfrtpejff5m";

struct CardFixture(Child);
impl Drop for CardFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Proof {
    bytes: Vec<u8>,
    root: Cid,
    record_cid: Option<Cid>,
    value: Option<J>,
}

fn verify_at_head(
    bytes: &[u8],
    did: &str,
    path: &str,
    key: &k256::ecdsa::VerifyingKey,
    expected_head: Cid,
) -> anyhow::Result<(Repo, Option<Cid>)> {
    anyhow::ensure!(bytes.len() <= 64 * 1024, "fixture proof too large");
    let cid = verify_record_proof(bytes, did, path, Some(key))?;
    let repo = Repo::from_car(bytes)?;
    anyhow::ensure!(repo.root == expected_head, "proof is not at current pinned head");
    Ok((repo, cid))
}

async fn current_proof(
    s: &TestServer,
    did: &str,
    collection: &str,
    rkey: &str,
    key: &k256::ecdsa::VerifyingKey,
) -> Proof {
    let before = s.latest_commit(did).await.0;
    let response = s
        .xrpc
        .get("com.atproto.sync.getRecord", &[("did", did), ("collection", collection), ("rkey", rkey)], &Auth::None)
        .await;
    assert_eq!(response.status, 200);
    assert!(response.body.len() <= 64 * 1024, "fixture proof must remain bounded");
    let path = format!("{collection}/{rkey}");
    let (repo, record_cid) =
        verify_at_head(&response.body, did, &path, key, before).expect("current native proof verifies");
    assert_eq!(s.latest_commit(did).await.0, before, "head must remain stable through verification");
    let value = record_cid.map(|_| repo.record(&path).expect("included record"));
    Proof { bytes: response.body.to_vec(), root: repo.root, record_cid, value }
}

async fn put(s: &TestServer, actor: &TestAccount, repo: &str, collection: &str, rkey: &str, value: J) -> Resp {
    s.xrpc
        .post(
            "com.atproto.repo.putRecord",
            &json!({"repo": repo, "collection": collection, "rkey": rkey, "record": value, "validate": false}),
            &actor.auth(),
        )
        .await
}

async fn remove(s: &TestServer, actor: &TestAccount, repo: &str, collection: &str, rkey: &str) -> Resp {
    s.xrpc
        .post(
            "com.atproto.repo.deleteRecord",
            &json!({"repo": repo, "collection": collection, "rkey": rkey}),
            &actor.auth(),
        )
        .await
}

// A fresh lookup, with no cached pointer fallback. These are actual repo reads,
// not the earlier JSON-only fixture reader.
async fn lookup(s: &TestServer, principal: &str, agent: &str) -> Option<String> {
    let endorsement = s.get_record(principal, ENDORSEMENT, agent).await;
    if endorsement.status == 400 && endorsement.error_name() == Some("RecordNotFound") {
        return None;
    }
    let endorsement = endorsement.ok();
    assert_eq!(endorsement["uri"], format!("at://{principal}/{ENDORSEMENT}/{agent}"));
    assert_eq!(endorsement["value"]["$type"], ENDORSEMENT);
    assert_eq!(endorsement["value"]["agent"], agent);
    let contact = s.get_record(agent, CONTACT, "self").await;
    if contact.status == 400 && contact.error_name() == Some("RecordNotFound") {
        return None;
    }
    let contact = contact.ok();
    assert_eq!(contact["uri"], format!("at://{agent}/{CONTACT}/self"));
    assert_eq!(contact["value"]["$type"], CONTACT);
    let card_url = contact["value"]["agentCardUrl"].as_str().expect("contact URL");
    assert_eq!(card_url, format!("{}{CARD_PATH}", s.url), "only this fixture's native card may be discovered");
    Some(card_url.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repository_backed_contact_lookup_proofs_and_removal() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = reserved.local_addr().unwrap();
    let backend_origin = format!("http://{backend_addr}");
    let s = TestServer::spawn_lone(|cfg| {
        cfg.workers = 1;
        cfg.shards = 1;
        cfg.agent_contact_pilot = Some(Mount::new(&backend_origin, &cfg.public_url, true).unwrap());
    })
    .await;
    drop(reserved);
    let mut child = CardFixture(
        Command::new("node")
            .arg(format!("{}/tools/agent-contact-pilot/fixtures/card-server.mjs", env!("CARGO_MANIFEST_DIR")))
            .arg(&s.url)
            .arg(backend_addr.port().to_string())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Node26 fixture runtime"),
    );
    let card_url = format!("{}{CARD_PATH}", s.url);
    let mut ready = false;
    for _ in 0..100 {
        assert!(child.0.try_wait().unwrap().is_none(), "card fixture exited");
        if s.xrpc.http.get(&card_url).send().await.unwrap().status() == 200 {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready, "native card fixture ready");
    let principal = s.create_account("exp710principal").await;
    let agent = s.create_account("exp710agent").await;
    assert_ne!(agent.did, FIXED_KODY_AGENT, "never alias synthetic repo ownership to a real agent identity");
    let principal_key = s.signing_key(&principal.did).await;
    let agent_key = s.signing_key(&agent.did).await;
    let endorsement_value = json!({"$type": ENDORSEMENT, "agent": agent.did});
    let contact_value = json!({"$type": CONTACT, "agentCardUrl": card_url});

    // Only the actual owner may write/delete the principal's endorsement.
    put(&s, &agent, &principal.did, ENDORSEMENT, &agent.did, endorsement_value.clone()).await.client_err();
    assert!(lookup(&s, &principal.did, &agent.did).await.is_none());
    let created_endorsement =
        put(&s, &principal, &principal.did, ENDORSEMENT, &agent.did, endorsement_value.clone()).await.ok();
    let created_contact = put(&s, &agent, &agent.did, CONTACT, "self", contact_value.clone()).await.ok();
    let discovered = lookup(&s, &principal.did, &agent.did).await.unwrap();
    let endorsement_json = s.get_record(&principal.did, ENDORSEMENT, &agent.did).await.ok();
    let contact_json = s.get_record(&agent.did, CONTACT, "self").await.ok();
    assert_eq!(created_contact["cid"], contact_json["cid"]);
    assert_eq!(created_endorsement["cid"], endorsement_json["cid"]);

    let endorsement_proof = current_proof(&s, &principal.did, ENDORSEMENT, &agent.did, &principal_key).await;
    assert_eq!(endorsement_proof.value.as_ref(), Some(&endorsement_value));
    assert_eq!(endorsement_proof.record_cid.unwrap().to_string(), endorsement_json["cid"].as_str().unwrap());
    let contact_proof = current_proof(&s, &agent.did, CONTACT, "self", &agent_key).await;
    assert_eq!(contact_proof.value.as_ref(), Some(&contact_value));
    assert_eq!(contact_proof.record_cid.unwrap().to_string(), contact_json["cid"].as_str().unwrap());
    let path = format!("{ENDORSEMENT}/{}", agent.did);
    assert!(verify_record_proof(&endorsement_proof.bytes, &principal.did, &path, Some(&agent_key)).is_err());
    assert!(verify_record_proof(&endorsement_proof.bytes, &agent.did, &path, Some(&principal_key)).is_err());
    let mut tampered = endorsement_proof.bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(verify_record_proof(&tampered, &principal.did, &path, Some(&principal_key)).is_err());

    let card: J = s.xrpc.http.get(&discovered).send().await.unwrap().json().await.unwrap();
    assert_eq!(card["supportedInterfaces"][0]["url"], format!("{}{AGENT_PATH}", s.url));
    assert_eq!(card["capabilities"]["extensions"][0]["params"]["agentDid"], FIXED_KODY_AGENT);
    // This intentionally remains a pointer to the separately fixed Kody test
    // agent, NOT a signed card bound to the synthetic repo agent's DID.
    assert_ne!(card["capabilities"]["extensions"][0]["params"]["agentDid"], agent.did);

    remove(&s, &agent, &principal.did, ENDORSEMENT, &agent.did).await.client_err();
    assert!(lookup(&s, &principal.did, &agent.did).await.is_some());
    remove(&s, &agent, &agent.did, CONTACT, "self").await.ok();
    assert!(lookup(&s, &principal.did, &agent.did).await.is_none());
    let contact_absence = current_proof(&s, &agent.did, CONTACT, "self", &agent_key).await;
    assert!(contact_absence.record_cid.is_none());
    assert_ne!(contact_absence.root, contact_proof.root, "old signed proof is stale after removal");
    assert!(verify_at_head(
        &contact_proof.bytes,
        &agent.did,
        &format!("{CONTACT}/self"),
        &agent_key,
        contact_absence.root
    )
    .is_err());
    assert_eq!(
        s.xrpc.http.get(&card_url).send().await.unwrap().status(),
        200,
        "pointer deletion does not revoke service auth"
    );
    put(&s, &agent, &agent.did, CONTACT, "self", contact_value).await.ok();
    assert!(lookup(&s, &principal.did, &agent.did).await.is_some());
    remove(&s, &principal, &principal.did, ENDORSEMENT, &agent.did).await.ok();
    assert!(lookup(&s, &principal.did, &agent.did).await.is_none());
    let endorsement_absence = current_proof(&s, &principal.did, ENDORSEMENT, &agent.did, &principal_key).await;
    assert!(endorsement_absence.record_cid.is_none());
    assert_ne!(endorsement_absence.root, endorsement_proof.root);
    assert!(verify_at_head(&endorsement_proof.bytes, &principal.did, &path, &principal_key, endorsement_absence.root)
        .is_err());
    // Old proof is still correctly signed. Current-head comparison, not mere
    // signature validity, is what prevents using it after endorsement removal.
    assert!(verify_record_proof(&endorsement_proof.bytes, &principal.did, &path, Some(&principal_key))
        .unwrap()
        .is_some());

    let evidence = json!({
        "result": "PASS", "storage": "disposable native PDS in-memory repos",
        "principalDid": principal.did, "agentDid": agent.did,
        "endorsementUri": created_endorsement["uri"], "endorsementCid": created_endorsement["cid"],
        "contactUri": created_contact["uri"], "contactCid": created_contact["cid"], "cardUrl": discovered,
        "principalCommitCid": endorsement_proof.root.to_string(), "agentCommitCid": contact_proof.root.to_string(),
        "principalAbsenceCommitCid": endorsement_absence.root.to_string(), "agentAbsenceCommitCid": contact_absence.root.to_string(),
        "publicPins": {
            "algorithm": "secp256k1", "encoding": "compressed SEC1 hex",
            "principalSigningKey": hex::encode(principal_key.to_sec1_point(true).as_bytes()),
            "agentSigningKey": hex::encode(agent_key.to_sec1_point(true).as_bytes())
        },
        "fixtureProofCarsBase64": {
            "principalEndorsement": base64::prelude::BASE64_STANDARD.encode(&endorsement_proof.bytes),
            "agentContact": base64::prelude::BASE64_STANDARD.encode(&contact_proof.bytes),
            "principalAbsence": base64::prelude::BASE64_STANDARD.encode(&endorsement_absence.bytes),
            "agentAbsence": base64::prelude::BASE64_STANDARD.encode(&contact_absence.bytes)
        },
        "keys": "Pinned from the local fixture PDS describeRepo before writes; no global PLC proof or key rotation qualification",
        "verifier": "Existing native Rust common::verify_record_proof using vlatproto block/CID, commit DID/signature and MST inclusion/absence; <=64KiB local fixture CARs only",
        "currentHeadCheckedBeforeAndAfter": true, "principalEndorsementRelationshipVerifiedLocally": true,
        "wrongRepoWriterAndDeleterDenied": true, "wrongKeyDidAndTamperedCarDenied": true,
        "contactRemovalStopsFreshLookup": true, "endorsementRemovalStopsFreshLookup": true,
        "signedAbsenceProofsVerified": true, "oldSignedProofsDistinguishedFromCurrentHeads": true,
        "cardOwnershipVerified": false, "cardSignerVerified": false, "unsignedCardStillClaimsSeparateFixedKodyDid": true,
        "dispatchAttempted": false, "liveRepoWrites": false, "jsCarParserUsed": false,
        "limits": "No global identity/service ownership proof; real signed-card and live pilot remain unqualified. Pointer removal is discovery revocation, not key or contact authorization revocation."
    });
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    vlpds::server::shutdown(&s.app).await;
    if let Ok(output) = std::env::var("VLPDS_EXP710_EVIDENCE_PATH") {
        std::fs::write(output, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

fn signed_worker(mode: &str, input: &J) -> Child {
    let mut child = Command::new("node")
        .arg(format!("{}/tools/agent-contact-pilot/fixtures/signed-card-worker.mjs", env!("CARGO_MANIFEST_DIR")))
        .arg(mode)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Node26 signed fixture");
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(input).unwrap()).unwrap();
    child
}

fn verify_signed(input: &J) -> J {
    let output = signed_worker("verify", input).wait_with_output().unwrap();
    assert!(output.status.success(), "signed fixture verifier process");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_did_signed_card_repository_discovery() {
    let s = TestServer::spawn_lone(|cfg| {
        cfg.workers = 1;
        cfg.shards = 1;
    })
    .await;
    let principal = s.create_account("exp710signedprincipal").await;
    let agent = s.create_account("exp710signedagent").await;
    assert_ne!(agent.did, FIXED_KODY_AGENT);
    let principal_key = s.signing_key(&principal.did).await;
    let agent_key = s.signing_key(&agent.did).await;
    let token = hex::encode(rand::random::<[u8; 32]>());
    let mut fixture = CardFixture(signed_worker(
        "serve",
        &json!({
            "agentDid": agent.did, "principalDid": principal.did, "token": token
        }),
    ));
    let stdout = fixture.0.stdout.take().unwrap();
    // The operator-owned fixture pipe pins the key BEFORE HTTP card discovery;
    // a key carried by the card or an untrusted URL is never a trust anchor.
    let descriptor = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            let size = BufReader::new(stdout).read_line(&mut line).unwrap();
            assert!(size > 0 && size <= 8192);
            serde_json::from_str::<J>(&line).unwrap()
        }),
    )
    .await
    .expect("signed fixture readiness deadline")
    .unwrap();
    assert_eq!(descriptor["agentDid"], agent.did);
    let pinned_document = descriptor["trustedDidDocument"].clone();
    assert_eq!(pinned_document["id"], agent.did);
    let card_url = descriptor["cardUrl"].as_str().unwrap();
    let endpoint = descriptor["endpoint"].as_str().unwrap();
    assert!(card_url.starts_with("http://127.0.0.1:"));
    let contact_value = json!({"$type": CONTACT, "agentCardUrl": card_url});
    let endorsement_value = json!({"$type": ENDORSEMENT, "agent": agent.did});
    put(&s, &principal, &principal.did, ENDORSEMENT, &agent.did, endorsement_value.clone()).await.ok();
    put(&s, &agent, &agent.did, CONTACT, "self", contact_value.clone()).await.ok();
    let endorsement = s.get_record(&principal.did, ENDORSEMENT, &agent.did).await.ok();
    assert_eq!(endorsement["value"]["agent"], agent.did);
    let contact = s.get_record(&agent.did, CONTACT, "self").await.ok();
    let endorsement_proof = current_proof(&s, &principal.did, ENDORSEMENT, &agent.did, &principal_key).await;
    let contact_proof = current_proof(&s, &agent.did, CONTACT, "self", &agent_key).await;
    assert_eq!(endorsement_proof.value, Some(endorsement_value));
    assert_eq!(contact_proof.value, Some(contact_value));
    assert_eq!(contact_proof.record_cid.unwrap().to_string(), contact["cid"].as_str().unwrap());
    let discovered_url = contact["value"]["agentCardUrl"].as_str().unwrap();
    assert_eq!(discovered_url, card_url);
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = http.get(discovered_url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let bytes = response.bytes().await.unwrap();
    assert!(bytes.len() <= 8192);
    let card: J = serde_json::from_slice(&bytes).unwrap();
    let input = json!({ "publisherDid": agent.did, "record": contact, "card": card,
        "trustedDidDocument": pinned_document, "expectedCardUrl": card_url, "expectedEndpoint": endpoint });
    let verified = verify_signed(&input);
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["result"]["publisherDid"], agent.did);
    assert_eq!(verified["result"]["advertisedDid"], agent.did);
    assert_eq!(verified["result"]["cardKeyId"], format!("{}#card-signing", agent.did));
    assert_eq!(verified["result"]["cardSignatureValid"], true);
    assert_eq!(verified["result"]["sameDidBinding"], true);
    assert_eq!(verified["result"]["authorizationGranted"], false);

    let mut mismatches = Vec::new();
    let mut wrong = input.clone();
    wrong["publisherDid"] = json!(principal.did);
    mismatches.push(("publisher DID", wrong));
    let mut wrong = input.clone();
    wrong["card"]["capabilities"]["extensions"][0]["params"]["did"] = json!(principal.did);
    mismatches.push(("advertised DID", wrong));
    let mut wrong = input.clone();
    wrong["trustedDidDocument"]["id"] = json!(principal.did);
    mismatches.push(("trusted document DID", wrong));
    let mut wrong = input.clone();
    wrong["trustedDidDocument"]["verificationMethod"][0]["publicKeyMultibase"] =
        descriptor["alternatePublicKeyForSubstitutionTest"].clone();
    mismatches.push(("trusted card key", wrong));
    let mut wrong = input.clone();
    wrong["record"]["uri"] = json!(format!("at://{}/link.ident.agent/other", agent.did));
    mismatches.push(("singleton rkey", wrong));
    let mut wrong = input.clone();
    wrong["card"]["name"] = json!("Tampered payload");
    mismatches.push(("payload", wrong));
    let mut wrong = input.clone();
    let changed_endpoint = format!("{}/changed", descriptor["origin"].as_str().unwrap());
    wrong["card"]["supportedInterfaces"][0]["url"] = json!(changed_endpoint);
    wrong["expectedEndpoint"] = json!(changed_endpoint);
    mismatches.push(("signed endpoint even with changed expected path", wrong));
    for (label, mismatch) in mismatches {
        assert_eq!(verify_signed(&mismatch)["ok"], false, "reject {label}");
    }
    // A real endpoint exists and requires its separate disposable credential.
    let rpc = json!({"jsonrpc": "2.0", "id": "fixture-call", "method": "SendMessage", "params": {"message": {
        "messageId": "fixture-call", "role": "ROLE_USER", "parts": [{"data": {
            "skillId": "resolve-identity-fixture", "agentDid": agent.did, "principalDid": principal.did
        }}]
    }}});
    assert_eq!(http.post(endpoint).json(&rpc).send().await.unwrap().status(), 401);
    let reply = http.post(endpoint).header("a2a-version", "1.0").bearer_auth(&token).json(&rpc).send().await.unwrap();
    assert_eq!(reply.status(), 200);
    let reply: J = reply.json().await.unwrap();
    assert_eq!(reply["result"]["message"]["parts"][0]["data"]["agentDid"], agent.did);
    assert_eq!(reply["result"]["message"]["parts"][0]["data"]["status"], "declared_unverified");
    remove(&s, &agent, &agent.did, CONTACT, "self").await.ok();
    let absence = current_proof(&s, &agent.did, CONTACT, "self", &agent_key).await;
    assert!(absence.record_cid.is_none());
    assert!(
        verify_at_head(&contact_proof.bytes, &agent.did, &format!("{CONTACT}/self"), &agent_key, absence.root).is_err()
    );
    fixture.0.kill().unwrap();
    fixture.0.wait().unwrap();
    vlpds::server::shutdown(&s.app).await;
    let evidence = json!({ "result": "PASS", "agentDid": agent.did, "principalDid": principal.did,
        "contact": input["record"], "signedCard": input["card"], "trustedCardDidDocument": input["trustedDidDocument"],
        "cardUrl": card_url, "endpoint": endpoint, "verification": verified["result"],
        "repoProofs": {"agentContact": base64::prelude::BASE64_STANDARD.encode(&contact_proof.bytes),
            "principalEndorsement": base64::prelude::BASE64_STANDARD.encode(&endorsement_proof.bytes),
            "contactAbsence": base64::prelude::BASE64_STANDARD.encode(&absence.bytes)},
        "repoPublicPins": {"algorithm": "secp256k1", "encoding": "compressed SEC1 hex",
            "agent": hex::encode(agent_key.to_sec1_point(true).as_bytes()), "principal": hex::encode(principal_key.to_sec1_point(true).as_bytes())},
        "cardTrustOrigin": "Synthetic operator-owned child IPC pinned before HTTP discovery; NOT a live DID document update or globally resolved card key",
        "principalRepoEndorsementVerifiedLocally": true, "repoCurrentHeadChecked": true,
        "publisherAdvertisedDidAndTrustedCardKeyAgree": true, "mismatchesAndPayloadEndpointTamperingDenied": true,
        "syntheticEndpointDeniedWithoutCredential": true, "syntheticEndpointReadOnlyReplyWithDisposableCredential": true,
        "cardSignatureFormat": "Experimental Kody detached ES256 JWS, clean-empty canonical JSON, P256 Multikey, raw64 P1363",
        "globalDidKeyBindingVerified": false, "httpsTransportQualified": false, "liveAgentRuntimeReady": false,
        "liveKeysOrKodyIdentityTouched": false, "cardChildKilledAndWaited": true, "pdsShutdownRequested": true,
        "privateKeysOrTokensExported": false
    });
    if let Ok(output) = std::env::var("VLPDS_EXP710_SIGNED_EVIDENCE_PATH") {
        std::fs::write(output, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}
