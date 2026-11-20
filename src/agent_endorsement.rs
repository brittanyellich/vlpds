//! Internal, network-free EXP-710 proof gate. Never mounted as an HTTP handler.
//! Trusted snapshots must come from the operator's bounded resolver/fetch layer,
//! not the caller, card, CAR or dispatcher. Equality of supplied heads is not an
//! independent proof of global freshness or of the authority's honesty.
use serde_json::{json, Value as J};
use std::collections::HashSet;
use vlatproto::{car::read_car, cid::Cid};

pub const AGENT: &str = "did:plc:6tlvgafuonoighfrtpejff5m";
pub const PRINCIPAL: &str = "did:plc:exquicw7jew5vxerpgvc3x6w";
pub const MAX_CAR_BYTES: usize = 65536;

/// Only a validated signed absence yields Absent. Transport errors belong to
/// the future fetch layer and must never be translated into this outcome.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Verified { commit: Cid, record: Cid },
    Absent { commit: Cid },
}

pub struct TrustedSnapshot<'a> {
    pub agent_document: &'a J,
    pub principal_document: &'a J,
    pub head_before: Cid,
    pub head_after: Cid,
}

/// Fixed-pair reciprocal declaration + principal signed endorsement. No fetch,
/// JS, Kody invocation, account credential, caller authorization or card proof.
pub fn verify(snapshot: &TrustedSnapshot<'_>, car: &[u8], fetched_record: Option<&J>) -> Result<Outcome, String> {
    let fail = |s: &str| Err(s.to_string());
    if car.is_empty() || car.len() > MAX_CAR_BYTES {
        return fail("Endorsement CAR byte limit");
    }
    for document in [snapshot.agent_document, snapshot.principal_document] {
        if serde_json::to_vec(document).map_err(|e| e.to_string())?.len() > 32768 {
            return fail("DID document byte limit");
        }
        if document.get("deactivated").is_some_and(|v| v != &json!(false)) {
            return fail("Deactivated or invalid DID metadata");
        }
    }
    if snapshot.agent_document["id"] != AGENT || snapshot.principal_document["id"] != PRINCIPAL {
        return fail("Fixed DID pair mismatch");
    }
    let declaration = format!("https://ident.link/agent-of/{PRINCIPAL}");
    let aliases = snapshot.agent_document["alsoKnownAs"].as_array().ok_or("Missing reciprocal declaration")?;
    if aliases.len() > 128 || !aliases.iter().all(J::is_string) || !aliases.iter().any(|v| v == &declaration) {
        return fail("Missing reciprocal declaration");
    }
    let key_id = format!("{PRINCIPAL}#atproto");
    let methods = snapshot.principal_document["verificationMethod"].as_array().ok_or("Missing principal key")?;
    if methods.len() > 128 {
        return fail("Too many verification methods");
    }
    let mut matching = methods.iter().filter(|m| m["id"] == key_id);
    let method = matching.next().ok_or("Missing principal key")?;
    if matching.next().is_some() || method["controller"] != PRINCIPAL || method["type"] != "Multikey" {
        return fail("Ambiguous or uncontrolled principal key");
    }
    let key = method["publicKeyMultibase"].as_str().ok_or("Missing principal multikey")?;
    if key.len() > 128 {
        return fail("Principal multikey too long");
    }
    if snapshot.head_before != snapshot.head_after {
        return fail("Head changed during observation");
    }
    let (roots, blocks) = read_car(car).map_err(|e| e.to_string())?;
    if roots.as_slice() != [snapshot.head_before] {
        return fail("Proof is not at pinned current head");
    }
    if blocks.len() > 64 {
        return fail("Proof block count limit");
    }
    let mut seen = HashSet::new();
    for &(cid, bytes) in &blocks {
        if bytes.len() > 16384 || !seen.insert(cid) {
            return fail("Oversized or duplicate proof block");
        }
    }
    // Application gate accepts only the repository commit version it qualifies.
    let commit_bytes = blocks.iter().find(|(cid, _)| *cid == snapshot.head_before).ok_or("Missing commit block")?.1;
    let commit = vlatproto::cbor::Value::decode(commit_bytes).map_err(|e| e.to_string())?;
    if commit.get("version") != Some(&vlatproto::cbor::Value::Int(3)) {
        return fail("Unsupported repository commit version");
    }
    let path = format!("link.ident.endorsement/{AGENT}");
    let (root, included) = crate::oauth::lexicon::verify_record_inclusion(car, PRINCIPAL, key, &path)?;
    let Some((cid, value)) = included else {
        if fetched_record.is_some() {
            return fail("Fetched record conflicts with signed absence");
        }
        return Ok(Outcome::Absent { commit: root });
    };
    let record = fetched_record.ok_or("Missing independent record read")?;
    if serde_json::to_vec(record).map_err(|e| e.to_string())?.len() > 4096 {
        return fail("Record JSON byte limit");
    }
    let uri = format!("at://{PRINCIPAL}/{path}");
    if record["uri"] != uri
        || record["cid"] != cid.to_string()
        || record["value"] != value
        || value != json!({"$type":"link.ident.endorsement","agent":AGENT})
    {
        return fail("Signed endorsement does not match fixed record read");
    }
    Ok(Outcome::Verified { commit: root, record: cid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlatproto::{
        car::{write_block, write_header},
        cbor::Value,
        crypto::Keypair,
        mst::Tree,
    };

    // These keys are disposable and have NO relationship to live fixed-DID keys.
    // A synthetic commit carrying the fixed DID tests mechanics relative to pins.
    struct Fixture {
        agent: J,
        principal: J,
        car: Vec<u8>,
        head: Cid,
        record: J,
    }
    impl Fixture {
        fn new(value: Option<J>, path: &str, commit_did: &str) -> Self {
            let key = Keypair::generate();
            let mut blocks = Vec::new();
            let mut tree = Tree::new();
            let mut record = J::Null;
            if let Some(value) = value {
                let bytes = Value::from_json(&value).unwrap().to_cbor();
                let cid = Cid::dag_cbor(&bytes);
                tree.insert_no_proof(path.as_bytes(), cid).unwrap();
                blocks.push((cid, bytes));
                record = json!({"uri":format!("at://{PRINCIPAL}/link.ident.endorsement/{AGENT}"),"cid":cid.to_string(),"value":value});
            }
            let data = tree.write_diff_blocks(&mut blocks).unwrap();
            let mut fields: Vec<(String, Value)> = vec![
                ("did".into(), Value::Text(commit_did.into())),
                ("version".into(), Value::Int(3)),
                ("rev".into(), Value::Text("3aaaaaaaaaaaa".into())),
                ("prev".into(), Value::Null),
                ("data".into(), Value::Link(data)),
            ];
            fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
            let sig = key.sign(&Value::Map(fields.clone()).to_cbor());
            fields.push(("sig".into(), Value::Bytes(sig.to_vec())));
            fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
            let commit = Value::Map(fields).to_cbor();
            let head = Cid::dag_cbor(&commit);
            blocks.push((head, commit));
            let mut car = Vec::new();
            write_header(&mut car, &head);
            for (cid, bytes) in blocks {
                write_block(&mut car, &cid, &bytes);
            }
            let agent = json!({"id":AGENT,"alsoKnownAs":[format!("https://ident.link/agent-of/{PRINCIPAL}")]});
            let principal = json!({"id":PRINCIPAL,"verificationMethod":[{"id":format!("{PRINCIPAL}#atproto"),"controller":PRINCIPAL,"type":"Multikey","publicKeyMultibase":key.public_multibase()}]});
            Self { agent, principal, car, head, record }
        }
        fn valid() -> Self {
            Self::new(
                Some(json!({"$type":"link.ident.endorsement","agent":AGENT})),
                &format!("link.ident.endorsement/{AGENT}"),
                PRINCIPAL,
            )
        }
        fn snapshot(&self) -> TrustedSnapshot<'_> {
            TrustedSnapshot {
                agent_document: &self.agent,
                principal_document: &self.principal,
                head_before: self.head,
                head_after: self.head,
            }
        }
        fn verify(&self) -> Result<Outcome, String> {
            verify(&self.snapshot(), &self.car, Some(&self.record))
        }
    }

    #[test]
    fn fixed_pair_proof_and_signed_absence() {
        let f = Fixture::valid();
        let result = f.verify();
        assert!(matches!(result, Ok(Outcome::Verified { .. })), "{result:?}");
        let f = Fixture::new(None, "", PRINCIPAL);
        assert_eq!(verify(&f.snapshot(), &f.car, None), Ok(Outcome::Absent { commit: f.head }));
        assert!(f.verify().is_err(), "JSON claim cannot override signed absence");
        let f = Fixture::valid();
        assert!(verify(&f.snapshot(), &f.car, None).is_err());
    }

    #[test]
    fn substitutions_tampering_and_stale_heads_fail_closed() {
        for change in 0..11 {
            let mut f = Fixture::valid();
            match change {
                0 => f.agent["id"] = json!(PRINCIPAL),
                1 => f.agent["alsoKnownAs"] = json!([]),
                2 => f.principal["verificationMethod"][0]["controller"] = json!(AGENT),
                3 => {
                    f.principal["verificationMethod"][0]["publicKeyMultibase"] =
                        json!(Keypair::generate().public_multibase())
                }
                4 => f.record["cid"] = json!(Cid::dag_cbor(b"wrong").to_string()),
                5 => f.record["uri"] = json!("at://wrong/link.ident.endorsement/self"),
                6 => f.record["value"]["agent"] = json!(PRINCIPAL),
                7 => {
                    let duplicate = f.principal["verificationMethod"][0].clone();
                    f.principal["verificationMethod"].as_array_mut().unwrap().push(duplicate);
                }
                8 => f.agent["deactivated"] = json!(true),
                9 => {
                    *f.car.last_mut().unwrap() ^= 1;
                }
                _ => f.head = Cid::dag_cbor(b"laterhead"),
            }
            assert!(f.verify().is_err(), "case {change}");
        }
        let f = Fixture::valid();
        let mut snapshot = f.snapshot();
        snapshot.head_after = Cid::dag_cbor(b"changed");
        assert!(verify(&snapshot, &f.car, Some(&f.record)).is_err());
        let f = Fixture::new(
            Some(json!({"$type":"link.ident.endorsement","agent":PRINCIPAL})),
            &format!("link.ident.endorsement/{AGENT}"),
            PRINCIPAL,
        );
        assert!(f.verify().is_err(), "correctly signed wrong relationship");
        let f = Fixture::new(
            Some(json!({"$type":"link.ident.endorsement","agent":AGENT})),
            "link.ident.endorsement/wrong",
            PRINCIPAL,
        );
        assert!(f.verify().is_err(), "wrong MST path");
        let f = Fixture::new(
            Some(json!({"$type":"link.ident.endorsement","agent":AGENT})),
            &format!("link.ident.endorsement/{AGENT}"),
            AGENT,
        );
        assert!(f.verify().is_err(), "signed wrong repo DID");
    }

    #[test]
    fn malformed_oversized_and_duplicate_blocks_are_rejected() {
        let f = Fixture::valid();
        for end in 0..f.car.len() {
            assert!(verify(&f.snapshot(), &f.car[..end], Some(&f.record)).is_err());
        }
        assert!(verify(&f.snapshot(), &vec![0; MAX_CAR_BYTES + 1], None).is_err());
        let mut duplicate = f.car.clone();
        let (_, blocks) = read_car(&f.car).unwrap();
        write_block(&mut duplicate, &blocks[0].0, blocks[0].1);
        assert!(verify(&f.snapshot(), &duplicate, Some(&f.record)).is_err());
        let mut too_many = f.car.clone();
        for n in 0..65 {
            let bytes = vec![n];
            write_block(&mut too_many, &Cid::dag_cbor(&bytes), &bytes);
        }
        assert!(verify(&f.snapshot(), &too_many, Some(&f.record)).is_err());
    }

    #[test]
    fn existing_lexicon_verifier_keeps_its_type_contract() {
        let f = Fixture::valid();
        let key = f.principal["verificationMethod"][0]["publicKeyMultibase"].as_str().unwrap();
        assert!(crate::oauth::lexicon::verify_record_proof(
            &f.car,
            PRINCIPAL,
            key,
            &format!("link.ident.endorsement/{AGENT}")
        )
        .unwrap_err()
        .contains("Invalid record type"));
        let value = json!({"$type":"com.atproto.lexicon.schema","lexicon":1});
        let path = "com.atproto.lexicon.schema/test.example";
        let f = Fixture::new(Some(value.clone()), path, PRINCIPAL);
        let key = f.principal["verificationMethod"][0]["publicKeyMultibase"].as_str().unwrap();
        assert_eq!(crate::oauth::lexicon::verify_record_proof(&f.car, PRINCIPAL, key, path).unwrap(), value);
    }
}
