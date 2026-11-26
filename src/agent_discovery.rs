//! Network-free, fixed-pilot discovery contract. No mount, publication, consent,
//! caller admission or dispatch is performed here. The fetch layer must supply
//! independently trusted fresh DID snapshots and current heads around each read.
use crate::{
    agent_card,
    agent_contact_pilot::{AGENT_PATH, CARD_PATH},
    agent_endorsement::{self, Outcome, TrustedSnapshot, AGENT, MAX_CAR_BYTES, PRINCIPAL},
};
use serde_json::{json, Value as J};
use std::collections::HashSet;
use vlatproto::{car::read_car, cid::Cid};

pub struct Snapshot<'a> {
    pub relationship: TrustedSnapshot<'a>,
    pub agent_head_before: Cid,
    pub agent_head_after: Cid,
}

/// Public routing metadata only. Possession is never caller authorization.
#[derive(Debug, PartialEq)]
pub struct Contact {
    pub agent: String,
    pub principal: String,
    pub card_url: String,
    pub endpoint: String,
    pub contact_commit: Cid,
    pub contact_record: Cid,
    pub endorsement_commit: Cid,
    pub endorsement_record: Cid,
}

/// Independent record reads distinguish confirmed absence from fetch failure.
pub enum RecordRead<'a> {
    Found(&'a J),
    Absent,
    Unavailable,
}
impl<'a> RecordRead<'a> {
    fn checked(self) -> Result<Option<&'a J>, String> {
        match self {
            Self::Found(record) => Ok(Some(record)),
            Self::Absent => Ok(None),
            Self::Unavailable => Err("Independent record read unavailable".into()),
        }
    }
}

pub struct Evidence<'a> {
    pub endorsement_car: &'a [u8],
    pub endorsement_record: RecordRead<'a>,
    pub contact_car: &'a [u8],
    pub contact_record: RecordRead<'a>,
    pub card: &'a J,
}

/// None means current signed endorsement or contact absence. Errors (including
/// unavailable evidence) must not fall back to a cached pointer or other URL.
/// The only supported record is the experimental link.ident.agent/self opt-in
/// with the fixed per-agent HTTPS Card URL; no credentials or private fields.
pub fn discover_fixed(
    snapshot: &Snapshot<'_>,
    evidence: Evidence<'_>,
    origin: &str,
    audience: &str,
) -> Result<Option<Contact>, String> {
    let Evidence { endorsement_car, endorsement_record, contact_car, contact_record, card } = evidence;
    let endorsement_record = endorsement_record.checked()?;
    let contact_record = contact_record.checked()?;
    let url = reqwest::Url::parse(origin).map_err(|_| "Invalid discovery origin")?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != origin {
        return Err("Exact HTTPS discovery origin required".into());
    }
    let (endorsement_commit, endorsement_cid) =
        match agent_endorsement::verify(&snapshot.relationship, endorsement_car, endorsement_record)? {
            Outcome::Verified { commit, record } => (commit, record),
            Outcome::Absent { .. } => return Ok(None),
        };
    if snapshot.agent_head_before != snapshot.agent_head_after {
        return Err("Agent head changed during discovery".into());
    }
    let document = snapshot.relationship.agent_document;
    let key_id = format!("{AGENT}#atproto");
    let methods = document["verificationMethod"].as_array().ok_or("Missing agent signing key")?;
    if methods.len() > 128 {
        return Err("Agent key count limit".into());
    }
    let mut matching = methods.iter().filter(|m| m["id"] == key_id);
    let method = matching.next().ok_or("Missing agent signing key")?;
    if matching.next().is_some() || method["controller"] != AGENT || method["type"] != "Multikey" {
        return Err("Ambiguous or uncontrolled agent signing key".into());
    }
    let key = method["publicKeyMultibase"].as_str().filter(|v| v.len() <= 128).ok_or("Invalid agent key")?;
    if contact_car.is_empty() || contact_car.len() > MAX_CAR_BYTES {
        return Err("Contact CAR byte limit".into());
    }
    let (roots, blocks) = read_car(contact_car).map_err(|e| e.to_string())?;
    if roots.as_slice() != [snapshot.agent_head_before] || blocks.len() > 64 {
        return Err("Contact proof is not at current head or exceeds block limit".into());
    }
    let mut seen = HashSet::new();
    if blocks.iter().any(|(cid, bytes)| bytes.len() > 16384 || !seen.insert(*cid)) {
        return Err("Oversized or duplicate contact block".into());
    }
    let commit_bytes =
        blocks.iter().find(|(cid, _)| *cid == snapshot.agent_head_before).ok_or("Missing agent commit")?.1;
    let commit = vlatproto::cbor::Value::decode(commit_bytes).map_err(|e| e.to_string())?;
    if commit.get("version") != Some(&vlatproto::cbor::Value::Int(3)) {
        return Err("Unsupported agent commit version".into());
    }
    let (contact_commit, included) =
        crate::oauth::lexicon::verify_record_inclusion(contact_car, AGENT, key, "link.ident.agent/self")?;
    let Some((contact_cid, value)) = included else {
        if contact_record.is_some() {
            return Err("Contact read conflicts with signed absence".into());
        }
        return Ok(None);
    };
    let record = contact_record.ok_or("Missing independent contact read")?;
    if serde_json::to_vec(record).map_err(|e| e.to_string())?.len() > 4096 {
        return Err("Contact record limit".into());
    }
    let card_url = format!("{origin}{CARD_PATH}");
    if record["uri"] != format!("at://{AGENT}/link.ident.agent/self")
        || record["cid"] != contact_cid.to_string()
        || record["value"] != value
        || value != json!({"$type":"link.ident.agent","agentCardUrl":card_url})
    {
        return Err("Signed contact record or Card URL differs".into());
    }
    agent_card::verify_origin(document, origin)?;
    let card_key = agent_card::current_key(document)?.ok_or("Current Card key unavailable")?;
    agent_card::verify(card, &card_key, origin, audience)?;
    Ok(Some(Contact {
        agent: AGENT.into(),
        principal: PRINCIPAL.into(),
        card_url,
        endpoint: format!("{origin}{AGENT_PATH}"),
        contact_commit,
        contact_record: contact_cid,
        endorsement_commit,
        endorsement_record: endorsement_cid,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use vlatproto::{
        car::{write_block, write_header},
        cbor::Value,
        crypto::Keypair,
        mst::Tree,
    };
    const ORIGIN: &str = "https://discovery.invalid";
    const AUD: &str = "did:web:discovery.invalid";

    fn proof(did: &str, key: &Keypair, path: &str, value: Option<J>) -> (Cid, Vec<u8>, Option<J>) {
        let mut blocks = Vec::new();
        let mut tree = Tree::new();
        let record = value.map(|value| {
            let bytes = Value::from_json(&value).unwrap().to_cbor();
            let cid = Cid::dag_cbor(&bytes);
            tree.insert_no_proof(path.as_bytes(), cid).unwrap();
            blocks.push((cid, bytes));
            json!({"uri":format!("at://{did}/{path}"),"cid":cid.to_string(),"value":value})
        });
        let data = tree.write_diff_blocks(&mut blocks).unwrap();
        let mut fields = vec![
            ("did".into(), Value::Text(did.into())),
            ("version".into(), Value::Int(3)),
            ("rev".into(), Value::Text("3aaaaaaaaaaaa".into())),
            ("prev".into(), Value::Null),
            ("data".into(), Value::Link(data)),
        ];
        fields.sort_by(|a: &(String, Value), b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        let signature = key.sign(&Value::Map(fields.clone()).to_cbor());
        fields.push(("sig".into(), Value::Bytes(signature.to_vec())));
        fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        let bytes = Value::Map(fields).to_cbor();
        let head = Cid::dag_cbor(&bytes);
        blocks.push((head, bytes));
        let mut car = Vec::new();
        write_header(&mut car, &head);
        for (cid, bytes) in blocks {
            write_block(&mut car, &cid, &bytes);
        }
        (head, car, record)
    }
    fn read(value: &Option<J>) -> RecordRead<'_> {
        match value {
            Some(record) => RecordRead::Found(record),
            None => RecordRead::Absent,
        }
    }
    struct Fixture {
        agent_key: Keypair,
        principal_key: Keypair,
        agent: J,
        principal: J,
        card: J,
        endorsement: (Cid, Vec<u8>, Option<J>),
        contact: (Cid, Vec<u8>, Option<J>),
    }
    impl Fixture {
        fn new() -> Self {
            let agent_key = Keypair::generate();
            let principal_key = Keypair::generate();
            let card_key = SigningKey::from_bytes((&rand::random::<[u8; 32]>()).into()).unwrap();
            let mut multikey = vec![0x80, 0x24];
            multikey.extend_from_slice(card_key.verifying_key().to_sec1_point(true).as_bytes());
            let pin = format!("z{}", bs58::encode(multikey).into_string());
            let agent = json!({"id":AGENT,"alsoKnownAs":[format!("https://ident.link/agent-of/{PRINCIPAL}")],
                "verificationMethod":[{"id":format!("{AGENT}#atproto"),"controller":AGENT,"type":"Multikey","publicKeyMultibase":agent_key.public_multibase()},
                {"id":format!("{AGENT}#card-signing"),"controller":AGENT,"type":"Multikey","publicKeyMultibase":pin}],
                "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":ORIGIN}]});
            let principal = json!({"id":PRINCIPAL,"verificationMethod":[{"id":format!("{PRINCIPAL}#atproto"),"controller":PRINCIPAL,"type":"Multikey","publicKeyMultibase":principal_key.public_multibase()}]});
            let mut card = agent_card::template(ORIGIN, AUD);
            let protected =
                B64.encode(format!("{{\"alg\":\"ES256\",\"typ\":\"JOSE\",\"kid\":\"{AGENT}#card-signing\"}}"));
            let signature: Signature =
                card_key.sign(format!("{protected}.{}", agent_card::payload(&card).unwrap()).as_bytes());
            card["signatures"] =
                json!([{"protected":protected,"signature":B64.encode(signature.normalize_s().to_bytes())}]);
            let endorsement = proof(
                PRINCIPAL,
                &principal_key,
                &format!("link.ident.endorsement/{AGENT}"),
                Some(json!({"$type":"link.ident.endorsement","agent":AGENT})),
            );
            let contact = proof(
                AGENT,
                &agent_key,
                "link.ident.agent/self",
                Some(json!({"$type":"link.ident.agent","agentCardUrl":format!("{ORIGIN}{CARD_PATH}")})),
            );
            Self { agent_key, principal_key, agent, principal, card, endorsement, contact }
        }
        fn snapshot(&self) -> Snapshot<'_> {
            Snapshot {
                relationship: TrustedSnapshot {
                    agent_document: &self.agent,
                    principal_document: &self.principal,
                    head_before: self.endorsement.0,
                    head_after: self.endorsement.0,
                },
                agent_head_before: self.contact.0,
                agent_head_after: self.contact.0,
            }
        }
        fn discover(&self) -> Result<Option<Contact>, String> {
            discover_fixed(
                &self.snapshot(),
                Evidence {
                    endorsement_car: &self.endorsement.1,
                    endorsement_record: read(&self.endorsement.2),
                    contact_car: &self.contact.1,
                    contact_record: read(&self.contact.2),
                    card: &self.card,
                },
                ORIGIN,
                AUD,
            )
        }
    }
    #[test]
    fn current_signed_opt_in_and_card_yield_only_public_routing() {
        let f = Fixture::new();
        let c = f.discover().unwrap().unwrap();
        assert_eq!(c.endpoint, format!("{ORIGIN}{AGENT_PATH}"));
        assert_eq!(c.card_url, format!("{ORIGIN}{CARD_PATH}"));
        assert_eq!(f.discover().unwrap(), Some(c)); // Pure lookup has no enrollment/dispatch side effect.
    }
    #[test]
    fn signed_contact_and_endorsement_removal_stop_discovery() {
        let mut f = Fixture::new();
        f.contact = proof(AGENT, &f.agent_key, "link.ident.agent/self", None);
        assert_eq!(f.discover().unwrap(), None);
        let mut f = Fixture::new();
        f.endorsement = proof(PRINCIPAL, &f.principal_key, &format!("link.ident.endorsement/{AGENT}"), None);
        assert_eq!(f.discover().unwrap(), None);
    }
    #[test]
    fn changed_heads_missing_and_tampered_evidence_never_fall_back() {
        let mut f = Fixture::new();
        f.contact.1[20] ^= 1;
        assert!(f.discover().is_err());
        let f = Fixture::new();
        let mut s = f.snapshot();
        s.agent_head_after = f.endorsement.0;
        assert!(discover_fixed(
            &s,
            Evidence {
                endorsement_car: &f.endorsement.1,
                endorsement_record: read(&f.endorsement.2),
                contact_car: &f.contact.1,
                contact_record: read(&f.contact.2),
                card: &f.card
            },
            ORIGIN,
            AUD
        )
        .is_err());
        let mut f = Fixture::new();
        f.contact.2 = None;
        assert!(f.discover().is_err());
        let mut f = Fixture::new();
        f.contact.1.clear();
        assert!(f.discover().is_err());
    }
    #[test]
    fn unavailable_read_is_distinct_from_signed_absence() {
        let mut f = Fixture::new();
        f.contact = proof(AGENT, &f.agent_key, "link.ident.agent/self", None);
        let evidence = Evidence {
            endorsement_car: &f.endorsement.1,
            endorsement_record: read(&f.endorsement.2),
            contact_car: &f.contact.1,
            contact_record: RecordRead::Unavailable,
            card: &f.card,
        };
        assert!(discover_fixed(&f.snapshot(), evidence, ORIGIN, AUD).is_err());
        f.endorsement = proof(PRINCIPAL, &f.principal_key, &format!("link.ident.endorsement/{AGENT}"), None);
        let evidence = Evidence {
            endorsement_car: &f.endorsement.1,
            endorsement_record: RecordRead::Absent,
            contact_car: &f.contact.1,
            contact_record: RecordRead::Unavailable,
            card: &f.card,
        };
        assert!(discover_fixed(&f.snapshot(), evidence, ORIGIN, AUD).is_err());
        let evidence = Evidence {
            endorsement_car: &f.endorsement.1,
            endorsement_record: RecordRead::Unavailable,
            contact_car: &f.contact.1,
            contact_record: RecordRead::Absent,
            card: &f.card,
        };
        assert!(discover_fixed(&f.snapshot(), evidence, ORIGIN, AUD).is_err());
    }
    #[test]
    fn arbitrary_override_card_or_authority_is_rejected() {
        let mut f = Fixture::new();
        f.contact = proof(
            AGENT,
            &f.agent_key,
            "link.ident.agent/self",
            Some(json!({"$type":"link.ident.agent","agentCardUrl":"https://other.invalid/card"})),
        );
        assert!(f.discover().is_err());
        let mut f = Fixture::new();
        f.card["name"] = json!("tampered");
        assert!(f.discover().is_err());
        let mut f = Fixture::new();
        f.agent["service"][0]["serviceEndpoint"] = json!("https://other.invalid");
        assert!(f.discover().is_err());
        let mut f = Fixture::new();
        f.agent["deactivated"] = json!(true);
        assert!(f.discover().is_err());
    }
}
