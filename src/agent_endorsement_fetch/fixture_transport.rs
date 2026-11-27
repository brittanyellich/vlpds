//! Compiled only inside this crate's tests. Bytes, not trusted verification outcomes.
use super::{AGENT, PDS, PLC, PRINCIPAL};
use serde_json::{json, Value as J};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use vlatproto::{
    car::{write_block, write_header},
    cbor::Value,
    cid::Cid,
    crypto::Keypair,
    mst::Tree,
};
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Valid,
    Absent,
    Unavailable,
    Tampered,
    WrongPair,
    ChangedHead,
    BadMedia,
    Redirect,
    Oversize,
    ChangedDid,
    Encoded,
}
struct Proof {
    agent: J,
    principal: J,
    record: Option<J>,
    car: Vec<u8>,
    head: Cid,
}
impl Proof {
    fn new(present: bool) -> Self {
        let key = Keypair::generate();
        let mut blocks = Vec::new();
        let mut tree = Tree::new();
        let path = format!("link.ident.endorsement/{AGENT}");
        let record = if present {
            let value = json!({"$type":"link.ident.endorsement","agent":AGENT});
            let bytes = Value::from_json(&value).unwrap().to_cbor();
            let cid = Cid::dag_cbor(&bytes);
            tree.insert_no_proof(path.as_bytes(), cid).unwrap();
            blocks.push((cid, bytes));
            Some(json!({"uri":format!("at://{PRINCIPAL}/{path}"),"cid":cid.to_string(),"value":value}))
        } else {
            None
        };
        let data = tree.write_diff_blocks(&mut blocks).unwrap();
        let mut fields = vec![
            ("did".into(), Value::Text(PRINCIPAL.into())),
            ("version".into(), Value::Int(3)),
            ("rev".into(), Value::Text("3aaaaaaaaaaaa".into())),
            ("prev".into(), Value::Null),
            ("data".into(), Value::Link(data)),
        ];
        fields.sort_by(|a: &(String, Value), b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        let signature = key.sign(&Value::Map(fields.clone()).to_cbor());
        fields.push(("sig".into(), Value::Bytes(signature.to_vec())));
        fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        let commit = Value::Map(fields).to_cbor();
        let head = Cid::dag_cbor(&commit);
        blocks.push((head, commit));
        let mut car = Vec::new();
        write_header(&mut car, &head);
        for (cid, bytes) in blocks {
            write_block(&mut car, &cid, &bytes);
        }
        let service = |did: &str| json!([{"id":format!("{did}#atproto_pds"),"type":"AtprotoPersonalDataServer","serviceEndpoint":PDS}]);
        let agent = json!({"id":AGENT,"alsoKnownAs":[format!("https://ident.link/agent-of/{PRINCIPAL}")],"service":service(AGENT)});
        let principal = json!({"id":PRINCIPAL,"verificationMethod":[{"id":format!("{PRINCIPAL}#atproto"),"controller":PRINCIPAL,"type":"Multikey","publicKeyMultibase":key.public_multibase()}],"service":service(PRINCIPAL)});
        Self { agent, principal, record, car, head }
    }
}
struct State {
    mode: Mode,
    heads: usize,
    agent_reads: usize,
}
pub(crate) struct Authority {
    valid: Proof,
    absent: Proof,
    state: Mutex<State>,
    pub requests: AtomicUsize,
    pause: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}
enum Context {
    DenyHttps,
    Authority(Arc<Authority>),
    Bytes(Arc<dyn Fn(&reqwest::Url) -> Result<reqwest::Response, String> + Send + Sync>),
}
tokio::task_local! {static CURRENT:Context;}
pub(crate) fn current() -> Option<Arc<Authority>> {
    CURRENT
        .try_with(|c| match c {
            Context::Authority(a) => Some(a.clone()),
            Context::DenyHttps | Context::Bytes(_) => None,
        })
        .ok()
        .flatten()
}
/// Test-only bounded raw responses; unknown requests must be rejected by the fixture.
pub(crate) fn byte_reply(url: &reqwest::Url) -> Option<Result<reqwest::Response, String>> {
    CURRENT
        .try_with(|c| match c {
            Context::Bytes(reply) => Some(reply(url)),
            _ => None,
        })
        .ok()
        .flatten()
}
pub(crate) async fn scope_bytes<T>(
    reply: Arc<dyn Fn(&reqwest::Url) -> Result<reqwest::Response, String> + Send + Sync>,
    future: impl std::future::Future<Output = T>,
) -> T {
    CURRENT.scope(Context::Bytes(reply), future).await
}
pub(crate) fn https_denied() -> bool {
    CURRENT.try_with(|c| matches!(c, Context::DenyHttps)).unwrap_or(false)
}
pub(crate) async fn scope<T>(authority: Arc<Authority>, future: impl std::future::Future<Output = T>) -> T {
    CURRENT.scope(Context::Authority(authority), future).await
}
pub(crate) async fn deny_real_https<T>(future: impl std::future::Future<Output = T>) -> T {
    CURRENT.scope(Context::DenyHttps, future).await
}
impl Authority {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            valid: Proof::new(true),
            absent: Proof::new(false),
            state: Mutex::new(State { mode: Mode::Valid, heads: 0, agent_reads: 0 }),
            requests: AtomicUsize::new(0),
            pause: Mutex::new(None),
        })
    }
    pub fn mode(&self, mode: Mode) {
        *self.state.lock().unwrap() = State { mode, heads: 0, agent_reads: 0 };
    }
    pub fn pause_proof(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *self.pause.lock().unwrap() = Some((entered.clone(), release.clone()));
        (entered, release)
    }
    pub async fn reply(&self, url: &reqwest::Url) -> Result<reqwest::Response, String> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if url.origin().ascii_serialization() == PDS && url.path() == "/xrpc/com.atproto.sync.getRecord" {
            let pause = self.pause.lock().unwrap().take();
            if let Some((entered, release)) = pause {
                entered.notify_one();
                release.notified().await;
            }
        }
        let mut state = self.state.lock().unwrap();
        let proof = if matches!(state.mode, Mode::Absent) { &self.absent } else { &self.valid };
        let mut status = 200;
        let mut media = "application/json";
        let mut length = None;
        let mut body = if matches!(state.mode, Mode::Unavailable) {
            status = 503;
            b"{}".to_vec()
        } else if url.origin().ascii_serialization() == PLC && url.query().is_none() {
            if url.path() == format!("/{AGENT}") {
                state.agent_reads += 1;
                let mut doc = proof.agent.clone();
                if matches!(state.mode, Mode::ChangedDid) && state.agent_reads.is_multiple_of(2) {
                    doc["fixtureChanged"] = json!(true);
                }
                if matches!(state.mode, Mode::WrongPair) {
                    doc["id"] = json!(PRINCIPAL);
                }
                serde_json::to_vec(&doc).unwrap()
            } else if url.path() == format!("/{PRINCIPAL}") {
                serde_json::to_vec(&proof.principal).unwrap()
            } else {
                return Err("Unknown synthetic DID request".into());
            }
        } else if url.origin().ascii_serialization() == PDS {
            let params: Vec<_> = url.query_pairs().collect();
            match url.path() {
                "/xrpc/com.atproto.sync.getLatestCommit" if params == [("did".into(), PRINCIPAL.into())] => {
                    state.heads += 1;
                    let cid = if matches!(state.mode, Mode::ChangedHead) && state.heads.is_multiple_of(2) {
                        Cid::dag_cbor(b"changed")
                    } else {
                        proof.head
                    };
                    serde_json::to_vec(&json!({"cid":cid.to_string()})).unwrap()
                }
                "/xrpc/com.atproto.repo.getRecord"
                    if params
                        == [
                            ("repo".into(), PRINCIPAL.into()),
                            ("collection".into(), "link.ident.endorsement".into()),
                            ("rkey".into(), AGENT.into()),
                        ] =>
                {
                    if let Some(record) = &proof.record {
                        serde_json::to_vec(record).unwrap()
                    } else {
                        status = 404;
                        br#"{"error":"RecordNotFound"}"#.to_vec()
                    }
                }
                "/xrpc/com.atproto.sync.getRecord"
                    if params
                        == [
                            ("did".into(), PRINCIPAL.into()),
                            ("collection".into(), "link.ident.endorsement".into()),
                            ("rkey".into(), AGENT.into()),
                        ] =>
                {
                    media = "application/vnd.ipld.car";
                    let mut car = proof.car.clone();
                    if matches!(state.mode, Mode::Tampered) {
                        let last = car.len() - 1;
                        car[last] ^= 1;
                    }
                    car
                }
                _ => return Err("Unknown synthetic proof request".into()),
            }
        } else {
            return Err("Unknown synthetic authority".into());
        };
        match state.mode {
            Mode::BadMedia => media = "text/html",
            Mode::Redirect => status = 302,
            Mode::Oversize => {
                length = Some(1000000);
                body.resize(1000000, b'x');
            }
            _ => {}
        }
        let mut response = axum::http::Response::builder()
            .status(status)
            .header("content-type", media)
            .header("content-encoding", if matches!(state.mode, Mode::Encoded) { "gzip" } else { "identity" });
        if let Some(n) = length {
            response = response.header("content-length", n);
        }
        Ok(reqwest::Response::from(response.body(reqwest::Body::from(body)).unwrap()))
    }
}
