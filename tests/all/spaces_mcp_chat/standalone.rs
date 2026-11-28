use super::http::FixtureSigner;
use serde_json::{json, Value as J};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
use vlatproto::crypto::Keypair;
use vlpds::plc::{self, mock::MockPlc};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires disposable workerd, OAuth bundle, Chrome and Moto executables"]
async fn standalone_browser_consent_and_chat() {
    let plc = MockPlc::start().await;
    let rotation = Keypair::generate();
    let audience = "did:web:preview-pds.invalid";
    let signer = FixtureSigner::register(&plc, audience.into()).await;
    let inputs = ["EXP711_WORKERD", "EXP711_OAUTH_PROVIDER", "EXP711_MOTO", "EXP711_CHROME"]
        .map(|name| std::env::var(name).unwrap_or_else(|_| panic!("Set {name} to an absolute local path")));
    let mut child = Command::new("node")
        .arg("tools/spaces-mcp-auth-fixture/check-standalone-preview.mjs")
        .arg(env!("CARGO_BIN_EXE_vlpds"))
        .args(inputs)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let config = json!({"plc": plc.url, "rotation": hex::encode(rotation.to_bytes()), "signer": signer.config()});
    input.write_all(format!("{config}\n").as_bytes()).await.unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    while let Some(line) = output.next_line().await.unwrap() {
        let Some(pair) = line.strip_prefix("EXP711_DECLARE ") else {
            println!("{line}");
            continue;
        };
        let pair: J = serde_json::from_str(pair).unwrap();
        let owner = pair["owner"].as_str().unwrap();
        let agent = pair["agent"].as_str().unwrap();
        assert_ne!(owner, agent);
        assert!(plc.data(owner).is_some());
        let mut operation = plc.last_op(agent).expect("provisioned agent registered in the disposable PLC");
        let previous = plc::op_cid(&operation).unwrap();
        operation.as_object_mut().unwrap().remove("sig");
        operation["prev"] = json!(previous.to_string());
        operation["alsoKnownAs"].as_array_mut().unwrap().push(json!(format!("https://ident.link/agent-of/{owner}")));
        let signed = plc::sign(operation, &rotation).unwrap();
        let response = client.post(format!("{}/{agent}", plc.url)).json(&signed).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "Disposable agent declaration failed: {}",
            response.text().await.unwrap()
        );
        input.write_all(b"ok\n").await.unwrap();
        input.shutdown().await.unwrap();
    }
    assert!(child.wait().await.unwrap().success());
}
