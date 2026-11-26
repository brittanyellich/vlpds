import { constants } from "node:fs";
import { copyFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

function requireLoopback(address, label) {
  const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(address);
  if (!match || Number(match[1]) > 65535) {
    throw new Error(`${label} must use an explicit IPv4 loopback port`);
  }
}

export function previewConfig({ listener, backend, bindings, bridgeToken, signer }) {
  requireLoopback(listener, "Listener");
  requireLoopback(backend, "Spaces backend");
  if (listener === backend) throw new Error("Listener and Spaces backend must be distinct");
  if (Boolean(bridgeToken) !== Boolean(signer)) throw new Error("Signed dispatch requires both fixture inputs");

  const literal = JSON.stringify;
  return `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "fixture", worker = (
    compatibilityDate = "2026-11-17",
    compatibilityFlags = ["global_fetch_strictly_public"],
    modules = [(name = "worker.mjs", esModule = embed "worker.mjs"),
               (name = "provider.mjs", esModule = embed "provider.mjs")],
    bindings = [(name = "ORIGIN", text = ${literal("http://" + listener)}),
                (name = "SPACES", service = "spaces"),
                (name = "SPACES_URL", text = ${literal("http://" + backend + "/mcp")}),
                (name = "BINDINGS", text = ${literal(bindings)}),
                (name = "BRIDGE_TOKEN", text = ${literal(bridgeToken ?? "")}),
                (name = "SIGNER", text = ${literal(signer ? literal(signer) : "")})]
  )), (name = "spaces", external = (address = ${literal(backend)}, http = ()) )],
  sockets = [(name = "http", address = ${literal(listener)}, http = (), service = "fixture")]
);
`;
}

// Stage only the two modules and the synthetic configuration in the
// harness's private, disposable directory.
export async function packagePreview({ directory, provider, ...inputs }) {
  const config = previewConfig(inputs);
  const path = join(directory, "fixture.capnp");
  await writeFile(path, config, { mode: 0o600, flag: "wx" });
  await copyFile(new URL("./worker.mjs", import.meta.url), join(directory, "worker.mjs"), constants.COPYFILE_EXCL);
  await copyFile(provider, join(directory, "provider.mjs"), constants.COPYFILE_EXCL);
  return path;
}
