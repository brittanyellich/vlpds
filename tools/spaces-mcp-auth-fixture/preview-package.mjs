import { constants } from "node:fs";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

function requireLoopback(address, label) {
  const match = /^127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(address);
  if (!match || Number(match[1]) > 65535) {
    throw new Error(`${label} must use an explicit IPv4 loopback port`);
  }
}

export function previewConfig({ listener, backend, bindings, bridgeToken, signer, ownerPds, ownerPdsOrigin, fixtureTests = true, enrollmentRelay = false, storage = "./issuer-state" }) {
  requireLoopback(listener, "Listener");
  requireLoopback(backend, "Spaces backend");
  if (listener === backend) throw new Error("Listener and Spaces backend must be distinct");
  if (Boolean(bridgeToken) !== Boolean(signer)) throw new Error("Signed dispatch requires both fixture inputs");

  if (signer) requireLoopback(ownerPds, "Owner PDS");
  const literal = JSON.stringify;
  const protocol = signer ? "https" : "http";
  const socket = signer
    ? 'options = (), tlsOptions = (keypair = (privateKey = embed "issuer-key.pem", certificateChain = embed "issuer-cert.pem"))'
    : "";
  return `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "fixture", worker = (
    compatibilityDate = "2026-11-17",
    compatibilityFlags = ["global_fetch_strictly_public"],
    modules = [(name = "worker.mjs", esModule = embed "worker.mjs"),
               (name = "provider.mjs", esModule = embed "provider.mjs")],
    durableObjectNamespaces = [(className = "PreviewIssuerStorage", uniqueKey = "exp711-preview-issuer")],
    durableObjectStorage = (localDisk = "issuer-disk"),
    bindings = [(name = "PREVIEW_MODE", text = ${literal(signer ? "isolated" : "fixture")}),
                (name = "ENROLLMENT_RELAY", text = ${literal(String(enrollmentRelay))}),
                (name = "FIXTURE_TESTS", text = ${literal(String(fixtureTests))}),
                (name = "ISSUER_STORAGE", durableObjectNamespace = "PreviewIssuerStorage"),
                (name = "ORIGIN", text = ${literal(protocol + "://" + listener)}),
                (name = "SPACES", service = "spaces"),
                (name = "SPACES_URL", text = ${literal("http://" + backend + "/mcp")}),
                (name = "BINDINGS", text = ${literal(bindings)}),
                (name = "BRIDGE_TOKEN", text = ${literal(bridgeToken ?? "")}),
                (name = "SIGNER", text = ${literal(signer ? literal(signer) : "")})${signer
                  ? `, (name = "OWNER_PDS", service = "owner-pds"), (name = "OWNER_PDS_ORIGIN", text = ${literal(ownerPdsOrigin ?? "http://" + ownerPds)})`
                  : ""}]
  )), (name = "issuer-disk", disk = (path = ${literal(storage)}, writable = true)),
      (name = "spaces", external = (address = ${literal(backend)}, http = ()) )${signer ? `, (name = "owner-pds", external = (address = ${literal(ownerPds)}, http = ()))` : ""}],
  sockets = [(name = "http", address = ${literal(listener)}, ${protocol} = (${socket}), service = "fixture")]
);
`;
}

// Stage only the two modules and the synthetic configuration in the
// harness's private, disposable directory.
export async function packagePreview({ directory, provider, ...inputs }) {
  const storage = join(directory, "issuer-state");
  const config = previewConfig({ ...inputs, storage });
  const path = join(directory, "fixture.capnp");
  await writeFile(path, config, { mode: 0o600, flag: "wx" });
  await mkdir(storage, { mode: 0o700 });
  await copyFile(new URL("./worker.mjs", import.meta.url), join(directory, "worker.mjs"), constants.COPYFILE_EXCL);
  await copyFile(provider, join(directory, "provider.mjs"), constants.COPYFILE_EXCL);
  return path;
}
