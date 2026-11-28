import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { packagePreview, previewConfig } from "./preview-package.mjs";

const inputs = { listener: "127.0.0.1:1234", backend: "127.0.0.1:5678", bindings: "{}" };

test("refuses non-loopback addresses and malformed ports before writing a package", () => {
  for (const address of ["0.0.0.0:1234", "localhost:1234", "example.invalid:443", "127.0.0.1:0",
    "127.0.0.1:65536", "127.0.0.1:1\n", "127.0.0.1:001", "127.0.0.1:1/"]) {
    for (const field of ["listener", "backend"]) {
      assert.throws(() => previewConfig({ ...inputs, [field]: address }), /explicit IPv4 loopback port/);
    }
  }
  assert.throws(() => previewConfig({ ...inputs, backend: inputs.listener }), /must be distinct/);
  assert.throws(() => previewConfig({ ...inputs, bridgeToken: "synthetic" }), /requires both/);
  assert.throws(() => previewConfig({ ...inputs, signer: {} }), /requires both/);
  const signed = { ...inputs, bridgeToken: "disposable", signer: {} };
  assert.throws(() => previewConfig({ ...signed, ownerPds: "example.invalid:443" }), /Owner PDS/);
  const config = previewConfig({ ...signed, ownerPds: "127.0.0.1:9012" });
  assert.match(config, /https:\/\/127\.0\.0\.1:1234/);
  assert.match(config, /address = "127\.0\.0\.1:9012"/);
});

test("stages only the expected modules and a private, non-overwriting configuration", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-preview-package-"));
  try {
    const provider = join(directory, "source.mjs");
    await writeFile(provider, "export const fixture = true;\n");
    const path = await packagePreview({ directory, provider, ...inputs });
    assert.deepEqual((await readdir(directory)).sort(), ["fixture.capnp", "issuer-state", "provider.mjs", "source.mjs", "worker.mjs"]);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal(await readFile(path, "utf8"), previewConfig({ ...inputs, storage: join(directory, "issuer-state") }));
    assert.equal((await stat(join(directory, "issuer-state"))).mode & 0o777, 0o700);
    assert.match(await readFile(path, "utf8"), /http:\/\/127\.0\.0\.1:5678\/mcp/);
    await assert.rejects(packagePreview({ directory, provider, ...inputs }), { code: "EEXIST" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
