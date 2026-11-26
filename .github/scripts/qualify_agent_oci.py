"""Bind a locally qualified AMD64 image to its OCI archive; never extract or run it."""
import hashlib
import gzip
import json
import re
import sys
import tarfile

REVISION = "703c118c66277ca42c45808a2f6cc620429c6718"
DIGEST = re.compile(r"sha256:([a-f0-9]{64})\Z")


def stream_digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def load_receipt(path):
    with open(path, "rb") as source:
        raw = source.read(8193)
    if len(raw) > 8192:
        raise ValueError("Receipt byte limit")
    return json.loads(raw)


def qualify(archive, receipt):
    fields = {"version", "revision", "runtime", "platform", "capabilityVerified",
              "configDigest", "imageId", "dockerClientVersion"}
    if (type(receipt) is not dict or set(receipt) != fields
            or type(receipt.get("version")) is not int or receipt.get("version") != 1 or receipt.get("revision") != REVISION
            or receipt.get("runtime") != "agent-a2a"
            or receipt.get("platform") != "linux/amd64"
            or receipt.get("capabilityVerified") is not True
            or not isinstance(receipt.get("dockerClientVersion"), str)
            or not re.fullmatch(r"[0-9]{2,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][A-Za-z0-9.-]{1,32})?", receipt["dockerClientVersion"])
            or not DIGEST.fullmatch(receipt.get("configDigest", ""))
            or not DIGEST.fullmatch(receipt.get("imageId", ""))):
        raise ValueError("Qualification receipt refused")
    with tarfile.open(archive, "r:") as tar:
        members = {}
        for member in tar:
            if member.name in members:
                raise ValueError("Duplicate archive member")
            members[member.name] = member

        def read(name):
            member = members[name]
            if not member.isfile() or not 0 < member.size <= 2 * 1024 * 1024:
                raise ValueError("Bounded regular metadata required")
            return tar.extractfile(member).read()

        def blob(descriptor):
            match = DIGEST.fullmatch(descriptor["digest"])
            if not match:
                raise ValueError("Invalid OCI digest")
            raw = read("blobs/sha256/" + match[1])
            if len(raw) != descriptor["size"] or hashlib.sha256(raw).hexdigest() != match[1]:
                raise ValueError("OCI digest/size mismatch")
            return json.loads(raw)

        if json.loads(read("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("OCI layout refused")
        index = json.loads(read("index.json"))
        if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
            raise ValueError("Single image manifest required")
        descriptor = index["manifests"][0]
        if descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
            raise ValueError("Image manifest required")
        manifest = blob(descriptor)
        if manifest["config"].get("mediaType") != "application/vnd.oci.image.config.v1+json":
            raise ValueError("OCI config descriptor required")
        config = blob(manifest["config"])
        if (manifest.get("schemaVersion") != 2
                or manifest["config"]["digest"] != receipt["configDigest"]
                or receipt["imageId"] not in {receipt["configDigest"], descriptor["digest"]}
                or config.get("architecture") != "amd64" or config.get("os") != "linux"):
            raise ValueError("Export differs from qualified image")
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if config.get("rootfs", {}).get("type") != "layers" or len(diff_ids) != len(manifest["layers"]):
            raise ValueError("Qualified root filesystem required")
        for layer, diff_id in zip(manifest["layers"], diff_ids):
            if layer.get("mediaType") not in {"application/vnd.oci.image.layer.v1.tar",
                    "application/vnd.oci.image.layer.v1.tar+gzip"}:
                raise ValueError("OCI layer descriptor required")
            match = DIGEST.fullmatch(layer["digest"])
            if not match:
                raise ValueError("Layer digest refused")
            member = members["blobs/sha256/" + match[1]]
            if not member.isfile() or member.size != layer["size"]:
                raise ValueError("Layer size/type mismatch")
            stream = tar.extractfile(member)
            digest = stream_digest(stream)
            if digest != match[1]:
                raise ValueError("Layer digest mismatch")
            stream = tar.extractfile(member)
            if layer["mediaType"].endswith("+gzip"):
                stream = gzip.GzipFile(fileobj=stream)
            if "sha256:" + stream_digest(stream) != diff_id:
                raise ValueError("Layer differs from qualified root filesystem")
    with open(archive, "rb") as stream:
        archive_digest = stream_digest(stream)
    return {"version": 1, "revision": REVISION, "runtime": "agent-a2a",
            "platform": "linux/amd64", "manifestDigest": descriptor["digest"],
            "configDigest": receipt["configDigest"], "imageId": receipt["imageId"],
            "archiveSha256": archive_digest, "capabilityVerified": True,
            "registryPublished": False, "localVerification": receipt}


if __name__ == "__main__":
    report = qualify(sys.argv[1], load_receipt(sys.argv[2]))
    encoded = json.dumps(report, indent=2) + "\n"
    if len(encoded.encode("utf-8")) > 8192:
        raise ValueError("Output receipt byte limit")
    with open(sys.argv[3], "x") as output:
        output.write(encoded)
