"""Bind a locally qualified AMD64 image to its OCI archive; never extract or run it."""
import hashlib
import json
import re
import sys
import tarfile

REVISION = "8fb5949c400018146ef58e594697859403c0d247"
DIGEST = re.compile(r"sha256:([a-f0-9]{64})\Z")


def stream_digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def qualify(archive, receipt):
    if (receipt.get("version") != 1 or receipt.get("revision") != REVISION
            or receipt.get("runtime") != "agent-a2a"
            or receipt.get("platform") != "linux/amd64"
            or receipt.get("capabilityVerified") is not True
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
        for layer in manifest["layers"]:
            if layer.get("mediaType") not in {"application/vnd.oci.image.layer.v1.tar",
                    "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"}:
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
    with open(archive, "rb") as stream:
        archive_digest = stream_digest(stream)
    return {"version": 1, "revision": REVISION, "runtime": "agent-a2a",
            "platform": "linux/amd64", "manifestDigest": descriptor["digest"],
            "configDigest": receipt["configDigest"], "imageId": receipt["imageId"],
            "archiveSha256": archive_digest, "capabilityVerified": True,
            "registryPublished": False}


if __name__ == "__main__":
    report = qualify(sys.argv[1], json.load(open(sys.argv[2])))
    with open(sys.argv[3], "x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
