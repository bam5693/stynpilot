#!/usr/bin/env python3
"""Make the signed release files for a built package (run by the release builder, never on the owner's computer).

  tools/sign_release.py dist/stynpilot_0.1.0~dev5_all.deb --commit <40 hex> --key ~/.stynpilot-release/release-ed25519.pem \
      --out release-out [--from-min 0.1.0~dev4] [--note "text" ...]

Writes into --out: the package under its public asset name, release-manifest.json and release-manifest.json.sig.
Upload exactly those three files to the GitHub release tagged v<version with ~ as ->. The machine accepts a release
only if the signature verifies under a key already installed on it.
"""
import argparse
import datetime
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from stynpilot import release  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("deb")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--from-min", default="")
    parser.add_argument("--note", action="append", default=[])
    args = parser.parse_args(argv)
    deb = Path(args.deb)
    version = subprocess.run(["dpkg-deb", "-f", str(deb), "Version"], check=True, capture_output=True, text=True).stdout.strip()
    tag = release.tag_for_version(version)
    data = deb.read_bytes()
    manifest = {"schema": release.SCHEMA, "package": release.PACKAGE, "version": version, "tag": tag,
                "asset": "stynpilot-%s.deb" % tag, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                "git_commit": args.commit, "from_min": args.from_min,
                "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "notes": args.note}
    signature = release.sign(manifest, release.load_private_key(args.key))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(deb, out / manifest["asset"])
    (out / "release-manifest.json").write_text(__import__("json").dumps(manifest, sort_keys=True, indent=1) + "\n")
    (out / "release-manifest.json.sig").write_text(signature + "\n")
    print("signed %s (tag %s, sha256 %s)" % (version, tag, manifest["sha256"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
