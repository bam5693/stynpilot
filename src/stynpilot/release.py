"""Signed StyNpilot releases (standard library + ``cryptography``, which the package already depends on).

A release is a .deb plus a small MANIFEST that names it exactly (version, SHA-256, size, git commit, where it is
published) and a detached Ed25519 SIGNATURE over that manifest. The machine trusts only the public keys in
``/usr/share/stynpilot/release-keys.json`` (installed by a package it already trusts, root-owned), never a key
that arrives with a release. Verification here is deliberately strict and has no "skip" switch:

* the manifest has exactly the known fields, each in a narrow shape;
* the download address is not given by the manifest or the assistant: it is BUILT from the pinned repository
  and the validated tag and file name, so a signed manifest can only ever point at this project's releases;
* the signature must verify under one of the trusted keys (the key id is recorded and shown to the owner).

The signature proves the release came from the holder of a trusted key. It does not replace the owner's approval:
the owner still sees the version, the SHA-256 and the key on his phone and signs in to approve.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

SCHEMA = 1
PACKAGE = "stynpilot"
REPOSITORY = "bam5693/stynpilot"                 # the only place a release may be downloaded from
RELEASE_HOST = "github.com"
# GitHub serves release assets through its own CDN hosts after a redirect; nothing else is followed.
REDIRECT_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
KEYS_FILE = Path("/usr/share/stynpilot/release-keys.json")
DOMAIN = b"stynpilot-release-v1\n"
MAX_SIZE = 200 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192

_VERSION = re.compile(r"[0-9][A-Za-z0-9.+~-]{0,63}\Z")
_TAG = re.compile(r"v[0-9][A-Za-z0-9.-]{0,40}\Z")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,90}\.deb\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_NOTE = re.compile(r"[ -~]{1,160}\Z")
_FIELDS = {"schema", "package", "version", "tag", "asset", "sha256", "size", "git_commit", "from_min", "created",
           "notes"}


class ReleaseError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def canonical(manifest):
    return json.dumps(manifest, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def validate_manifest(manifest):
    """The manifest, if and only if it has exactly the expected shape. Returns it unchanged."""
    if type(manifest) is not dict or set(manifest) != _FIELDS:
        raise ReleaseError("manifest_invalid")

    def text(name, regex):
        value = manifest[name]
        if type(value) is not str or regex.fullmatch(value) is None:
            raise ReleaseError("manifest_invalid_" + name)
        return value

    if manifest["schema"] != SCHEMA or type(manifest["schema"]) is not int:
        raise ReleaseError("manifest_invalid_schema")
    if manifest["package"] != PACKAGE:
        raise ReleaseError("manifest_wrong_package")
    text("version", _VERSION)
    text("tag", _TAG)
    text("asset", _ASSET)
    text("sha256", _HEX64)
    text("git_commit", _HEX40)
    text("created", _STAMP)
    if manifest["from_min"] != "":
        text("from_min", _VERSION)
    size = manifest["size"]
    if type(size) is not int or not 1024 <= size <= MAX_SIZE:
        raise ReleaseError("manifest_invalid_size")
    notes = manifest["notes"]
    if type(notes) is not list or len(notes) > 6 or any(type(n) is not str or _NOTE.fullmatch(n) is None for n in notes):
        raise ReleaseError("manifest_invalid_notes")
    return manifest


def download_url(manifest):
    """Built here, from pinned parts. The manifest cannot name another host, repository or path."""
    validate_manifest(manifest)
    return "https://%s/%s/releases/download/%s/%s" % (RELEASE_HOST, REPOSITORY, manifest["tag"], manifest["asset"])


def manifest_urls(tag):
    if type(tag) is not str or _TAG.fullmatch(tag) is None:
        raise ReleaseError("invalid_release_tag")
    base = "https://%s/%s/releases/download/%s/" % (RELEASE_HOST, REPOSITORY, tag)
    return base + "release-manifest.json", base + "release-manifest.json.sig"


def tag_for_version(version):
    """The git tag a release is published under: v + the version with '~' written as '-'."""
    if type(version) is not str or _VERSION.fullmatch(version) is None:
        raise ReleaseError("invalid_version")
    return "v" + version.replace("~", "-")


# -- keys ------------------------------------------------------------------------------------------------------
def key_id(public_raw):
    return hashlib.sha256(public_raw).hexdigest()[:16]


def load_trusted_keys(path=KEYS_FILE):
    """{key_id: Ed25519PublicKey}. Each listed id must equal the hash of its key, or the file is refused whole."""
    try:
        data = json.loads(Path(path).read_text("utf-8"))
        keys = {}
        for item in data["keys"]:
            raw = base64.b64decode(item["public"], validate=True)
            if len(raw) != 32 or item["key_id"] != key_id(raw):
                raise ValueError("key id mismatch")
            keys[item["key_id"]] = Ed25519PublicKey.from_public_bytes(raw)
    except (OSError, ValueError, KeyError, TypeError):
        raise ReleaseError("trusted_keys_unreadable") from None
    if not keys:
        raise ReleaseError("no_trusted_keys")
    return keys


def public_entry(private_key):
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"key_id": key_id(raw), "public": base64.b64encode(raw).decode("ascii")}


def sign(manifest, private_key):
    """Detached signature (base64 text) over the validated manifest. Used by the release tool, not on the machine."""
    validate_manifest(manifest)
    return base64.b64encode(private_key.sign(DOMAIN + canonical(manifest))).decode("ascii")


def verify(manifest, signature, trusted):
    """Raise ReleaseError unless ``signature`` is valid for ``manifest`` under a trusted key. Returns the key id."""
    validate_manifest(manifest)
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        raise ReleaseError("signature_malformed") from None
    if len(raw) != 64:
        raise ReleaseError("signature_malformed")
    message = DOMAIN + canonical(manifest)
    for kid, public in sorted(trusted.items()):
        try:
            public.verify(raw, message)
            return kid
        except InvalidSignature:
            continue
    raise ReleaseError("signature_not_trusted")


def new_private_key():
    return Ed25519PrivateKey.generate()


def load_private_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def private_pem(private_key):
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())


def summary_lines(manifest, key, installed=None):
    """Plain-English owner text for an upgrade. Produced on the root side from the verified manifest."""
    lines = ["Upgrade StyNpilot%s to version %s." % (" from %s" % installed if installed else "", manifest["version"]),
             "Package SHA-256: %s" % manifest["sha256"],
             "Built from source commit %s; signed by release key %s." % (manifest["git_commit"][:12], key),
             "Downloaded from %s/%s only (the address is fixed in StyNpilot, not chosen by an assistant)."
             % (RELEASE_HOST, REPOSITORY)]
    lines += ["Release note: " + note for note in manifest["notes"]]
    lines.append("Before changing anything StyNpilot saves its own records and a full copy of the current version. "
                 "It then installs the new version, restarts itself (about a minute), and checks that it works. "
                 "If the checks fail it automatically puts the current version back.")
    lines.append("This only replaces StyNpilot's own program files. Your settings, approvals and sign-in setup are "
                 "not touched. The package has no install scripts.")
    return lines


# -- download ----------------------------------------------------------------------------------------------------
def https_get(url, max_bytes, *, timeout=60, opener=None):
    """Fetch ``url`` over HTTPS from the pinned release host (following redirects only to GitHub's own file hosts).
    Refuses anything larger than ``max_bytes``. Raises ReleaseError; never returns partial data."""
    import urllib.error
    import urllib.parse
    import urllib.request

    def allowed(address):
        parts = urllib.parse.urlsplit(address)
        return parts.scheme == "https" and parts.hostname in REDIRECT_HOSTS and parts.username is None and parts.port in (None, 443)

    if not allowed(url) or urllib.parse.urlsplit(url).hostname != RELEASE_HOST:
        raise ReleaseError("download_address_not_allowed")

    class Guard(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not allowed(newurl):
                raise ReleaseError("download_redirect_not_allowed")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = opener or urllib.request.build_opener(Guard)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "stynpilot-release"}), timeout=timeout) as reply:
            declared = reply.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ReleaseError("download_too_large")
            data = reply.read(max_bytes + 1)
    except ReleaseError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise ReleaseError("download_failed") from None
    if len(data) > max_bytes:
        raise ReleaseError("download_too_large")
    return data
