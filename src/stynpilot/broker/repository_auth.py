"""Passkey-granted private repository access and GitLab device flow.

The root broker is the only process that opens the credential records. The
provider adapter gets a fixed URL from the installation configuration, never
an OAuth endpoint or repository URL supplied by an assistant.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from urllib import error, parse, request

from .. import repo_archive, vault

ACTIONS = frozenset({"repository_authorize", "repository_revoke", "repository_suspend", "repository_resume"})
OPERATIONS = ("read", "fetch")
_ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_REQUEST = re.compile(r"[a-f0-9]{64}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_VALUE = re.compile(r"[A-Za-z0-9._~+\-/=]{16,1024}\Z")
MAX_STATE = 512 << 10
MAX_GRANTS = 64
SIGN_IN_SECONDS = 600


class AuthorizationError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FetchLease:
    """Broker-only authorization for a bounded asynchronous native fetch."""
    request_id: str
    client: str
    repository: str
    source: tuple[str, str]
    expires: int
    epoch: int
    credential: tuple[str, str] = field(repr=False)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _gitlab_http(endpoint, data=None, bearer=None):
    if endpoint not in {"/oauth/authorize_device", "/oauth/token", "/oauth/token/info"}:
        raise AuthorizationError("repository_provider_endpoint_invalid")
    headers = {"Accept": "application/json"}
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    body = None if data is None else parse.urlencode(data).encode("ascii")
    opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
    try:
        try:
            response = opener.open(request.Request("https://gitlab.com" + endpoint, data=body, headers=headers), timeout=8)
        except error.HTTPError as failure:
            response = failure
        with response:
            raw = response.read(32769)
            if len(raw) > 32768:
                raise ValueError
            value = json.loads(raw)
            if type(value) is not dict:
                raise ValueError
    except (OSError, ValueError, TimeoutError):
        raise AuthorizationError("repository_provider_unavailable") from None
    return response.code, value


def _valid(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


class GitLab:
    scope = "read_repository"

    def __init__(self, http=_gitlab_http):
        self.http = http

    def start(self, target):
        status, row = self.http("/oauth/authorize_device", {"client_id": target["application"], "scope": self.scope})
        device = row.get("device_code")
        url = row.get("verification_uri_complete")
        expires = row.get("expires_in")
        interval = row.get("interval")
        if (status != 200 or not _valid(_VALUE, device) or type(url) is not str or len(url) > 1024
                or type(expires) is not int or not 1 <= expires <= SIGN_IN_SECONDS
                or type(interval) is not int or not 1 <= interval <= 60):
            raise AuthorizationError("repository_guided_sign_in_unavailable")
        parsed = parse.urlsplit(url)
        params = parse.parse_qs(parsed.query, max_num_fields=2)
        code = params.get("user_code", [])
        if (parsed.scheme != "https" or parsed.netloc != "gitlab.com" or parsed.path != "/oauth/device" or parsed.fragment
                or set(params) != {"user_code"} or len(code) != 1 or code[0] != row.get("user_code")
                or not _valid(re.compile(r"[A-Z0-9-]{6,24}\Z"), code[0])):
            raise AuthorizationError("repository_guided_sign_in_unavailable")
        return {"device_code": device, "url": url, "interval": interval, "expires_in": expires}

    def poll(self, target, code):
        status, result = self.http("/oauth/token", {"client_id": target["application"], "device_code": code,
                                   "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
        if status != 200:
            kind = result.get("error")
            if kind in ("authorization_pending", "slow_down"):
                return kind, None
            raise AuthorizationError("repository_provider_authorization_refused")
        return "connected", self._verify(target, result)

    def renew(self, target, refresh):
        status, result = self.http("/oauth/token", {"client_id": target["application"], "refresh_token": refresh,
                                   "grant_type": "refresh_token"})
        if status != 200:
            raise AuthorizationError("repository_renewal_requires_sign_in")
        return self._verify(target, result)

    def _verify(self, target, result):
        access, refresh, expiry = result.get("access_token"), result.get("refresh_token"), result.get("expires_in")
        if (not _valid(_VALUE, access) or not _valid(_VALUE, refresh)
                or str(result.get("token_type", "")).lower() != "bearer"
                or type(expiry) is not int or not 1 <= expiry <= 86400):
            raise AuthorizationError("repository_provider_credential_invalid")
        status, info = self.http("/oauth/token/info", bearer=access)
        application = info.get("application")
        if (status != 200 or info.get("scope") != [self.scope] or type(application) is not dict
                or application.get("uid") != target["application"] or type(info.get("resource_owner_id")) is not int
                or info["resource_owner_id"] != target["principal"]):
            raise AuthorizationError("repository_provider_scope_mismatch")
        return {"access": access, "refresh": refresh, "expires_in": expiry}

    def probe(self, source, credential):
        origin = repo_archive.source_origin(*source)["url"]
        authorization = base64.b64encode(":".join(credential).encode("ascii")).decode("ascii")
        url = origin + "/info/refs?service=git-upload-pack"
        opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(request.Request(url, headers={"Authorization": "Basic " + authorization}), timeout=8) as reply:
                allowed = (reply.status == 200 and reply.headers.get_content_type() == "application/x-git-upload-pack-advertisement"
                           and reply.read(30) == b"001e# service=git-upload-pack\n")
        except (OSError, TimeoutError):
            allowed = False
        if not allowed:
            raise AuthorizationError("repository_provider_read_refused")
        return {"readable": True}


def load_targets(path):
    """Load administrator-attested one-project identities from the fixed private config."""
    try:
        rows = json.loads(vault._read_private(path, 16384))
    except FileNotFoundError:
        return {}
    if type(rows) is not dict or len(rows) > 16:
        raise AuthorizationError("repository_provider_config_invalid")
    principals, origins = set(), set()
    for name, target in rows.items():
        if (not _valid(_ID, name) or type(target) is not dict
                or set(target) != {"provider", "origin", "application", "principal"}
                or target["provider"] != "gitlab" or not _valid(_REQUEST, target["application"])
                or type(target["principal"]) is not int or target["principal"] < 1 or target["principal"] in principals):
            raise AuthorizationError("repository_provider_config_invalid")
        repo_archive.source_origin(target["provider"], target["origin"])
        if target["origin"] in origins:
            raise AuthorizationError("repository_provider_config_invalid")
        origins.add(target["origin"])
        principals.add(target["principal"])
    return rows


class Store:
    def __init__(self, state, targets, *, provider=None, clock=time.time):
        self.root, self.targets, self.provider, self.clock = Path(state) / "repository-authorization", targets, provider or GitLab(), clock

    @contextmanager
    def _state(self):
        self.root.mkdir(mode=0o700, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise AuthorizationError("repository_state_untrusted")
        lock = os.open(self.root / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise AuthorizationError("repository_state_untrusted")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AuthorizationError("repository_authorization_busy") from None
            try:
                state = json.loads(vault._read_private(self.root / "grants.json", MAX_STATE))
            except FileNotFoundError:
                if os.fstat(lock).st_size:
                    raise AuthorizationError("repository_state_untrusted") from None
                state = {"suspended": False, "grants": {}, "epoch": 0}
                self._save(state)
                os.write(lock, b"provisioned\n")
                os.fsync(lock)
            if (type(state) is not dict or set(state) not in ({"suspended", "grants"}, {"suspended", "grants", "epoch"})
                    or type(state["suspended"]) is not bool
                    or type(state["grants"]) is not dict or len(state["grants"]) > MAX_GRANTS):
                raise AuthorizationError("repository_state_untrusted")
            epoch = state.setdefault("epoch", 0)
            if type(epoch) is not int or not 0 <= epoch < 2**63 - 1:
                raise AuthorizationError("repository_state_untrusted")
            # Every consumer sheds expired credentials before reading the store.
            self._purge_expired(state, int(self.clock()))
            yield state
        finally:
            os.close(lock)

    def purge_expired(self):
        """Maintenance entry point. Do not initialize state until first use."""
        if self.root.exists():
            with self._state():
                pass

    def _purge_expired(self, state, now):
        changed = False
        for key, row in list(state["grants"].items()):
            if type(row) is not dict or type(row.get("expires")) is not int:
                raise AuthorizationError("repository_state_untrusted")
            if row["expires"] <= now:
                del state["grants"][key]
                changed = True
            elif row.get("state") in ("approved", "connecting"):
                until = row.get("connect_until")
                if type(until) is not int:
                    raise AuthorizationError("repository_state_untrusted")
                if until <= now:
                    self._clear_session(row, "sign_in_expired")
                    changed = True
        if changed:
            self._save(state)

    def _save(self, state):
        data = json.dumps(state, sort_keys=True).encode()
        if len(data) > MAX_STATE:
            raise AuthorizationError("repository_grant_limit")
        vault._write_atomic(self.root, "grants.json", data)

    def target(self, repository):
        target = self.targets.get(repository) if _valid(_ID, repository) else None
        if target is None:
            raise AuthorizationError("repository_provider_not_configured")
        return target

    def describe(self, repository):
        target = self.target(repository)
        binding = hashlib.sha256(json.dumps(target, sort_keys=True).encode()).hexdigest()
        return {"origin": target["origin"], "authorization_profile": binding}

    def validate(self, action, client, repository, operations, days):
        if not _valid(_CLIENT, client) or action not in ACTIONS or type(operations) is not list or type(days) is not int:
            raise AuthorizationError("repository_grant_invalid")
        if action in ("repository_authorize", "repository_revoke"):
            self.target(repository)
        elif repository != "":
            raise AuthorizationError("repository_grant_invalid")
        if action == "repository_authorize":
            if operations not in (["read"], ["fetch"], ["read", "fetch"]) or not 1 <= days <= 30:
                raise AuthorizationError("repository_operation_not_supported")
        elif operations or days:
            raise AuthorizationError("repository_grant_invalid")

    def apply(self, action, client, repository, operations, days, rid):
        self.validate(action, client, repository, operations, days)
        with self._state() as state:
            grants = state["grants"]
            now = int(self.clock())
            if action == "repository_suspend":
                state["suspended"] = True
                state["epoch"] += 1
                # A suspended OAuth handoff can never become active afterwards.
                for key in [key for key, row in grants.items() if row["state"] != "active"]:
                    del grants[key]
            elif action == "repository_resume":
                state["suspended"] = False
            elif action == "repository_revoke":
                for key in [key for key, row in grants.items() if row["repository"] == repository and row["client"] == client]:
                    del grants[key]
            else:
                self._enabled(state)
                for key in [key for key, row in grants.items() if row["expires"] <= now
                            or (row["repository"] == repository and row["client"] == client and row["state"] != "active")]:
                    del grants[key]
                if len(grants) >= MAX_GRANTS or not _valid(_REQUEST, rid):
                    raise AuthorizationError("repository_grant_limit")
                source = self.target(repository)
                grants[rid] = {"client": client, "repository": repository, "operations": operations,
                               "expires": now + 86400 * days, "connect_until": now + SIGN_IN_SECONDS,
                               "source": source, "state": "approved"}
            self._save(state)
            return {"ok": True, "action": action, "repository": repository,
                    "state": "connect_required" if action == "repository_authorize" else "done"}

    @staticmethod
    def _enabled(state):
        if state["suspended"]:
            raise AuthorizationError("repository_access_suspended")

    def status(self, client):
        with self._state() as state:
            now = int(self.clock())
            rows = [{key: row[key] for key in ("repository", "operations", "expires", "state")}
                    for row in state["grants"].values() if row["client"] == client and row["expires"] > now]
            return {"suspended": state["suspended"], "grants": rows}

    def connect(self, rid, poll):
        if not _valid(_REQUEST, rid) or type(poll) is not bool:
            raise AuthorizationError("repository_sign_in_invalid")
        with self._state() as state:
            self._enabled(state)
            row = state["grants"].get(rid)
            now = int(self.clock())
            if row is None or now >= row["expires"] or row["source"] != self.target(row["repository"]):
                raise AuthorizationError("repository_grant_unavailable")
            if row["state"] == "active":
                return {"state": "connected"}
            if row["state"] not in ("approved", "connecting") or now >= row["connect_until"]:
                raise AuthorizationError("repository_sign_in_expired")
            if row["state"] == "approved" and not poll:
                device = self.provider.start(row["source"])
                row.update(device, state="connecting", next_poll=now + device["interval"],
                           connect_until=min(row["connect_until"], now + device["expires_in"]))
                self._save(state)
            if row["state"] != "connecting":
                raise AuthorizationError("repository_sign_in_not_started")
            if not poll or now < row["next_poll"]:
                return {"state": "waiting", "url": row["url"]}
            row["next_poll"] = now + row["interval"]
            self._save(state)
            try:
                outcome, credential = self.provider.poll(row["source"], row["device_code"])
            except AuthorizationError:
                self._clear_session(row, "sign_in_failed")
                self._save(state)
                raise
            if outcome == "connected":
                self._clear_session(row, "active")
                row.update(credential=credential, token_until=int(self.clock()) + credential["expires_in"])
                grants = state["grants"]
                for key in [key for key, previous in grants.items() if key != rid and previous["client"] == row["client"]
                            and previous["repository"] == row["repository"]]:
                    del grants[key]
            elif outcome == "slow_down":
                row["interval"] += 5
                row["next_poll"] += 5
            self._save(state)
            return {"state": "connected"} if outcome == "connected" else {"state": "waiting", "url": row["url"]}

    @staticmethod
    def _clear_session(row, status):
        for key in ("device_code", "url", "interval", "expires_in", "next_poll", "connect_until"):
            row.pop(key, None)
        row["state"] = status

    def _grant(self, state, client, repository, operation, *, request_id=None):
        self._enabled(state)
        if operation not in OPERATIONS:
            raise AuthorizationError("repository_operation_not_supported")
        target, now = self.target(repository), int(self.clock())
        for rid, row in state["grants"].items():
            if ((request_id is None or rid == request_id) and row["client"] == client
                    and row["repository"] == repository and row["state"] == "active"
                    and row["source"] == target and row["expires"] > now and operation in row["operations"]):
                return rid, row, target
        raise AuthorizationError("repository_grant_unavailable")

    def _credential(self, state, row, target, *, seconds=60):
        if row["token_until"] <= int(self.clock()) + seconds:
            refresh = row.pop("credential")["refresh"]
            row["state"] = "renewal_uncertain"
            self._save(state)
            credential = self.provider.renew(target, refresh)
            row.update(state="active", credential=credential, token_until=int(self.clock()) + credential["expires_in"])
            self._save(state)
        return ("oauth2", row["credential"]["access"])

    def use(self, client, repository, operation, consumer):
        """Invoke a broker-owned typed consumer; no RPC ever returns a credential."""
        with self._state() as state:
            _, row, target = self._grant(state, client, repository, operation)
            return consumer((target["provider"], target["origin"]), self._credential(state, row, target))

    def archive_read(self, client, repository, profile, source):
        try:
            with self._state() as state:
                _, _, target = self._grant(state, client, repository, "read")
                return {"allowed": (profile == self.describe(repository)["authorization_profile"]
                                    and source == {"provider": target["provider"], "url": target["origin"]})}
        except AuthorizationError:
            return {"allowed": False}

    def begin_fetch(self, client, repository, *, seconds):
        """Release the grant store lock before starting network IO."""
        if type(seconds) is not int or not 1 <= seconds <= 600:
            raise AuthorizationError("repository_fetch_deadline_invalid")
        with self._state() as state:
            rid, row, target = self._grant(state, client, repository, "fetch")
            minimum = int(self.clock()) + seconds
            if minimum >= row["expires"]:
                raise AuthorizationError("repository_fetch_grant_expires_too_soon")
            credential = self._credential(state, row, target, seconds=max(60, seconds))
            if row["token_until"] <= minimum:
                raise AuthorizationError("repository_fetch_grant_expires_too_soon")
            return FetchLease(rid, client, repository, (target["provider"], target["origin"]),
                              minimum, state["epoch"], credential)

    def check_fetch(self, lease):
        """Refuse publication if the original exact grant, credential or deadline changed."""
        with self._state() as state:
            _, row, target = self._grant(state, lease.client, lease.repository, "fetch", request_id=lease.request_id)
            if ((target["provider"], target["origin"]) != lease.source or lease.expires <= int(self.clock())
                    or state["epoch"] != lease.epoch
                    or not secrets.compare_digest(row["credential"]["access"], lease.credential[1])):
                raise AuthorizationError("repository_fetch_grant_changed")
    def probe(self, client, repository):
        return self.use(client, repository, "read", self.provider.probe)
