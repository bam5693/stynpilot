"""Packaged service entry points (G6): the owner-side service and the root installer, assembled from one
private config file each. Nothing here touches Auth0, Tailscale, Cloudflare, the pairing database or any
live setting: it only reads the values the owner put in the config and starts local listeners.

Owner service start order (the order is the point):
  1. state folder checked private; the client-revocation file is created ONCE on first run only
  2. request store opened
  3. restart reconciliation: every request left approved/running is settled from the root installer's own
     durable record (never retried, never reported as "nothing changed" unless the record proves it)
  4. only then does the approval page start listening (127.0.0.1 only; the owner's HTTPS proxy fronts it)
The approval worker is the single background thread inside ApprovalFlow(background=True).
"""
from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .approval import ApprovalFlow
from .broker import apt
from .requests import RequestStore
from .server import run
from .server.clients import RevocationFile
from .server.oidc import https_origin

_MAX_CONFIG = 16 * 1024
OWNER_KEYS = {"issuer", "approval_client_id", "authorize_endpoint", "token_endpoint", "approval_public_host",
              "approval_port", "state_dir", "broker_socket"}
INSTALLER_KEYS = {"issuer", "approval_client_id", "owner", "device", "owner_uid", "state_dir", "socket_path"}


class ConfigError(ValueError):
    pass


def read_private_json(path, keys):
    """A config file the owner (or root) wrote: regular file, ours, not group/world readable, exact keys."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ConfigError("config_unreadable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ConfigError("config_must_be_a_private_file_owned_by_the_service_user")
        if info.st_size > _MAX_CONFIG:
            raise ConfigError("config_too_large")
        try:
            data = json.loads(os.read(fd, _MAX_CONFIG + 1).decode("utf-8"))
        except (ValueError, UnicodeError):
            raise ConfigError("config_not_valid_json") from None
    finally:
        os.close(fd)
    if type(data) is not dict or set(data) != keys:
        raise ConfigError("config_has_unexpected_or_missing_fields")
    return data


def _abs(value, field):
    if type(value) is not str or not Path(value).is_absolute():
        raise ConfigError("%s_must_be_an_absolute_path" % field)
    return Path(value)


@dataclass(frozen=True)
class OwnerConfig:
    issuer: str
    approval_client_id: str
    authorize_endpoint: str
    token_endpoint: str
    approval_public_host: str
    approval_port: int
    state_dir: Path
    broker_socket: Path

    @classmethod
    def from_file(cls, path):
        return cls.from_dict(read_private_json(path, OWNER_KEYS))

    @classmethod
    def from_dict(cls, data):
        try:
            origin = https_origin(data["issuer"])
            for field in ("authorize_endpoint", "token_endpoint"):
                if https_origin(data[field]) != origin:
                    raise ConfigError("%s_must_stay_on_the_issuer" % field)
            host = run.check_approval_host(data["approval_public_host"])
        except ConfigError:
            raise
        except (ValueError, KeyError):
            raise ConfigError("config_value_invalid") from None
        port = data["approval_port"]
        if type(port) is not int or isinstance(port, bool) or not 1024 < port <= 65535:
            raise ConfigError("approval_port_must_be_unprivileged")
        if type(data["approval_client_id"]) is not str or not data["approval_client_id"]:
            raise ConfigError("approval_client_id_required")
        return cls(data["issuer"], data["approval_client_id"], data["authorize_endpoint"], data["token_endpoint"],
                   host, port, _abs(data["state_dir"], "state_dir"), _abs(data["broker_socket"], "broker_socket"))

    @property
    def redirect_uri(self):
        return "https://%s/approve/callback" % self.approval_public_host


@dataclass
class OwnerService:
    flow: ApprovalFlow
    approval: object
    recovered: list
    revocations_created: bool

    def stop(self):
        self.approval.stop()
        if self.flow._pool is not None:
            self.flow._pool.shutdown(wait=True)


def start_owner_service(config, *, broker=None, exchange=None, start_listener=None, clock=time.time):
    """Assemble and start the owner side. ``broker``/``exchange``/``start_listener`` are injectable for tests."""
    from .approval_web import token_exchange
    from .broker.service import BrokerClient
    state = config.state_dir
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(state)
    if state.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ConfigError("state_dir_must_be_private_and_owned_by_the_service_user")
    store_path, revoked_path = state / "requests.sqlite3", state / "revoked-clients.json"
    revocations, created = RevocationFile(state / "revoked-clients.json"), False
    if not store_path.exists():
        created = revocations.provision()                  # first run only: empty list, created once, 0600
    elif not revoked_path.exists():
        # A previous run existed but the list is gone: re-creating it empty could silently re-admit a revoked
        # AI client. Refuse to start; the owner re-provisions deliberately and re-revokes anyone who must stay out.
        raise ConfigError("revocation_list_missing_owner_must_reprovision")
    revocations.revoked()                                  # must be readable and trusted, or we don't start
    store = RequestStore(store_path, clock=clock)
    flow = ApprovalFlow(store=store, broker=broker or BrokerClient(config.broker_socket),
                        exchange=exchange or token_exchange(token_endpoint=config.token_endpoint,
                                                            client_id=config.approval_client_id,
                                                            redirect_uri=config.redirect_uri),
                        authorize={"endpoint": config.authorize_endpoint, "client_id": config.approval_client_id,
                                   "redirect_uri": config.redirect_uri},
                        clock=clock, background=True)
    recovered = flow.recover()                             # settle anything left over BEFORE accepting decisions
    try:
        listener = (start_listener or run.start_approval)(flow=flow, public_host=config.approval_public_host,
                                                          port=config.approval_port)
    except Exception:
        flow._pool.shutdown(wait=False)
        raise
    return OwnerService(flow, listener, recovered, created)


# ---------------------------------------------------------------------------------------------------- root
@dataclass(frozen=True)
class InstallerConfig:
    issuer: str
    approval_client_id: str
    owner: str
    device: str
    owner_uid: int
    state_dir: Path
    socket_path: Path

    @classmethod
    def from_file(cls, path):
        return cls.from_dict(read_private_json(path, INSTALLER_KEYS))

    @classmethod
    def from_dict(cls, data):
        try:
            https_origin(data["issuer"])
        except (ValueError, KeyError):
            raise ConfigError("config_value_invalid") from None
        for field in ("approval_client_id", "owner", "device"):
            if type(data[field]) is not str or not data[field]:
                raise ConfigError("%s_required" % field)
        uid = data["owner_uid"]
        if type(uid) is not int or isinstance(uid, bool) or uid < 1000:
            raise ConfigError("owner_uid_must_be_a_normal_user")
        return cls(data["issuer"], data["approval_client_id"], data["owner"], data["device"], uid,
                   _abs(data["state_dir"], "state_dir"), _abs(data["socket_path"], "socket_path"))


def fetch_jwks(issuer, fetch=None):
    """The issuer's signing keys, fetched once at installer start from its own HTTPS origin (strict discovery)."""
    from .server.oidc import OIDCConfig, jwks_uri_from_discovery

    class _Durable:
        durable = True

        @staticmethod
        def revoked_before(*_):
            return None
    cfg = OIDCConfig(issuer=issuer, audience="installer", revocations=_Durable(), allowed_scopes=frozenset(),
                     fetch=fetch)
    discovery = cfg._fetch(issuer.rstrip("/") + "/.well-known/openid-configuration")
    return cfg._fetch(jwks_uri_from_discovery(issuer, discovery))


def build_installer(config, *, jwks, run_command=apt.real_run, require_root=True, **executor_options):
    """The root installer and its socket. Creating the Executor marks any run left 'running' by a crash as
    needing the owner and blocks new installs until the owner has checked."""
    from .broker.executor import Executor
    from .broker.proof import ProofVerifier
    from .broker.service import BrokerService
    verifier = ProofVerifier(issuer=config.issuer, approval_client_id=config.approval_client_id, jwks=jwks)
    executor = Executor(state_dir=config.state_dir, owner=config.owner, device=config.device, verifier=verifier,
                        run=run_command, require_root=require_root, **executor_options)
    return BrokerService(socket_path=config.socket_path, executor=executor, allowed_uid=config.owner_uid)


def main(argv=None):                                       # pragma: no cover - thin process wrapper
    import argparse
    import signal
    import threading
    parser = argparse.ArgumentParser(prog="stynpilot-service")
    parser.add_argument("role", choices=("owner", "installer"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    if args.role == "installer":
        config = InstallerConfig.from_file(args.config)
        service = build_installer(config, jwks=fetch_jwks(config.issuer))
        service.serve_forever()
        return 0
    config = OwnerConfig.from_file(args.config)
    service = start_owner_service(config)
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    done.wait()
    service.stop()
    return 0


if __name__ == "__main__":                                 # pragma: no cover
    raise SystemExit(main())
