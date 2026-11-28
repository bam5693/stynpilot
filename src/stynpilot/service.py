"""Packaged service entry points (G6): the owner-side service and the root installer, assembled from one
private config file each. Nothing here touches Auth0, Tailscale, Cloudflare, the pairing database or any
live setting: it only reads the values the owner put in the config and starts local listeners.

Owner service start order (the order is the point):
  0. state is created ONLY by the explicit owner command ``provision`` (never by a normal start, never by an
     AI): if any of the provisioned files is missing the service refuses to start, so lost state can't
     silently turn into a pristine one that re-admits revoked AI clients
  1. state folder checked private; revocation list and request store opened (fail closed)
  2. restart reconciliation, PATIENT: a request left approved/running is settled from the root installer's own
     durable record. If the installer simply isn't up yet (or says the run is still going) the request is left
     as it is and retried in the background; only a long outage is reported, honestly, as "owner must verify".
     Nothing is ever replayed.
  3. the approval page (127.0.0.1 only; the owner's HTTPS proxy fronts it), then the AI-facing MCP endpoint
     (also 127.0.0.1) which can only FILE requests; it has no way to approve, deny or run anything.
The approval worker is the single background thread inside ApprovalFlow(background=True).
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .approval import ApprovalFlow
from . import release
from .broker import apt
from .requests import RequestStore
from .server import run
from .server.clients import RevocationFile
from .server.oidc import https_origin

_MAX_CONFIG = 16 * 1024
OWNER_KEYS = {"issuer", "approval_client_id", "authorize_endpoint", "token_endpoint", "approval_public_host",
              "approval_port", "state_dir", "broker_socket", "pairing_db", "mcp_public_host", "mcp_port",
              "enrolled_clients"}
PROVISIONED = ("requests.sqlite3", "revoked-clients.json", "token-revocations.sqlite3", "provisioned.json")
PROJECT_ROOTS_FILE = "read-roots.json"        # optional, owner-private; absent = no project folders readable
INSTALLER_KEYS = {"issuer", "approval_client_id", "owner", "device", "owner_uid", "state_dir", "socket_path"}
PASSKEY_KEYS = {"passkey_rp_id", "passkey_origin"}
RELEASE_KEYS = {"build_user"}
RELEASE_SETTINGS_NAME = "release.json"      # beside installer.json; absent = release publishing not configured
PASSKEY_SETTINGS_NAME = "passkeys.json"      # beside installer.json; installer.json itself keeps exactly dev14's keys, so rolling back
                                             # to dev14 never meets a field it rejects (dev14 simply never reads this file)


MIN_OWNER_UID = 1000          # the owner is a normal login account, never a system account (tests running AS one lower it)


class ConfigError(ValueError):
    pass


def read_private_json(path, keys, optional=frozenset()):
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
    if type(data) is not dict or not (keys <= set(data) <= keys | optional):
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
    pairing_db: Path
    mcp_public_host: str
    mcp_port: int
    enrolled_clients: tuple

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
            mcp_host = run.check_public_host(data["mcp_public_host"])
        except ConfigError:
            raise
        except (ValueError, KeyError):
            raise ConfigError("config_value_invalid") from None
        port = data["approval_port"]
        if type(port) is not int or isinstance(port, bool) or not 1024 < port <= 65535:
            raise ConfigError("approval_port_must_be_unprivileged")
        if type(data["approval_client_id"]) is not str or not data["approval_client_id"]:
            raise ConfigError("approval_client_id_required")
        mcp_port = data["mcp_port"]
        if type(mcp_port) is not int or isinstance(mcp_port, bool) or not 1024 < mcp_port <= 65535 or mcp_port == port:
            raise ConfigError("mcp_port_must_be_unprivileged_and_different")
        clients = data["enrolled_clients"]
        if (type(clients) is not list or not 1 <= len(clients) <= 8
                or any(type(c) is not dict or set(c) != {"client_id", "name", "kind"} for c in clients)):
            raise ConfigError("enrolled_clients_invalid")
        return cls(data["issuer"], data["approval_client_id"], data["authorize_endpoint"], data["token_endpoint"],
                   host, port, _abs(data["state_dir"], "state_dir"), _abs(data["broker_socket"], "broker_socket"),
                   _abs(data["pairing_db"], "pairing_db"), mcp_host, mcp_port, tuple(dict(c) for c in clients))

    @property
    def redirect_uri(self):
        return "https://%s/approve/callback" % self.approval_public_host


@dataclass
class OwnerService:
    flow: ApprovalFlow
    approval: object
    mcp: object
    recovered: list
    waiting: list
    _stop: object = None
    _thread: object = None
    unreachable_since: dict = None
    vault: object = None
    _vault_stop: object = None

    def __post_init__(self):
        self.unreachable_since = {}

    def stop(self):
        if self._vault_stop is not None:
            self._vault_stop.set()
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        for part in (self.mcp, self.approval):
            if part is not None:
                part.stop()
        if self.flow._pool is not None:
            self.flow._pool.shutdown(wait=True)


def _check_state_dir(state):
    info = os.lstat(state)
    if state.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ConfigError("state_dir_must_be_private_and_owned_by_the_service_user")


def provision_owner_state(config, *, resume=False):
    """The ONE place the owner's request store and revocation lists are created. Run deliberately by the owner
    (or the owner-approved installer), never by a normal start and never reachable by an AI. Refuses if any
    state is already there: restoring access to revoked AI clients must be an explicit, visible decision.

    ``resume=True`` (first-run setup that was interrupted): only the MISSING files are created, existing ones are
    never touched, and the completion marker is written last. Once the marker exists, provisioning is finished:
    any later loss of state is NEVER recreated here (restore a backup instead)."""
    state = config.state_dir
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    _check_state_dir(state)
    present = [name for name in PROVISIONED + ("requests.sqlite3-journal",) if (state / name).exists()]
    if present and not resume:
        raise ConfigError("state_already_present_refusing_to_reset_it")
    if (state / "provisioned.json").exists():
        if all((state / name).exists() for name in PROVISIONED):
            return []                                       # already complete: nothing to do
        raise ConfigError("state_lost_after_setup_restore_a_backup_not_recreated")
    created = []
    if not (state / "revoked-clients.json").exists():
        RevocationFile(state / "revoked-clients.json").provision()
        created.append("revoked-clients.json")
    if not (state / "token-revocations.sqlite3").exists():
        from .identity import SQLiteRevocations
        SQLiteRevocations(state / "token-revocations.sqlite3").close()
        created.append("token-revocations.sqlite3")
    if not (state / "requests.sqlite3").exists():
        RequestStore(state / "requests.sqlite3")
        created.append("requests.sqlite3")
    fd = os.open(state / "provisioned.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps({"provisioned_at": int(time.time()), "version": 1}).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    created.append("provisioned.json")
    return sorted(created if resume else PROVISIONED)


def _installed_stynpilot_version():
    from .diagnostics import real_run
    code, out = real_run(["dpkg-query", "-W", "-f", "${Version}", "stynpilot"], 15)
    return out.strip() or "unknown"


def owner_vault(config, *, settings_path=None, **kw):
    """The owner side's encrypted daily backups: owner state + owner settings + pairing database + project roots.
    Settings files are checked against their own schema (so token_endpoint, a URL, is fine; any unexpected field is refused)."""
    from . import __version__, vault
    settings = Path(settings_path or os.path.expanduser("~/.config/stynpilot/owner.json"))
    extras = [("owner.json", settings, "json", True, OWNER_KEYS), ("pairing.sqlite3", config.pairing_db, "sqlite", True, None),
              ("read-roots.json", config.state_dir / PROJECT_ROOTS_FILE, "json", False, {"project_roots"})]
    kw.setdefault("isolate", True)
    # Owner-side PRUNING is disabled in Dev23 stage 1: it would need coordination with the installer's policy that survives
    # concurrency and restarts (tracked follow-up). Owner backups and verification continue; the hold is reported.
    kw.setdefault("prune_allowed", False)
    return vault.Vault(side="owner", state_dir=config.state_dir, folder=config.state_dir / "vault", extras=extras,
                       version=__version__, **kw)


def root_vault_extras(config_path, state_dir):
    """What the root vault adds to the installer's own records. Deliberately NOT here: /var/lib/stynpilot/release/ (the release
    signing key and the GitHub token) -- those are recovered by rotation, never from a backup."""
    from . import release
    etc = Path(config_path).parent
    extras = [("installer.json", etc / "installer.json", "json", True, INSTALLER_KEYS),
              (PASSKEY_SETTINGS_NAME, etc / PASSKEY_SETTINGS_NAME, "json", False, PASSKEY_KEYS),
              (RELEASE_SETTINGS_NAME, etc / RELEASE_SETTINGS_NAME, "json", False, RELEASE_KEYS),
              ("trusted-release-keys.json", release.ADDENDUM_FILE, "json", False, {"keys", "revoked"})]
    tx = Path(state_dir) / "release-tx"
    if tx.is_dir() and not tx.is_symlink():
        extras += [("release-tx/" + p.name, p, "json", False, None) for p in sorted(tx.glob("*.json"))[:200]]
    return extras


def root_vault(config_path, config, **kw):
    from . import __version__, vault

    class _Extras:                                     # re-read every run, so new release records are included
        def __iter__(self):
            return iter(root_vault_extras(config_path, config.state_dir))
    kw.setdefault("isolate", True)
    return vault.Vault(side="root", state_dir=config.state_dir, folder=config.state_dir / "vault", extras=_Extras(),
                       version=__version__, **kw)


def _owner_backup_before_upgrade(state):
    """Before an upgrade runs, save the owner's own records (request queue, revocations) with integrity hashes."""
    def before(payload, rid):
        if payload.get("kind") != "upgrade":
            return
        from . import backup
        folder = state / "backups"
        backup.make_backup(state, folder / ("pre-upgrade-%s.tar" % rid[:16]), kind="owner")
        old = sorted(folder.glob("pre-upgrade-*.tar"), key=lambda p: p.stat().st_mtime)
        for extra in old[:-5]:
            extra.unlink()
    return before


def _owner_after_approval(get_vault, *, sleep=time.sleep, attempts=20):
    """After the installer verified and spent an owner-side key-rotation approval, rotate the owner's own vault with it.
    Completion is reported only from the owner vault's own durable state; an interrupted rotation stays 'running' (pending) and
    the vault's scheduler finishes it and settles the request."""
    def after(payload, rid, result):
        if (payload.get("kind") != "backup" or payload.get("action") != "rotate_key" or payload.get("side") != "owner"
                or result.get("owner_side_authorized") != rid):
            return None
        vault_ = get_vault()
        if vault_ is None:
            return dict(result, ok=False, stopped="backups_not_available", rotation="failed")
        for _ in range(attempts):                       # a scheduled backup may hold the vault for a while: wait for it
            outcome = vault_.rotate_key(payload["mode"], rid)
            if outcome.get("error") != "another_backup_operation_is_running":
                break
            sleep(30)
        merged = dict(result, **{k: v for k, v in outcome.items() if k != "ok"})
        merged["ok"] = bool(outcome.get("ok"))
        if not outcome.get("ok"):
            merged["stopped"] = outcome.get("error", "key_rotation_failed")
            if outcome.get("rotation") == "in_progress" or outcome.get("error") == "another_backup_operation_is_running":
                merged["pending"] = True                # durable journal/marker present: finished later by the vault
        return merged
    return after


def _owner_before_run(state, get_vault, restore_status=None):
    """Owner-side steps before the installer is asked: the upgrade backup, and the durable rotation marker."""
    upgrade = _owner_backup_before_upgrade(state)

    def before(payload, rid):
        if payload.get("action") in ("restore_root", "rotate_key") and restore_status is not None:
            owner_vault = get_vault()
            if owner_vault is not None:
                owner_vault.reconcile_restore_intent(restore_status)
        if payload.get("action") == "restore_root":
            from datetime import datetime, timezone
            owner_vault = get_vault()
            if owner_vault is None:
                raise _vault_error("backups_not_available")
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            owner_vault.reserve_root_restore(rid, int(expires.timestamp()))
        if payload.get("kind") in ("upgrade", "release"):
            vault_ = get_vault()
            if vault_ is not None and vault_.journal_request() is not None:
                raise _vault_error("owner_key_rotation_in_progress")   # never replace the package under an owner-side rotation
        upgrade(payload, rid)
        if payload.get("kind") == "backup" and payload.get("action") == "rotate_key" and payload.get("side") == "owner":
            from datetime import datetime, timezone
            vault_ = get_vault()
            if vault_ is None:
                raise _vault_error("backups_not_available")
            expires = int(datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
            prepared = vault_.prepare_rotation(payload["mode"], rid, expires)
            if not prepared.get("ok"):
                raise _vault_error(prepared.get("error", "key_rotation_could_not_be_prepared"))
    return before


def _vault_error(code):
    from .vault import VaultError
    return VaultError(code)


def _rotation_authorization(broker):
    """rid -> what the installer's own durable record says about an owner-side rotation."""
    def check(rid):
        try:
            record = broker.status(rid)
        except Exception:
            return "unknown"
        state, result = record.get("state"), record.get("result") or {}
        if state == "done" and result.get("ok") and result.get("owner_side_authorized") == rid:
            return "authorized"
        if state in ("denied", "failed", "not_started"):
            return "refused"
        return "unknown"
    return check


def _settle_request(store, flow):
    def settle(rid, result):
        store.transition(rid, "approved", "running")
        store.transition(rid, "running", flow._state_for(result), result={k: v for k, v in result.items() if k != "pending"})
    return settle


def _owner_rotation_reconciler(store, flow, vault_, broker):
    """Startup and every vault tick: (1) an owner rotation whose completion the vault recorded durably but whose request was
    never settled (crash between the two) is settled from that record and its exact request id; (2) an installer-side rotation
    first reported as interrupted gets its real final outcome from the installer's record."""
    settle = _settle_request(store, flow)

    def reconcile():
        current = vault_.journal_request()
        for rid in store.in_flight():
            payload = store.payload(rid)
            if (isinstance(payload, dict) and payload.get("kind") == "backup" and payload.get("action") == "rotate_key"
                    and payload.get("side") == "owner" and (current or ("",))[0] != rid):
                outcome = vault_.rotation_outcome(rid)
                if outcome == "completed":
                    settle(rid, {"ok": True, "action": "rotate_key", "side": "owner", "rotation": "completed"})
                elif outcome == "cancelled":
                    settle(rid, {"ok": False, "action": "rotate_key", "side": "owner", "rotation": "failed",
                                 "stopped": "installer_did_not_authorize_or_it_could_not_start", "changed_anything": False})
        if hasattr(vault_, "reconcile_restore_intent"):
            vault_.reconcile_restore_intent(broker.status)
        for rid in store.unsettled_restores():
            try:
                store.settle_restore(rid, broker.status(rid))
            except Exception:
                continue
        for rid in store.interrupted_rotations():
            try:
                record = broker.status(rid)
            except Exception:
                continue
            result = record.get("result") or {}
            if result.get("action") != "rotate_key" or result.get("side") != "root":
                continue
            state = record.get("state")
            if (state, result.get("rotation"), result.get("ok")) in (("done", "completed", True), ("failed", "failed", False)):
                store.settle_rotation(rid, state, result)
    return reconcile


def start_owner_service(config, *, broker=None, exchange=None, start_listener=None, start_mcp=None, tokens=None,
                        clock=time.time, monotonic=time.monotonic, reconcile_interval=5.0, give_up_after=600.0,
                        resolve_apt=None, vault=None, backups=True):
    """Assemble and start the owner side. The keyword hooks are for tests; production passes none."""
    import threading
    from .approval_web import token_exchange
    from .broker.service import BrokerClient, BrokerLedger
    from .devices import PairingDeviceGrants
    from .identity import SQLiteRevocations
    from .server.clients import EnrolledClients
    state = config.state_dir
    if not state.is_dir():
        raise ConfigError("not_provisioned_owner_must_run_provision")
    _check_state_dir(state)
    if any(not (state / name).exists() for name in PROVISIONED):
        # Lost or misplaced state must NEVER be recreated empty here: that could re-admit revoked AI clients.
        raise ConfigError("not_provisioned_or_state_missing_owner_must_run_provision_or_restore")
    revocations = RevocationFile(state / "revoked-clients.json")
    revocations.revoked()                                  # must be readable and trusted, or we don't start
    revocations.enable_archive_fence()
    store = RequestStore(state / "requests.sqlite3", clock=clock)
    broker = broker or BrokerClient(config.broker_socket)
    service_vault = [None]                                  # the owner vault, once it exists (the approval flow needs it later)
    flow = ApprovalFlow(store=store, broker=broker,
                        exchange=exchange or token_exchange(token_endpoint=config.token_endpoint,
                                                            client_id=config.approval_client_id,
                                                            redirect_uri=config.redirect_uri),
                        authorize={"endpoint": config.authorize_endpoint, "client_id": config.approval_client_id,
                                   "redirect_uri": config.redirect_uri},
                        clock=clock, background=True, before_run=_owner_before_run(state, lambda: service_vault[0], broker.status))
    recovered, waiting = flow.recover(patient=True)        # settle what the installer already knows, BEFORE accepting anything
    service = OwnerService(flow, None, None, recovered, waiting)
    try:
        service.approval = (start_listener or run.start_approval)(
            flow=flow, public_host=config.approval_public_host, port=config.approval_port)
        if tokens is None:
            from .server.oidc import OIDCConfig
            from .server import run as _run
            tokens = OIDCConfig(issuer=config.issuer, audience="https://%s/mcp" % config.mcp_public_host,
                                revocations=SQLiteRevocations(state / "token-revocations.sqlite3"),
                                allowed_scopes=_run.PROPOSE_SCOPES).build_verifier()
        from . import health, inventory, service_status
        grants = PairingDeviceGrants(config.pairing_db)
        router = run.router_for_paired_device(tokens=tokens, grants=grants, read_health=health.snapshot,
                                              read_service_status=service_status.read_service_status,
                                              read_inventory=inventory.snapshot)
        propose = dict(clients=EnrolledClients([dict(c) for c in config.enrolled_clients], revocations=revocations),
                       store=store, ledger=BrokerLedger(config.broker_socket),
                       resolve_apt=resolve_apt or apt.resolve,
                       analyze_apt=apt.analyze, installed_apt=apt.installed_versions, search_apt=apt.search,
                       approval_url="https://%s" % config.approval_public_host,
                       fetch_release=release.https_get, installed_version=_installed_stynpilot_version)
        from . import safefs
        from .diagnostics import Diagnostics
        from .system_status import SystemStatus
        home = os.path.expanduser("~")
        service.vault = vault or owner_vault(config, retention_source=lambda: broker.vault_settings())
        service_vault[0] = service.vault
        service.vault.authorization_source = _rotation_authorization(broker)
        service.vault.on_rotation_finished = _settle_request(store, flow)
        reconcile = _owner_rotation_reconciler(store, flow, service.vault, broker)
        service.vault.tick_hooks.append(reconcile)
        try:
            reconcile()
        except Exception:
            pass
        flow.after_run = _owner_after_approval(lambda: service.vault)
        diag = dict(policy=safefs.Policy(home=home,
                                         project_roots=safefs.load_project_roots(state / PROJECT_ROOTS_FILE, home),
                                         extra_deny=[config.state_dir, config.pairing_db, config.broker_socket,
                                                     os.path.join(home, "StyNpilot-Projects", "deckplay-hq")]),
                    diagnostics=Diagnostics(), system=SystemStatus(backup_dir=config.state_dir / "backups", vault=service.vault),
                    vault=service.vault, broker=broker)
        from . import archive_store, repo_archive
        def private_archive_read(client, access, source):
            try:
                return broker.runner("repository_archive_read", {"client": client, "repository": access["repository"],
                                     "profile": access["authorization_profile"], "source": source}).get("allowed") is True
            except Exception:
                return False

        archives = archive_store.Store(state / "repository-archives", private_read=private_archive_read)
        try:
            archives.reconcile()
        except (OSError, repo_archive.ArchiveError) as error:
            logging.getLogger("stynpilot.archive").warning("archive recovery held: %s", getattr(error, "code", type(error).__name__))
        runner_tools = dict(broker=broker, projects_dir=os.path.join(home, "StyNpilot-Projects"), vault=service.vault,
                            archive_store=archives)
        service.mcp = (start_mcp or run.start)(router=router, public_host=config.mcp_public_host,
                                               port=config.mcp_port, propose=propose, diag=diag, runner=runner_tools)
    except Exception:
        service.stop()
        raise
    if backups:
        from . import vault as _vault
        service._vault_stop, _ = _vault.start_scheduler(service.vault)   # first backup shortly after start; never raises
    if waiting:
        stop, thread = threading.Event(), None

        def keep_trying():
            while service.waiting and not stop.wait(reconcile_interval):
                try:
                    reconcile_waiting(service, now=monotonic(), give_up_after=give_up_after)
                except Exception:
                    pass                                         # a bad pass must not end the monitoring
        service._stop = stop
        service._thread = thread = threading.Thread(target=keep_trying, name="stynpilot-reconcile", daemon=True)
        thread.start()
    return service


def reconcile_waiting(service, *, now=None, give_up_after=600.0):
    """One more try at requests whose installer record wasn't available at startup.

    A reachable installer that says "running" is a legitimate long install: keep watching it, however long
    it takes (if the installer itself crashes, its own restart marks the run for the owner, which we then
    report). Only an UNREACHABLE installer is an outage, and only after it has been unreachable continuously
    for ``give_up_after`` seconds is the owner told, honestly, to verify. Nothing is ever re-run."""
    flow, now = service.flow, (time.monotonic() if now is None else now)
    for rid in list(service.waiting):
        kind, record = flow._root_record(rid)
        if kind == "unreachable":
            began = service.unreachable_since.setdefault(rid, now)
            if now - began >= give_up_after:
                flow.give_up_waiting([rid])
                service.waiting.remove(rid)
                service.unreachable_since.pop(rid, None)
            continue
        service.unreachable_since.pop(rid, None)                 # reachable again: the outage clock restarts
        if kind == "record" and (record or {}).get("state") == "running":
            continue                                             # still legitimately running: keep monitoring
        flow._settle_from_root(rid)
        service.waiting.remove(rid)
        service.recovered.append(rid)
    return list(service.waiting)


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
    passkey_rp_id: str = None
    passkey_origin: str = None
    release_build_user: str = None

    @classmethod
    def from_file(cls, path):
        data = dict(read_private_json(path, INSTALLER_KEYS))
        sibling = Path(path).with_name(PASSKEY_SETTINGS_NAME)
        if os.path.lexists(sibling):
            data.update(read_private_json(sibling, PASSKEY_KEYS))
        extra = Path(path).with_name(RELEASE_SETTINGS_NAME)
        if os.path.lexists(extra):
            data["release_build_user"] = read_private_json(extra, RELEASE_KEYS)["build_user"]
        return cls.from_dict(data)

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
        if type(uid) is not int or isinstance(uid, bool) or uid < MIN_OWNER_UID:
            raise ConfigError("owner_uid_must_be_a_normal_user")
        rp_id, origin = data.get("passkey_rp_id"), data.get("passkey_origin")
        if (rp_id is None) != (origin is None):
            raise ConfigError("passkey_rp_id_and_origin_go_together")
        if rp_id is not None:
            from .broker.passkeys import PasskeyStore
            try:
                PasskeyStore.check_identity(rp_id, origin)
            except ValueError:
                raise ConfigError("passkey_identity_invalid") from None
        return cls(data["issuer"], data["approval_client_id"], data["owner"], data["device"], uid,
                   _abs(data["state_dir"], "state_dir"), _abs(data["socket_path"], "socket_path"), rp_id, origin,
                   _build_user(data.get("release_build_user")))


BUILD_ROOT = Path("/var/lib/stynpilot-build")        # root-owned 0755; each build gets a 0700 folder owned by the build account
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,30}\Z")


def _build_user(name):
    if name is None:
        return None
    if type(name) is not str or not _ACCOUNT.fullmatch(name) or name == "root":
        raise ConfigError("release_build_user_invalid")
    return name


def build_authority(config, state_dir=None, **options):
    """The release authority for this installer, or None when release publishing is not configured (the default)."""
    if config.release_build_user is None:
        return None
    import pwd
    from .broker.release_authority import Authority
    try:
        account = pwd.getpwnam(config.release_build_user)
    except KeyError:
        raise ConfigError("release_build_user_does_not_exist") from None
    if account.pw_uid == 0:
        raise ConfigError("release_build_user_invalid")
    from . import runner

    def sandbox(job, argv, workspace, *, seconds, memory_mb, tasks, network):
        # The same sandbox the owner's project jobs use (systemd-run unit: no privileges, read-only system, hidden installer folders,
        # memory/process/CPU/time limits, own /tmp), run as the build account. Network only where a step is allowed it.
        return runner.unit_command(job, argv, workspace, seconds=seconds, memory_mb=memory_mb, tasks=tasks, writes=True,
                                   network=network, run_user=account.pw_name, resolver=network)

    options.setdefault("work_root", BUILD_ROOT)
    options.setdefault("retain_lab_source", True)
    return Authority(state_dir or config.state_dir, sandbox=sandbox, mount_work=True, build_uid=account.pw_uid, **options)


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


def build_installer(config, *, jwks, jwks_loader=None, run_command=apt.real_run, require_root=True,
                    **executor_options):
    """The root installer and its socket. Creating the Executor marks any run left 'running' by a crash as
    needing the owner and blocks new installs until the owner has checked."""
    from .broker.executor import Executor
    from .broker.proof import ProofVerifier
    from .broker.service import BrokerService
    verifier = ProofVerifier(issuer=config.issuer, approval_client_id=config.approval_client_id, jwks=jwks,
                             jwks_loader=jwks_loader)
    executor_options.setdefault("owner_uid", config.owner_uid)
    if "jobs" not in executor_options and require_root:
        import pwd
        from . import __version__
        from .broker.jobs import JobRunner
        home = pwd.getpwuid(config.owner_uid).pw_dir
        executor_options["jobs"] = JobRunner(config.state_dir, owner_uid=config.owner_uid, home=home, run=run_command,
                                             projects_dir=os.path.join(home, "StyNpilot-Projects"), version=__version__)
    if config.passkey_rp_id is not None and "passkeys" not in executor_options:
        from .broker.passkeys import PasskeyStore
        config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        executor_options["passkeys"] = PasskeyStore(config.state_dir / "passkeys.sqlite3", rp_id=config.passkey_rp_id,
                                                    origin=config.passkey_origin)
    if "authority" not in executor_options and require_root:
        executor_options["authority"] = build_authority(config)
    executor = Executor(state_dir=config.state_dir, owner=config.owner, device=config.device, verifier=verifier,
                        run=run_command, require_root=require_root, **executor_options)
    # Only the installed, fixed-layout root service provisions the fence.
    # An existing durable claim forbids silently recreating a missing fence.
    if (require_root and config.state_dir == Path("/var/lib/stynpilot-installer")
            and config.socket_path == Path("/run/stynpilot/installer.sock")):
        from .broker import repository_auth
        from . import repo_archive, vault
        if executor.passkeys is not None:
            try:
                targets = repository_auth.load_targets(Path("/etc/stynpilot/repository-authorization.json"))
                executor.repositories = repository_auth.Store(config.state_dir, targets)
            except (OSError, ValueError, repo_archive.ArchiveError, repository_auth.AuthorizationError, vault.VaultError) as error:
                logging.getLogger("stynpilot.repository").warning("repository authorization unavailable: %s", type(error).__name__)
        if executor.jobs is not None:
            from .broker.archive_jobs import Jobs as ArchiveJobs
            executor.archive_jobs = ArchiveJobs(config.state_dir, executor.repositories,
                                                executor.jobs.helper, executor.jobs.home)
        from . import inference_fence, managed_activity
        if executor.authority is not None and executor.lab is None:
            from .broker.lab import LabJobs
            executor.lab = LabJobs(config.state_dir, executor.authority, owner=config.owner, device=config.device)
        try:
            inference_fence.provision(config.owner_uid, allow_create=not managed_activity.held(config.state_dir))
        except (OSError, KeyError, managed_activity.ActivityError):
            # Inference stays unavailable; unrelated recovery/installer
            # functionality must not fail merely because the pilot is absent.
            pass
        else:
            executor.inference_settlement_fence = lambda: inference_fence.settlement(config.owner_uid)
    return BrokerService(socket_path=config.socket_path, executor=executor, allowed_uid=config.owner_uid)


def passkeys_console(config_path, action, kid, *, input_fn=input, is_tty=None, out=print):
    """Root, at the computer: look at or activate passkeys directly in the installer's own database (see passkey_console.py)."""
    from . import passkey_console
    from .broker.passkeys import PasskeyStore
    config = InstallerConfig.from_file(config_path)
    if config.passkey_rp_id is None:
        out("Passkeys are not enabled in this installer's config. Nothing was changed.")
        return 1
    if os.geteuid() != 0:
        out("Run this with sudo: it opens the installer's private records.")
        return 1
    store = PasskeyStore(config.state_dir / "passkeys.sqlite3", rp_id=config.passkey_rp_id, origin=config.passkey_origin)
    if action == "activate":
        return passkey_console.activate(store, kid, input_fn=input_fn, is_tty=is_tty, out=out)
    if action == "confirm-restored":
        return passkey_console.confirm_restored(store, kid, input_fn=input_fn, is_tty=is_tty, out=out)
    return passkey_console.show(store, out=out)


def release_console_main(config_path, action, *, out=print):
    """Root, at the computer: create the release key, enter the GitHub token, check status (see release_console.py)."""
    from . import release, release_console
    config = InstallerConfig.from_file(config_path)
    if os.geteuid() != 0:
        out("Run this with sudo: it opens the installer's private records.")
        return 1
    authority = build_authority(config)
    if authority is None:
        out("Release publishing is not configured: create /etc/stynpilot/release.json with {\"build_user\": \"stynpilot-build\"} "
            "(root, mode 0600) and that account first. Nothing was changed.")
        return 1
    if action == "init":
        return release_console.init(authority, release.ADDENDUM_FILE, out=out)
    if action == "set-token":
        return release_console.set_token(authority, out=out)
    return release_console.status(authority, release.ADDENDUM_FILE, out=out)


def _protect_credential_process():
    """Keep credential-bearing services out of kernel core files and pipe handlers."""
    import ctypes
    import resource

    # A hard zero survives a unit override or a manual service launch. Linux
    # pipe handlers can ignore RLIMIT_CORE, so also disable kernel dumping for
    # this process before it reads credentials or opens any listening socket.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(4, 0, 0, 0, 0) != 0 or prctl(3, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE, PR_GET_DUMPABLE
        raise ConfigError("credential_process_protection_failed")


def main(argv=None):                                       # pragma: no cover - thin process wrapper
    import argparse
    import signal
    import threading
    parser = argparse.ArgumentParser(prog="stynpilot-service")
    parser.add_argument("role", choices=("owner", "installer", "provision", "passkeys", "release", "restore-worker"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--action", choices=("list", "activate", "confirm-restored", "init", "set-token", "status"), default="list")
    parser.add_argument("--kid", default="")
    args = parser.parse_args(argv)
    if args.role in ("owner", "installer"):
        _protect_credential_process()
    if args.role == "restore-worker":
        from . import restore_service
        return restore_service.run(args.config, InstallerConfig.from_file(args.config))
    if args.role == "installer":
        config = InstallerConfig.from_file(args.config)
        from . import root_restore
        if (root_restore.control(config.state_dir) / "safe.json").exists():
            from .restore_service import serve_safe
            return serve_safe(config)
        if not root_restore.start_allowed(config.state_dir):
            return 0  # the independent recovery worker starts the service when the tree is intact
        service = build_installer(config, jwks=fetch_jwks(config.issuer), root_vault=root_vault(args.config, config),
                                  jwks_loader=lambda: fetch_jwks(config.issuer))     # rotation: only on an unknown key ID
        from . import vault as _vault
        from .restore_service import watcher_ready
        service.executor.restore_available = lambda: watcher_ready(config, args.config)
        service.vault = service.executor.vault
        _vault.start_scheduler(service.vault)                 # first backup shortly after start, then hourly checks; never raises
        service.serve_forever()
        return 0
    if args.role in ("passkeys", "release"):
        from . import root_restore
        state = InstallerConfig.from_file(args.config).state_dir
        with root_restore.admission(state):
            if root_restore.held(state):
                raise ConfigError("root_restore_in_progress")
            if args.role == "passkeys":
                return passkeys_console(args.config, args.action, args.kid)
            return release_console_main(args.config, args.action)
    config = OwnerConfig.from_file(args.config)
    if args.role == "provision":
        print("created:", ", ".join(provision_owner_state(config)))
        return 0
    service = start_owner_service(config)
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    done.wait()
    service.stop()
    return 0


if __name__ == "__main__":                                 # pragma: no cover
    raise SystemExit(main())
