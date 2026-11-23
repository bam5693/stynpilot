"""First-run setup for the owner: a small local web page (no terminal needed), then ONE polkit-protected root step.

``stynpilot setup`` (started from the application menu) listens on 127.0.0.1 on a random port, behind a one-time
secret in the URL, and opens the owner's browser. The owner types only what only they know (Auth0 domain, the
approval app's client ID, two host names, the AI connector IDs). It then:
  1. validates everything, writes ~/.config/stynpilot/owner.json (0600, never overwritten),
  2. creates the owner state ONCE (stynpilot.service.provision_owner_state),
  3. works out the owner/device from the EXISTING pairing database (read-only), and writes a proposed root config,
  4. on the owner's click, asks polkit (the normal password prompt) to run ``stynpilot root-setup``, which copies the
     proposed config to /etc/stynpilot/installer.json for exactly this user.
Nothing here starts or enables a service, and nothing touches Auth0, Tailscale, Cloudflare, Forgejo, the pairing
database or the existing Preview26 service.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import stat
import subprocess
from pathlib import Path

from .service import ConfigError, InstallerConfig, OwnerConfig, provision_owner_state

ROOT_CONFIG = Path("/etc/stynpilot/installer.json")
RECEIPT_NAME = "setup-receipt.json"
ROOT_HELPER = "/usr/libexec/stynpilot/root-helper"
PKCHECK = "/usr/bin/pkcheck"
APPROVAL_PORT, MCP_PORT = 18444, 18443
FIELDS = ("issuer", "approval_client_id", "approval_public_host", "mcp_public_host", "pairing_db",
          "chatgpt_client_id", "claude_client_id")


def default_paths(home):
    home = Path(home)
    return {"config": home / ".config/stynpilot/owner.json", "proposed": home / ".config/stynpilot/installer.proposed.json",
            "done": home / ".config/stynpilot/setup-complete.json", "state": home / ".local/state/stynpilot"}


def discover_pairing_db(home):
    """The existing build's pairing database, found read-only at its known location (never created or changed)."""
    from .compat_check import STATE_DIR
    from .devices import PairingDeviceGrants
    candidate = Path(home) / STATE_DIR / "pairing.sqlite3"
    try:
        grants = PairingDeviceGrants(candidate)
        try:
            return str(candidate) if len(grants.paired_devices()) == 1 else None
        finally:
            grants.close()
    except Exception:
        return None


def owner_config_from_form(form, home):
    """Form values -> a validated owner config dict (raises ConfigError with a plain code)."""
    for name in FIELDS:
        if type(form.get(name)) is not str or not form[name].strip():
            raise ConfigError("%s_required" % name)
    issuer = form["issuer"].strip()
    if not issuer.startswith("https://"):
        issuer = "https://" + issuer
    issuer = issuer.rstrip("/") + "/"
    clients = [{"client_id": form["chatgpt_client_id"].strip(), "name": "chatgpt", "kind": "chatgpt"},
               {"client_id": form["claude_client_id"].strip(), "name": "claude", "kind": "claude"}]
    data = {"issuer": issuer, "approval_client_id": form["approval_client_id"].strip(),
            "authorize_endpoint": issuer + "authorize", "token_endpoint": issuer + "oauth/token",
            "approval_public_host": form["approval_public_host"].strip(), "approval_port": APPROVAL_PORT,
            "mcp_public_host": form["mcp_public_host"].strip(), "mcp_port": MCP_PORT,
            "state_dir": str(default_paths(home)["state"]), "broker_socket": "/run/stynpilot/installer.sock",
            "pairing_db": form["pairing_db"].strip(), "enrolled_clients": clients}
    OwnerConfig.from_dict(data)
    return data


def canonical_bytes(data):
    """The one byte layout used for every settings file we write, so a hash of it is reproducible."""
    return json.dumps(data, indent=2, sort_keys=True).encode()


def write_new_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(canonical_bytes(data))


def installer_proposal(owner_data, uid):
    """Owner + device come from the existing pairing database (read-only), never from typing."""
    from .devices import PairingDeviceGrants
    grants = PairingDeviceGrants(owner_data["pairing_db"])
    try:
        paired = grants.paired_devices()
    finally:
        grants.close()
    if len(paired) != 1:
        raise ConfigError("exactly_one_paired_device_required")
    owner, device = paired[0]
    data = {"issuer": owner_data["issuer"], "approval_client_id": owner_data["approval_client_id"], "owner": owner,
            "device": device, "owner_uid": uid, "state_dir": "/var/lib/stynpilot-installer",
            "socket_path": "/run/stynpilot/installer.sock"}
    InstallerConfig.from_dict(data)
    return data


def _read_private(path):
    from .service import INSTALLER_KEYS, OWNER_KEYS, read_private_json
    return read_private_json(path, OWNER_KEYS if Path(path).name == "owner.json" else INSTALLER_KEYS)


def setup_status(home, uid, root_config=ROOT_CONFIG):
    """Where first-run setup stands, read-only. config / proposal / state / system / complete."""
    from .service import PROVISIONED
    paths = default_paths(home)
    out = {"config": "missing", "proposal": "missing", "state": "missing", "system": "pending", "complete": False}
    config = None
    if paths["config"].exists() or paths["config"].is_symlink():
        try:
            config = OwnerConfig.from_file(paths["config"])
            out["config"] = "ok"
        except ConfigError:
            out["config"] = "invalid"
    if config is not None:
        state = config.state_dir
        have = [(state / n).exists() for n in PROVISIONED]
        out["state"] = "complete" if all(have) else "partial" if any(have) else "missing"
        if paths["proposed"].exists() or paths["proposed"].is_symlink():
            try:
                existing = _read_private(paths["proposed"])
                out["proposal"] = "ok" if existing == installer_proposal(_read_private(paths["config"]), uid) else "mismatch"
            except Exception:
                out["proposal"] = "mismatch"
    out["system"] = _system_state(root_config, paths, config, uid)
    out["was_finished"] = out["system"] == "done" or paths["done"].exists()     # setup got to the end at some point
    out["complete"] = (out["system"] == "done" and out["config"] == "ok" and out["proposal"] == "ok"
                       and out["state"] == "complete")
    return out


ROOT_UID = 0                                             # who must own the system files (tests override)


def _lstat_ok(path, *, kind, forbidden_mode):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not kind(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & forbidden_mode:
        raise ValueError("unsafe")
    return info


def _system_state(root_config, paths, config, uid):
    """Did the privileged step finish FOR THIS OWNER with THESE settings?  The normal-user wizard cannot (and must
    not) read the root-only 0600 settings file, so root leaves a small public RECEIPT next to it (root-owned, not
    writable by anyone else) holding the owner's uid and the SHA-256 of the exact settings bytes it installed. The
    wizard compares that hash with the settings this owner's setup proposed, and checks only the metadata of the real
    file (root-owned, private, regular). "done" needs all of it; anything else is "mismatch"; nothing there (or the
    settings file there without a receipt: root will finish it if identical, refuse otherwise) is "pending"."""
    cfg = Path(root_config)
    receipt = cfg.with_name(RECEIPT_NAME)
    have_cfg, have_receipt = os.path.lexists(cfg), os.path.lexists(receipt)
    if not have_receipt:
        return "pending"
    if not have_cfg or config is None:
        return "mismatch"
    try:
        _lstat_ok(cfg.parent, kind=stat.S_ISDIR, forbidden_mode=0o022)
        _lstat_ok(cfg, kind=stat.S_ISREG, forbidden_mode=0o077)                 # metadata only: contents are root-only
        info = _lstat_ok(receipt, kind=stat.S_ISREG, forbidden_mode=0o022)
        if info.st_size > 4096:
            return "mismatch"
        record = json.loads(receipt.read_text())
        if type(record) is not dict or set(record) != {"schema", "owner_uid", "config_sha256"} or record["schema"] != 1:
            return "mismatch"
        wanted = hashlib.sha256(canonical_bytes(installer_proposal(_read_private(paths["config"]), uid))).hexdigest()
        return "done" if record["owner_uid"] == uid and record["config_sha256"] == wanted else "mismatch"
    except Exception:
        return "mismatch"


def resume_setup(form, home, uid, root_config=ROOT_CONFIG):
    """First-run setup that can be started, interrupted, and started again. Each stage is idempotent and never
    overwrites or resets anything: owner settings -> proposed root settings -> owner state (created last).
    Existing settings that don't match what was typed, or that fail their checks, stop everything (fail closed).
    After setup is complete, lost state is never recreated here."""
    status = setup_status(home, uid, root_config)
    paths = default_paths(home)
    if status["config"] == "invalid":
        raise ConfigError("existing_settings_invalid_not_changing_them")
    if status["config"] == "ok":
        existing = _read_private(paths["config"])
        if form is not None and owner_config_from_form(form, home) != existing:
            raise ConfigError("existing_settings_differ_from_what_was_typed_not_changing_them")
        data = existing
    else:
        if form is None:
            raise ConfigError("nothing_to_resume_fill_in_the_form")
        data = owner_config_from_form(form, home)
        installer_proposal(data, uid)                          # fail before anything is written
        write_new_private(paths["config"], data)
    if status["proposal"] == "mismatch":
        raise ConfigError("proposed_settings_do_not_match_not_changing_them")
    if status["proposal"] == "missing":
        write_new_private(paths["proposed"], installer_proposal(data, uid))
    config = OwnerConfig.from_dict(data)
    if status["state"] != "complete":
        if status["was_finished"]:
            raise ConfigError("state_missing_after_setup_restore_a_backup")
        provision_owner_state(config, resume=True)
    return setup_status(home, uid, root_config)


def run_setup(form, home, uid, root_config=ROOT_CONFIG):
    return resume_setup(form, home, uid, root_config)


def mark_complete(home):
    path = default_paths(home)["done"]
    if not path.exists():
        write_new_private(path, {"completed": True})


# ----------------------------------------------------------------------------------------------- root step
def root_setup(source, *, dest=ROOT_CONFIG, invoking_uid=None, geteuid=os.geteuid, environ=os.environ):
    """Run as root through pkexec. Copies the owner's proposed installer config to /etc, for that owner only."""
    if geteuid() != 0:
        raise ConfigError("must_run_through_polkit_as_root")
    try:
        uid = int(invoking_uid if invoking_uid is not None else environ["PKEXEC_UID"])
    except (KeyError, ValueError):
        raise ConfigError("not_started_by_polkit") from None
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size > 16384:
            raise ConfigError("proposed_config_must_be_a_private_file_owned_by_the_caller")
        data = json.loads(os.read(fd, 16385).decode())
    except (ValueError, UnicodeError):
        raise ConfigError("proposed_config_not_valid") from None
    finally:
        os.close(fd)
    from .service import INSTALLER_KEYS
    if type(data) is not dict or set(data) != INSTALLER_KEYS:
        raise ConfigError("proposed_config_has_unexpected_fields")
    config = InstallerConfig.from_dict(data)
    if config.owner_uid != uid:
        raise ConfigError("owner_uid_must_be_the_person_who_asked")
    if str(config.state_dir) != "/var/lib/stynpilot-installer" or str(config.socket_path) != "/run/stynpilot/installer.sock":
        raise ConfigError("paths_must_be_the_packaged_ones")
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    receipt = dest.with_name(RECEIPT_NAME)
    wanted = canonical_bytes(data)
    if os.path.lexists(dest):
        if os.path.lexists(receipt):
            raise FileExistsError(str(dest))                  # finished before: never replaced
        # Died between writing the settings and the receipt: finish ONLY if the file is exactly what we'd write.
        fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            same = (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
                    and os.read(fd, len(wanted) + 1) == wanted)
        finally:
            os.close(fd)
        if not same:
            raise ConfigError("a_different_system_settings_file_is_already_there_not_replacing_it")
    else:
        write_new_private(dest, data)                         # O_EXCL: never replaces an existing config
    _write_receipt(receipt, uid, hashlib.sha256(wanted).hexdigest())
    return str(dest)


# ------------------------------------------------------------------------------- finishing from a terminal (SSH)
def pkexec_reason(returncode, text=""):
    """Plain words for how a pkexec run ended. pkexec: 126 = the prompt was dismissed, 127 = not authorized / failed."""
    if returncode == 0:
        return "done"
    if returncode == 126:
        return "cancelled: the password prompt was dismissed"
    if returncode == 127 or "not authorized" in (text or "").lower():
        return "refused: the password was not accepted, or this login is not allowed to ask"
    return "did not finish (exit %s)" % returncode


def _polkit_would_ask(action, pid, check=None):
    """Read-only question to polkit: would THIS login get a password prompt? 'ask' / 'allowed' / 'no' / None=unknown."""
    check = check or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=30).returncode)
    try:
        code = check([PKCHECK, "--action-id", action, "--process", str(pid)])
    except (OSError, subprocess.SubprocessError):
        return None
    return {0: "allowed", 2: "ask", 1: "no"}.get(code)


def finish_system(home, uid, root_config=ROOT_CONFIG, *, run=None, check=None, interactive=None, out=None):
    """``stynpilot setup-system``: the same one-file root step as the page's button, run in the terminal you are in
    (so it works over SSH). Uses the settings already saved; asks polkit for the owner's password right here; starts
    nothing. Safe to repeat: when it is already finished it only says so."""
    import sys
    out = out or sys.stdout
    paths = default_paths(home)
    status = setup_status(home, uid, root_config)
    if status["config"] != "ok" or status["proposal"] != "ok" or status["state"] != "complete":
        print("Nothing was changed. Setup has not been saved yet (or the saved settings do not match): open "
              "'stynpilot setup' and press 'Save and prepare' first.", file=out)
        return 1
    if status["system"] == "done":
        mark_complete(home)
        print("The system step is already finished. Nothing was changed, no password needed. Next: stynpilot start", file=out)
        return 0
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        print("Nothing was changed. This step asks for your password, so run it in a terminal you are typing in.", file=out)
        return 1
    if _polkit_would_ask("org.stynpilot.root-setup", os.getpid(), check) == "no":
        print("Nothing was changed. This computer's permission rules do not let this login ask for a password for "
              "this step (an older StyNpilot package only allowed someone sitting at the machine). Install the current "
              "package, then run this again.", file=out)
        return 1
    print("Asking for your password. It lets StyNpilot copy ONE settings file to %s for your account only. "
          "It installs and starts nothing." % ROOT_CONFIG, file=out, flush=True)
    run = run or (lambda argv: subprocess.run(argv, timeout=600))
    try:
        result = run(["pkexec", ROOT_HELPER, "root-setup", "--from", str(paths["proposed"])])
    except KeyboardInterrupt:                                              # Ctrl-C at the password prompt
        print("\nCancelled. Nothing was changed. You can run it again.", file=out)
        return 1
    code = getattr(result, "returncode", 1)
    status = setup_status(home, uid, root_config)
    if code != 0 or status["system"] != "done":
        print("The system step did not finish (%s). Nothing was started. You can run it again." % pkexec_reason(code), file=out)
        return 1
    mark_complete(home)
    print("System settings are in place. Nothing was started. Next: stynpilot start", file=out)
    return 0


def _write_receipt(path, uid, digest):
    """Public (0644) proof that the privileged step finished: no secrets, only the owner uid and a hash."""
    tmp = path.with_name(".%s.tmp" % path.name)
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(canonical_bytes({"schema": 1, "owner_uid": uid, "config_sha256": digest}))
        handle.flush()
        os.fchmod(handle.fileno(), 0o644)
        os.fsync(handle.fileno())
    os.rename(tmp, path)


# ------------------------------------------------------------------------------------------------- web page
_STYLE = ("body{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem}"
          "label{display:block;margin:.8rem 0 .2rem;font-weight:600}input{width:100%;padding:.5rem;font-size:1rem}"
          "button{font-size:1.1rem;padding:.7rem 1.4rem;margin-top:1rem}small{color:#555}li{margin:.3rem 0}")
LABELS = {"issuer": ("Auth0 domain", "like your-tenant.us.auth0.com"),
          "approval_client_id": ("Approval app client ID", "the Auth0 application used only for approvals"),
          "approval_public_host": ("Approval page address", "your computer's HTTPS name and port, e.g. pc.tailnet.ts.net:8444"),
          "mcp_public_host": ("AI connection address", "your computer's HTTPS name, e.g. pc.tailnet.ts.net"),
          "pairing_db": ("Existing pairing database", "found automatically when possible"),
          "chatgpt_client_id": ("ChatGPT connector ID", "from the ChatGPT connector settings"),
          "claude_client_id": ("Claude connector ID", "from the Claude connector settings")}
_STAGES = (("config", "Your settings are saved"), ("proposal", "System settings are prepared"),
           ("state", "Your private records are created"), ("system", "System part is allowed"))


async def _form_values(request) -> dict:
    """Reads a plain urlencoded form without Starlette's form parser (which needs an extra library that the Ubuntu
    package set does not reliably provide). Anything else, or anything large, is refused as empty."""
    if not request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
        return {}
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > 16384:
            return {}
    from urllib.parse import parse_qsl
    return {k: v for k, v in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True) if len(v) < 512}


def build_app(*, home, uid, token, port, root_runner=None, root_config=ROOT_CONFIG, setup=resume_setup,
              start_runner=None):
    """The link is a ONE-TIME entry: the first visit trades the secret URL for a browser session cookie and the URL
    stops working. Close the browser and start Setup again from the menu to get a new link. Every later request
    needs that cookie, the exact Host, and (for posts) the exact Origin."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, RedirectResponse
    from starlette.routing import Route
    host = "127.0.0.1:%d" % port
    session = secrets.token_urlsafe(24)
    used = {"entered": False}
    runner = root_runner or (lambda src: subprocess.run(["pkexec", ROOT_HELPER, "root-setup", "--from", src],
                                                        capture_output=True, text=True, timeout=300))

    starter = start_runner or (lambda: subprocess.run(["/usr/bin/stynpilot", "start"], capture_output=True, text=True,
                                                      timeout=400))

    def page(title, body, status=200):
        out = HTMLResponse("<!doctype html><meta charset=utf-8><title>%s</title><style>%s</style>%s"
                           % (html.escape(title), _STYLE, body), status_code=status)
        out.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
                            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})
        return out

    def nope():
        return page("Not found", "<p>Not found.</p>", 404)

    def why_not(request):
        """None when the request may proceed, else a short code. Browsers send ``Origin: null`` on a form post when the
        page's Referrer-Policy is no-referrer, so the pages use same-origin (the exact-Origin check stays strict)."""
        if request.headers.get("host") != host:
            return "host"
        if not hmac.compare_digest(request.cookies.get("sp_setup", ""), session):
            return "cookie"
        if request.method != "GET" and request.headers.get("origin") != "http://" + host:
            return "origin"
        return None

    def allowed(request):
        return why_not(request) is None

    def refused(request):
        """A real explanation (403) instead of a bare 'Not found'. Nothing is changed and no secret is shown."""
        code = why_not(request) or "unknown"
        sent = html.escape((request.headers.get("host") if code == "host" else request.headers.get("origin")) or "nothing")
        if code == "host":
            why = ("This page was opened as <b>%s</b> but StyNpilot is waiting at <b>%s</b>. Open the setup page with exactly the "
                   "address <code>stynpilot setup</code> printed; if you forward the port, the number on your side must be the same."
                   % (sent, html.escape(host)))
        elif code == "cookie":
            why = ("Your browser did not present this setup session. Close this page, run <code>stynpilot setup</code> again "
                   "and open the new link once (each link works one time). Cookies must be allowed for 127.0.0.1.")
        else:
            why = ("Your browser did not send the expected <b>Origin</b> (it sent <b>%s</b>, expected <b>http://%s</b>). "
                   "Reload the setup page and try again; if it repeats, tell your helper this exact line." % (sent, html.escape(host)))
        return page("Not accepted", "<h1>Not accepted, nothing was changed</h1><p>%s</p><p><small>Reason code: %s</small></p>" % (why, code), 403)

    async def enter(request: Request):
        if request.headers.get("host") != host:
            return refused(request)
        if used["entered"]:
            return page("Link already used", "<h1>This setup link was already used</h1><p>Each link works once. Run "
                        "<code>stynpilot setup</code> again for a new one. Nothing was changed.</p>", 410)
        if not hmac.compare_digest(request.path_params.get("token", ""), token):
            return nope()
        used["entered"] = True                                  # one-time: the URL secret is spent now
        response = RedirectResponse("/setup", status_code=303)
        response.set_cookie("sp_setup", session, httponly=True, samesite="strict", path="/")
        return response

    def progress(status):
        rows = "".join("<li>%s %s</li>" % ("&#10003;" if status[k] in ("ok", "complete", "done") else "&#9675;", html.escape(t))
                       for k, t in _STAGES)
        return "<ul>%s</ul>" % rows

    def next_step(status, note=""):
        if status["config"] == "ok" and status["proposal"] == "ok" and status["state"] == "complete" \
                and status["system"] == "done":
            return page("Setup finished", "<h1>Setup is finished</h1>%s<p>Nothing is running yet. Starting is a separate step "
                        "with its own password prompt: it starts the software installer (only changes software you approve "
                        "one request at a time) and your approval page.</p><form method=post action=/setup/start><button>"
                        "Start StyNpilot now</button></form><p><small>You can also start or stop it later from the menu. "
                        "<b>StyNpilot Doctor</b> checks everything.</small></p>" % progress(status))
        if status["system"] == "mismatch" and status["proposal"] == "ok":
            return page("Needs a look", "<h1>A different system settings file is already there</h1>%s<p>The file "
                        "/etc/stynpilot/installer.json does not match the settings you just made (or is not private to "
                        "root). Setup will <b>not</b> replace it and nothing was changed. Ask your helper to look at it "
                        "with Doctor.</p>" % progress(status))
        if status["config"] == "ok" and status["proposal"] == "ok" and status["state"] == "complete":
            return page("Almost done", "<h1>One step left</h1>%s%s<p>Your computer will ask for your password. That approves ONE thing: "
                        "copying the settings you just made to <code>/etc/stynpilot/installer.json</code>, readable only by "
                        "administrators and set up for your account alone. It installs nothing and starts nothing. You can "
                        "cancel and come back: nothing is lost.</p><form method=post action=/setup/system><button>Allow system "
                        "part</button></form>" % (note, progress(status)))
        return page("Resume setup", "<h1>Setup was not finished</h1>%s%s<form method=post action=/setup/resume>"
                    "<button>Continue where I left off</button></form>" % (note, progress(status)))

    async def home_page(request: Request):
        if not allowed(request):
            return refused(request)
        status = setup_status(home, uid, root_config)
        if status["config"] != "missing":
            return next_step(status)
        found = discover_pairing_db(home) or ""
        rows = "".join("<label>%s</label><input name=%s autocomplete=off value='%s'><small>%s</small>"
                       % (html.escape(LABELS[n][0]), n, html.escape(found if n == "pairing_db" else ""),
                          html.escape(LABELS[n][1])) for n in FIELDS)
        return page("StyNpilot setup", "<h1>StyNpilot first-time setup</h1><p>Nothing starts or changes until you finish "
                    "the last step. Your existing sign-in, pairing and Preview26 are not modified. This page can be "
                    "closed and reopened at any time: setup resumes where it stopped.</p>"
                    "<form method=post action=/setup/save>%s<button>Save and prepare</button></form>" % rows)

    async def save(request: Request):
        if not allowed(request):
            return refused(request)
        values = await _form_values(request)
        try:
            status = setup(values, home, uid, root_config)
        except ConfigError as error:
            return page("Check the form", "<h1>Not saved</h1><p>%s</p><p><a href=/setup>Back</a></p>"
                        % html.escape(str(error)), 400)
        return next_step(status)

    async def resume(request: Request):
        if not allowed(request):
            return refused(request)
        try:
            status = setup(None, home, uid, root_config)
        except ConfigError as error:
            return page("Cannot resume safely", "<h1>Stopped, nothing was changed</h1><p>%s</p><p>Run <b>StyNpilot Doctor</b> "
                        "or restore a backup.</p>" % html.escape(str(error)), 400)
        return next_step(status)

    async def system(request: Request):
        if not allowed(request):
            return refused(request)
        status = setup_status(home, uid, root_config)
        if not (status["config"] == "ok" and status["proposal"] == "ok" and status["state"] == "complete"):
            return page("Not ready", "<h1>Not ready for this step</h1><p><a href=/setup>Back</a></p>", 400)
        result = runner(str(default_paths(home)["proposed"]))
        status = setup_status(home, uid, root_config)
        if getattr(result, "returncode", 1) != 0 or status["system"] != "done":
            why = html.escape(str(getattr(result, "stderr", "") or "")[:300])
            return next_step(status, "<p><b>The system step did not finish</b> (cancelled or refused). Nothing was "
                                     "started. You can try again.</p>%s<p>Connected over SSH? Open a second terminal and run "
                                     "<b>stynpilot setup-system</b> there; it asks for your password in that terminal, then "
                                     "reload this page.</p>" % ("<p><small>%s</small></p>" % why if why else ""))
        mark_complete(home)
        return next_step(setup_status(home, uid, root_config))
    async def start(request: Request):
        if not allowed(request):
            return refused(request)
        status = setup_status(home, uid, root_config)
        if status["system"] != "done":
            return page("Not ready", "<h1>Finish setup first</h1><p><a href=/setup>Back</a></p>", 400)
        result = starter()
        said = html.escape(str(getattr(result, "stdout", "") or getattr(result, "stderr", "") or "")[:400])
        if getattr(result, "returncode", 1) != 0:
            return page("Not started", "<h1>StyNpilot was not started</h1><p>%s</p><form method=post action=/setup/start>"
                        "<button>Try again</button></form>" % said, 500)
        return page("Started", "<h1>StyNpilot is running</h1><p>%s</p><p>Next: connect ChatGPT or Claude. Anything they ask "
                    "for waits for your approval.</p>" % said)
    return Starlette(routes=[Route("/setup/{token}", enter), Route("/setup", home_page),
                             Route("/setup/save", save, methods=["POST"]), Route("/setup/resume", resume, methods=["POST"]),
                             Route("/setup/system", system, methods=["POST"]),
                             Route("/setup/start", start, methods=["POST"])])


def serve(home=None, uid=None, open_browser=True):                     # pragma: no cover - interactive wrapper
    import socket
    import threading
    import uvicorn
    import webbrowser
    home = home or Path.home()
    uid = os.getuid() if uid is None else uid
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    token = secrets.token_urlsafe(24)
    server = uvicorn.Server(uvicorn.Config(build_app(home=home, uid=uid, token=token, port=port), host="127.0.0.1",
                                           port=port, log_level="warning", proxy_headers=False))
    url = "http://127.0.0.1:%d/setup/%s" % (port, token)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print("Setup page:", url, flush=True)
    server.run()
