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
APPROVAL_PORT, MCP_PORT = 18444, 18443
FIELDS = ("issuer", "approval_client_id", "approval_public_host", "mcp_public_host", "pairing_db",
          "chatgpt_client_id", "claude_client_id")


def default_paths(home):
    home = Path(home)
    return {"config": home / ".config/stynpilot/owner.json", "proposed": home / ".config/stynpilot/installer.proposed.json",
            "state": home / ".local/state/stynpilot"}


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


def write_new_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


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


def run_setup(form, home, uid):
    """Steps 1-3. Returns what was written. Refuses to overwrite anything."""
    paths = default_paths(home)
    if paths["config"].exists():
        raise ConfigError("already_set_up_refusing_to_overwrite")
    data = owner_config_from_form(form, home)
    proposal = installer_proposal(data, uid)                  # fails before anything is written
    write_new_private(paths["config"], data)
    created = provision_owner_state(OwnerConfig.from_dict(data))
    write_new_private(paths["proposed"], proposal)
    return {"config": str(paths["config"]), "state_files": created, "proposed": str(paths["proposed"])}


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
    write_new_private(dest, data)                             # O_EXCL: never replaces an existing config
    return str(dest)


# ------------------------------------------------------------------------------------------------- web page
_STYLE = ("body{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem}"
          "label{display:block;margin:.8rem 0 .2rem;font-weight:600}input{width:100%;padding:.5rem;font-size:1rem}"
          "button{font-size:1.1rem;padding:.7rem 1.4rem;margin-top:1rem}small{color:#555}")
LABELS = {"issuer": ("Auth0 domain", "like your-tenant.us.auth0.com"),
          "approval_client_id": ("Approval app client ID", "the Auth0 application used only for approvals"),
          "approval_public_host": ("Approval page address", "your computer's HTTPS name and port, e.g. pc.tailnet.ts.net:8444"),
          "mcp_public_host": ("AI connection address", "your computer's HTTPS name, e.g. pc.tailnet.ts.net"),
          "pairing_db": ("Existing pairing database", "full path of the file your current StyNpilot already uses"),
          "chatgpt_client_id": ("ChatGPT connector ID", "from the ChatGPT connector settings"),
          "claude_client_id": ("Claude connector ID", "from the Claude connector settings")}


def build_app(*, home, uid, token, port, root_runner=None, setup=run_setup):
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import HTMLResponse
    from starlette.routing import Route
    host = "127.0.0.1:%d" % port
    runner = root_runner or (lambda src: subprocess.run(["pkexec", "/usr/bin/stynpilot", "root-setup", "--from", src],
                                                        capture_output=True, text=True, timeout=300))

    def page(title, body, status=200):
        out = HTMLResponse("<!doctype html><meta charset=utf-8><title>%s</title><style>%s</style>%s"
                           % (html.escape(title), _STYLE, body), status_code=status)
        out.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})
        return out

    def allowed(request):
        return (request.headers.get("host") == host
                and hmac.compare_digest(request.path_params.get("token", ""), token)
                and (request.method == "GET" or request.headers.get("origin") == "http://" + host))

    async def form_page(request: Request):
        if not allowed(request):
            return page("Not found", "<p>Not found.</p>", 404)
        rows = "".join("<label>%s</label><input name=%s autocomplete=off><small>%s</small>"
                       % (html.escape(LABELS[n][0]), n, html.escape(LABELS[n][1])) for n in FIELDS)
        return page("StyNpilot setup", "<h1>StyNpilot first-time setup</h1><p>Nothing starts or changes until you finish "
                    "the last step. Your existing sign-in, pairing and Preview26 are not modified.</p>"
                    "<form method=post action=/setup/%s/save>%s<button>Save and prepare</button></form>" % (token, rows))

    async def save(request: Request):
        if not allowed(request):
            return page("Not found", "<p>Not found.</p>", 404)
        values = {k: v for k, v in (await request.form()).items() if isinstance(v, str) and len(v) < 512}
        try:
            done = setup(values, home, uid)
        except ConfigError as error:
            return page("Check the form", "<h1>Not saved</h1><p>%s</p><p><a href=/setup/%s>Back</a></p>"
                        % (html.escape(str(error)), token), 400)
        return page("Almost done", "<h1>Saved</h1><p>Your settings were saved privately.</p><p>Last step: allow the "
                    "system part. Your computer will ask for your password.</p><form method=post action=/setup/%s/system>"
                    "<input type=hidden name=go value=1><button>Allow system part</button></form>" % token) \
            if done else page("Error", "<p>Nothing saved.</p>", 500)

    async def system(request: Request):
        if not allowed(request):
            return page("Not found", "<p>Not found.</p>", 404)
        result = runner(str(default_paths(home)["proposed"]))
        if getattr(result, "returncode", 1) != 0:
            return page("Not completed", "<h1>The system step did not finish</h1><p>Nothing was started. You can "
                        "close this and try again from the menu.</p>", 400)
        return page("Done", "<h1>Setup finished</h1><p>Nothing is running yet. Run <b>StyNpilot Doctor</b> from the menu "
                    "to check everything. Starting the services is a separate step that needs your approval.</p>")
    return Starlette(routes=[Route("/setup/{token}", form_page), Route("/setup/{token}/save", save, methods=["POST"]),
                             Route("/setup/{token}/system", system, methods=["POST"])])


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
    print("Setup page:", url)
    server.run()
