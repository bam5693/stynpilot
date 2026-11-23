# Finishing setup over SSH (remote owner authorization)

## Why "Not authorized. This incident has been reported." happened
polkit decides per login session. An SSH login is a *remote* session with no seat, so polkit uses an action's
`allow_any` value. StyNpilot's five actions said `allow_any = no`, so polkit answered "no" immediately and never asked
for a password. No authentication agent (pkttyagent, pkexec's own text agent, KDE's dialog) is consulted for a plain
"no", which is why registering an agent changed nothing. Reproduced on a 26.04 test machine: `Remote=yes, Seat=`,
`pkcheck` exit 1, `pkexec` -> "Not authorized".

## The fix (package 0.1.0~dev0, commit after 5705ec3)
* `packaging/org.stynpilot.policy`: `allow_any` is now `auth_admin` for the five root-* actions (`allow_inactive` stays
  `no`, `allow_active` stays `auth_admin`). A remote login must now type an administrator's password, the same bar as
  `sudo`, for ONE fixed helper command each (matched by exec path and argv1). Nothing is "yes" anywhere.
* The root helper is unchanged: it still acts only for the person polkit authenticated (PKEXEC_UID) and checks it against
  the saved settings, so another account that knows the password is still refused.
* New `stynpilot setup-system`: runs the page's password step in the terminal you are typing in, using the settings
  already saved (nothing is re-entered). It asks polkit read-only first (`pkcheck`), shows the prompt, verifies the
  receipt, marks setup complete, starts nothing, and does nothing when repeated.
* The page's failure message now points to `stynpilot setup-system`; `start`/`stop` say whether the prompt was
  cancelled or refused.

## Evidence
`docs/evidence/vm-run-remote.txt` (19 checks over a real sshd login, real polkit): wrong password, Ctrl-D, Ctrl-C,
correct password, repeat, another account with the correct admin password, remote start/stop.
Unit tests: `RemoteAuthTests` in `tests/test_g7.py`.

## Second problem: "No session for cookie" (polkit 127 bug, upstream polkit issue #686)
After the policy fix the prompt appears but a correct password is refused. Ubuntu 26.04's polkit 127 checks the
password in a socket-activated helper that reads the caller's *effective* uid. pkexec's built-in text agent is setuid
root, so the helper answers as root while polkitd knows the session by the owner's real uid: "No session for cookie".
It hits any `pkexec` typed in a terminal or SSH login that has no desktop agent.

Reproduced on a 26.04 VM with polkitd 127-2ubuntu1.1 and the socket-activated, non-setuid helper (the Ryzen's setup):
* plain `pkexec ...`: FAILS. `exec pkexec ...` (same PID): FAILS the same way. Not a workaround.
* `pkttyagent --process <pid>` run **as the owner**, in a second terminal or the same shell: WORKS.
* the same agent started with `sudo` (root): FAILS. The agent must run as the owner.
* Warning: in an interactive shell a background (`&`) agent is stopped by the terminal and your typed password is
  echoed. Use two terminals, or let StyNpilot do it.

Fix: `terminal_agent` (setup_wizard.py) starts `pkttyagent --process <own pid> --fallback` as the owner for the duration
of every StyNpilot pkexec call (setup-system, the page button, start, stop), only when a person is at a terminal, and
never replaces a desktop agent. If it cannot start, pkexec behaves as before. Same password, same polkit decision, same
root helper checks; nothing is bypassed.

`stynpilot auth-check` (read-only) shows: remote or local login, what polkit would do for the setup action, whether the
terminal agent exists, and whether the socket-activated helper (the bug) is in use.
