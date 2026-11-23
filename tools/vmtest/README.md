# StyNpilot isolated VM test (free, no cloud)

Runs the real `.deb` on a real Ubuntu 26.04 ("resolute") machine under QEMU, with real systemd, real logind
sessions, real polkit password prompts, and a test-only identity provider. Nothing here touches a real computer.

    python3 tools/build_deb.py
    python3 tools/vmtest/run_vm_test.py --base base.img --kernel vmlinuz --initrd initrd.img \
        --deb dist/stynpilot_*_all.deb --work work --key keys/id        # about 10 minutes without KVM, far less with it

It uses `-accel kvm` automatically when `/dev/kvm` exists (the Ryzen has it). It prints one `PASS`/`FAIL` line per
check and exits nonzero if anything failed. Latest result: `docs/evidence/vm-run-1.txt`.

## What the base image is (built by hand with debootstrap; recipe, not a script)
Ubuntu 26.04 minimal + openssh-server, polkitd, systemd-networkd (DHCP), python3 stack, `sudo`; user `owner` (uid 1000,
group sudo, test password) ; a root ssh key for the harness only; `/etc/hosts` maps the test provider name to 127.0.0.1;
a throw-away test CA is in the system trust store and `g8-fake-idp.service` serves a fake OpenID provider with it.

## Deliberate differences from a real Kubuntu desktop (so nobody over-trusts this test)
1. The owner logs in on the serial console, not in KDE. A tiny PAM line gives that login `XDG_SEAT=seat0`, which is
   what a display manager does; without a seat polkit treats the session as remote.
2. polkit's socket-activated password helper failed in this VM ("No session for cookie"), so the image uses the older
   setuid helper (`chmod 4755 /usr/lib/polkit-1/polkit-agent-helper-1`, socket masked). The prompts, messages and
   decisions are real polkit; only the helper's plumbing differs. **If the real KDE prompt ever rejects a correct
   password with that message, that is this issue, not StyNpilot.**
3. The prompt is polkit's text agent, not KDE's dialog: the wording is identical, the look is not.
4. Packages come from the real Ubuntu archive over https through the sandbox's proxy; archive is whatever is current.
5. The identity provider is fake (the test checks our side of PKCE, nonce-bound proof, forged tokens). Real Auth0
   behaviour is only proven on the real machine.
6. Software emulation is slow, so waits are long.
