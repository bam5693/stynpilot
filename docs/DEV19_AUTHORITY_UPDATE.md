# Dev19: second (and last planned) manual authority update

Dev19 try #4 (6718b5f): the whole suite passed in the live sandbox, then root failed with `package_missing`.
Cause: the installer service has its own mount namespace (PrivateTmp, ProtectHome). Its `mount -t tmpfs` over the work folder
existed only there; the sandbox units systemd starts in the host namespace wrote into the plain folder underneath, and root,
looking at its empty tmpfs, found no package. (It also meant the build was not in the size-limited tmpfs at all.)
This is installed authority code, so a candidate commit cannot fix it.

Fix: the work area is mounted and unmounted in the HOST mount namespace (`nsenter --mount=/proc/1/ns/mnt`), which propagates
into the installer's slave namespace. Before any build step root proves both views are the same tmpfs: root's mountinfo must show
tmpfs at the work path, and a sandbox step must read back a fresh random token root wrote there (exclusive, no-follow). Either
check failing stops the build (`work_area_not_visible_to_root`, `work_area_not_shared_with_the_sandbox`). No-follow artifact
reading and verification are unchanged.

Also in Dev19 (since Dev18): corrected setid_calls_denied self-test (reopens the runner gate), sandbox-compatible test suite
(unix-socket transport where TCP is forbidden, disk reserve option, no-op chown avoided, owner line constant with production
test, umask-0077 rollback-copy fix), system status shows bracketed values. Dev20 (version bump only) = first fully automated release.
