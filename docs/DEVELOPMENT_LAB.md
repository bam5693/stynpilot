# Offline StyNpilot development lab

Run the lab from a normal account on Ubuntu with working KVM access and Bubblewrap. The default state location is an owner-private directory under `~/.local/share/stynpilot-dev`. The scripts keep downloaded packages, signed image metadata and wheel artifacts in `cache`, with test results under `work`. Set `STYNPILOT_DEV_DIR` for a different absolute location and pass that location to `guest.py --directory`.

- `tools/dev/bootstrap.sh` downloads or reuses Ubuntu QEMU packages and verifies the cloud image with the installed Ubuntu cloud-image keyring. It extracts packages into the user cache and creates a venv that reuses distro Python dependencies. Add `--guest-deps` to download the Ubuntu package closure for guest recovery testing.
- Put the hash-pinned wheel from `packaging/vendor.lock` into `cache/wheels`. `tools/dev/checkpoint.sh` verifies each wheel, logs the revision and worktree status, builds twice, and compares package SHA-256. Use a clean checkout when recording release evidence.
- `tools/dev/offline_suites.py PREPARED_WORK_DIRECTORY normal sandbox check` runs the local suites in separate Bubblewrap namespaces. Generate the work directory from an exact commit with `tools/dev/prepare-offline.sh HEAD`. It contains a frozen source checkout in `src`, pinned wheels in `cache`, extracted MCP wheel in `vendor`, and the Ubuntu Python seccomp binding under `seccomp/usr/lib/python3/dist-packages`. The release-sandbox lane uses the release seccomp filter. Logs remain in the work directory and the script returns failure if any lane fails.
- `tools/dev/smoke-seed.sh /absolute/path/seed.iso` makes a boot smoke seed. Run `python3 tools/dev/guest.py --seed /absolute/path/seed.iso --marker STYNPILOT_GUEST_BOOT_OK`.
- `tools/dev/restore-media.sh /absolute/path/stynpilot.deb` packages the candidate, synthetic authentication helpers and cached Ubuntu dependency packages from `cache/guest-debs` onto separate seed and read-only artifact ISOs. Run `python3 tools/dev/guest.py --seed PATH/seed.iso --payload PATH/payload.iso --marker STYNPILOT_APPROVED_RESTORE_OK`. The fixture checks the guest DMI marker and requires loopback-only networking before it changes guest files.

The guest uses two vCPUs, 3 GiB of guest RAM, a 16 GiB virtual drive, serial logging, and a single-run lock. The launcher checks host memory and disk headroom, verifies the base image, attaches artifact media read-only, disables the NIC and monitor, and deletes its own disposable overlay at exit. A fresh run creates a fresh overlay from the cached base image. The serial log and emulator output survive cleanup. The optional `--power-cycle-marker` ends only that QEMU process at an explicit serial milestone and restarts the same disposable overlay once. The guest fixture must emit the milestone after its intended durable checkpoint. Run destructive scenarios only in this lab.

The launcher requires each marker on its own complete serial line. A final pass also requires QEMU to exit successfully. Both boots share the configured wall-clock deadline after overlay setup. The host caps serial logs at 8 MiB per boot and QEMU diagnostics at 8 MiB total. Exit 124 records a deadline and exit 125 records an output cap. Both stop QEMU and preserve the captured evidence. Serial markers are guest assertions. Candidate identity and the host-observed exit must accompany them in a review.

### Restricted executor development

The offline worker implements the fixed `offline_normal` recipe. It requires an unprivileged worker with verified cgroup v2 limits (up to 2 GiB RAM, zero swap, 64 tasks, and two CPUs). It stages only a bounded uncompressed Git archive with the expected commit comment and SHA-256. Extraction rejects linked, special, duplicate and traversing entries. The executor runs the recipe from a read-only snapshot under networkless Bubblewrap with private temporary storage and nested user namespaces disabled. It uses synthetic account records and verifies the packaged MCP wheel digest before extracting the wheel inside the sandbox. It caps console output and wall time, redacts complete results before returning them, and discards output on cancellation or overflow.

The module's CLI is an owner-side verification entry point. A future installer worker must supply trusted paths and obtain enrolled commit and artifact identity from the broker. The CLI accepts operator-supplied inputs for testing and carries no enrollment or MCP authority. Keep KVM and release-sandbox scenarios disabled on this surface until their trusted assets and executor are available.

Docker and Compose can be reused where a scoped runtime already exists. This repository has no Node dependency or Compose project. Keep runner, daemon and user privileges unchanged when adding project-specific environments. Git remains the source of revision identity. A local Forgejo service can be used where the project already has an authorized remote.

The packaged Stage 3 operation restores selected installer records using a verified archive, existing authority, vault keys, and a fresh verified safety copy. It preserves settings and owner-side state. Complete system restore, lost vault keys and lost installer authority require separate procedures.

For a scoped source review, run ShellCheck on `tools/dev/*.sh`, Pyflakes on the modified Python files, and Bandit with Python 3.14 support on the privileged code paths. Keep the findings with the candidate logs. These checks complement the package, runtime and confinement tests.

For recovery fault scenarios, build media with `tools/dev/restore-media.sh PACKAGE --fault-cases` and require the serial marker `STYNPILOT_RESTORE_FAULT_CASES_OK`. This exercises a temporary owner endpoint outage and a persistent outage in the disposable guest. For a power interruption, build media with `--power-case` and launch with `--power-cycle-marker STYNPILOT_CUT_POWER_NOW --marker STYNPILOT_POWER_RECOVERY_OK`. Preserve both serial logs. A missing marker is a failed or incomplete run.


## Restricted MCP integration (development only)

The first integration stage adds `dev_lab_status`, a read-only, paired-device
preflight that checks fixed owner lab metadata, KVM API access, available RAM
and free work-volume storage. It returns booleans and planned scenario names,
not host paths or raw cache files. Cache presence is NOT artifact integrity
verification. A successful preflight never authorizes execution; launch remains
disabled in this stage. The fixed default location is used; a custom lab
location needs separate owner enrollment.

The planned execution vocabulary is exact lowercase 40-hex Git commit and one
of: offline_normal, offline_release_sandbox, static_checks, reproducible_build,
guest_boot_smoke, guest_restore, guest_restore_faults, guest_power_recovery.
No caller-selected commands, paths, URLs, ISO files, or success markers.
Launch, progress, output, cancellation, owner enrollment and managed cleanup
are not yet exposed. Before implementing launch, provision trusted immutable
launcher and cache identity, make preparation strictly cache-only, isolate
candidate builds and tests, and run in a bounded managed cgroup with private
results and durable recovery exclusion. The current interactive launcher is
not itself a remote execution trust boundary.
