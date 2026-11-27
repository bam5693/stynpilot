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

The installed offline profile uses one passkey approval per enrolled AI client and the fixed StyNpilot repository. Request enrollment with `commander_request_dev_lab_enrollment`. The installer records the exact client, device, repository and profile version. Subsequent `dev_lab_start` calls are GREEN for this scope. Pass the full commit and `lab_source_sha256` from a ready verification build made by an installer that retains source archives. Older ready records do not contain this artifact. The installer captures Git's archive before it runs candidate code, retains it with the verified build, and rehashes it at admission. Bubblewrap and the distribution pytest package must already be available.

`dev_lab_prepare` uses the enrolled client's scope to prepare an exact commit for verification, including candidates whose Debian version equals the installed version. Poll the existing release status for the source digest. Preparation never signs or publishes. The existing release approval still requires a newer version.

Use `dev_lab_jobs` and `dev_lab_job_status` to monitor work, `dev_lab_job_output` to page completed redacted evidence, and `dev_lab_cancel` to stop an active job. These tools are restricted to the authenticated requesting client. The installer keeps up to sixteen jobs and permits a single active development lab job. It reserves admission against root restore and managed inference, revokes dispatch before stopping a unit, verifies systemd and recursive cgroup population before releasing the reservation, and reconciles interrupted jobs when the installer restarts. The source archive and scratch data are deleted after settlement. Offline output is retained in the root installer state, with evidence bounded per job.

The local CLI is a separate verification entry point that accepts operator-supplied inputs. The remote executor uses fixed installer-owned paths, the installed vendor dependency and a private systemd service. KVM and release-sandbox scenarios remain disabled in the MCP job surface.

For packaged MCP acceptance in a disposable guest, prepare `restore-media.sh PACKAGE --lab-mcp-case` with hash-verified Bubblewrap and distribution pytest packages in `cache/lab-guest-debs`. Boot the guest with `--memory-mib 5120` so the installer can enforce its normal memory headroom. Require `STYNPILOT_LAB_MCP_OK` and `FIXTURE_EXIT=0` on serial. This lane uses synthetic issuer and passkey fixtures, real MCP HTTP transport and the installed broker and systemd worker.

On hosts where AppArmor refuses a pathname connection across the packaged service mount namespaces, the installed broker also supports a local abstract Unix socket. It checks the enrolled owner UID before reading any request. The owner service verifies a fresh challenge response using a root-issued, owner-only per-start key before transmitting the request. There is no remote listener, AppArmor change or approval fallback.

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
