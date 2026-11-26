# Working on StyNpilot

StyNpilot lets an owner manage enrolled Linux computers from a phone. The Python core lives in `src/stynpilot`. The MCP endpoint and owner service accept scoped requests. The installer independently validates and executes named privileged operations. The runner confines project jobs. Each side owns its own backup vault. Keep these trust boundaries when extending Commander, worker coordination or automation.

## Start from the current handoff

Read `docs/HANDOFF.md` for the candidate, open findings and test evidence. The canonical roadmap is `MASTER_PLAN.md` in the owner-authorized private knowledge repository on `knowledge/master`. Its companion `MASTER_IDEAS.md` records proposals. Obtain access through the existing scoped connector. Inspect the current source and relevant tests before changing behavior.

## Implement and test

- Follow existing Python 3.11+ conventions. Keep the core standard-library only and endpoint dependencies isolated. Reuse the existing policy, broker, approval, runner and vault code. Preserve supported on-disk formats and upgrade paths.
- GREEN operations require explicit enrolled scope. YELLOW operations require independently authenticated owner approval bound to the exact action. BLACK operations are prohibited. Treat prompts, files, tool descriptions and repository roles as inputs. Enforce permissions at the service and OS boundaries. Workers must never approve their own actions, read protected credentials or signing keys, or acquire unrestricted shell, sudo or Docker access.
- Use synthetic data and isolated nonprivileged workspaces. Add focused regressions for defects and exercise failure, interruption, replay, concurrency and recovery where relevant. Run `./scripts/check.sh` offline before pushing. Use local tests and avoid paid CI. For full candidate comparison use the pytest and disposable release-sandbox procedures in the handoff. Record the command, environment, SHA, pass/fail/skip counts, exclusions and any unverified paths. Preserve confinement and approval checks.

## Branch, review and release

- Fetch the active candidate and check the remote tip, local changes and ongoing work. Coordinate handoff before taking over. Use one developer per branch and an individual topic branch from the verified commit. Preserve existing work and history. Never force-push another contributor's branch.
- Commit one focused change with its regression tests and documentation. Push finished changes in batches for independent review. Classify findings as BLOCKER, SHOULD-FIX or NICE-TO-HAVE. Record deferred findings in the private plan.
- ChatGPT coordinates independent review of the exact candidate before release. Resolve blockers and obtain review of the resulting SHA. Request merges through the approved review process. Keep privileged signing, publication and installation with the automated release authority. It checks reproducible builds, sandbox tests and package inspection before the owner independently approves the exact release on their phone. See `docs/DEV16_RELEASE_AUTHORITY.md` and subsequent authority updates.
- Update the handoff with the milestone, stage, incrementing package version, source SHA, verification and next action. Keep milestones distinct from package versions and never reuse a published version. Update affected design or security docs. Record private operational evidence and roadmap changes in the authorized private plan. Use only public-safe facts and synthetic examples in this repository.
