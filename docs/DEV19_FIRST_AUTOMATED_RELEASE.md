# Dev19: first fully automated release

Version bump only. Gated on successful live verification of Dev18 (the manually published authority update).
Flow: commander_prepare_stynpilot_release on this exact commit -> stynpilot_release_status ready -> commander_request_stynpilot_release
-> one owner fingerprint approval -> the Ryzen signs, publishes and installs. If it stops after approval: commander_resume_stynpilot_release.
Rollback: Dev18, then Dev17.
