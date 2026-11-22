# G7: install, check, back up, roll back (owner guide, draft)

Nothing here is deployed yet. G8 (owner-approved upgrade of the Ryzen) will give the exact commands.

- **Install:** open the `.deb` with Discover/Dolphin (or `sudo apt install ./stynpilot_*.deb`). Installing starts and
  enables nothing and changes nothing else. Preview26 is not touched.
- **First run:** open **StyNpilot Setup** from the menu. Type the seven values, press *Save and prepare*, then *Allow
  system part* (your normal password prompt). Nothing is started.
- **Check:** open **StyNpilot Doctor** from the menu. It only reads; it prints OK / WARN / FAIL.
- **Back up:** `stynpilot backup` (one verified file with hashes). **Recover lost state:** `stynpilot restore --archive FILE`.
  Restoring keeps revoked AI connectors revoked. A normal start never recreates lost state on its own.
- **Roll back the package:** `sudo apt remove stynpilot`. This removes only the program; your settings, state and Preview26
  stay. `sudo apt install ./older.deb` brings back an earlier build.
