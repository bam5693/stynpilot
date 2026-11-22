# Founder setup: Claude on the Ryzen, controlled from your phone

**Goal:** from your phone, ask Claude to read a file, edit a file, run the tests and report back, with all the work happening on the Ryzen.
**Time:** about 15 minutes at the Ryzen. **Cost:** $0 (it uses your existing Claude plan).

The Ryzen opens no ports. Claude Code connects *out* to Anthropic, and your phone is just a window into that session.

## Before you start

- You're signed in to Kubuntu on the Ryzen as your normal user.
- Your phone has the Claude app, signed in to the same Claude account you'll use on the Ryzen.
- **Never type a password into any AI chat.** If something needs your password, you type it yourself in the terminal.

Open a terminal on the Ryzen (**Konsole**, in the app menu). Paste each block, press Enter, and wait for it to finish before the next one.

## 1. Take a restore point first

```bash
sudo apt install -y timeshift
```

Then open **Timeshift** from the app menu, choose **RSYNC**, keep the suggested disk, and press **Create**. Wait until it says the snapshot is done. This is your undo button for the whole system.

## 2. Install Claude Code (official installer, no sudo)

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Close the terminal, open a new one, then check:

```bash
claude --version
[ -n "$ANTHROPIC_API_KEY" ] && echo "API key IS set - stop and tell Claude" || echo "API key: not set (good)"
```

You should see a version number and `API key: not set (good)`. An API key would bill differently, and Remote Control does not work with one anyway.

## 3. Make the workspace

```bash
mkdir -p ~/dev && cd ~/dev && git clone https://github.com/bam5693/stynpilot.git && cd stynpilot && git checkout claude/foundation
```

The last part switches to the branch that has the tests, until PR #2 is merged.

## 4. Sign in, and turn on phone notifications

```bash
claude
```

Follow the sign-in in the browser using your Claude account. When it asks whether you trust this folder, choose yes. Then, inside Claude:

1. Type `/config`, find **Push when actions required**, turn it on, and leave the menu.
2. Type `/exit`.

## 5. Start Remote Control

```bash
cd ~/dev/stynpilot && claude remote-control --name "Ryzen"
```

Press the **spacebar** to show a QR code, scan it with your phone, and the session opens in the Claude app. **Leave this terminal window open.** Closing it ends the session.

## 6. First test (from your phone)

Send this message in the session:

> Read README.md and summarize it in three lines. Then run ./scripts/check.sh and tell me exactly how many tests ran and whether they passed. Then create notes/hello.txt containing today's date and show me `git status`.

When Claude asks permission to run a command or edit a file, the request appears on your phone. Read it, then approve it.

**Success:** you get the summary, a test result that matches what the terminal shows, and `git status` listing `notes/hello.txt`. Send a screenshot of the result to ChatGPT or to me.

## Stop, undo, remove

- **Stop:** press `Ctrl+C` in the Remote Control terminal.
- **Undo test changes:** run `cd ~/dev/stynpilot && git status`, then `git checkout -- . && git clean -fd` to throw away uncommitted edits.
- **Remove Claude Code completely:** `rm -f ~/.local/bin/claude && rm -rf ~/.local/share/claude ~/.claude ~/.claude.json`
- **Undo the whole system:** open Timeshift and restore the snapshot from step 1.

## Not yet (after the first test works)

- **Starting automatically at boot:** not until the manual session works.
- **Installing software that needs `sudo`:** Claude can't do this yet, because it doesn't have your password and shouldn't. For now Claude tells you the exact command and you paste it yourself. The options for later are in "Privileged installs" below.
- **Turning off permission prompts globally:** no.

## Privileged installs: how owner approval can work

| Option | How it works | Your effort | Risk |
| --- | --- | --- | --- |
| A. You run it | Claude writes the exact `sudo` command and you paste it into the terminal | A terminal paste each time | Lowest |
| B. Narrow sudo rule | A rule lets Claude's account run only package installs (`apt-get install`, `flatpak install`) without a password. Claude still asks you on your phone before each one. | One approval tap | Package installs run scripts as root, so this equals trusting Claude with root on this machine. Acceptable on a fresh test computer with a Timeshift snapshot; not on a machine with personal data. |
| C. StyNpilot broker (the product) | The AI submits an exact plan, you approve that plan on your phone, and a separate root helper runs exactly that plan once | One approval tap | Lowest risk among the options that need no typing. This is what `src/stynpilot/plan.py` is the first piece of. |

Start with A. Move to B only if you decide to, and only after a Timeshift snapshot. C replaces B when it's built and tested.
