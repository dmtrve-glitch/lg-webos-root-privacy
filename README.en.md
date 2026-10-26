# LG webOS Root & Privacy Skill

[English](README.en.md) | [Русский](README.md)

A portable skill for **Codex and Claude Code** to check LG webOS root compatibility, audit advertising and data collection, apply reversible system controls, and restore the original behavior.

The skill provides a workflow and helper scripts for an agent running on a computer connected to your TV's local network. It selects an approach using the full model number, region, hardware platform, webOS version, and firmware version. Rooting and replacing firmware are separate operations; this repository does not provide a universal firmware image or flasher.

## Features

- Identify the TV, software versions, and existing root access, then verify compatibility against current primary sources.
- Pair through SSAP and use a temporary maintenance channel after a compatible root service has been installed.
- Audit ACR, capture, advertising, recommendations, and diagnostic uploads through processes, executables, and startup configuration.
- Prepare an explicit component plan with original SHA-256 hashes and functional consequences; preserve features you need, including universal remote control.
- Apply a trial with an independent rollback timer, enable persistence after validation, and validate the first reboot separately.
- Separate evidence from interpretation: a process name does not prove screenshot uploads, and a short period without connections does not prove the absence of collection.

Applications and game emulators are outside this skill's scope. Third-party rooting code is obtained and reviewed separately after the agent establishes compatibility.

## Installation

You need Git and a local installation of Codex or Claude Code. Choose the instructions for your agent below. The destination directory must not already exist. The clone commands work in PowerShell and Unix shells such as Bash or Zsh.

### Codex

Clone the repository into your personal skills directory:

```sh
git clone https://github.com/dmtrve-glitch/lg-webos-root-privacy.git "$HOME/.agents/skills/lg-webos-root-privacy"
```

This is the user-level location listed in the current [Codex skills documentation](https://learn.chatgpt.com/docs/build-skills). Installations configured to use the earlier `~/.codex/skills` or `CODEX_HOME/skills` location can use that directory instead; verify discovery in your installed version. If the skill does not appear, restart Codex.

Invoke it in a Codex message:

```text
$lg-webos-root-privacy
Check my LG TV on the home network, verify root compatibility, and prepare an advertising and telemetry removal plan with rollback. Keep universal remote control working. Reply in English.
```

### Claude Code

Clone the repository into your personal skills directory:

```sh
git clone https://github.com/dmtrve-glitch/lg-webos-root-privacy.git "$HOME/.claude/skills/lg-webos-root-privacy"
```

Then invoke it in Claude Code:

```text
/lg-webos-root-privacy Check my LG TV on the home network, verify root compatibility, and prepare an advertising and telemetry removal plan with rollback. Keep universal remote control working. Reply in English.
```

If the new directory is not picked up, run `/reload-skills` or restart the session. See the official [Claude Code skills documentation](https://code.claude.com/docs/en/skills).

In either installation, `SKILL.md` must sit directly inside the `lg-webos-root-privacy` directory. Installing the skill does not itself connect to a TV, execute a rooting method, or modify device settings. The core workflow and detailed references are currently written in Russian; you can ask the agent to respond in English.

## Requirements and operation

On the computer: Python 3, Git or another way to obtain reviewed upstream sources, and access to the TV's LAN. The person operating the TV must be able to approve pairing and check the picture and controls.

The bundled system policy runs on the TV and requires Linux root access, Python 2.7 or 3, a compatible bind-mount implementation, and the other facilities listed in [policy.md](references/policy.md). Developer Mode alone is not root. The policy accepts only explicitly selected, reviewed component families; other names or paths require adaptation and review.

Read [SKILL.md](SKILL.md) for the workflow and [INSTALL.md](INSTALL.md) for installation notes. Preserve any existing pairing credentials and session data outside the skill directory.

## Repository contents

| File | Purpose |
| --- | --- |
| [scripts/tv_audit.py](scripts/tv_audit.py) | Bounded inventory on the TV; does not disable components |
| [scripts/tv_bridge.py](scripts/tv_bridge.py) | Pairing, TV information, and temporary execution through an already installed Homebrew root service |
| [scripts/tv_policy.py](scripts/tv_policy.py) | Reversible policy with trial, confirmation, rollback, and a boot hook |
| [scripts/self_test.py](scripts/self_test.py) | Offline checks without a live TV |
| [references/](references/) | Compatibility, audit, transport, recovery, and a historical case |
| [agents/openai.yaml](agents/openai.yaml) | Codex skill metadata |

## Validation

From the repository directory, run:

```sh
python scripts/self_test.py
```

If your system names Python 3 `python3`, use that command instead.

The 18 offline checks cover hash mismatches, partial application failures, mounts owned by another policy, timer expiry, late confirmation, restoration of originally active services, and temporary HTTP-server boundaries. These checks do not establish compatibility with a particular TV. The portable scripts have not been tested on every LG model; the [historical case](references/known-case.md) records an earlier, separately completed setup on one webOS 6 TV.

## Sources and privacy

- [webOS Homebrew: Rooting](https://www.webosbrew.org/rooting/)
- [SlopBro upstream](https://github.com/throwaway96/slopbro)
- [Homebrew Channel](https://github.com/webosbrew/webos-homebrew-channel)

The repository contains no pairing keys, passwords, device-specific IP addresses, serial numbers, MAC addresses, user logs, backups, or firmware images. Keep data from each new session outside the skill directory.

Upstream projects retain their own licenses. SlopBro uses AGPL-3.0; its source code is not bundled here.
