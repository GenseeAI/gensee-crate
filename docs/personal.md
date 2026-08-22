# Gensee Crate Personal

Gensee Crate Personal is a local-first macOS app and CLI for individual
developers who delegate work to Codex, Claude Code, Cursor, GitHub Copilot,
Antigravity, or Omnigent. It lets routine work continue quietly and brings you
back when the outcome needs a decision: scope drift, missing or stale
verification, a blocked or high-risk operation, or incomplete evidence.

Your policy, activity, reviews, audit baselines, recovery metadata, and feedback
remain in your local Gensee store.

## Start with the macOS app

**[Download the latest notarized macOS app](https://github.com/GenseeAI/gensee-crate/releases/latest/download/Gensee-Crate.dmg)**

The signed app bundles the Gensee backend and SQLite support. It does not
require Homebrew, Rust, Xcode, `jq`, or a separate SQLite installation. Follow
the [Gensee Crate Personal for macOS guide](macos-app.md) for installation,
first-run setup, optional Apple approvals, harness protection, and local data
controls.

## What Personal adds

- A **Review Queue** that groups work by session and request instead of making
  you search several agent transcripts.
- **Scope-drift detection** that compares declared tool intent with file
  mutations independently observed by macOS Endpoint Security.
- **Smart recovery points** before risky Git-workspace changes, with a Restore
  action on the matching request.
- **Configuration Audit** for instructions, skills, MCP servers, hooks,
  permissions, plugins, command rules, and other inputs that can change agent
  behavior.
- Request-scoped timelines, affected files, grouped findings, verification
  freshness, local policy decisions, activity highlights, native notifications,
  and a menu-bar review summary.

Endpoint Security and Full Disk Access are optional. Hook-based reviews, smart
recovery points, and Config Audit provide value before you grant broad system
access. Enable the independent sensor later when you want operating-system
verification of supported process and file activity.

## See it in use

![Gensee Crate Personal overview showing work that needs review and recent activity](images/personal/gensee-crate-personal-overview.png)

*Start with the work that needs you; clean completions remain available without
creating noise.*

![Gensee Crate Personal Review Queue showing scope drift, findings, and a recovery point](images/personal/gensee-crate-personal-review-queue.png)

*Review scope drift, evidence, affected files, verification freshness, and the
recovery point in one request-scoped view.*

![Gensee Crate Personal configuration audit with prioritized Codex findings](images/personal/gensee-crate-personal-config-audit.png)

*Audit static agent configuration without running it.*

## Use the CLI instead

Install the CLI and initialize the local store:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | bash
export GENSEE_HOME="${GENSEE_HOME:-$HOME/.gensee}"
```

Configure the harnesses you use:

```bash
gensee setup codex --gensee-home "$GENSEE_HOME"
gensee setup claude-code --gensee-home "$GENSEE_HOME"
```

Run an agent through Gensee when you want an explicit managed session:

```bash
gensee run -- codex
# or
gensee run -- claude
```

Inspect configuration and recorded work:

```bash
gensee audit codex
gensee run list --json
gensee timeline --latest
gensee status --json
```

The app is the recommended macOS experience. The CLI remains useful for
automation, terminals, and Linux workstations. Continue with [harness
integrations](claude-code-hooks.md), [policy](policy.md), [Config
Audit](config-audit.md), or [managed run modes](run-and-sandbox.md).

## Current boundaries

Recovery points restore Git-workspace files. They cannot undo database changes,
network requests, remote repository actions, running processes, ignored files,
or files outside the selected Git workspace. Endpoint Security verifies
supported operating-system activity but is not a packet-level network sensor.
