# Antigravity Integration

Gensee supports Antigravity's documented `hooks.json` lifecycle hooks and keeps
the sidecar/watch coverage for runs where hooks are not installed.

## Setup

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup antigravity
```

The setup command writes the global Antigravity hook file at
`~/.gemini/config/hooks.json` by default. Use
`--hooks /path/to/workspace/.agents/hooks.json` only when a project needs a
workspace-local hook definition. Existing non-Gensee commands in Gensee's
managed events are preserved, while stale or duplicate Gensee commands are
replaced. Changed files are backed up and written atomically; unchanged setup
runs do not rewrite them.

## What Gensee Protects

- `PreToolUse` returns Antigravity-native `allow`, `ask`, or `deny` decisions.
- `PostToolUse` records completed tool activity and artifact observations.
- `PreInvocation` scans auto-loaded memory, skills, plugins, and rules for
  instruction-poisoning and injects an ephemeral counter-instruction when
  needed.
- `gensee watch` can still record filesystem effects while Antigravity agents
  work in a repository.
- `gensee run -- <antigravity command>` can launch a runnable Antigravity
  surface under Gensee's managed runtime controls.

The default policy treats Antigravity `.agents/` customizations and
`~/.gemini/config` files as agent control-plane or instruction artifacts,
including `.agents/hooks.json`, skills, plugins, rules, MCP config, and
sidecars.

See [`docs/antigravity-support.md`](../../docs/antigravity-support.md) for the
full contract and smoke-test examples.
