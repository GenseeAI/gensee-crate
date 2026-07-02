# Claude Code hooks

Claude Code hooks record prompts and tool intent and enforce the deterministic
[safety policy](policy.md). Hooks are separate from
[`gensee watch`](watch.md): `watch` observes filesystem effects and macOS system
events, while Claude Code must be configured to call `gensee hook claude-code`
for user prompts and tool intent. Use the same `GENSEE_HOME` for `watch`, hooks,
and `timeline` when you want the signals to appear together.

> The examples below use `/path/to/gensee-crate/target/debug/gensee` — replace
> it with the absolute path to your built binary, and pick a `GENSEE_HOME`.

## Build

```bash
cargo build -p gensee-crate-cli
```

## Configure `~/.claude/settings.json`

Install or update the Claude Code hook config:

```bash
gensee setup claude-code --gensee-home "$GENSEE_HOME"
```

When running from a source checkout, invoke the binary you built:

```bash
./target/debug/gensee setup claude-code --gensee-home "$GENSEE_HOME"
```

The setup command backs up the previous settings file, preserves unrelated
settings, and installs hooks for `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
and `Stop`.

To route Claude Code traffic through an inspecting company gateway at the same
time, pass the gateway URL and one credential source:

```bash
gensee setup claude-code \
  --gensee-home "$GENSEE_HOME" \
  --anthropic-base-url https://llm-gateway.example.com \
  --anthropic-auth-token "$GATEWAY_TOKEN"
```

Use `--anthropic-api-key` instead when the gateway expects `x-api-key`, or
`--api-key-helper ~/bin/get-gateway-key` when credentials come from SSO or a
vault. The setup command writes these values into the `env` block of
`~/.claude/settings.json` and removes stale static Claude credentials that would
conflict with the selected gateway credential.

This makes requests observable by the gateway; the gateway must still log,
reject, or canonicalize suspicious request bodies itself. For strict enforcement,
pair this with network policy that blocks direct Claude provider egress from
developer machines.

## Local Anthropic gateway screening

For local testing or a small team rollout, Gensee ships a minimal
Anthropic-compatible gateway:

```bash
cargo build -p gensee-crate-cli

GENSEE_HOME="$GENSEE_HOME" \
GENSEE_BIN="$PWD/target/debug/gensee" \
GENSEE_GATEWAY_TOKEN="local-gateway-token" \
ANTHROPIC_UPSTREAM_API_KEY="$ANTHROPIC_API_KEY" \
node scripts/anthropic_gateway.mjs
```

Then configure Claude Code to use the local gateway:

```bash
./target/debug/gensee setup claude-code \
  --gensee-home "$GENSEE_HOME" \
  --anthropic-base-url http://127.0.0.1:8787 \
  --anthropic-auth-token local-gateway-token
```

The gateway screens JSON request bodies before forwarding to Anthropic. By
default it blocks invisible/bidirectional/variation/tag Unicode markers anywhere
in the request, and blocks variant punctuation in trusted prompt scaffolding such
as `system` and tool descriptions. Blocks are recorded with
`policy_prompt_steganography_detected` through `gensee gateway-alert`, so they
appear in `timeline` and the dashboard. Set `GENSEE_GATEWAY_STEGO_ACTION=warn`
to record but forward suspicious requests.

The relevant settings shape is:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://llm-gateway.example.com",
    "ANTHROPIC_AUTH_TOKEN": "sk-gateway-token"
  },
  "hooks": {
    "UserPromptSubmit": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "GENSEE_HOME=/tmp/gensee-watch-store /path/to/gensee-crate/target/debug/gensee hook claude-code" } ] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "GENSEE_HOME=/tmp/gensee-watch-store /path/to/gensee-crate/target/debug/gensee hook claude-code" } ] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "GENSEE_HOME=/tmp/gensee-watch-store /path/to/gensee-crate/target/debug/gensee hook claude-code" } ] }
    ],
    "Stop": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "GENSEE_HOME=/tmp/gensee-watch-store /path/to/gensee-crate/target/debug/gensee hook claude-code" } ] }
    ]
  }
}
```

## Run

Fully restart Claude Code, then run the sidecar plus Claude normally:

```bash
GENSEE_HOME=/tmp/gensee-watch-store ./target/debug/gensee watch \
  --workspace /path/to/project --watch-root ~/.aws --watch-root ~/.ssh
```

```bash
cd /path/to/project && claude
```

After Claude runs tools, inspect the combined timeline:

```bash
GENSEE_HOME=/tmp/gensee-watch-store ./target/debug/gensee timeline
```

## What is recorded

Hook events are stored in `$GENSEE_HOME/hooks.jsonl` (or `~/.gensee/hooks.jsonl`
when `GENSEE_HOME` is not set). `UserPromptSubmit` prompts and `Stop` assistant
responses are stored from the **redacted** Claude hook payload and shown in
`timeline` as per-turn conversation events.

Redaction is pattern-based: known secret assignments, secret-looking JSON
fields, private keys, and common token prefixes are redacted, but ordinary
prompt and response text is otherwise persisted.

For `PreToolUse`, the bridge makes a deterministic policy decision and returns
`allow`, `ask`, or `deny` to Claude Code — see [policy.md](policy.md).

Bash file intents are parsed from Claude tool commands; copy commands are
represented as `copy_source` and `copy_dest` so later graph logic can trace
lineage from the input path to the output path. File effects whose timestamps
fall inside a Claude `PreToolUse`/`PostToolUse` window are shown under that tool
call as time-window correlated evidence. This correlation is **not** PID proof;
FSEvents does not expose the actor process.
