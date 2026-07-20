# Codex Integration

Hook bridge for Codex session, request, tool-call attribution, and deterministic
policy enforcement.

## Setup

Build or install `gensee`, then let the setup command write Codex hooks:

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup codex
```

The setup command merges Gensee into `~/.codex/hooks.json`, preserving
non-Gensee commands in the same events and replacing stale or duplicate Gensee
entries. Changed files are backed up and written atomically; unchanged setup
runs do not rewrite them. The command prints the exact hook it installed. Open
`/hooks` in Codex and trust the
Gensee hook before testing enforcement. Codex records trust against the hook
definition, so re-trust it when the binary path, command, or `GENSEE_HOME`
changes.

For a custom hooks path or binary path:

```bash
./target/debug/gensee setup codex \
  --gensee-home "$PWD/.gensee-dev" \
  --hooks "$HOME/.codex/hooks.json" \
  --bin "$PWD/target/debug/gensee"
```

For non-interactive automation only, Codex may also be run with its
hook-trust bypass flag. Do not use that as the normal local setup path; it skips
the review step that helps users see which commands will run.

## Installed Hooks

Gensee configures one command hook for these Codex events:

- `UserPromptSubmit`
- `PreToolUse`
- `PermissionRequest`
- `PostToolUse`
- `Stop`

The generated command is equivalent to:

```bash
GENSEE_HOME=/absolute/gensee-home /absolute/path/to/gensee hook codex
```

See [hooks.sample.json](hooks.sample.json) for a hand-editable example. Prefer
`gensee setup codex` when possible because it quotes absolute paths correctly
and preserves any unrelated hook settings in the file.

## Enforcement Behavior

Gensee records all configured Codex hook events into the local store. For tool
gates, it evaluates the same policy subjects used by other agent providers.

Codex `PreToolUse`:

- `allow` findings emit no hook output, so Codex proceeds normally.
- `ask` findings are recorded as `warn` alerts and emit no hook output, so
  Codex proceeds while the dashboard/timeline still surfaces the concern.
- Fork suggestions for exploratory commands are recorded as `allow` alerts in
  the dashboard/timeline. Codex `PreToolUse` stays silent for these non-blocking
  suggestions because Codex does not accept a visible allow-level message today.
- `block` findings emit a Codex `deny`.

Codex `PermissionRequest`:

- Gensee parses the top-level `command` field and evaluates it as Bash intent.
- `allow` emits an explicit `allow` response.
- `ask` findings are recorded as `warn` and emit `allow`.
- `block` emits `deny`.
- Missing or unparseable commands fail closed with a high-severity alert.

Codex `UserPromptSubmit`:

- Gensee scans auto-loaded memory and skill files for instruction-override
  poison.
- Repeated notices are quieted per session so the hook does not spam the user.
- Findings are recorded in the dashboard/timeline.

## Smoke Tests

Use a repo-local store so hook output, timeline, and dashboard all read the same
data:

```bash
export GENSEE_HOME="$PWD/.gensee-dev"
cargo build -p gensee-crate-cli
```

PreToolUse deny:

```bash
sed "s#__CWD__#$PWD#g" integrations/codex/smoke-pretool-deny.json \
  | ./target/debug/gensee hook codex
```

Expected output contains:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}
```

PermissionRequest deny:

```bash
sed "s#__CWD__#$PWD#g" integrations/codex/smoke-permission-request-deny.json \
  | ./target/debug/gensee hook codex
```

Expected output contains:

```json
{"hookSpecificOutput":{"hookEventName":"PermissionRequest","permissionDecision":"deny"}}
```

Allowed command:

```bash
printf '%s\n' '{"session_id":"smoke","hook_event_name":"PreToolUse","cwd":"'"$PWD"'","tool_name":"Bash","tool_use_id":"ok","tool_input":{"command":"pwd"}}' \
  | ./target/debug/gensee hook codex
```

Expected output is empty. The event is still recorded:

```bash
./target/debug/gensee timeline --latest
```

## What Gets Parsed

Current Codex coverage includes:

- user prompts and assistant stop responses, redacted before storage;
- Bash commands from `tool_input.command`;
- Codex approval commands from top-level `PermissionRequest.command`;
- `apply_patch` changed paths from the documented command field and common
  fallback shapes;
- MCP tools named `mcp__<service>__<method>` through common explicit path/file,
  command, and URL fields;
- tool stdout/stderr, duration, interruption state, permission mode, and effort
  level when present.

MCP tool argument schemas are service-specific. The generic parser deliberately
avoids free-form text fields; add deeper parser coverage per MCP server when a
concrete server is in scope.

## Troubleshooting

- **No events in timeline/dashboard:** make sure the hook, `gensee timeline`,
  and dashboard are using the same `GENSEE_HOME`.
- **Codex says the hook is untrusted:** open `/hooks`, review the command, and
  trust it. Re-run this when setup changes the hook command.
- **Allowed hooks print output:** Codex `PreToolUse` allow should be silent. If
  it prints a bare `permissionDecision: "allow"`, check that the provider is
  `codex` and the binary includes the provider-aware decision adapter.
- **Denied command missing from timeline:** check whether Codex denied before a
  tool call. Gensee derives unsafe agent refusals from user prompts and
  assistant responses when no tool event exists.
