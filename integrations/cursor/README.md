# Cursor Integration

Hook bridge for Cursor session, request, tool-call attribution, and deterministic
policy enforcement.

## Setup

Build or install `gensee`, then let the setup command write Cursor hooks:

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup cursor
```

The setup command merges Gensee into `~/.cursor/hooks.json`, preserving
non-Gensee commands in the same events and replacing stale or duplicate Gensee
entries. Changed files are backed up and written atomically; unchanged setup
runs do not create another backup. Cursor watches `hooks.json` and reloads it
automatically; for enforcement to take full effect, fully restart Cursor after
running setup.

For a custom hooks path or binary path:

```bash
./target/debug/gensee setup cursor \
  --gensee-home "$PWD/.gensee-dev" \
  --hooks "$HOME/.cursor/hooks.json" \
  --bin "$PWD/target/debug/gensee"
```

## Installed Hooks

Gensee configures one command hook for these Cursor events:

- `preToolUse` — fires before every tool call (Shell, Write, Delete, MCP, …)
- `postToolUse` — fires after successful tool execution
- `beforeShellExecution` — fires before every shell command; supports `ask` to pop a UI dialog
- `beforeSubmitPrompt` — fires before each user prompt is submitted
- `stop` — fires when the agent loop ends

The generated command is equivalent to:

```bash
GENSEE_HOME=/absolute/gensee-home /absolute/path/to/gensee hook cursor
```

Cursor may also load Claude-compatible hook settings. Gensee detects imported
Claude invocations from conservative Cursor runtime markers and suppresses one
only when a native Gensee Cursor hook covers the same event. Otherwise the
payload is processed through the Cursor parser, preserving enforcement without
requiring users to remove either configuration.

A hand-editable `~/.cursor/hooks.json` looks like:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook cursor",
        "timeout": 30
      }
    ],
    "postToolUse": [
      {
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook cursor",
        "timeout": 30
      }
    ],
    "beforeShellExecution": [
      {
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook cursor",
        "timeout": 30
      }
    ],
    "beforeSubmitPrompt": [
      {
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook cursor",
        "timeout": 30
      }
    ],
    "stop": [
      {
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook cursor",
        "timeout": 30
      }
    ]
  }
}
```

Prefer `gensee setup cursor` when possible because it quotes absolute paths
correctly and preserves any unrelated hook settings in the file.

## Enforcement Behavior

Gensee records all configured Cursor hook events into the local store and
evaluates the same policy subjects used by other agent providers.

Cursor `preToolUse`:

- `allow` findings emit no hook output, so Cursor proceeds normally.
- `warn` findings are recorded and emit no output, so Cursor proceeds while
  the dashboard/timeline still surfaces the concern.
- `ask` findings emit `{ "permission": "ask" }`. Cursor's schema accepts this
  value but does not currently pop an approval dialog for `preToolUse`; the
  finding is still recorded.
- `block` findings emit `{ "permission": "deny", "user_message": "...",
  "agent_message": "..." }` and Cursor blocks the tool call.
- Known or file-shaped tools whose paths cannot be parsed safely produce an
  `ask` response instead of passing silently. Gensee also records a
  `hook_schema_drift` telemetry event when local collection is enabled.

Cursor `beforeShellExecution`:

- Gensee evaluates the shell command against the same policy rules as
  `preToolUse`. This hook is registered separately because Cursor supports
  `"ask"` here (pops a UI approval dialog), whereas `preToolUse` treats `"ask"`
  as unenforceable.
- `allow` / `warn` findings emit `{ "permission": "allow" }`.
- `ask` findings emit `{ "permission": "ask", ... }` to trigger the dialog.
- `block` findings emit `{ "permission": "deny", ... }`.

Cursor `beforeSubmitPrompt`:

- Gensee scans auto-loaded memory and skill files for instruction-override
  poison before each prompt is sent.
- Findings are recorded in the dashboard/timeline.
- The prompt always proceeds (`continue: true`); the downstream `preToolUse`
  and `beforeShellExecution` rules hard-block any harmful action the poisoned
  instruction might trigger.
- A `user_message` security notice is included in the response. Cursor's schema
  documents this field as "shown when blocked", so it may not be visible when
  `continue: true`, but it is included for forward-compatibility.
- Repeated notices are quieted per session.

## Hook Event Mapping

Cursor uses camelCase event names. Gensee normalizes them internally:

| Cursor event           | Internal name     | Handling                          |
|------------------------|-------------------|-----------------------------------|
| `preToolUse`           | `PreToolUse`      | Policy evaluation + enforcement   |
| `postToolUse`          | `PostToolUse`     | Artifact observation + recording  |
| `beforeShellExecution` | `PermissionRequest`| Bash policy evaluation (if configured) |
| `beforeSubmitPrompt`   | `UserPromptSubmit`| Memory/skill integrity scan       |
| `stop`                 | `Stop`            | Session record                    |

The `conversation_id` field Cursor sends is stored as `session_id` so events
group correctly in `gensee timeline`.

## Viewing Results

```bash
GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee timeline --latest
```

For runtime verification, exercise one shell command and one file operation in
your installed Cursor build, then confirm both appear in the latest timeline.
