# Cursor hooks

Gensee connects to Cursor's native hooks to record prompts and tool calls and
to evaluate file and shell operations before they run.

## Setup

Build or install `gensee`, then configure the global Cursor hook file:

```bash
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup cursor
```

By default this updates `~/.cursor/hooks.json`. Existing non-Gensee commands,
including commands registered for the same events, are preserved; stale or
duplicate Gensee commands are replaced with one current entry. Changed files
are backed up and written atomically, while unchanged setup runs do not create
additional backups. Restart Cursor after setup.

Cursor can also import Claude-compatible hook settings. If Gensee's Claude Code
hooks are present, Gensee recognizes Cursor payloads using `cursor_version` plus
an independent conversation or transcript marker. A Claude compatibility
invocation is suppressed only after the matching native Cursor invocation has
been observed recently for the same conversation, normalized event, and tool or
generation ID. Hook configuration on disk is not treated as proof that a native
hook is live. If the compatibility invocation wins a startup race, required
identifiers are absent, or evidence cannot be read, it continues through the
Cursor parser. This can produce a duplicate event but preserves enforcement.

Gensee writes a warning to the host hook log on the first suppressed
compatibility invocation and periodically thereafter. The notice is rate-limited
per native provider and does not depend on telemetry collection being enabled.

The one-line installer can configure Cursor non-interactively:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh \
  | GENSEE_CONFIGURE_CURSOR=1 bash
```

For custom paths:

```bash
gensee setup cursor \
  --gensee-home /absolute/gensee-home \
  --hooks /absolute/path/to/hooks.json \
  --bin /absolute/path/to/gensee
```

## Hook coverage

Gensee installs handlers for `preToolUse`, `postToolUse`,
`beforeShellExecution`, `beforeSubmitPrompt`, and `stop`. Cursor's
`conversation_id` is stored as the Gensee session ID so related events group in
the dashboard and timeline.

Before a tool runs, known file operations are evaluated against path policy.
If a known or file-shaped Cursor tool cannot be parsed safely, Gensee asks for
review instead of allowing it silently and records a `hook_schema_drift`
telemetry event when local telemetry collection is enabled.

## Verification

After restarting Cursor, run one shell command and create one file from an
agent request. Then inspect the latest session:

```bash
GENSEE_HOME="$PWD/.gensee-dev" gensee timeline --latest
```

Confirm that the shell command and file path appear and that policy decisions
match the active policy. Cursor payloads can change between builds, so this
live check complements the checked-in parser tests.

For the generated JSON shape, event mapping, and enforcement responses, see
the [integration reference](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/cursor).
