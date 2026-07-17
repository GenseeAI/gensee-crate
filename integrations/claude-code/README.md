# Claude Code Integration

Hook bridge for high-fidelity session, request, and tool-call attribution.

## Hook Bridge With Deterministic Policy

The bridge records Claude Code hook payloads into local JSONL and SQLite. On
`PreToolUse`, it also evaluates a deterministic default policy and can return
`allow`, `ask`, or `deny` to Claude Code.

```bash
cargo build -p gensee-crate-cli
./target/debug/gensee hook claude-code
```

Claude Code should invoke that command from hook settings and pass the hook JSON
on stdin. For development, point `GENSEE_HOME` at a repo-local directory:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee-crate/target/debug/gensee hook claude-code"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee-crate/target/debug/gensee hook claude-code"
          }
        ]
      }
    ]
  }
}
```

The bridge currently extracts:

- `session_id`
- `hook_event_name`
- `cwd`
- `transcript_path`
- `tool_name`
- `tool_use_id`
- nested `tool_input.command`, when present
- nested `tool_input.description`, when present
- nested `tool_response.stdout` and `tool_response.stderr`, when present
- `tool_response.interrupted`
- `duration_ms`
- `permission_mode`
- nested `effort.level`

`gensee timeline` groups matching `PreToolUse` and `PostToolUse` records by
`session_id + tool_use_id`:

```text
Claude Code tool calls
  session=03245ffa... | tool_use=toolu_... | tool=Bash | status=completed | duration=73ms
    command: echo gensee-hook-test
    description: Echo test string
    claude: permission_mode=default effort=high
    stdout: gensee-hook-test
    interrupted: false
```

Use filters when the local JSONL store has old smoke-test rows:

```bash
GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee timeline --latest
GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee timeline --session 03245ffa-0b61-4375-b9c8-1891960ee38e
```

On `PreToolUse`, the bridge also starts a short background process sampler.
When `ps` access is available, newly observed processes in the tool-call window
are correlated back to the same `session_id + tool_use_id`:

```text
Claude Code tool calls
  session=03245ffa... | tool_use=toolu_... | tool=Bash | status=completed | duration=500ms
    command: sleep 0.5
    process correlation:
      source=claude-code-process-sampler confidence=medium pid=37626 ppid=37593 /bin/sleep 0.5
```

The process sampler is still observational. It is a stopgap until
EndpointSecurity is available, so it can miss very short processes or include
unrelated processes that start in the same narrow window. EndpointSecurity
should replace this with exact `exec` attribution.

Layer 1 EndpointSecurity spikes can now be ingested from Apple's `eslogger`:

```bash
sudo cargo run -p gensee-crate-macos --bin endpoint-spike -- exec \
  | GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee ingest eslogger
```

The timeline renders those as `Layer 1 system events`. When their timestamps
fall inside a Claude `PreToolUse`/`PostToolUse` window, they are also shown
under that tool call as kernel-backed system evidence.

The bridge also derives low-confidence file intents from Bash tool input before
the command runs. These are intent-level signals from Claude's requested command,
not ground-truth kernel observations:

```text
file intents:
  source=claude-bash-command-parser confidence=low op=read sensitive=true path=/Users/example/.ssh/config
  source=claude-bash-command-parser confidence=low op=write sensitive=false path=/repo/tmp/demo.txt
  source=claude-bash-command-parser confidence=low op=delete sensitive=false path=/repo/.git/test
```

Currently parsed operations include:

- reads: `cat`, `less`, `more`, `head`, `tail`, `open`
- writes: shell redirection and `tee`
- mutations: `rm`, `mv`, `cp`, `touch`, `mkdir`
- metadata: `chmod`, `chown`, `chgrp`

The rules are data-driven: the engine loads a versioned policy document
(`crate/gensee-crate-rules/policy/default-policy.json` by default). Point
`GENSEE_POLICY_FILE` at a copy to customize it without rebuilding. If that file
is set but unreadable or invalid, the hook **fails closed** — it denies every
tool call (with a `policy_load_failed` reason) rather than silently running the
default policy. The same document drives both the active `PreToolUse` decision
and the passive risk alerts recorded over observed filesystem effects.

The default policy:

- **blocks** protected secret locations (`.ssh`, `.aws`, `.azure`, `.gnupg`,
  `.kube`, `.docker`, `.env`/`.env.*`, `.npmrc`, `.netrc`, `id_rsa`,
  `.git-credentials`, `~/.config/gcloud`, …), while allow-listing
  `.env`-family templates including nested ones (`.env.example`,
  `.env.local.example`, `.env.production.sample`, …);
- **blocks** destructive operations and writes outside the current workspace
  (after lexically folding `..`, so traversal and globs cannot escape);
- **blocks** requests to cloud instance-metadata (IMDS) endpoints — matched only
  against the host of an actual `scheme://host` URL in the command or a tool's
  `url`/`uri` field, not a bare mention elsewhere in the payload;
- **asks** before credential-like filename hints (`credentials.json`),
  persistence/startup files (`.bashrc`, `.zshrc`, `.profile`, `.gitconfig`,
  `.git/hooks/*`, `.vscode/tasks.json`), permission/ownership changes, wildcard
  file operations, and environment-variable dumps (`env`, `printenv`).
- **suggests a forked run** for exploratory commands such as dependency
  upgrades, migrations, broad refactors, lockfile changes, destructive cleanup,
  test-strategy changes, and destructive database commands.

Source files (`.rs`, `.ts`, `.go`, `.css`, …) are never treated as secrets, so
`tokenizer.rs` or `secret_test.go` are not blocked. Set
`GENSEE_POLICY_ALLOW_PATH_PREFIXES` to a colon-separated list of trusted path
prefixes to exempt known-safe project files; the allowlist suppresses only the
secret/credential and persistence findings — destructive, out-of-workspace,
metadata, and wildcard checks still apply under an allowlisted path. Findings
are also persisted to the SQLite `alerts` table and shown in `gensee timeline`.

For `PreToolUse`, stdout is reserved for Claude Code's policy response:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Protected secret read: /Users/example/.ssh/config"}}
```
