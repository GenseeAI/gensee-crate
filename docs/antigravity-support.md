# Antigravity Support

Status: **native hook support plus sidecar policy coverage**.

Antigravity documents JSON hooks in `hooks.json` under a customization
directory such as workspace `.agents/` or `~/.gemini/config/`. Gensee supports
that contract with `gensee setup antigravity` and `gensee hook antigravity`.

The installed Antigravity desktop chat surface may not show a `/hooks` slash
command. That does not mean hooks are unavailable; the supported setup path is
the documented `hooks.json` file.

## Setup

Build or install `gensee`, then configure global Antigravity hooks:

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup antigravity
```

By default, setup writes `~/.gemini/config/hooks.json`. For a custom binary or
workspace-local Antigravity hook file:

```bash
./target/debug/gensee setup antigravity \
  --gensee-home "$PWD/.gensee-dev" \
  --hooks "/path/to/workspace/.agents/hooks.json" \
  --bin "$PWD/target/debug/gensee"
```

Restart Antigravity after changing hook settings.

Prefer the global hook file for local desktop use so every Antigravity project
gets the same Gensee policy bridge. Use workspace-local `.agents/hooks.json`
only when a project intentionally needs a different hook setup. Avoid keeping
multiple `.agents/hooks.json` files under one selected workspace tree unless
you intentionally want Antigravity to load more than one hook definition;
otherwise repeated tool attempts can show duplicate audit rows.

## Installed Hooks

Gensee installs a `gensee-policy` hook with:

- `PreToolUse` for inline allow/ask/deny policy decisions.
- `PostToolUse` for recording completed tool activity and write-time artifact
  observations.
- `PreInvocation` for memory, skill, plugin, and rule integrity checks before
  the next model call.

The generated command is equivalent to:

```bash
GENSEE_HOME=/absolute/gensee-home /absolute/path/to/gensee hook antigravity
```

## Coverage

Gensee parses Antigravity's documented `toolCall` payloads:

- `run_command` shell commands.
- file and directory tools such as `view_file`, `write_to_file`,
  `replace_file_content`, `multi_replace_file_content`, `list_dir`, and
  `find_by_name`.
- `conversationId`, `workspacePaths`, `transcriptPath`, `stepIdx`, and error
  metadata for timeline attribution.

The hook response uses Antigravity's native top-level schema:

```json
{"decision":"ask","reason":"Requires review"}
```

`PreInvocation` poison notices are returned as Antigravity `injectSteps` with an
ephemeral security message.

## Policy Coverage

The default policy recognizes Antigravity customizations under `.agents/`:

- `.agents/hooks.json` and `~/.gemini/config/hooks.json` are
  persistence/control-plane files.
- `.agents/skills/`, `.agents/plugins/`, and `.agents/rules/` are instruction
  artifacts.
- Antigravity MCP and sidecar configuration under `~/.gemini/config` are
  persistence/control-plane paths.
- Antigravity state under `~/.gemini/antigravity` is classified as
  control-plane state where appropriate.

You can still run `gensee watch --workspace <repo>` beside Antigravity for
sidecar filesystem audit, and use `gensee run -- <antigravity command>` when a
runnable command surface is available and you want managed launch controls.
