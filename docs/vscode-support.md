# VS Code / GitHub Copilot hooks

Gensee integrates with VS Code agent mode through its command-hook interface.
The hook records prompts and tool intent in the shared Gensee timeline and
evaluates `PreToolUse` events against the active safety policy before a tool
runs.

## Setup

Install Gensee, then configure the user-level VS Code hooks file:

```bash
gensee setup vscode --gensee-home "$GENSEE_HOME"
```

When running from a source checkout:

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup vscode
```

The setup command writes `~/.copilot/hooks/gensee.json`, preserves unrelated
hook entries, backs up an existing file, and prints the exact command it
installed. VS Code reloads hook files automatically when they are saved.

The one-line installer also supports an explicit VS Code toggle:

```bash
curl -fsSL https://raw.githubusercontent.com/GenseeAI/gensee-crate/main/scripts/install_oss.sh | GENSEE_CONFIGURE_VSCODE=1 bash
```

VS Code also loads Claude-compatible hooks from `~/.claude/settings.json`. If
Claude Code hooks are already installed, they may run inside VS Code too. Avoid
configuring both the Claude Code and VS Code providers for the same VS Code
sessions, because that can invoke Gensee twice. The dedicated `vscode` provider
is preferred when VS Code-native tool names must be parsed correctly.

## Custom hook locations

Pass `--hooks` for another user-level path or for a workspace hook checked into
source control:

```bash
gensee setup vscode \
  --gensee-home "$GENSEE_HOME" \
  --hooks .github/hooks/gensee.json
```

Use `--bin` when the generated hook should call a different Gensee binary:

```bash
gensee setup vscode \
  --gensee-home "$GENSEE_HOME" \
  --bin /absolute/path/to/gensee
```

## Enforcement behavior

Gensee installs hooks for `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and
`Stop`. `PreToolUse` returns VS Code's allow, ask, or deny decision before the
tool runs. Known native file tools are converted into read, write, edit, or
delete policy subjects:

| VS Code tool | Policy operation |
| --- | --- |
| `runTerminalCommand`, `runInTerminal` | Shell command and parsed file intents |
| `editFiles`, `edit_files` | Edit each path in `tool_input.files` |
| `createFile`, `create_file` | Write |
| `replaceStringInFile`, `replace_string_in_file` | Write |
| `insertEditIntoFile`, `insert_edit_into_file` | Write |
| `readFile`, `read_file` | Read |
| `deleteFile`, `delete_file` | Delete |

If a known file tool cannot be parsed, or an unknown tool carries file-shaped
inputs, Gensee asks for approval instead of silently bypassing path policy. It
also records a schema-drift event so runtime payload changes are visible.

## Verify the installation

Run one terminal command and one file creation through VS Code agent mode, then
inspect the VS Code Agent Log to confirm the actual `tool_name` and `tool_input`
payloads. Hook schemas are evolving, so the runtime log is the source of truth
for the installed VS Code build.

Inspect the resulting Gensee activity with:

```bash
gensee timeline --latest
```

For generated hook JSON examples and implementation details, see the
[integration README](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/vscode).
