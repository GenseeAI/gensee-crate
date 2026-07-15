# VS Code / GitHub Copilot Integration

Hook bridge for VS Code agent session, request, and tool-call attribution and
deterministic policy enforcement.

## Setup

Build or install `gensee`, then let the setup command write VS Code hooks:

```bash
cargo build -p gensee-crate-cli
GENSEE_HOME="$PWD/.gensee-dev" ./target/debug/gensee setup vscode
```

The setup command writes `~/.copilot/hooks/gensee.json`, backs up any existing
file, and prints the exact hook command it installed. VS Code reloads hook files
automatically when they are saved.

For a custom hooks path or binary path:

```bash
./target/debug/gensee setup vscode \
  --gensee-home "$PWD/.gensee-dev" \
  --hooks "$HOME/.copilot/hooks/gensee.json" \
  --bin "$PWD/target/debug/gensee"
```

For project-level hooks (checked into source control, shared with the team):

```bash
./target/debug/gensee setup vscode \
  --gensee-home "$GENSEE_HOME" \
  --hooks ".github/hooks/gensee.json"
```

## Hook file locations

VS Code searches for hooks in several places. All of these work with the hook
command written by `gensee setup vscode`:

| Location | Scope |
|---|---|
| `~/.copilot/hooks/gensee.json` | User-level (default) |
| `.github/hooks/gensee.json` | Workspace / project (team-shared) |
| `~/.claude/settings.json` | Also read by VS Code (Claude Code compat) |

Note: VS Code also reads `.claude/settings.json` natively, so an existing
`gensee setup claude-code` installation already fires hooks inside VS Code.
The `vscode` provider adds correct parsing of VS Code-specific tool names
(e.g. `runTerminalCommand` and `runInTerminal` for shell commands) that the
`claude-code` provider does not handle.

## Installed Hooks

Gensee configures one command hook for these VS Code events:

- `UserPromptSubmit` — fires before each user prompt is submitted
- `PreToolUse` — fires before every tool call
- `PostToolUse` — fires after successful tool execution
- `Stop` — fires when the agent session ends

The generated `~/.copilot/hooks/gensee.json` looks like:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "type": "command",
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook vscode",
        "timeout": 30
      }
    ],
    "PreToolUse": [
      {
        "type": "command",
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook vscode",
        "timeout": 30
      }
    ],
    "PostToolUse": [
      {
        "type": "command",
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook vscode",
        "timeout": 30
      }
    ],
    "Stop": [
      {
        "type": "command",
        "command": "GENSEE_HOME=/path/to/gensee-store /path/to/gensee hook vscode",
        "timeout": 30
      }
    ]
  }
}
```

VS Code uses a flat hook entry format (no nested `matcher`/`hooks` arrays like
Claude Code). Prefer `gensee setup vscode` when possible because it quotes
absolute paths correctly and preserves any unrelated hook settings in the file.

## Enforcement Behavior

### `PreToolUse`

The output format is identical to Claude Code (`hookSpecificOutput` with
`permissionDecision`):

- `allow` / `warn` → `{ "hookSpecificOutput": { "permissionDecision": "allow" } }`
- `ask` → `{ "hookSpecificOutput": { "permissionDecision": "ask" } }` — VS Code
  prompts the user for approval before running the tool.
- `block` → `{ "hookSpecificOutput": { "permissionDecision": "deny" } }` — VS Code
  blocks the tool call and shows the reason to the user.

### `UserPromptSubmit`

- Gensee scans auto-loaded memory and skill files for instruction-override poison.
- Findings are recorded in the dashboard/timeline.
- The prompt always proceeds (`continue: true`) so the turn runs; the downstream
  `PreToolUse` rules hard-block any harmful action.
- When poison is found, a `systemMessage` security notice is shown to the user
  directly in the VS Code chat panel. This is more visible than Claude Code's
  model-only `additionalContext`.
- Repeated notices are quieted per session.

## VS Code tool name mapping

VS Code uses different tool names from Claude Code. Gensee maps them correctly:

| VS Code tool | Operation | Notes |
|---|---|---|
| `runTerminalCommand`, `runInTerminal` | Bash shell command | Full bash intent parsing applied |
| `editFiles` | File edit (multi-file) | `tool_input.files` array |
| `createFile`, `create_file` | File write | `tool_input.filePath` |
| `replaceStringInFile`, `replace_string_in_file` | File write | `tool_input.filePath` |
| `readFile` | File read | `tool_input.filePath` |
| `deleteFile` | File delete | `tool_input.filePath` |

## Viewing Results

```bash
GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee timeline --latest
```
