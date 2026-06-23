# Design note: OpenAI Codex CLI support

Status: **Implemented baseline**. Tracks the provider-specific contract for
[OpenAI Codex CLI](https://developers.openai.com/codex/) within Gensee's
multi-agent hook architecture.

## TL;DR

Gensee treats coding-agent integrations as explicit providers behind a shared
hook pipeline. Codex is a supported provider in that model. The shield's core
policy engine, SQLite store, lineage model, tamper-evident log, and dashboard
stay provider-generic; only setup, provider tagging, and provider-specific hook
response semantics live at the edge.

Codex-specific edge behavior:

- Codex `PreToolUse` supports `deny` for blocking, and `allow` only as part of
  a tool-call rewrite with `updatedInput`. Gensee emits no hook output for
  allowed or warning-level Codex tool calls, and emits `deny` for hard blocks.
  True interactive approval belongs to Codex's approval-policy flow plus the
  `PermissionRequest` hook.
- Codex file edits arrive through `apply_patch`. Full file-edit coverage needs
  patch parsing in both policy evaluation and lineage/artifact recording.
- Codex non-managed command hooks require user review/trust through `/hooks`,
  and trust is tied to the hook definition hash.

## Verification against a real install and public docs

Checked against local Codex CLI installs and the current public
[Codex hooks doc](https://developers.openai.com/codex/hooks).

Confirmed present:

- **Input fields** (PreToolUse): `session_id`, `turn_id`, `transcript_path`,
  `hook_event_name`, `model`, `permission_mode`, `tool_name`, `tool_input`,
  `tool_use_id`, `tool_response`. Public docs specify that Bash and
  `apply_patch` use `tool_input.command`.
- **Events:** `SessionStart`, `PreToolUse`, `PermissionRequest`,
  `PostToolUse`, `UserPromptSubmit`, `Stop`, `PreCompact`, `PostCompact`,
  `SubagentStart`, `SubagentStop`.
- **Tool names:** `Bash`, `apply_patch`, MCP tools as
  `mcp__<service>__<method>`.
- **Matcher behavior:** `PreToolUse`, `PostToolUse`, and `PermissionRequest`
  match on tool name; `apply_patch` matchers may also use `Edit` or `Write`.
  The public docs specify `matcher` as a regex string, with `"*"`, `""`, or
  an omitted matcher treated as match-all for supported events.
- **Hook timeout:** Codex hook handler `timeout` is in seconds. Setup writes an
  explicit 30-second timeout instead of relying on Codex's 600-second default.
- **Config locations:** `~/.codex/hooks.json`, `~/.codex/config.toml`
  (`[hooks]` table), or project-local `.codex/{hooks.json,config.toml}` when
  the project config layer is trusted.
- **Hook trust:** non-managed command hooks must be reviewed and trusted before
  they run. Codex records trust against the hook definition hash, so changed
  hook commands are skipped until re-trusted.

### Important correction: `allow` / `ask`

Testing against Codex showed that a bare `permissionDecision: "allow"` is
rejected; the public contract reserves `allow` for rewrites that include
`updatedInput`. `permissionDecision: "ask"` is not a supported `PreToolUse`
approval path. Treat `permissionDecision: "deny"` as the Codex `PreToolUse`
decision for hard blocks only; use no output for allowed and warning calls.

Implication for Gensee: Codex needs a provider-aware decision adapter. For
Codex, Gensee `PolicyAction::Allow` and warning-level findings should produce
no `PreToolUse` hook output, while `PolicyAction::Ask` cannot be emitted as
`permissionDecision: "ask"`. The provider adapter downgrades Codex asks to
dashboard-visible warnings unless a hard `Block` finding is present.

1. **Warn and proceed:** convert Gensee `Ask` findings to `warn` alerts and
   emit no `PreToolUse` output, so Codex proceeds while the dashboard/timeline
   still highlights review-worthy behavior. This is the current behavior.
2. **Use Codex-native approvals:** rely on Codex `approval_policy` to make a
   class of actions require approval, then handle the resulting
   `PermissionRequest` hook to allow or deny. This works only for actions Codex
   already routes through its approval boundary; it cannot make arbitrary
   `PreToolUse` findings become interactive prompts.

## Codex hook contract

| Concern | Codex CLI behavior | Gensee handling |
| --- | --- | --- |
| PreToolUse deny | `permissionDecision: "deny"` + reason | Emit for Gensee `Block` findings |
| PreToolUse allow | Exit 0 with no output | Emit nothing so Codex proceeds without an unsupported bare `allow` decision |
| PreToolUse ask | Parsed but unsupported today | Convert `Ask` to `warn` and emit no hook output, or handle `PermissionRequest` when Codex already asks |
| PreToolUse rewrite | `permissionDecision: "allow"` + `updatedInput.command` for Bash/apply_patch | Not implemented; reserve bare `allow` avoidance for non-rewrite allows |
| Input fields | `session_id`, `turn_id`, `transcript_path`, `hook_event_name`, `model`, `permission_mode`, `tool_name`, `tool_input`, `tool_use_id`, `tool_response` | Parsed by `build_hook_event(payload, provider)` |
| Event names | `SessionStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `PreCompact`, `PostCompact`, `SubagentStart`, `SubagentStop` | Record known fields; ignore unsupported extras until needed |
| Tool names | `Bash`, `apply_patch`, `mcp__*` | Bash and `apply_patch` are enforced; MCP tools get conservative generic parsing for explicit path, command, and URL fields |
| Hook config | `~/.codex/hooks.json` / `~/.codex/config.toml` | `gensee setup codex` writes `hooks.json` |
| Hook trust | Non-managed command hooks are hash-trusted through `/hooks` | Setup prints the exact hook command and trust guidance |
| Hook timeout | Handler `timeout` in seconds; omitted default is 600 | Setup writes an explicit 30-second timeout |

## Provider seam in this repo

The implementation supports `claude-code` and `codex` as explicit peer
providers. Shared hook parsing, timeline compaction, daemon dispatch, Bash
intent parsing, and process sampling use provider-neutral names. Provider names
remain only where behavior or setup is intentionally provider-specific:

1. **CLI dispatch** - `gensee hook <claude-code|codex>` and
   `handle_agent_hook(provider)` thread the explicit provider into event
   parsing. There is no implicit default provider.
2. **Provider tag** - `build_hook_event(payload, provider)`
   (`crate/gensee-crate-cli/src/command_parse.rs`) stores the provider supplied
   by the hook entrypoint or daemon envelope.
3. **Decision output** - `decision_json_for_provider()`
   (`crate/gensee-crate-cli/src/policy_eval.rs`) is provider-aware. For
   `PreToolUse`, Codex emits no output for `Allow` or warning-level findings
   and emits `deny` only for `Block`. Ask findings are recorded as `warn` for
   Codex. For Codex `PermissionRequest`, Gensee emits an explicit allow/deny
   response so Codex-native approval boundaries are visible in the Gensee store.
4. **PermissionRequest support** - Codex setup installs a `PermissionRequest`
   hook and the handler evaluates the same policy subjects where possible, then
   allows or denies the approval request. Codex `PermissionRequest` payloads
   carry the command at top-level `command`; Gensee normalizes that into the
   shared Bash command field before policy evaluation. If a `PermissionRequest`
   command cannot be parsed, Gensee denies by default and records a
   high-severity alert instead of silently deferring to Codex.
5. **Bash intent parsing** - Bash payloads use `tool_input.command` for normal
   tool events and top-level `command` for Codex `PermissionRequest` events, so
   `file_intents_from_hook()` can evaluate both through the same policy path.
6. **`apply_patch` policy subjects** - `native_policy_subjects()` in
   `crate/gensee-crate-cli/src/policy_eval.rs` uses the shared core extractor
   and parser to evaluate touched patch paths. The public Codex contract uses
   `tool_input.command`; the extractor also accepts direct-string and common
   string-key shapes. If an `apply_patch` payload cannot be parsed into changed
   paths, Claude Code gets an `ask` finding where review is supported; Codex
   gets an allow-level high-severity alert and relies on filesystem watch as the
   backstop.
7. **`apply_patch` lineage/artifacts** - `native_file_tools()` in
   `crate/gensee-crate-store/src/lib.rs` uses the same core extractor/parser
   and shared path normalization so policy and lineage agree on touched files.
8. **Trusted native-tool handling** -
   `crate/gensee-crate-store/src/lib.rs` trusts parsed native file-tool events
   without duplicating file-operation alerts. Keep that trust explicit by
   provider/tool support as more Codex native tools are added.
9. **Setup** - `gensee setup codex` writes `~/.codex/hooks.json`, prints the
   exact hook command, and tells the user to run `/hooks` to trust or re-trust
   the command. For automation, document `--dangerously-bypass-hook-trust` as a
   test-only shortcut, not the normal setup path.
10. **Provider constants** - provider-specific strings should stay concentrated
    at CLI/setup boundaries. Shared internal sources use generic IDs such as
    `"bash-command-parser"` and `"process-sampler"`.
11. **Policy integrity scan** - `.codex` is in `artifact_registries` and the
    integrity-scan descend list, so Codex skills/plugins are scanned by the
    shared memory/skill poisoning rules.
12. **Docs / integration dir** - add `integrations/codex/` with a README,
    sample `hooks.json`, approval-policy guidance, and smoke-test commands.

Already generic: timeline correlation by `session_id` + `tool_use_id`;
provider storage (`event.provider` -> `sessions.agent_id`,
`agent_events.source`); Bash intent parsing; process sampling.

## Open questions / risks

- **Codex `Ask` semantics.** There is no direct `PreToolUse` ask today. Gensee
  records `Ask` findings as `warn` for Codex and can use `PermissionRequest`
  for actions Codex already prompts through approval policy.
- **Non-interactive execution.** Under `codex exec`, fresh approvals cannot be
  surfaced. `GENSEE_NONINTERACTIVE=1` makes medium+ `Ask` findings fail closed
  as blocks; live smoke testing confirmed the unsafe tool call does not run.
- **`apply_patch` path extraction.** A patch can edit, create, delete, or rename
  multiple files. The parser is shared between policy evaluation and store
  lineage. Unknown payload shapes become a review prompt where the provider
  supports it; for Codex, they are allowed with a high-severity alert because
  Codex has no `PreToolUse` ask path and filesystem watch can still record
  unsafe file effects after execution.
- **MCP coverage.** MCP tools show up as `mcp__<service>__<method>`. Gensee
  now intercepts common explicit path/file, command, and URL fields; add deeper
  service-specific parser coverage when a concrete MCP server is in scope.
- **Hook trust UX.** `gensee setup codex` cannot silently make non-managed hooks
  trusted in the normal user flow. It should clearly surface `/hooks`, changed
  hook command hashes, and the managed-hook alternative for enterprise rollout.
- **Build variance.** Codex CLI releases can differ in flag availability and
  hook-trust behavior. Prefer the public hook contract and keep smoke tests
  pinned to the Codex version being validated.

## Implementation state

- **Implemented:** explicit provider seam (`gensee hook codex`, provider tag),
  provider-aware decision output with Codex `Allow`/`Ask-as-warn` -> no output,
  Bash intent reuse, shared `apply_patch` path parser, policy/store
  lineage tests for patch operations, trusted-hook provider generalization for
  implemented native subjects, `PermissionRequest` handling for Codex-native
  approvals, `gensee setup codex` hook writing, `/hooks` trust guidance,
  generic MCP explicit field interception, `integrations/codex/` setup and
  smoke-test docs, and focused tests.
- **Remaining implementation work:** service-specific MCP parser coverage for
  selected servers and `updatedInput` command rewrite support.
