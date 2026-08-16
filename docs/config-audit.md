# `gensee audit` — coding-agent configuration review

`gensee audit` performs a static, read-only security and privacy review of local
Codex and VS Code agent configuration. It inventories effective local settings
and extension surfaces, reports concrete and potential risks, and preserves
account-side or runtime-only checks instead of treating them as passed.

The implementation has three leaf audit targets and two convenience aliases:

| Requested target | Resolved leaf targets |
| --- | --- |
| `codex` | `codex-cli` |
| `vscode` | `vscode-agent-host`, `github-copilot-vscode` |
| `codex-cli` | `codex-cli` only |
| `github-copilot-vscode` | `github-copilot-vscode` only |
| `vscode-agent-host` | `vscode-agent-host` only |

The auditor does not start Codex, VS Code, extensions, MCP servers, hooks,
skills, plugins, command rules, or package launchers.

## Run an audit

Audit Codex CLI configuration using `CODEX_HOME`, or `~/.codex` when the
environment variable is unset:

```bash
gensee audit codex
```

Audit the complete VS Code bundle. The GitHub Copilot leaf remains visible but is
excluded from summary counts and `--fail-on` when its extension is not detected:

```bash
gensee audit vscode
```

Audit another workspace or a named Codex profile:

```bash
gensee audit codex --workspace /path/to/repo --codex-profile sensitive

gensee audit vscode --workspace /path/to/repo \
  --vscode-user-data /path/to/Code/User --vscode-profile profile-id
```

Emit the versioned machine-readable report and make high-or-critical findings
fail CI:

```bash
gensee audit codex --json --fail-on high
```

Options:

| Option | Meaning |
| --- | --- |
| `--target NAME` | Explicit alias or leaf target. |
| `--provider codex\|vscode` | Alternate spelling for selecting a top-level alias. |
| `--workspace PATH` | Workspace whose trusted project layer and repository extensions are inspected. Defaults to the current directory. |
| `--codex-home PATH` | Override `CODEX_HOME` discovery. |
| `--codex-profile NAME` | Apply `$CODEX_HOME/NAME.config.toml` after the user config. |
| `--profile NAME` | Alias for `--codex-profile`. |
| `--vscode-user-data PATH` | VS Code `User` directory containing `settings.json` and profile data. |
| `--vscode-profile ID` | Apply `profiles/ID/settings.json` and `mcp.json`. |
| `--json` | Print JSON instead of the human review. |
| `--fail-on LEVEL` | Exit 1 for actionable findings at or above `critical`, `high`, `medium`, `low`, or `info`. Use `none` to disable. |

Without `--fail-on`, policy findings do not change the exit status. Invalid
audit inputs return an error, and incomplete audits caused by parse or I/O
failures exit 2. A `--fail-on` policy match exits 1.

## Dashboard view

The native dashboard includes **Config Audit** under Configuration. It defaults
to the `vscode` bundle and exposes only the `vscode` and `codex` user-facing
targets. Leaf coverage remains visible in the result and raw JSON. It uses the
same Rust rulesets and versioned bundle as the CLI, with filters,
expandable evidence and remediation, capability inventory, manual account-side
checks, source provenance, limitations, and raw JSON. The view communicates
through local Tauri IPC and does not launch the CLI or configured extensions.

## Codex CLI target

`codex-cli` audits the local OpenAI Codex command-line tool. It does not model
the OpenAI Codex VS Code extension. The `codex` alias resolves only to this
leaf.

### What is inspected

The auditor reconstructs the local Codex view as far as static files permit:

- user `config.toml`, an explicitly selected profile file, and a trusted
  workspace `.codex/config.toml`;
- Codex's documented project-scope exclusions for provider, profile,
  notification, and telemetry-routing keys;
- the Unix `/etc/codex/requirements.toml` or Windows system equivalent;
- user and trusted-project `.rules` files;
- enabled repository, user, administrator, and legacy Codex skills;
- inline and JSON hook commands;
- MCP servers, Apps defaults, plugin manifests, and marketplace sources;
- `AGENTS.md` and `AGENTS.override.md` files under the audited workspace;
- file ownership-boundary signals such as group/world writable files and
  symlinks.

Discovery is bounded to eight directory levels and text files of at most 256
KiB. Symlinked directories are not traversed.

### Findings and categories

The initial ruleset is `codex-local-v1`, version `1.0.0`. Rules report a
severity, confidence, and assessment:

- `confirmed`: the risky configuration fact is present;
- `potential`: the fact is present but risk depends on content or operational
  context; and
- `not_assessable`: reserved for checks that cannot be decided locally. The
  current implementation emits those as explicit `manual_checks` instead of
  pretending they passed.

The auditor intentionally has no aggregate score. A numerical score would hide
important compound cases—for example, `approval_policy = "never"` combined with
`sandbox_mode = "danger-full-access"` is critical even if many unrelated
settings are conservative. Consumers can select their own gate with
`--fail-on` while retaining the complete evidence.

### Configuration provenance and managed constraints

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `CAX-CFG-001`–`003`, `006` | High | Invalid/unreadable active config, an ignored security-sensitive project key, or a selected profile that is absent. |
| `CAX-CFG-004` | High | An inspected control-plane file is group- or world-writable on Unix. |
| `CAX-CFG-005` | Medium | An inspected control-plane file is a symlink. |
| `CAX-MGD-001` | Medium–High | System requirements permit `never`, `danger-full-access`, or live web search. This is potential because availability does not prove selection. |

### Autonomy, sandbox, network, and environment

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `CAX-AUT-001` | High | `sandbox_mode = "danger-full-access"`. |
| `CAX-AUT-002` | Critical | Full host access and `approval_policy = "never"` are both active. |
| `CAX-AUT-003` | High | Writable/networked execution is paired with `never`. |
| `CAX-AUT-004` | Medium | More than eight agent threads amplify an already networked or unsandboxed posture. |
| `CAX-RUL-001` | Medium–High | An `allow` command rule covers a one-token command, shell, interpreter, privilege wrapper, or environment wrapper. |
| `CAX-NET-001`, `002` | High | Workspace networking lacks scoped proxy policy, or a global `*` domain rule is allowed. |
| `CAX-NET-003` | Medium | Live web retrieval is enabled. |
| `CAX-SBX-001` | High | An additional writable root includes a broad system, home, credential, or configuration path. |
| `CAX-SBX-002`, `003` | High | A permission profile grants full networking or enables a dangerous socket/proxy escape hatch. |
| `CAX-ENV-001`–`003` | Medium–High | Secret filtering is disabled, the full environment is inherited without an allowlist, or a secret-like literal is configured. |

### Privacy, retention, and external services

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `CAX-PRV-003` | High | Raw user prompts are exported through OpenTelemetry. |
| `CAX-PRV-004`, `005` | High | Telemetry contains a secret-like literal or uses non-loopback plaintext HTTP. |
| `CAX-PRV-006` | Low | Saved session history has no configured size bound. |
| `CAX-PRV-007` | Medium | An explicit plaintext TUI log directory is configured. |
| `CAX-PRV-008` | Medium | A custom model provider receives repository context. |
| `CAX-CTX-001` | Medium | External tool context remains eligible for persistent memory. |

Secret-like evidence values are replaced with `<redacted>` before they enter
the report. The detector recognizes environment references and does not report
the referenced variable name as a literal secret.

### MCP, Apps, skills, plugins, hooks, and instructions

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `CAX-MCP-001` | Medium | An enabled MCP server has no `enabled_tools` allowlist. |
| `CAX-MCP-002` | High | MCP tools are approved by default. |
| `CAX-MCP-003`–`005` | High | A remote MCP endpoint uses plaintext HTTP, a server launches through a shell, or a package launcher dependency is mutable/unpinned. |
| `CAX-MCP-006`–`008` | Medium–High | MCP config embeds a secret, requests a broad OAuth scope, or uses a non-loopback OAuth callback. |
| `CAX-MCP-009` | Info | An MCP endpoint is not a valid absolute URL, so its transport and host posture cannot be fully evaluated; embedded credentials are still reported when a safe scheme-recovery parse proves them. |
| `CAX-APP-001` | High | Destructive Apps tools are enabled and approved by default. |
| `CAX-SKL-001`–`004` | Medium–High | Duplicate names, symlinked skills, poisoning indicators, or download-to-shell content affect skill trust. |
| `CAX-SKL-005` | Info | An enabled skill includes scripts and needs code/dependency review. |
| `CAX-SKL-006` | Medium | More than ten enabled skills are discoverable but local config has no auditable per-skill review record. This is an explicit prototype heuristic, not a claim that eleven skills are inherently unsafe. |
| `CAX-INS-001`, `002` | High | Agent instruction files contain hidden/override indicators or download-to-shell guidance. |
| `CAX-HOK-001` | High | A hook downloads and executes remote content. |
| `CAX-PLG-001`, `002` | Medium | A plugin combines several capability surfaces or a marketplace uses a mutable revision. |
| `CAX-COV-001` | Medium | Active effective hooks do not include `gensee hook codex`, or Codex hooks are disabled. |

## VS Code agent-host target

`vscode-agent-host` reconstructs user, selected-profile, and workspace settings
using JSON-with-comments parsing and VS Code's documented precedence. It also
inspects workspace/profile `mcp.json`, project and personal skills, instruction
files, custom agents, hooks, and locally installed extension manifests.

### Approvals, sandbox, networking, and trust

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `VSC-CFG-001`–`004` | Medium–High | An active settings/MCP layer is invalid, a selected profile is absent, or a control-plane file is symlinked or writable by another principal. |
| `VSC-AUT-001`, `002` | High | Global tool auto-approval or a default Bypass Approvals/Autopilot posture is configured. |
| `VSC-AUT-003` | Critical | Approval bypass is combined with the agent sandbox being off. |
| `VSC-AUT-004`–`006` | High | Built-in terminal rules are ignored, a broad terminal command is auto-approved, or sensitive edits are broadly auto-approved. |
| `VSC-SBX-001`–`003` | Medium–High | Sandboxed commands have unrestricted networking, may retry outside the sandbox, or receive broad filesystem exceptions. |
| `VSC-NET-001`–`003` | High | An autonomous posture disables network filtering, permits `*`, or broadly auto-approves URL requests/responses. |
| `VSC-TRU-001`, `002` | Medium–High | Workspace Trust is disabled or an extension is forced to run in untrusted workspaces. |
| `VSC-PRV-001` | Low | Full VS Code usage telemetry is enabled. This does not imply that extension telemetry is disabled. |

### Native MCP, skills, instructions, hooks, and extensions

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `VSC-MCP-001`–`003` | High | MCP configuration is invalid, obtains input by executing an editor command, or grants broad sandbox access. |
| `VSC-MCP-004`–`009` | Medium–High | An endpoint is plaintext or embeds credentials, a server launches through a shell or mutable package, a local server is unsandboxed, or configuration embeds a secret. |
| `VSC-MCP-010` | Info | An MCP endpoint is not a valid absolute URL, so its transport and host posture cannot be fully evaluated; embedded credentials are still reported when a safe scheme-recovery parse proves them. |
| `VSC-SKL-001`–`004` | Info–High | Skills contain scripts, poisoning/download-to-shell indicators, auto-invocable executable workflows, or an unusually large auto-invocable executable set. |
| `VSC-INS-001`, `VSC-AGT-001` | Medium–High | Instructions/custom agents contain dangerous content or request a broad tool surface. |
| `VSC-HOK-001` | High | A lifecycle hook downloads and executes remote content. |
| `VSC-EXT-001` | Info | An installed extension contributes agent tools, skills, MCP, or agent participants and needs publisher/version review. |

## GitHub Copilot VS Code target

`github-copilot-vscode` evaluates the provider-specific GitHub Copilot
extension layer. It records `applicable`, `partial`, or `not_detected` based on
installed extension manifests, Copilot settings, and workspace extension
recommendations. The generic VS Code host target retains responsibility for
approvals, sandboxing, trust, MCP, skills, hooks, and extension-host risks.

### Copilot privacy and telemetry

| Rule | Default severity | Criterion |
| --- | --- | --- |
| `VSC-PRV-002` | High | Copilot OpenTelemetry captures full prompts, responses, instructions, tool arguments, or results. |
| `VSC-PRV-003`, `004` | Medium–High | Copilot traces use a plaintext remote collector or are written to a plaintext file. |

GitHub Copilot account training/data-use controls, current VS Code runtime
approvals and trust, and remote/policy layers remain manual checks
(`VSC-PRV-005`, `VSC-TRU-003`, and `VSC-REM-001`).

## Account-side privacy checks

Two high-priority checks always remain manual because local Codex files cannot
prove them:

1. Verify the authenticated account or organization's model-training/data
   sharing preference.
2. Verify any separate setting governing use of full Codex environments for
   training.

This distinction is deliberate: absence of a local opt-in key is not evidence
that account-side sharing is disabled.

## JSON contract

The complete schema is [config-audit-report.schema.json](config-audit-report.schema.json).

Every command emits the same bundle shape. Each leaf report keeps its own
ruleset, inventory, sources, findings, manual checks, and limitations:

```json
{
  "schema_version": 1,
  "requested_target": "vscode",
  "resolved_targets": ["vscode-agent-host", "github-copilot-vscode"],
  "summary": {},
  "reports": [
    {
      "target": "vscode-agent-host",
      "applicability": "applicable",
      "report": {}
    },
    {
      "target": "github-copilot-vscode",
      "applicability": "not_detected",
      "applicability_reason": "...",
      "report": {}
    }
  ]
}
```

`not_detected` reports remain visible but do not contribute to the bundle
summary or `--fail-on`. `partial` reports do contribute, with their uncertainty
preserved. Schema version changes are reserved for incompatible bundle changes;
individual ruleset versions change when criteria or severity decisions change.
Finding fingerprints hash the rule ID and evidence locations/keys, not secret
values, so automation can track findings without leaking their contents.

## Limits and threat model

- Command-line `-c` overrides and dedicated Codex launch flags can change the
  effective posture after the audit.
- Cloud-fetched enterprise requirements, MDM preferences, account settings,
  runtime OAuth grants, remote server behavior, and provider retention cannot
  be proven by an offline local scan.
- Local VS Code extension discovery covers the standard stable, Insiders, and
  common VSCodium extension directories. Portable installations and custom
  `--extensions-dir` locations are not detected yet.
- Static pattern checks identify review targets; they do not prove malicious
  intent or fully parse Starlark, shell, Markdown, or every plugin format.
- The audit reports configuration risk. It is not a source-code vulnerability
  scanner and does not replace runtime enforcement.

## Design references

The criteria follow the current Codex configuration, rules, MCP, skills,
plugins, and security documentation. The design also borrows useful patterns
from ecosystem auditing work: deterministic rule IDs and supply-chain checks
from [OpenSSF Scorecard](https://github.com/ossf/scorecard), static MCP
inventory and tool-risk review from
[Invariant MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan), static skill
content scanning from
[Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner),
and agent/MCP threat categories from the
[OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/).

Primary Codex references:

- [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Command rules](https://learn.chatgpt.com/docs/agent-configuration/rules)
- [Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
- [MCP](https://learn.chatgpt.com/docs/extend/mcp)
- [Skills](https://learn.chatgpt.com/docs/build-skills)

Primary VS Code and Copilot references:

- [Agent security](https://code.visualstudio.com/docs/agents/security)
- [Agent approvals](https://code.visualstudio.com/docs/agents/approvals)
- [MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [Agent skills](https://code.visualstudio.com/docs/agent-customization/agent-skills)
- [Agent hooks](https://code.visualstudio.com/docs/agent-customization/hooks)
- [Copilot policy and data controls](https://docs.github.com/en/copilot/how-tos/manage-your-account/manage-policies)
