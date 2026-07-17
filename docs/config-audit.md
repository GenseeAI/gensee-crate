# `gensee audit config` — Codex configuration review

`gensee audit config` performs a static, read-only security and privacy review
of local Codex configuration. It inventories the effective local settings and
extension surfaces, reports concrete and potential risks, and identifies
account-side checks that cannot be proven from files.

The prototype supports Codex CLI and the Codex IDE extension. It does not start
Codex or execute configured MCP servers, hooks, skills, plugins, command rules,
or package launchers.

## Run an audit

Audit the current workspace using `CODEX_HOME`, or `~/.codex` when the
environment variable is unset:

```bash
gensee audit config
```

The Codex-specific shorthand is equivalent:

```bash
gensee audit codex
```

Audit another workspace or a named Codex profile:

```bash
gensee audit codex --workspace /path/to/repo --profile sensitive
```

Emit the versioned machine-readable report and make high-or-critical findings
fail CI:

```bash
gensee audit codex --json --fail-on high
```

Options:

| Option | Meaning |
| --- | --- |
| `--provider codex` | Explicit provider selection. Other providers are not supported yet. |
| `--workspace PATH` | Workspace whose trusted project layer and repository extensions are inspected. Defaults to the current directory. |
| `--codex-home PATH` | Override `CODEX_HOME` discovery. |
| `--profile NAME` | Apply `$CODEX_HOME/NAME.config.toml` after the user config. |
| `--json` | Print JSON instead of the human review. |
| `--fail-on LEVEL` | Exit 1 for actionable findings at or above `critical`, `high`, `medium`, `low`, or `info`. Use `none` to disable. |

Without `--fail-on`, findings do not change the exit status. Parse and I/O
failures still return an error.

## What is inspected

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
  symlinks; and
- on Windows, the workspace VS Code setting that selects WSL execution.

Discovery is bounded to eight directory levels and text files of at most 256
KiB. Symlinked directories are not traversed.

## Findings and categories

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
| `CAX-APP-001` | High | Destructive Apps tools are enabled and approved by default. |
| `CAX-SKL-001`–`004` | Medium–High | Duplicate names, symlinked skills, poisoning indicators, or download-to-shell content affect skill trust. |
| `CAX-SKL-005` | Info | An enabled skill includes scripts and needs code/dependency review. |
| `CAX-SKL-006` | Medium | More than ten enabled skills are discoverable but local config has no auditable per-skill review record. This is an explicit prototype heuristic, not a claim that eleven skills are inherently unsafe. |
| `CAX-INS-001`, `002` | High | Agent instruction files contain hidden/override indicators or download-to-shell guidance. |
| `CAX-HOK-001` | High | A hook downloads and executes remote content. |
| `CAX-PLG-001`, `002` | Medium | A plugin combines several capability surfaces or a marketplace uses a mutable revision. |
| `CAX-COV-001` | Medium | Active effective hooks do not include `gensee hook codex`, or Codex hooks are disabled. |
| `CAX-IDE-001` | Low | On Windows, the workspace does not select documented WSL execution for the Codex IDE. |

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
The top-level contract is:

```json
{
  "schema_version": 1,
  "ruleset": { "id": "codex-local-v1", "version": "1.0.0" },
  "target": {},
  "summary": {},
  "sources": [],
  "effective_security_config": {},
  "inventory": {},
  "findings": [],
  "manual_checks": [],
  "limitations": []
}
```

`schema_version` changes only for incompatible report-shape changes. The
ruleset version changes when criteria or severity decisions change. Finding
fingerprints hash the rule ID and evidence locations/keys, not secret values,
so automation can track a finding without leaking its content.

## Limits and threat model

- Command-line `-c` overrides and dedicated Codex launch flags can change the
  effective posture after the audit.
- Cloud-fetched enterprise requirements, MDM preferences, account settings,
  runtime OAuth grants, remote server behavior, and provider retention cannot
  be proven by an offline local scan.
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
