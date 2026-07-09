# `gensee policy`

`gensee policy` is the CLI for inspecting, creating, validating, and updating
the local policy document used by hooks, `gensee run`, and the dashboard.

Gensee Crate always has a bundled default policy. For local customization, use
`gensee policy setup` to walk through the dashboard-style settings, artifact
definitions, and decision rules, then write a user policy to
`$GENSEE_HOME/policy.json`. When `GENSEE_POLICY_FILE` is unset, that user
policy is auto-loaded if present.

## Commands

| Command | Effect |
| --- | --- |
| `gensee policy path` | Show which policy source is active. |
| `gensee policy print-default` | Print the bundled default policy. |
| `gensee policy init` | Write the bundled default to `$GENSEE_HOME/policy.json`. |
| `gensee policy init --force` | Overwrite the user policy with the bundled default. |
| `gensee policy setup` | Walk through dashboard-style policy settings, artifact definitions, and decision rules, then write `$GENSEE_HOME/policy.json`. |
| `gensee policy validate <file>` | Validate a policy file with the same parser used by the runtime. |
| `gensee policy get <key>` | Read a supported dotted config key. |
| `gensee policy set <key> <value>` | Update a supported dotted config key in the user policy. |

## Common Workflow

```bash
export GENSEE_HOME="$PWD/.gensee-dev"

gensee policy path
gensee policy setup
gensee policy validate "$GENSEE_HOME/policy.json"
```

After validation passes, the next hook or CLI policy evaluation will use the
updated policy automatically.

## Guided Setup

`gensee policy setup` prompts through the same high-level sections shown in the
dashboard Policy tab:

- resource governance limits
- network egress hosts, proxy URL, and proxy requirement
- max runtime
- non-interactive fail-closed enforcement
- watch system-event backend
- allowlisted path prefixes
- artifact definitions for executable, memory, skill, and control-plane files
- decision-rule actions for file access, command, executable-content, and URL
  rules

Press Enter to keep each current value, or type a new value. Lists are
comma-separated; nullable fields such as proxy URL and max runtime accept
`none` or `unset`. Watch system events accept `eslogger` or `none`; decision
rules accept `deny`, `ask`, or `allow`.

## Supported `set` Keys

`gensee policy set` is intentionally limited to runtime configuration knobs.
Use a text editor for rule-content changes.

- `resource_governance.max_read_bytes`
- `resource_governance.max_file_subjects_per_tool`
- `resource_governance.max_shell_segments_per_tool`
- `resource_governance.max_tool_calls_per_session`
- `resource_governance.max_network_egress_per_session`
- `resource_governance.max_file_accessed_rate_per_min`
- `resource_governance.max_network_rate_per_min`
- `egress.allow_hosts`
- `egress.proxy_url`
- `egress.require_proxy`
- `runtime.max_runtime_seconds`
- `linux.seccomp.enabled`
- `linux.seccomp.deny_ptrace`
- `linux.seccomp.deny_bpf`
- `linux.seccomp.deny_kernel_modules`
- `linux.seccomp.deny_mount_namespace_changes`
- `linux.fanotify.paths`
- `linux.network.mode`
- `linux.network.allow`
- `linux.network.deny`
- `enforcement.noninteractive`
- `watch.system_events`
- `allow_path_prefixes`

## Precedence

Policy configuration resolves in this order:

1. Environment variables.
2. Active JSON policy document.
3. Built-in defaults.

`GENSEE_POLICY_FILE` can point at a custom policy path. If that file is
unreadable, invalid JSON, or has an unsupported `schema_version`, Gensee Crate
fails closed and denies tool calls until the policy is fixed.

## Rule Authoring

For the full policy document format, default rule behavior, matcher structure,
and JSON schema notes, see [Safety policy](policy.md).
