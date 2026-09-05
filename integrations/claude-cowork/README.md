# Claude Cowork endpoint visibility (macOS pilot)

This adapter records what Claude Cowork causes on a managed Mac without
claiming visibility that the endpoint does not have. It combines the macOS
Endpoint Security stream with Cowork's local audit stream and assigns every
Cowork boundary event exactly one execution-origin label:

| Label | Meaning |
| --- | --- |
| `host-native` | A known Cowork host tool ran locally and its endpoint effects can be observed and enforced with Endpoint Security. |
| `vm-mediated` | A local shell/code tool crossed the Linux VM boundary. Crate records the boundary and host-visible result, not guest commands or process lineage. |
| `cloud-mediated` | The session was explicitly identified as cloud mode. Crate records only effects bridged back through the endpoint; cloud execution is outside endpoint visibility. |
| `unattributed` | Available evidence cannot establish the execution surface. Crate does not guess. |

## Pilot contract

1. Crate provides high-fidelity monitoring and enforcement for host-native
   Cowork activity captured by macOS Endpoint Security.
2. For local shell execution, Crate records the VM boundary and resulting
   endpoint changes but does not claim guest command-level visibility.
3. For cloud sessions, Crate records only local bridged effects and marks cloud
   execution as outside endpoint visibility.
4. Every Cowork boundary event carries one of the four labels above. Missing,
   legacy, and unknown records resolve to `unattributed`.

The label describes causal execution origin, not merely the process that
eventually issued a macOS syscall. A signed Claude helper can serve both local
and cloud sessions, so its signing identity alone is intentionally insufficient
to label an action `host-native`.

## Local audit ingestion

Enable the opt-in managed process root and set the independently established
session mode:

```sh
gensee policy set cowork_endpoint_visibility.enabled true
gensee policy set cowork_endpoint_visibility.session_mode local
```

In `protect` or `strict` Endpoint Security mode, the signed Claude Desktop root
and its host descendants are then subject to the configured protected-path and
blocked-executable rules. The system extension verifies Anthropic's signing and
team identities before trusting the PID supplied by the desktop app.

Cowork local-session audit records can be streamed into Crate without an
Anthropic API integration:

```sh
tail -F "$HOME/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<org>/<session>/audit.jsonl" \
  | gensee ingest cowork-audit
```

For per-user installations the base is usually under the user's
`~/Library/Application Support/Claude` directory. Deployments should discover
the path rather than hard-code account, organization, or session identifiers.

The ingester defaults to `cowork_endpoint_visibility.session_mode`, keeping the
audit and Endpoint Security paths on one mode. `--session-mode` accepts `local`,
`cloud`, or `unknown` as an explicit override when policy is `unknown`; a flag
that conflicts with a concrete policy mode is rejected. The endpoint cannot
reliably infer the mode from the Claude process name, so use `unknown` whenever
the tenant/session setting has not been independently established.

The ingester recognizes native file tools such as `Read`, `Write`, `Edit`,
`Glob`, and `Grep`, and the local VM shell tool `mcp__workspace__bash`. It stores
tool name, tool-use ID, session ID, timestamp, file path when present, origin,
and the applicable visibility limitation. File contents and shell commands are
omitted.

The local audit format is not a public Anthropic compatibility contract. Treat
this parser as a versioned pilot adapter and fail to `unattributed` if the
format or tool identity is unknown.

## Endpoint Security correlation

The first-party macOS sensor records host-side process identity, parent PID,
signing identity, file reads/opens, writes, creates, closes, renames, truncates,
and deletes. The Cowork audit boundary timestamp, file path, session ID, and
tool-use ID provide the semantic side of correlation.

When visibility is enabled for an already-running Claude Desktop instance, the
host registers its current recursive descendant set as well as the app PID.
The extension still validates each adopted PID as an Anthropic-signed Claude
Desktop/helper process or Apple's platform-signed VM process before trusting it;
later descendants continue to be learned from Endpoint Security fork/exec events.

Apple's signed `com.apple.Virtualization.VirtualMachine` process is recognized
as a VM boundary. Seeing that boundary does not reveal the Linux process that
performed a command. A filesystem result should therefore remain
`vm-mediated`, even when Crate can hash or diff the final file on the Mac.

Endpoint Security records include `cowork_visibility` evidence with the match
method, confidence, and visibility limitation. A Claude host process stays
`unattributed` until local audit/session evidence establishes whether it came
from a local host tool or a cloud bridge.

## Enforcement boundary

Crate can enforce policy on endpoint-visible file, process, and network actions.
It cannot enforce an individual syscall inside Cowork's Linux VM or a command
running in Anthropic's cloud. If a customer requires complete guest or cloud
command telemetry, endpoint-only deployment is insufficient and must be paired
with a supported upstream audit source.

## Pilot validation

For each supported Claude Desktop build, run both operations against a connected
test folder:

1. Ask Cowork's shell tool to create a file.
2. Ask Cowork's native file tool to create another file without shell.
3. Confirm the native event is `host-native` and has Endpoint Security process,
   parent, signing, and file-event evidence.
4. Confirm the shell boundary is `vm-mediated`, the resulting file is captured,
   and no guest command/process claim is emitted.
5. Repeat with an explicitly cloud-mode session and confirm bridged effects are
   `cloud-mediated` with the cloud visibility limitation.
6. Feed an unknown tool/mode and confirm it is `unattributed`.
