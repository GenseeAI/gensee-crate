# Claude Cowork on macOS

Claude Cowork is a separate integration in **Harnesses**, alongside Claude Code.
The endpoint-visibility pilot records supported host activity and local tool-audit
boundaries. It supports native file tools and visibility at the local Linux VM
boundary. Guest commands and cloud execution are outside the Mac sensor’s coverage.

## Enable visibility

1. [Install the macOS app](macos-app.md#install) and open **Settings → Endpoint
   Security**. Approve the extension and Full Disk Access in macOS, and confirm the
   sensor is connected.
2. Open **Harnesses → Claude Cowork** and choose **Enable visibility**. This opt-in
   is separate from Claude Code hooks and the setup assistant’s bulk hook setup.
3. Expand **Session & evidence**. Select **local** only for an independently
   confirmed local session, **cloud** for a confirmed cloud session, or **unknown**
   for mixed or unverified sessions. The Claude process name cannot establish mode.
4. Start a manual audit stream for the session, as described below.
5. Run a native file task and a VM shell task in an isolated test folder, then
   choose **Verify**. Check that the corresponding evidence times advance.

**Verify** samples the latest 2,000 stored system events. Missing evidence in that
sample does not establish that older evidence is absent. Historical timestamps
also do not prove that an audit collector is still running. The CLI provides the
same metadata diagnostics through `gensee cowork-status`.

The Harnesses **Protected** total includes enabled Cowork visibility. The Cowork
row says **Visibility enabled**: this does not mean hook interception, VM guest
inspection, or cloud enforcement is available.

## Collect local tool-audit records

Use the app’s bundled CLI if `gensee` is not on your shell’s PATH:

```sh
"$HOME/.gensee/bin/gensee" cowork-status
```

Find the actual account, organization, and session directory beneath
`~/Library/Application Support/Claude/local-agent-mode-sessions/`, then replace
the placeholders in this command:

```sh
tail -F "$HOME/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<org>/<session>/audit.jsonl" \
  | "$HOME/.gensee/bin/gensee" ingest cowork-audit
```

Start one stream per session. Stop it with **Ctrl-C** in its terminal when done,
and restart it after changing session mode. **Disable visibility** stops the
endpoint opt-in; it does not stop an independently launched audit collector.
The app does not start or supervise these collectors.

The adapter records metadata such as tool name, tool-use ID, session ID, timestamp,
path, and execution origin. It omits file contents and shell command text. The
local audit format is a versioned pilot adapter, not a public Anthropic API contract.

## Understand execution origin

| Label | Available evidence |
| --- | --- |
| `host-native` | A known native host tool is identified. Audit intent alone does not prove that its effect occurred. |
| `vm-mediated` | A local shell/code tool crossed the Linux VM boundary. Guest commands and guest process lineage are unavailable. |
| `cloud-mediated` | An explicitly cloud-mode session produced locally bridged evidence. Remote execution remains unobserved. |
| `unattributed` | The evidence cannot establish the execution surface. Gensee does not infer it from the process name. |

Known native audit tools include `Read`, `Write`, `Edit`, `Glob`, and `Grep`;
`mcp__workspace__bash` identifies the local VM shell boundary. The audit and sensor
streams are recorded separately. Automatic causal joining of audit session/tool
IDs to sensor process-tree sessions is not implemented.

## Choose Mac-wide protection

Use **Settings → Protection Level** for all enabled harnesses:

- **Fast** records Endpoint Security evidence; configured hook rules still apply.
- **Review** enables supported host protected-path and blocked-executable controls.
- **Sensitive** also turns risky hook approvals into denials. It adds no Cowork
  guest-command or cloud enforcement beyond the same supported host controls.

Start with Fast while validating coverage. Claude Desktop can share host processes
across activities, so the opt-in process-tree policy is broader than one task.
See [sensor modes and limitations](endpoint-security.md#modes).

For process adoption, signing checks, replay buffering, and the tested Claude build,
see the [adapter contract](https://github.com/GenseeAI/gensee-crate/tree/main/integrations/claude-cowork)
and [validation notes](https://github.com/GenseeAI/gensee-crate/blob/main/integrations/claude-cowork/VALIDATION.md).
