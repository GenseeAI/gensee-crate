# Safety policy

On an agent `PreToolUse` hook, Gensee makes a **deterministic** policy decision
and returns the provider-appropriate allow/ask/deny response. The same engine
also produces the passive risk **alerts** recorded over observed filesystem
effects (see [lineage-graph.md](lineage-graph.md)).

## Rules are data, not code

Rule *content* lives in a versioned JSON document,
`crate/gensee-crate-rules/policy/default-policy.json`, evaluated by
`gensee-crate-rules::policy`. The matchers are structured (path
segment / filename / path-suffix predicates) rather than regex, which keeps
evaluation allocation-light and free of ReDoS surface.

| Environment variable | Effect |
| --- | --- |
| `GENSEE_POLICY_FILE` | Path to a custom policy document that overrides the bundled default. |
| `GENSEE_POLICY_ALLOW_PATH_PREFIXES` | Colon-separated trusted path prefixes that exempt known-safe project files. |

**Fail-closed override.** If `GENSEE_POLICY_FILE` is set but unreadable or
invalid, the hook denies every tool call (with a `policy_load_failed` reason)
rather than silently falling back to the default policy.

## Configuration: the `gensee policy` interface

The policy is a single JSON document. Manage it with `gensee policy`:

| Command | Effect |
| --- | --- |
| `gensee policy print-default` | Print the bundled default (authoring template). |
| `gensee policy init` | Write the default to `$GENSEE_HOME/policy.json` to edit. |
| `gensee policy setup` | Walk through dashboard-style policy settings, artifact definitions, and decision rules, then write `$GENSEE_HOME/policy.json`. |
| `gensee policy validate <file>` | Parse + schema-version check; exit `1` if invalid. |
| `gensee policy get <key>` | Read a dotted key, e.g. `egress.allow_hosts`. |
| `gensee policy set <key> <value>` | Set a dotted key (writes the user policy file). |
| `gensee policy path` | Show the active policy source. |

**Auto-discovery.** When `GENSEE_POLICY_FILE` is unset, the loader reads
`$GENSEE_HOME/policy.json` (else `~/.gensee/policy.json`) if present — so a file
written by `gensee policy set` takes effect with no env var. A file that fails
to parse, or whose `schema_version` differs from the binary's, **fails closed**.

**Config lives in the document**, not just env vars — these top-level sections
(all optional; omitted ⇒ built-in defaults):

- `resource_governance` — `max_read_bytes`, `max_file_subjects_per_tool`,
  `max_shell_segments_per_tool`, `max_tool_calls_per_session`,
  `max_network_egress_per_session`, `max_file_accessed_rate_per_min`,
  `max_network_rate_per_min`
- `egress` — `allow_hosts` (list), `proxy_url`, `require_proxy`
- `runtime` — `max_runtime_seconds`
- `linux.seccomp` — `enabled`, `deny_ptrace`, `deny_bpf`,
  `deny_kernel_modules`, `deny_mount_namespace_changes`
- `linux.fanotify` — `paths` (extra Linux fanotify sensitive paths, added on
  top of built-in credential-path defaults)
- `linux.network` — `mode`, `allow`, `deny`
- `enforcement` — `noninteractive` (escalate medium+ `ask` → `deny`)
- `watch` — `system_events` (`eslogger` by default; set `none` to disable)
- `allow_path_prefixes` — list (JSON form of `GENSEE_POLICY_ALLOW_PATH_PREFIXES`)

**Precedence: env var > JSON document > built-in default.** The matching
`GENSEE_*` env vars still override the JSON (handy for CI / one-off runs); the
JSON is the persistent source `gensee policy set` writes. Internal plumbing vars
(`GENSEE_HOME`, `GENSEE_RUN_ID`, `GENSEE_WORKSPACE`, `GENSEE_PROCESS_SAMPLER`,
`GENSEE_POLICY_FILE`) are not policy and stay env-only.

> Today `set` edits a single document (materializing the full default on first
> write); there is no overlay/merge yet, so a custom policy must be re-synced if
> the bundled default changes.

## Authoring a custom policy

The fastest path is the guided setup: `gensee policy setup` walks through the
same settings, artifact definitions, and decision-rule actions shown in the
dashboard Policy tab and writes `$GENSEE_HOME/policy.json`; `gensee policy
validate <file>` checks it; it is auto-loaded on the next hook. The document is
**fail-closed** — a parse error or a `schema_version` mismatch denies every
tool call rather than silently reverting.

**Editor autocomplete + external validation.** A JSON Schema ships at
[`crate/gensee-crate-rules/policy/policy.schema.json`](https://github.com/GenseeAI/gensee-crate/blob/main/crate/gensee-crate-rules/policy/policy.schema.json).
Map your editor's JSON schema setting to it (e.g. VS Code `json.schemas`), or
validate out-of-band with any draft-07 validator. `gensee policy validate`
remains the authoritative check (it parses with the same types the engine uses).

### Document sections

| Key | Required | Purpose |
| --- | :--: | --- |
| `schema_version` | yes | Must be `1`; mismatches are rejected. |
| `operations` | yes | Which file operations are read / destructive / metadata / mutating. |
| `secret_paths` | yes | Protected-secret + credential-hint path matchers (`segments` / `filenames` / `filename_prefixes` / `filename_suffixes` / `filename_contains` / `exact_paths` / `path_suffixes` / `path_contains`, plus per-rule `action` / `severity` / `message`). |
| `persistence_writes` | yes | Persistence/startup-file matcher (ask). |
| `categories` | yes | `action` / `severity` / `message` per finding category (secret, destructive, metadata, workspace, wildcard, …). |
| `artifact_registries` | no | Executable / memory / persistence / control-plane path registries. |
| `content_rules` | no | Substring/shape matchers over an executed script's content (`all_of` / `patterns`). |
| `url_rules` | no | Host-matched URL rules (`host_substrings`); hosts are canonicalized (IP encodings, `/dev/tcp`). |
| `command_rules` | no | Token-boundary command matchers (`commands` / `bare_commands` / `arg_any` / `arg_all`). |
| `resource_governance`, `egress`, `runtime`, `linux`, `enforcement`, `allow_path_prefixes` | no | Configuration (see above); env vars override where supported. |

Matchers are **structured, not regex** — predicates are exact segment /
filename / path-suffix tests, so authoring is declarative and there is no ReDoS
surface.

### Minimal example (add one secret dir + an egress allowlist)

Start from `gensee policy print-default` and change just what you need. The two
quickest edits via the CLI (no manual JSON):

```bash
gensee policy set allow_path_prefixes /Users/me/trusted-templates
gensee policy set egress.allow_hosts github.com,internal.example.com
gensee policy set linux.fanotify.paths '/tmp/gensee-demo-secret/**'
gensee policy validate "$GENSEE_HOME/policy.json"
```

## What the default policy does

**Blocks:**

- protected secret locations — `.ssh`, `.aws`, `.azure`, `.gnupg`, `.kube`,
  `.docker`, `.env` / `.env.*`, `.npmrc`, `.netrc`, `id_rsa`,
  `.git-credentials`, `~/.config/gcloud`, … — while allow-listing `.env`-family
  templates including nested ones (`.env.example`, `.env.local.example`,
  `.env.production.sample`, …);
- **system identity/credential files** an agent has no routine reason to read —
  `/etc/shadow`, `/etc/gshadow`, `/etc/master.passwd`, `/etc/sudoers`,
  `/etc/passwd`, shell history (`.bash_history`, `.zsh_history`), DB credential
  files (`.pgpass`, `.my.cnf`), and Kubernetes service-account tokens — reads of
  these are recon or credential theft;
- **broad-sweep / encapsulated reads** that reach the above without naming the
  file — `grep -r KEY ~/.aws`, `tar czf - ~/.ssh`, `find ~/.ssh -exec cat {} +`,
  `grep root /etc/passwd`. These read commands are parsed for their target paths
  so the secret-path rule still fires. A recursive sweep rooted at a **broad
  scope** (the home directory or a system root like `/`, `/etc`) — where the
  individual secret files are never named on the command line — is additionally
  flagged (`policy_broad_sweep_read`, `ask` → block when noninteractive), since
  it would traverse `~/.ssh`, `~/.aws`, and friends. A recursive read scoped to a
  project directory (`grep -rn TODO ./src`) is not flagged;
- destructive operations and writes outside the current workspace (paths are
  lexically normalized first, so `..` traversal and globs cannot escape);
- requests to cloud instance-metadata (IMDS) endpoints — see
  [URL/host matching](#urlhost-matching) below;
- **dangerous content inside a script being executed** — disk wipes, in-script
  credential reads, reverse shells — see
  [pre-execution artifact inspection](#pre-execution-artifact-inspection);
- writes to Gensee's own **control plane** (its store and policy file), so the
  agent cannot disable the shield; the default registry also treats local
  `.omnigent` state as control-plane material for thin Omnigent runs;
- **dangerous shell one-liners** that never reach an executable artifact —
  fork bombs (`:|:` self-pipe), firewall flush/disable (`iptables -F`/`--flush`),
  and SIGKILL-all (`kill -9 -1`) — see
  [dangerous command rules](#dangerous-command-rules).

**Asks (returns `ask`, surfacing a human-in-the-loop prompt):**

- credential-like filename hints (e.g. `credentials.json`);
- persistence/startup files (`.bashrc`, `.zshrc`, `.profile`, `.gitconfig`,
  `.git/hooks/*`, `.vscode/tasks.json`);
- writes outside the current workspace;
- permission/ownership changes (`chmod`/`chown` and friends);
- mutating wildcard file operations;
- environment-variable dumps (`env`, `printenv`);
- privilege escalation (`sudo`/`doas`), privileged containers
  (`docker run --privileged`), broad process kills (`pkill`/`killall`),
  file-immutability changes (`chattr ±i`), and DNS resolver changes
  (`networksetup -setdnsservers`) — see
  [dangerous command rules](#dangerous-command-rules);
- executing an artifact the agent authored in a **different session**, or one
  **modified outside the agent** — see
  [provenance-aware checks](#provenance-aware-checks-artifact-facts);
- policy-bypass or covert instructions written to (or found in) a **memory**
  artifact or a **skill/plugin manifest** (`SKILL.md`), and network egress after
  such poison is detected — see
  [memory and skill poisoning defense](#memory-and-skill-poisoning-defense);
- **network egress after a sensitive artifact was read** in the same session —
  see [sensitive-read egress chain](#sensitive-read-egress-chain).
- resource-governance pressure — large reads, high shell/file fan-out, session
  API/tool quotas, network egress quotas, and proxy/host egress constraints —
  see [resource governance](#resource-governance).

Source files (`.rs`, `.ts`, `.go`, `.css`, …) are never treated as secrets, so
`tokenizer.rs` or `secret_test.go` are not blocked.

## Allowlist scoping

`GENSEE_POLICY_ALLOW_PATH_PREFIXES` suppresses only the false-positive-prone
**secret/credential** and **persistence** findings under a matching path. The
genuinely dangerous categories — destructive, out-of-workspace, metadata, and
mutating wildcard operations — still apply, so allowlisting a project path
cannot silence an `rm` or `chmod`.

## URL/host matching

URL rules are scoped to the shell command and explicit `url`/`uri`/`endpoint`
tool fields — not free-form content fields — so writing a document that merely
mentions a URL is not blocked. A Bash command is only scanned when it actually
invokes a network tool (`curl`, `wget`, `nc`, `ssh`, `python`, HTTPie, …) or
uses a `/dev/tcp/` or `/dev/udp/` socket redirect.

Host matching is **canonical**, not string equality, so a blocked address
cannot be disguised:

- the `:port` suffix and a trailing root-FQDN dot are normalized away;
- a host that is an IP literal is parsed and compared numerically, covering
  decimal-integer, hex, octal, 1–4 part shorthand, and IPv4-mapped IPv6 forms;
- `/dev/tcp/HOST/PORT` redirects (which carry the host as a path segment, not a
  `scheme://authority`) are detected, including IP-encoded hosts.

The default rule targets the link-local IMDS address and cloud
`metadata.*.internal` hostnames.

### Known limits

- IPv6 addresses that are not IPv4-mapped are not canonicalized.
- DNS names that resolve to a metadata IP at request time are not caught — the
  matcher is static and runs before resolution. Closing this would require
  runtime DNS resolution or an egress proxy.

## Dangerous command rules

Some terminal-dangerous shell commands never pass through an executable
artifact (so [pre-exec inspection](#pre-execution-artifact-inspection) never
sees them) — a one-liner typed straight into Bash. Data-driven `command_rules`
match these over the live `tool_input_command`:

| Rule | Action | Shape |
| --- | --- | --- |
| `policy_fork_bomb` | block | fork bomb — needs **both** `:(){` (self-function) and `:|:` (self-pipe) |
| `policy_firewall_disable` | block | `iptables`/`ip6tables`/`nft` with `-F`/`--flush`/`-X` |
| `policy_kill_all_processes` | block | `kill -9 -1` |
| `policy_privilege_escalation` | ask | `sudo` / `doas` |
| `policy_container_privileged` | ask | `docker`/`podman` `run --privileged` |
| `policy_broad_process_kill` | ask | `pkill` / `killall` |
| `policy_filesystem_immutability` | ask | `chattr ±i` / `±a` |
| `policy_dns_tamper` | ask | `networksetup -setdnsservers` |

Matching is **token-boundary aware** (basename + argument tokens), not
substring, so `iptables -L`, `kill -9 <pid>`, and `docker run` without
`--privileged` are not flagged. A leading `sudo`/`doas` (and its options, e.g.
`sudo -n`, `sudo -u root`, `sudo --`) is transparently unwrapped, so
`sudo -n iptables -F` still blocks on the firewall rule rather than being
downgraded to the `sudo` ask. Shape rules (the fork bomb) match the whole
command — and require **all** their distinctive substrings present, so a
single quoted/`grep`'d fragment (`echo ':|:'`) does not false-positive.

**Calibration.** Clear-destructive, low-legitimate-use shapes are `block`;
commands with real developer uses (`sudo`, privileged containers) are `ask` to
preserve task success. In non-interactive deployments, set
`GENSEE_NONINTERACTIVE=1` or `enforcement.noninteractive=true` to escalate
medium+ `ask` findings to blocks when no operator is present.

## Pre-execution artifact inspection

Before allowing a command that runs a local script (`bash f`, `sh f`, `zsh f`,
`python f`, `node f`, `ruby f`, `perl f`, `source f` / `. f`, `./f`,
`bash < f`, `cat f | bash`), Gensee reads the file's **current** content
(bounded to 64 KB, behind a 150 ms read watchdog that returns `ask` if the read
stalls) and evaluates the **whole assembled content** — not the individual write
fragments.

This is what defeats **fragment-assembly** attacks: a dangerous command split
across requests/sessions (`echo 'dd ' >> f; echo 'if=/dev/zero of=' >> f; …`
then `bash f`) is benign one fragment at a time, but Gensee inspects the actual
file at execution time regardless of how it was assembled or of "do not read it"
instructions.

Data-driven `content_rules` (plus a built-in disk-wipe check) block on:

- raw disk wipes (`dd if=/dev/zero of=/dev/…`, in any argument order);
- protected-credential reads inside a script (`cat ~/.ssh/id_rsa`,
  `~/.aws/credentials`, `/etc/shadow`) — `$HOME` and absolute home paths are
  normalized to `~` before matching;
- reverse-shell shapes (`/dev/tcp/…`, `bash -i >&`, `nc -e`), matched on command
  token boundaries so `rsync -e ssh` is not a false positive.

Findings are persisted as **digest-keyed risk tags**: a tag is honored only when
the file's current SHA-256 digest matches the tagged digest, so a script that
was dangerous and later overwritten clean is no longer blocked (stale tags are
ignored). Captured content is redacted before storage. On `PostToolUse`, writes
to registered artifacts are re-read and tagged so the later execution is a fast
tag lookup.

The executable resolver is intentionally best-effort for common forms; obscure
`eval`/subshell cases are a known gap, with EndpointSecurity exec attribution as
the durable backstop.

### Python-intent parsing (encapsulated file ops)

A `python -c "<code>"` or `python <script.py>` invocation is parsed for
`open()` reads/writes, `os.remove`/`shutil.rmtree` deletes, and
`os.system`/`subprocess` calls (whose command string is recursed into), with
simple `IDENT = "literal"` variable resolution — so a secret read or exfil
hidden in Python is gated, not just shell. The parser **follows local imports**:
`from scripts.validator import EnvValidator` is resolved to `scripts/validator.py`
(relative to the run directory) and scanned too, closing the "hide the `open()`
one import away" evasion. Following is bounded (depth 3, a 20-file budget, a
cycle-guard) and **local-only** — a module is read only if it exists on disk
relative to `cwd`, so stdlib/site-packages are never followed. Dynamic imports
(`importlib`, `__import__`), `exec()`, and runtime-constructed paths remain out
of scope.

## Provenance-aware checks (artifact facts)

Gensee maintains a URI-keyed `artifact_facts` table (see
[lineage-graph.md](lineage-graph.md)) summarizing what is known about each path
*across* content versions — last modifier, whether it was agent-authored,
whether it was modified without a matching agent intent, registry membership,
and current risk. It is updated at ingest time from hook events, write-time
observations, FSEvents effects, and eslogger/system events, so a `PreToolUse`
decision is a single indexed lookup rather than a raw event scan.

Following the **deny-on-content, ask-on-heuristic** calibration:

- executing an artifact the agent authored in a **different session** → `ask`;
- executing an artifact **recently modified without a matching agent intent**
  (changed outside the agent, or by another local process) → `ask`.

These provenance findings never override a clean current-content read, and a
fact whose risk digest no longer matches the file is treated as stale.

Known limit: without EndpointSecurity, "modified outside the agent" is a
path/time correlation — FSEvents cannot attribute the actor — so these are
`ask`, never `deny`. Modifications attributable to the current agent session
(correlated to a recent file intent) are not flagged.

## Memory and skill poisoning defense

Two classes of **agent-instruction artifact** are registries Gensee defends on
both sides: **memory** artifacts (`CLAUDE.md`, `MEMORY.md`, `SOUL.md`,
persona/config) and **skill/plugin/rule** files. The skill registry is
**directory-scoped** — files under `.claude/skills/`, `.codex/skills/`,
`.claude/plugins/`, `.codex/plugins/`, and Antigravity `.agents/`
customization directories (e.g. a poisoned `SKILL.md` or `.agents/rules/*.md`)
— *not* any file merely named `SKILL.md`, so a project doc that happens to be
called `SKILL.md` is unaffected. Both classes carry instructions the agent will
follow, so a poisoned one is a control-flow hijack.

**Write-side (deterministic).** When the agent writes/edits — or reads — one of
these artifacts, Gensee evaluates its content against the
`policy_memory_integrity` rule (`applies_to: ["memory"]`) or
`policy_skill_integrity` rule (`applies_to: ["skill"]`). The memory rule matches
policy-bypass instructions ("ignore safety", "skip confirmation", "always
forward", "whenever the user asks … also …"); the skill rule adds covert-agent
phrases ("ignore previous instructions", "without telling the user", "do not
mention", "exfiltrate", "send all files"). On a write the *new* content is
inspected before it lands; on a read the file's current content is inspected, so
**pre-seeded** poison (planted in a prior session, by another process, or by an
installed third-party skill) is surfaced too. The action is `ask`.

**Trigger-side (deterministic skeleton).** Once a poisoned memory *or* skill
instruction has been detected earlier in the session, a subsequent
**network-egress** action is escalated to `ask`
(`policy_memory_triggered_egress`) — a deterministic stand-in for "the poison
caused an unrequested exfiltration".

Known limit: full "memory caused an action the user did not request" detection
is prompt-vs-action mismatch and is semantic — deferred to the semantic layer.
And because agents can auto-load memory files into context without a tool call,
the trigger keys off *detected* poison content rather than a read event.

## Sensitive-read egress chain

Exfiltration is rarely a single bad call — it is a **chain across requests**:
read something sensitive, then send it off the box. Each step is individually
unremarkable, so the danger is the *sequence*. Gensee surfaces it with the same
session-state mechanism as the memory trigger.

**Detection side (deterministic).** When the agent reads an artifact whose path
classifies as a **protected secret** or a **credential hint** (the same curated
secret-path lists used for read/write blocking), Gensee records a non-escalating
`policy_sensitive_read` session marker (an `allow` alert). The read's own
decision is unchanged — the secret-path rule still denies/asks it. A read in a
tool call the policy **blocks** is *not* marked: a denied call yields no data, so
it cannot seed the chain, and marking it would escalate later egress as if data
had been observed. The marker therefore fires only for sensitive reads in calls
that proceed.

**Trigger side (deterministic).** Once a sensitive read has been marked earlier
in the session, a subsequent **network-egress** action is escalated to `ask`
(`policy_sensitive_read_egress`). Egress is detected for both Bash network tools
(`curl`, `wget`, `nc`, `scp`, a `/dev/tcp` redirect, …) and **native tools with
an explicit network `url`/`uri`/`endpoint` field** (e.g. `https://...` in
`WebFetch`), so a non-Bash network call is not a bypass. Following
deny-on-content / ask-on-heuristic, this is an `ask`: the correlation does not
prove the egress *carries* the sensitive bytes, so it prompts rather than
blocks.

Known limits: the marker is scoped to the curated sensitive-path classes, so a
read of an arbitrary out-of-workspace file is not yet treated as sensitive
(a deliberately tight first cut to control false positives); and the trigger is
a read-then-egress correlation, not a content/destination data-flow proof.

## Resource governance

Gensee adds deterministic resource guards to the same `PreToolUse` decision
path. They are intentionally bounded, local, and configurable:

| Control | Default | Environment variable |
| --- | ---: | --- |
| Maximum file size for a read before prompting | 10 MiB | `GENSEE_MAX_READ_BYTES` |
| Maximum file subjects in one tool call before prompting | 50 | `GENSEE_MAX_FILE_SUBJECTS_PER_TOOL` |
| Maximum shell segments/process fan-out before prompting | 25 | `GENSEE_MAX_SHELL_SEGMENTS_PER_TOOL` |
| Maximum `PreToolUse` tool calls per session before blocking | 500 | `GENSEE_MAX_TOOL_CALLS_PER_SESSION` |
| Maximum network egress actions per session before blocking | 100 | `GENSEE_MAX_NETWORK_EGRESS_PER_SESSION` |
| Maximum per-request file-access rate before prompting | 120/min | `GENSEE_MAX_FILE_ACCESSED_RATE_PER_MIN` |
| Maximum per-request network-egress rate before blocking | 30/min | `GENSEE_MAX_NETWORK_RATE_PER_MIN` |
| Require egress proxy mode | off | `GENSEE_REQUIRE_EGRESS_PROXY=1` or `GENSEE_EGRESS_PROXY_URL=...` |
| Network host allowlist | off | `GENSEE_EGRESS_ALLOW_HOSTS=api.example.com,updates.example.com` |

Network egress is recorded with a non-escalating `policy_network_egress` marker
only when the immediate `PreToolUse` decision is `allow`. The later quota check
uses that marker, so denied or still-pending `ask` network calls do not consume
quota. Host allowlisting matches exact hosts and subdomains, and covers explicit
URLs plus `/dev/tcp` and `/dev/udp` socket paths. When proxy mode is required,
direct socket tools and known proxy-bypass options such as `--noproxy` are
blocked.

Per-request rates are stored on the existing `requests.file_accessed_rate` and
`requests.network_rate` columns as events per minute over the current request
window, with a one-minute minimum denominator. That keeps the fields stable for
audit and timeline use while avoiding a new counter table in the first pass.

`GENSEE_EGRESS_PROXY_URL` is also propagated by `gensee run` as `HTTP_PROXY`,
`HTTPS_PROXY`, and `ALL_PROXY` for managed agents. Hook-only integrations can
still enforce the pre-tool proxy/host policy, but cannot force an already
launched external agent process to inherit proxy environment variables.

Known limits: CPU and memory quotas require OS/container enforcement and are not
implemented in the hook process. The fan-out guard is a deterministic shell
shape check, not a complete process-tree proof; EndpointSecurity/eBPF or a
container runtime should become the durable process-limit layer.

## Decision output

For `PreToolUse`, stdout is reserved for the agent hook policy response:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Protected secret read: /Users/example/.ssh/config"}}
```

Findings are also persisted to the SQLite `alerts` table and shown in
`gensee timeline`.
