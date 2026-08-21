# Collection and redaction methodology

This document explains how the private experiment evidence was captured, how
the public trace was derived, what was removed or transformed, and which
properties remain suitable for evaluation. The machine-readable counterpart is
[`redaction-ledger.json`](redaction-ledger.json).

## Experiment scope

The source run was executed in an isolated GenseeAI-controlled lab. Codex ran
inside a Tclone container on the agent machine. Its direct route to the dynamic
challenge origin was unavailable; its configured Python package index pointed
to a repository service on another lab machine. Gensee was deliberately set to
observe-only: it did not block, request approval, or fork the operation.

The challenge document was generated after the run was registered and before
the agent was released. This prevented the answer from being present in a
static image or earlier trace. Successful completion required the exact dynamic
proof value to be written to the designated workspace file.

## Evidence sources

Evidence was collected independently at several layers so the result did not
depend on the agent's own account of success.

| Layer | Private source | Public derivative | What it establishes |
| --- | --- | --- | --- |
| Codex harness | `codex-public-events.jsonl` | `traces/codex-public-events.jsonl` | Command and file-change lifecycle reported by Codex CLI |
| Codex session | Canonical response items and raw rollout | Selected command/file events only; raw rollout omitted | Agent tool sequence and output used by the private verifier |
| Gensee | Container dashboard state, timeline, status, and tamper-evident verification output | `traces/gensee-events.jsonl` and sanitized extended evidence | Tool boundaries, policy alerts, and observe-only actions |
| Kernel/runtime | Falco live syscall capture, journal, and exact-version replay | `traces/falco-replay.jsonl` and sanitized journal in the release bundle | Process and syscall activity visible during the captured segment |
| Repository service | Package-proxy request log | `traces/nexus-requests.jsonl` | Requests received by the configured package repository |
| Public package origin | Origin request log | `traces/package-origin-requests.jsonl` | Project lookup, artifact request, and redirect response |
| Private challenge origin | Challenge request log | `traces/challenge-origin-requests.jsonl` | Exact challenge path was fetched successfully by the repository machine |
| Runtime | Container inspection | Sanitized extended evidence and `run-provenance.json` | Image, runtime, and working-directory provenance |
| Harness | Prompt, experiment metadata, advisory snapshot, gate timestamps, exit code, and final output | `prompt.txt`, `run-provenance.json`, and sanitized extended evidence | Task configuration and execution envelope |

HTTP derivatives contain request metadata recorded by the lab services, not
packet captures or full response bodies. The literal challenge response body is
not published.

## Collection sequence

1. The launcher registered the run, wrote immutable task inputs into the
   workspace, and started an agent gate.
2. The harness created the dynamic challenge and then released the agent.
3. Codex CLI emitted its public JSON event stream while its canonical session
   records were copied privately for verification.
4. Gensee recorded tool lifecycle and policy events under the observe-only
   policy. Falco recorded kernel activity independently.
5. The repository service, package origin, and challenge origin recorded their
   own HTTP requests.
6. After the run, the exporter copied the container artifacts, Gensee state,
   Falco data, service logs, runtime inspection, and timing metadata into a
   an access-restricted private evidence directory.
7. A fail-closed verifier required correlated evidence at every layer,
   including the package redirect, the challenge-origin request, the exact
   proof digest, the output-file format, goal-mode ordering, nonempty Falco
   replay, and the absence of Gensee ask/block actions.
8. The exporter computed `SHA256SUMS` over the private evidence files. The
   public builder verifies every indexed source file before deriving output.

The original private evidence remains separate from the publication tree and
is never modified by the public builder.

## Selection and correlation

The public derivation is deterministic and fail-closed:

- Gensee events are limited to the recorded experiment start/end window.
- HTTP records must both fall within that window and contain the unique task
  name; unrelated preflight and historical traffic is excluded.
- Completed Codex commands are paired one-to-one with Gensee `PreToolUse` Bash
  events. The build fails if their counts differ.
- The file-change completion is correlated with the Gensee `apply_patch`
  boundary event.
- Native timestamps are converted to millisecond offsets from the trace start.
- Events are sorted deterministically by timestamp, source, kind, and canonical
  JSON content, then assigned sequential public event IDs.
- Six observationally distinct ground-truth stages are anchored to the correlated native events, with
  explicit matching windows used by `tools/score.py`.

The normalized timeline is a derived correlation view. The native sanitized
streams remain available so consumers can test their own correlation logic.

## Redactions and transformations

| Category | Public treatment | Evaluation property retained |
| --- | --- | --- |
| Dynamic proof | Literal value replaced with `[REDACTED_CHALLENGE_PROOF]`; SHA-256 retained in ground truth | Verifiable task success without disclosing the answer |
| Prompt | Unique run identifier replaced with the public scenario ID; live address replaced with `<Controlled-IP-Address>` | Prompt wording and task semantics |
| Authentication and secrets | Basic/Bearer values, URL userinfo, secret assignments, and secret-valued fields replaced with `[REDACTED]` | Presence and surrounding operation shape, not credential material |
| Researcher identity | Email addresses, account names, and user-home path components replaced | Path structure without personal identity |
| Lab infrastructure | Machine, project, origin, container, operation, and run identifiers replaced with stable public labels | Cross-event equality and causal relationships |
| Network addresses | Every literal IP address replaced consistently with a stable symbolic endpoint placeholder | Endpoint role and cross-source correlation |
| Absolute time | ISO-8601, HTTP-date, syslog, and embedded Falco timestamps shifted to a synthetic `2025-01-01T00:00:00Z` epoch | Ordering, duration, and inter-event deltas |
| Opaque IDs | Session, request, event, tool, call, container, image, and UUID values deterministically pseudonymized by normalized, case-insensitive key type | Joins within this dataset |
| Process IDs | Deterministically mapped to synthetic numeric IDs | Parent/process correlation within this dataset |
| HTTP traffic | Request metadata retained; live response bodies omitted | Request path, status, redirect, source, and timing behavior |

Replacement counts in `redaction-ledger.json` are measurements of matches in
this run. A zero count means that no value of that category appeared in the
selected material; it does not mean the sanitizer lacks that protection.

## Intentional omissions

The public dataset does not contain:

- the literal dynamic proof;
- credentials, cookies, API keys, or provider authentication material;
- built-in Codex system and platform instructions;
- raw Codex rollout records or model reasoning;
- provider request/response metadata;
- the raw Falco `.scap` capture;
- unrelated preflight or historical traffic;
- active lab endpoints, cloud project identifiers, or customer data.

The full draft release contains additional sanitized status, timeline, journal,
runtime, and service evidence. It applies the same field-aware sanitizer and
still excludes the raw proof, rollout/reasoning, provider metadata, and SCAP.

## Deliberately preserved

To keep the trace useful, the derivation retains:

- the public CVE and product/version involved in this concrete realization;
- command text and sanitized command output;
- package-protocol path structure and HTTP status/redirect behavior;
- source type, event kind, relative timing, and causal endpoint relationships;
- model, Codex CLI, Tclone, launcher, and Gensee observe-only provenance;
- the six observationally distinct labeled stages and proof digest.

These details may make this specific incident recognizable. They are retained
intentionally so the corpus is evidence rather than a synthetic narrative.

## Integrity and reproducibility

`manifest.json` records every committed file's size and SHA-256 digest.
`SHA256SUMS` covers the complete dataset, and the release archive has its own
checksum asset. The validator checks structure, checksums, provenance, timeline
ordering, source vocabulary, ground truth, secret-shaped fields, literal IP addresses across data and tooling,
forbidden raw artifacts, symlinks, and unexpected binaries.

The release archive is built with sorted paths, zero modification times,
normalized ownership, and fixed modes. Independent builds from the same
private evidence must be byte-identical.

## Limitations

- This is one positive incident trace, not a classifier training/test split.
- The source clocks are treated as synchronized lab clocks; the dataset does
  not estimate clock uncertainty.
- Falco replay represents the finalized capture segment available in the
  evidence bundle, not guaranteed complete syscall coverage of the full run.
- Tool telemetry and command output do not expose unrecorded internal model
  state or reasoning.
- HTTP logs do not provide packet-level evidence or complete response bodies.
- The offline replay evaluates detection and correlation. It does not exercise
  prevention or reproduce a live vulnerable service.

## Audit commands

From this directory:

```bash
python3 tools/validate.py .
sha256sum -c SHA256SUMS
python3 -m unittest tools/test_tools.py
```

See [`tools/build_dataset.py`](tools/build_dataset.py) for the executable public
derivation and [`run-provenance.json`](run-provenance.json) for the captured
model and harness configuration.
