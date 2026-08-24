# Public trace data dictionary

All JSONL files contain one JSON object per line. `schemas/event.schema.json`
discriminates the ten runtime event kinds; `schemas/model-interaction.schema.json`
discriminates the four model item kinds and their nested content blocks.

## Common runtime envelope

| Field | Type | Meaning | Provenance |
| --- | --- | --- | --- |
| `schema_version` | string | Public contract version, currently `1.0` | synthetic |
| `trial_id` | enum | `trial-01` through `trial-04` | synthetic |
| `event_id` | string | Present in `unified-timeline`; globally unique trial-qualified sequence | synthetic |
| `ts` | date-time | Shifted lane-local timestamp | synthetic from observed time |
| `ts_offset_ms` | integer | Milliseconds since that trial's release | derived |
| `cohort_offset_ms` | integer | Release offset plus lane offset; shared merge clock | derived |
| `source` | enum/string | Normalized producing evidence source | derived |
| `machine_role` | enum | Public topology attribution | derived or correlated |
| `kind` | discriminator | Event type listed below | derived |
| `data` | object | Kind-specific payload | observed/derived as marked |
| `provenance` | object | Field/path to `observed`, `derived`, `correlated`, or `synthetic` | synthetic annotation |

Source-specific JSONL files omit `event_id`; the same records in
`unified-timeline.jsonl` add it. For one trial, order by `ts_offset_ms` and then
the stable file order. Across trials, order by `cohort_offset_ms`, `trial_id`,
and the lane-local sequence. Do not merge lanes by `ts`.

## Runtime event kinds

| `kind` | Source file | Important `data` fields |
| --- | --- | --- |
| `benchmark.submission.accepted` | `benchmark-events` | attempt, metric, reported score, visibility, kind, rows, pseudonymous ID |
| `codex.command.completed` | `codex-commands` | full sanitized command, category, exit code, status, target domains |
| `controller.trial.completed` | `controller-events` | outcome and highest independently confirmed level |
| `controller.boundary_escape.confirmed` | Trial 3 controller events | L4 effect, ten authenticated 200s, model ordinal, non-claims |
| `falco.runtime.signal` | `falco-relevant-events` | rule, process, command, connection, container pseudonym, selection reason |
| `gcp.network.firewall` | `cloud-network-events` | endpoint roles, port, protocol, disposition, selection reason |
| `gcp.network.flow` | `cloud-network-events` | same normalized flow fields when a non-firewall source is selected |
| `package_service.http.request` | `nexus-http-events` | request sequence, method, path, status, response bytes, duration |
| `protected_origin.http.request` | `origin-http-events` | request sequence, method, path, status, auth presence/public fingerprint |
| `relay.request.decided` | `relay-events` | audit sequence, method/path, decision/reason, status, duration; source role is `unknown` because the local relay proxy obscured it |

An event may be observed at one source while individual normalized fields are
derived. For example, origin status and authentication presence are observed;
the public credential fingerprint and endpoint role are derived. The
`provenance` object records exceptions to the event's default.

## Model interaction envelope

| Field | Type | Meaning |
| --- | --- | --- |
| `trial_id` | enum | Lane attribution; required on every item |
| `interaction_seq` | integer | Complete lane-local retained order, restarting at 1 |
| `ts`, `ts_offset_ms`, `cohort_offset_ms` | time fields | Same clock model as runtime events |
| `item` | discriminated object | One of the four variants below |
| `provenance` | object | Item observed; timestamps/identifiers derived or synthetic |

`item.item_id` is a stable public pseudonym and is globally unique across this
cohort. It is an identity, not an ordering key. `call_id` joins a tool call to
its result within one trial.

## Model item variants

### `message`

- `role=user`: model input with `input_text` blocks.
- `role=assistant`: model output with `output_text` blocks and phase.
- `role=developer`: explicit `redacted_content` placeholder. The original
  built-in harness instruction is intentionally withheld.

### `reasoning`

The retained source exposed no readable summary. `reasoning_summary` is empty,
`reasoning_summary_available` is false, and `encrypted_content` records
`bytes`, `sha256`, and `published:false`. The digest is completeness metadata,
not a decryptable reasoning record.

### `custom_tool_call`

Model output containing `name`, `status`, sanitized string `input`, and
pseudonymous `call_id`.

### `custom_tool_call_output`

Model input containing the corresponding `call_id` and an array of
`input_text` result blocks. Nested credential, address, account, host, source
time, and opaque-ID redaction is applied recursively.

## Nested metadata

When available, `item.metadata` contains a public `turn_id`. It may also contain
`create_ts`, `create_ts_offset_ms`, and `create_cohort_offset_ms`. Validators
bind all three coordinates to the lane epoch and cohort release offset.

## Machine-role vocabulary

The complete vocabulary is machine-readable in `topology.json`:

- `machine_a`: Codex/Tclone environment;
- `package_service`: Nexus 2 on Machine B;
- `inference_relay`: hardened Machine E;
- `benchmark_evaluator`: lane-local scorer;
- `protected_origin`: controlled origin outside A's envelope;
- `network_control_plane`: GCP telemetry;
- `controller`: experiment controller/authenticated replay;
- `relay_local_probe`, `public_external`, `private_unknown`, `unknown`:
  narrower attribution unavailable or intentionally abstracted.

## Trial metadata

| File | Meaning |
| --- | --- |
| `outcome.json` | Uniform positive/negative outcome and archive qualification |
| `trial-summary.json` | Duration and record totals plus outcome |
| `trace-coverage.json` | Raw counts, published counts, selection rules, and capture drops |
| `run-provenance.json` | Model, harness, task, and Gensee settings |
| `redaction-ledger.json` | Preserved/omitted categories and replacement counts |
| `model-interaction-availability.json` | Captured, withheld, encrypted, and unavailable model content |
| `ground-truth.json` | Trial 3's independently confirmed L4 claim, public model-action identity, private-source locator, stage windows, and explicit non-claims |

## Provenance vocabulary

- `observed`: copied from a retained evidence source after safe normalization;
- `derived`: mechanically calculated or one-way pseudonymized;
- `correlated`: conclusion requiring two or more independent evidence sources;
- `synthetic`: publication-only identifier, timestamp, label, or annotation.

Schema `x-provenance` annotations state the expected source class. Record-level
`provenance` maps state the actual class used for key fields.
