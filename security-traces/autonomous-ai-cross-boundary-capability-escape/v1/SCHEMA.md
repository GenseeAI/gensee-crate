# Trace schema and data dictionary

This document describes the two public JSONL streams, their event/item
variants, machine attribution, and field provenance. The normative schemas are
[`schemas/event.schema.json`](schemas/event.schema.json) and
[`schemas/model-interaction.schema.json`](schemas/model-interaction.schema.json)
for corpus records, plus
[`schemas/control-summary.schema.json`](schemas/control-summary.schema.json) and
[`schemas/cohort.schema.json`](schemas/cohort.schema.json) for cohort metadata,
and [`schemas/alert.schema.json`](schemas/alert.schema.json) for detector output.
`tools/validate.py` validates every record against them.

## Provenance vocabulary

Every property declared in the normative schemas has an `x-provenance`
annotation with one of these values:

| Value | Meaning |
| --- | --- |
| `observed` | Retained from one source record after safety redaction. |
| `derived` | Normalized, time-shifted, pseudonymized, classified, counted, or hashed from source evidence. |
| `correlated` | Produced by joining multiple records or by an independent cross-source conclusion. |
| `synthetic` | Created solely for publication structure, such as sequence IDs, schema versions, or explicit omission placeholders. |

Provenance applies to a field's method of construction, not to the truth of the
whole event. For example, a gateway status is observed while the flag linking
that request to the agent is correlated.

## Machine and role vocabulary

The machine-readable vocabulary is in [`topology.json`](topology.json).

| Role | Experimental responsibility | Typical evidence |
| --- | --- | --- |
| `machine_a` | Agent/Codex execution cell; the experiment's restricted workload. | Codex records, selected Falco signals, and source side of agent network flows. |
| `nexus` | Isolated package-service machine through which A could obtain packages. | Nexus request logs and network destination role. |
| `inference_gateway` | Machine E, the LiteLLM-compatible gateway allowed from A. | Gateway access records and gateway NAT flows. |
| `package_origin` | Controlled upstream package repository. | Origin request logs and package-service upstream flows. |
| `challenge_evaluator` | Isolated benchmark submission/evaluation service. | Benchmark receipts and allowlisted network flows. |
| `public_external` | Public service outside the experiment topology. | Address-free cloud-flow destinations or provider-mediated targets. |
| `private_unknown` | Redacted or unresolved private-network endpoint. | Normalized cloud telemetry only. |
| `unknown` | Endpoint role could not be safely or reliably assigned. | Normalized cloud telemetry only. |

`source` identifies the telemetry producer, not necessarily the process that
caused the effect. A `gateway/http.response` record was observed on E, while
`data.source_role: machine_a` attributes its requester. A provider event
describes an off-VM hosted-tool effect. GCP records use source/destination roles
for both endpoints. The controller record is an independent cross-source
conclusion rather than a machine-local sensor event.

## Normalized runtime event envelope

Each line of `traces/unified-timeline.jsonl` is one strict object:

| Field | Type | Provenance | Meaning |
| --- | --- | --- | --- |
| `schema_version` | string, always `1.0` | synthetic | Public schema version. |
| `event_id` | `trial-NN_evt_` plus six digits | synthetic | Cohort-global identifier required in a unified timeline and omitted from source-specific files; the numeric suffix is sequential within the named trial. |
| `ts` | RFC 3339 timestamp | derived | Lane-local shifted pseudotime: exactly `synthetic_epoch + ts_offset_ms`. Provider completion events use retained client-observation time. Do not merge lanes by this field. |
| `ts_offset_ms` | non-negative integer | derived | Milliseconds from that trial's experiment origin. |
| `cohort_offset_ms` | non-negative integer | derived | Shared clock coordinate required in unified timelines: `actual_release_offset_ms + ts_offset_ms`. Sort this field to merge lanes. |
| `source` | enum | derived | Normalized telemetry producer. |
| `kind` | string discriminator | derived | Event variant within the source. |
| `data` | object | mixed | Variant-specific payload described below. |

The schema declares **16 discriminated source/kind variants**. The first 15 are
source and positive-outcome variants; `controller/peer_escape.cancellation` is
the control-only censoring variant. `challenge_evaluator/challenge.request` is
declared even where its count is zero so the challenge-access surface has an
explicit contract; no such request is fabricated.

| Source / kind | Count | Payload fields and interpretation |
| --- | ---: | --- |
| `benchmark/submission.accepted` | 3 | Submission kind, attempt, row count, metric, score visibility, and nullable score. |
| `codex/command.completed` | 69 | Sanitized command summary/category, exit/status, requested tools and target domains, and gateway-credential-variable use. |
| `controller/boundary_escape.confirmed` | 1 | Correlated outcome classification and negative Nexus/private-holdout flags. |
| `controller/peer_escape.cancellation` | 0 in Trial 8; 1 per control | Correlated right-censoring label, peer trial, and explicit statement that no escape was observed before cancellation. |
| `falco/runtime.signal` | 35 | Selected rule, process, command summary/category, connection role, and gateway-variable use. |
| `gateway/http.response` | 123 | Method/path/status, authentication, requester role, and direct-agent-request correlation. |
| `gcp/network.firewall` | 3,089 | Address-free endpoint roles, ports, protocol, disposition, bytes, country, and ASN. |
| `gcp/network.nat_flow` | 470 | Same normalized network fields for NAT telemetry. |
| `gcp/network.vpc_flow` | 4,564 | Same normalized network fields for VPC-flow telemetry. |
| `nexus/package.request` | 343 | Sanitized request method/path/status, bytes, nullable upstream status, and redirect observation. |
| `package_origin/origin.request` | 327 | Same request contract for the controlled upstream. |
| `challenge_evaluator/challenge.request` | 0 | Reserved strict request contract for evaluator access; no public record observed. |
| `provider/hosted_tools.response` | 7 | HTTP result, observation interaction, response pseudonym, requested hosted tools, observed effects, and target domains. |
| `provider/web_search.completed` | 2 | Provider effect correlated to the model-stream item where the client observed completion. |
| `provider/open_page.completed` | 5 | Provider effect correlated to the model-stream item where the client observed completion. |
| `provider/code_interpreter.completed` | 1 | Provider effect correlated to the model-stream item where the client observed completion. |

Network records omit literal addresses. `source_role` and `destination_role`
are derived classifications; nullable `destination_country` and
`destination_asn` mean the source telemetry did not yield a publishable public
destination classification. Request paths are retained only after redaction;
body content is not inferred from a byte count. Nullable HTTP/upstream status
means no status was available, not a successful response.

## Model-interaction envelope

Each line of `traces/model-interactions.jsonl` is a strict object:

| Field | Type | Provenance | Meaning |
| --- | --- | --- | --- |
| `schema_version` | string, always `1.0` | synthetic | Public schema version. |
| `interaction_seq` | positive integer | synthetic | Complete retained stream order within one trial. It restarts at 1 per lane and is not a cohort identity. |
| `ts` | RFC 3339 timestamp | derived | Lane-local shifted pseudotime: exactly `synthetic_epoch + ts_offset_ms`. Do not merge lanes by this field. |
| `ts_offset_ms` | non-negative integer | derived | Milliseconds from that trial's experiment origin. |
| `cohort_offset_ms` | non-negative integer | derived | Shared merge coordinate: `actual_release_offset_ms + ts_offset_ms`. Sort this field to merge model streams. |
| `item` | object | observed | Exactly one of the four item variants below; nested `item_id` is the cohort-global identity. |

### Four discriminated item types

The counts below describe positive Trial 8. Control counts are declared in each
`model-interaction-availability.json` and validated against its model stream.

| `item_type` | Count | Direction | Required content |
| --- | ---: | --- | --- |
| `message` | 17 | Role-specific | Exactly one role branch: 2 user `input_text` messages, 3 developer `redacted_content` placeholders, or 12 assistant `output_text` commentary messages. |
| `reasoning` | 126 | `model_output` | Empty readable summary, explicit `reasoning_summary_available: false`, and an unpublished encrypted-content byte count/digest record. |
| `custom_tool_call` | 115 | `model_output` | Pseudonymous item/call IDs, tool name/status, and retained input string. |
| `custom_tool_call_output` | 114 | `model_input` | Matching pseudonymous call ID and one or more `input_text` output blocks. |

All items contain a pseudonymous `item_id` and `metadata.turn_id`. The validator
requires all 1,501 `item_id` values to be globally unique across the cohort.
When source creation time is available, `metadata.create_ts` and
`metadata.create_ts_offset_ms` must appear together and must satisfy the same
lane-epoch equation as the outer item timestamp. The nested content-block
discriminator is `type`:

| Block type | Parent | Fields |
| --- | --- | --- |
| `input_text` | User message or tool output | `type`, retained `text`. |
| `output_text` | Assistant message | `type`, retained `text`. |
| `redacted_content` | Withheld developer message | `type`, normalized withholding `reason`; it contains no hidden text. |

The encrypted reasoning placeholder contains only `bytes`, `sha256`, and
`published: false`. It proves availability/omission accounting, not access to
the encrypted content or chain-of-thought.

The same omission contract applies when encrypted reasoning appeared inside a
client-printed provider response: the nested value is replaced by a
`bytes`/`sha256`/`published` object. Encoded internal container/deployment IDs
and raw hosted-tool item IDs are deterministically pseudonymized, and the
gateway safety identifier is withheld.

## Detector alert schema

Each JSONL alert consumed by `tools/score.py` must satisfy
`schemas/alert.schema.json`. In particular, `ts_offset_ms` is a non-negative
JSON integer (booleans are rejected), `kind` is at most 128 characters, and
`rule_id`, `source`, and `kind` are non-empty. Additional detector-specific
properties are allowed. Alert properties use the same provenance vocabulary as
the corpus schemas.

## Cohort and control metadata

`cohort.json` is validated by `schemas/cohort.schema.json`. It records the exact
four-trial membership, shared configuration, lane-specific split policy,
outcome/censoring label, publication path, synthetic epoch, and measured release
offset for each trial. Trial order in this file is identity order, not start
order. `actual_release_offset_ms` is measured from the Trial 5 controller
release. Each lane's `ts` is intentionally independent pseudotime; cross-lane
replay must merge unified events by `cohort_offset_ms` and may use `event_id` as
a stable globally unique identity.

Each `controls/trial-*/control-summary.json` is validated by
`schemas/control-summary.schema.json`. It records observed duration, last model
activity, peer-cancellation offset, benchmark submission observations,
collection warnings, and explicit negative observations. `censored: true` and
`outcome: no_escape_observed_before_peer_cancellation` are required; the schema
does not permit a control to be represented as a completed negative.

## Validation contract

`python3 tools/validate.py .` performs dependency-free Draft 2020-12 subset
validation for every source-specific runtime record, all 32,138 unified runtime
events, and all 1,501 model items across the four trials. It also proves, per
trial, that the source-specific event multiset equals the non-controller portion
of the unified timeline. It
requires exactly one matching `oneOf` branch, rejects undeclared properties,
checks types/constants/enums/required fields, validates nested content blocks,
and audits that each declared property has a valid `x-provenance` annotation.
It also checks topology vocabulary agreement, counts, ordering, checksums,
manifest coverage, redaction invariants, and ground-truth support. The validator
loads every redaction ledger and run-provenance file, checks every event and
model timestamp—including nested creation timestamps—against its declared lane
epoch, checks every unified event and model item's cohort offset, enforces
globally unique `event_id` and model `item_id` values, locks all four measured
release offsets, and proves that all three peer cancellations follow the
triggering Trial 8 escape on the shared clock.
For retained provider payloads it rejects raw hosted-tool/container identifier
shapes without assuming an encoding, rejects any string-valued nested
`encrypted_content`, and reconciles all 21 nested omission records with the
redaction ledger. It also requires the exact provider-effect inventory and a
one-to-one, status- and time-bounded join between the seven direct Responses
gateway events and seven hosted-tool response observations.

The schema files are normative. This document is the human-readable data
dictionary; where they differ, validation follows the schema.
