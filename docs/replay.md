# Authenticated telemetry replay

`gensee replay` turns heterogeneous JSONL telemetry into a deterministic,
integrity-checkable replay bundle. Signed bundles are tamper-evident when their
public-key fingerprint is anchored separately. It is intended for incident reconstruction and
defense evaluation, not for re-executing agent commands or network traffic.
The output represents observed evidence; it must not be described as native
runtime enforcement or as a replayed side effect.

## Build a bundle

Create a JSON manifest that identifies each source, its clock, and the fields
needed for later correlation. Paths are resolved relative to the manifest.
Inputs may be plain or gzip-compressed JSONL.

```console
gensee replay build \
  --manifest integrations/replay/example-manifest.json \
  --output replay-bundle
```

Sources with clocks are reordered independently within the configured bounded
window, then merged into one globally ordered `timeline.jsonl`. An event that
arrives later than that window fails the build instead of silently producing a
false order. `max_record_bytes` and `max_buffered_events` put hard, validated
bounds around adversarial records and dense reorder windows. Sources that have sequence but no trustworthy timestamps go to
`sequence.jsonl`; Gensee never invents timestamps for them.

The safe default emits only explicitly selected fields, and those fields still
pass through Gensee's secret-redaction floor. Setting
`include_record` includes the source record after applying Gensee's secret
redaction floor. This remains potentially sensitive evidence and should be
reviewed before publication.

Every input receives record, byte, digest, timestamp-range, regression, and
emission accounting in `coverage.json`. `bundle-manifest.json` authenticates
the exact replay manifest, timeline, sequence stream, coverage, and provenance
by SHA-256 digest.

## Sign and verify

To authenticate the bundle's origin, create a 32-byte Ed25519 seed as lowercase
or uppercase hexadecimal, keep it outside the bundle, and pass it at build
time. For example, `openssl rand -hex 32` can generate a seed; restrict the
resulting file to its owner.

```console
gensee replay build --manifest replay.json --output bundle \
  --signing-key replay-signing-seed.hex
gensee replay verify --bundle bundle --require-signature \
  --trusted-key trusted-replay-public-key.hex
```

The bundle contains its public key so it can verify its own consistency. That
embedded key alone does not establish who created the bundle. Distribute or
pin `public-key.hex` through a separate trusted channel and use `--trusted-key`
when authenticity matters.

Verification checks every artifact digest, the optional Ed25519 signature,
global timestamp monotonicity, JSON validity, and coverage totals.

## Correlate causal evidence

Correlation rules describe ordered event categories without embedding one
incident's IP addresses, timestamps, or service names in Gensee. Each step may
match a source, exact selected-field values, and required fields. `max_span_ms`
defines the causal window. A later step can list normalized field names in
`same_as_previous` to require the same request ID, connection fingerprint, or
other join key as the immediately preceding observation.

```console
gensee replay correlate --bundle bundle \
  --rules integrations/replay/example-rules.json \
  --output correlation-report.json \
  --require-signature --trusted-key trusted-replay-public-key.hex
```

Candidate and result counts are explicitly bounded. The report records dropped
candidates and truncated matches so resource limits cannot masquerade as
complete analysis.

## Manifest clocks

- `numeric`: tries JSON pointers in order and converts the declared seconds,
  milliseconds, microseconds, or nanoseconds unit.
- `rfc3339`: tries JSON pointers in order and parses an RFC 3339 timestamp.
- `sequence`: retains source order separately without joining the timed stream.

Falco manifests can list `/output_fields/evt.rawtime`,
`/output_fields/evt.time`, and `/output_fields/evt.time.iso8601` as numeric
nanosecond alternatives. Other collectors can use their own pointers without
requiring source-specific product code.

## Deliberate boundaries

- Replay does not execute recorded commands, tool calls, HTTP requests, or
  packets.
- JSONL normalization does not infer missing packets or repair sensor loss.
- Packet decoding and protocol-specific transaction reconstruction happen in
  the collection/export layer; their normalized events can then be replayed.
- A correlation match is evidence that declared observations occurred in order
  within a window. It is not by itself proof of causation.
