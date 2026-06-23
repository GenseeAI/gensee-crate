# PreToolUse latency benchmark

Measures the **in-process** latency the gensee-crate `PreToolUse` hook adds per
decision. Cold start (process spawn) is deliberately out of scope — the pipeline
is driven in an in-process loop (policy + store opened once).

## Feature-gated — production builds contain none of this

All harness code lives behind the `bench` Cargo feature and is **not compiled**
into a default (production) build:

```
cargo build --release -p gensee-crate-cli          # production — no bench code, no `bench` subcommand
cargo build --release -p gensee-crate-cli --features bench   # adds `gensee bench`
```

Verify: `nm target/release/gensee | grep -c run_bench` → `0` for a production build.

## Methodology

- **E2E mode** times the whole decision call from *outside* the pipeline (one
  clock pair per iteration, in the driver). The measured code carries no
  instrumentation, so these are the reported overhead numbers.
- **Breakdown mode** brackets each coarse phase (parse / intents / evaluate /
  serialize). Its per-phase *shares* are reported; its absolute totals are not
  comparable to e2e (the extra clock reads perturb them).
- "without gensee-crate" = a no-op passthrough hook (decode + emit `allow`); the
  gap to "with" is our evaluation overhead.
- Request mix weights are derived from `platform-analysis/report-5-25` (gated
  tool counts): benign file ops dominate; the pre-exec script path (`exec_script`)
  is ~14% and drives the tail.

## Run

```
cargo build --release -p gensee-crate-cli --features bench
./target/release/gensee bench --mode e2e        --iterations 20000 --warmup 2000 --out bench/results
./target/release/gensee bench --mode breakdown  --iterations 20000 --warmup 2000 --out bench/results
python3 bench/plot_latency.py --dir bench/results   # -> latency-cdf.png, latency-breakdown.png
```

## Snapshot (release, dev laptop — not the target VM)

| config | p50 | p90 | p99 | p999 | max |
| --- | --- | --- | --- | --- | --- |
| with gensee-crate | 10µs | 125µs | 150µs | 285µs | 840µs |
| without (no-op floor) | 0.9µs | 1.0µs | 1.3µs | 2.9µs | 12µs |

Budget is **200ms p50 / 500ms p99 added** — we are ~1000× under it in-process.
The tail is entirely `exec_script`: evaluate = 130µs (96%), i.e. the pre-exec
content read + SHA-256 + risk-tag SQLite lookup. Everything else is a few µs
with a flat ~3.5µs parse floor.

> Run on the target VM before quoting numbers externally; this snapshot is a
> warm-cache dev-laptop figure.
