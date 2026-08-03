# Endpoint Security spike

The EndpointSecurity spike is isolated from the current release path. The
current watch path uses Apple's `/usr/bin/eslogger` as the default system-event
source when available; a signed EndpointSecurity client remains future work.

```bash
cargo run -p gensee-crate-macos --bin endpoint-spike -- list
cargo run -p gensee-crate-macos --bin endpoint-spike -- exec
cargo run -p gensee-crate-macos --bin endpoint-spike -- file-mutation
cargo run -p gensee-crate-macos --bin endpoint-spike -- file-open
```

The current implementation uses Apple's `/usr/bin/eslogger` as a temporary event
source. Production should replace this with a signed EndpointSecurity client.

## Ingesting `eslogger` events

For normal sidecar capture, use [`gensee watch`](watch.md). It starts
`/usr/bin/eslogger` by default on macOS and writes normalized system events into
the active `GENSEE_HOME` store. The manual ingester is still useful for focused
experiments and saved event streams.

Pipe `eslogger` JSON into Gensee to persist normalized Layer 1 system events:

```bash
cargo build -p gensee-crate-cli

sudo cargo run -p gensee-crate-macos --bin endpoint-spike -- exec \
  | GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee ingest eslogger

GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee timeline
```

`exec` is system-wide and intentionally noisy. Use `--select` during local
testing to keep the stream focused:

```bash
sudo cargo run -p gensee-crate-macos --bin endpoint-spike -- exec \
  --select /bin/sleep --duration-seconds 10 \
  | GENSEE_HOME=$PWD/.gensee-dev ./target/debug/gensee ingest eslogger
```

`endpoint-spike` writes status text to stderr and leaves stdout for JSON events.
The ingester redacts common secret-bearing environment variables and JSON fields
before storing raw event JSON.

## File-open experiments

For file-open experiments, capture a short bounded window and filter the Gensee
timeline afterward. Apple's `eslogger --select` is best for process path
filters, not target file path filters:

```bash
sudo ./target/debug/endpoint-spike file-open --duration-seconds 30 \
  | GENSEE_HOME=$PWD/.gensee-pdf-test ./target/debug/gensee ingest eslogger

GENSEE_HOME=$PWD/.gensee-pdf-test ./target/debug/gensee timeline \
  --path "/path/to/target/dir"
```
