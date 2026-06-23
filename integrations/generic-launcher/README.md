# Generic Launcher Integration

Launcher support for `gensee run -- <agent>` run attribution.

Initial behavior:

```bash
gensee run -- claude
gensee run list
gensee timeline
```

The launcher mints a local run id, records the child agent root PID, captures
cwd/repo metadata, sets `GENSEE_RUN_ID`, `AGENT_SHIELD_SESSION_ID`, and
`AGENT_SHIELD_START_TIME_MS`, and stores run records under `~/.gensee`.

`gensee session list` remains a compatibility alias for older local tests.
