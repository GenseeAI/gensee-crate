# Agent-security traces and evaluation

The repository publishes sanitized traces from controlled autonomous-agent
experiments, together with a study, an animated timeline, and offline validation
and scoring tools. They help examine how authority crosses service boundaries and
how evidence accumulates during long-running work.

- [Study and experiment overview](https://github.com/GenseeAI/gensee-crate/tree/main/security-traces)
- [Study PDF](https://github.com/GenseeAI/gensee-crate/blob/main/security-traces/papers/characterizing-transitive-authority-in-autonomous-coding-agents.pdf)
- [Animated event timeline](https://github.com/GenseeAI/gensee-crate/blob/main/security-traces/assets/trial-03-package-service-boundary-escape-timeline.gif)
- [Cross-boundary capability-escape dataset](https://github.com/GenseeAI/gensee-crate/tree/main/security-traces/autonomous-ai-cross-boundary-capability-escape/v1)
- [Package-service boundary-escape dataset](https://github.com/GenseeAI/gensee-crate/tree/main/security-traces/autonomous-ai-package-service-boundary-escape/v1)

Gensee and Tclone ran in **observe-only** mode in these trials. The data supports
behavioral analysis, observability, correlation, and replay; it does not establish
active-defense effectiveness. Dataset methodology, sanitization, checksums,
schemas, and licensing are included with each release.

For product tooling that reconstructs an integrity-checked timeline from source
evidence without re-executing agent actions, see [authenticated replay](replay.md).
For an explicit enforcing runtime demonstration, use the
[boundary conformance proof](generic-boundary-proof.md) and
[end-to-end operation demo](generic-end-to-end-demo.md).
