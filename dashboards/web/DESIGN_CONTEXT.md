## Design Context

### Users
Gensee Crate is for individual developers who own their endpoint and install the product to protect themselves while using coding agents. They are technical, time-constrained, and close to the machine being protected. They need to see what the agent is doing now, understand why a decision was made, and trace how files, prompts, and tool calls relate after the fact.

### Brand Personality
Security console, local-first, precise. The interface should feel calm under pressure: serious enough for policy enforcement, fast enough for live monitoring, and transparent enough that a developer can trust it without feeling managed by someone else.

### Aesthetic Direction
Operational security console for a single endpoint. Prefer a light, high-contrast workspace with graphite navigation, crisp table-like density, restrained status color, and purpose-built graph/timeline visuals. Avoid cyberpunk neon, marketing hero layouts, generic SaaS cards, and decorative threat-map theater.

### Design Principles
- Make live protection the first read: current run, pending asks, denies, and watched surfaces should be visible immediately.
- Treat every alert as explainable: show the policy reason, evidence, artifact, and available action in the same context.
- Keep the developer in control: local state, profile selection, allowlists, and staged decisions should feel inspectable and reversible.
- Make lineage concrete: connect prompts, tools, files, and derived artifacts without requiring database knowledge.
- Stay quiet until risk matters: use color and motion only for status, severity, and state changes.
