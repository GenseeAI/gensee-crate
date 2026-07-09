---
layout: home

hero:
  name: Gensee Crate
  text: Full-stack, long-horizon runtime safety<br>for AI coding agents.
  tagline: Gensee Crate watches system events,<br>requests, tool calls, skills, and memory<br>behind Claude Code, Codex, and Antigravity.
  image:
    src: /gensee-crate-defense-in-depth.png
    alt: Gensee Crate defense-in-depth architecture
  actions:
    - theme: brand
      text: Get Started
      link: /architecture
    - theme: alt
      text: Safety Policy
      link: /policy
    - theme: alt
      text: GitHub
      link: https://github.com/GenseeAI/gensee-crate

features:
  - title: Observe What Agents Do
    details: Capture prompts, tool intent, commands, files, network targets, alerts, and timeline context in a local store.
    link: /watch
    linkText: Run the sidecar
  - title: Enforce Before Risky Tools Run
    details: Apply configurable allow, ask, and deny decisions for secrets, destructive operations, control-plane writes, suspicious artifacts, and Linux fanotify file events.
    link: /policy
    linkText: Read the policy model
  - title: Launch With Extra Containment
    details: Use managed macOS sandboxing and staged workspace review when you want Gensee to launch the agent.
    link: /run-and-sandbox
    linkText: Use gensee run
  - title: Connect Agent Surfaces
    details: Wire Claude Code, Codex, and Antigravity hooks into the same timeline, with sidecar coverage for unmanaged runs.
    link: /claude-code-hooks
    linkText: Configure integrations
  - title: Protect Linux Hosts
    details: Inspect Linux capabilities, monitor direct agent process trees through /proc, enforce sensitive-path access with fanotify, launch agents under seccomp, and plan cgroup-scoped nftables egress controls.
    link: /linux
    linkText: Explore Linux support
  - title: Trace Long-Horizon Behavior
    details: Link prompts, tool calls, file effects, artifacts, alerts, and review verdicts for post-run inspection.
    link: /lineage-graph
    linkText: Explore lineage
  - title: Inspect The Local Dashboard
    details: Review live activity, lineage, policy decisions, alerts, and policy edits against the same endpoint store.
    link: /dashboard
    linkText: Open dashboard docs
---
