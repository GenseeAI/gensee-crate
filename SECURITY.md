# Security Policy

Gensee Crate is security software, so we treat vulnerability reports with
priority and care.

## Supported Versions

The project is pre-1.0. Until a stable release line exists, security fixes are
made on `main` and included in the next tagged release.

## Reporting a Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Report security issues through GitHub's private vulnerability reporting for
this repository. If private reporting is unavailable, contact the maintainers
through https://www.gensee.ai/contact.html with:

- Affected version or commit.
- A clear description of the issue and impact.
- Reproduction steps or a proof of concept, when safe to share.
- Any known mitigations.

We aim to acknowledge reports within 3 business days, provide an initial
assessment within 10 business days, and coordinate disclosure timing with the
reporter.

## Local Data Handling

Gensee Crate is local-first. By default it stores telemetry under
`$GENSEE_HOME` or `~/.gensee`, including hook events, policy alerts, lineage
data, and SQLite/JSONL state. Secret-like values are redacted before storage,
but paths, command structure, policy evidence, and other local security
telemetry may still be sensitive.

Fresh telemetry stores are encrypted at rest by default. The local store key is
kept in `$GENSEE_HOME/gensee.key`; keep that key private and do not attach it
with store snapshots in public issues or support requests. Sharing the key and
encrypted store together gives readers access to the telemetry. Existing
plaintext development stores remain readable rather than breaking hooks; move or
remove the old `GENSEE_HOME` to start a fresh encrypted store. Set
`GENSEE_STORE_ENCRYPTION=0` only for disposable local debugging stores.

## Scope

Examples of in-scope issues include:

- Bypasses of documented allow/ask/deny policy behavior.
- Secret leakage from captured telemetry or dashboard rendering.
- Unsafe handling of attacker-controlled prompts, commands, paths, or tool
  output.
- Dashboard vulnerabilities that could modify local policy or expose local
  telemetry.
- Supply-chain, release, or packaging flaws that affect users installing
  Gensee Crate.

Out-of-scope examples include:

- Attacks that require the user to intentionally disable Gensee Crate.
- Findings against unreleased experiments that are clearly marked as
  non-production.
- Social engineering or physical access attacks.

## Disclosure

When a report is validated, we will work with the reporter on a fix and
release note. Public advisories will include enough detail for users to assess
impact and upgrade safely.
