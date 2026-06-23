# Contributing

Thanks for helping improve Gensee Crate. This project is early, and careful
bug reports, threat models, tests, docs, and small focused patches are all
valuable.

## Getting Started

```bash
git clone https://github.com/GenseeAI/gensee-crate.git
cd gensee-crate
cargo build -p gensee-crate-cli
cargo test --workspace
```

Dashboard checks:

```bash
cd dashboards/web
npm run check
```

## Development Checks

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd dashboards/web && npm run check
```

Some daemon/socket tests may need normal local process permissions. If they fail
inside a restricted sandbox with `Operation not permitted`, rerun them in a
regular local shell before assuming the product code is broken.

## Pull Request Guidelines

- Keep changes focused and explain the security or user-facing behavior being
  changed.
- Include tests for policy, parsing, storage, or dashboard behavior when the
  change affects those surfaces.
- Update docs when commands, policy behavior, data formats, or support status
  changes.
- Do not commit local telemetry stores, generated benchmark results, secrets,
  credentials, or machine-specific paths.

## Security-Sensitive Changes

For parser, policy, redaction, storage, dashboard rendering, or release-flow
changes, describe the threat model in the pull request. Call out any known
false positives, false negatives, compatibility breaks, or migration behavior.

## License

By contributing, you agree that your contribution is licensed under the Apache
License, Version 2.0.
