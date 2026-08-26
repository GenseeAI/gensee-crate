# Boundary extension protocol examples

These files show the language-neutral configuration and result shapes for the
three executable extension roles:

- `intent-analyzer-result.json` — output from an external intent analyzer;
- `semantic-verifier-config.json` and `semantic-verifier-result.json` — pinned
  verifier registration and bounded stdout result;
- `capability-provider-config.json` — pinned provider registration.

They are deliberately generic and are not production-ready registrations. The
paths and SHA-256 values are placeholders. See
`docs/boundary-extension-authoring.md` for deployment and trust requirements.
