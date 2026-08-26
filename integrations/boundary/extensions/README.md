# Boundary extension protocol examples

The canonical, compile-checked JSON protocol examples are packaged with
`gensee-crate-rules` under
[`crate/gensee-crate-rules/fixtures/boundary/extensions/`](../../../crate/gensee-crate-rules/fixtures/boundary/extensions/).
Keeping the fixtures inside the crate ensures `cargo package` can include and
validate them without reading files outside the package root.

They are deliberately generic and are not production-ready registrations. See
[`docs/boundary-extension-authoring.md`](../../../docs/boundary-extension-authoring.md)
for deployment and trust requirements.
