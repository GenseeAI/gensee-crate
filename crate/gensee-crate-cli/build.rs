use sha2::{Digest, Sha256};
fn main() {
    let mut hash = Sha256::new();
    for path in [
        "src/main.rs",
        "src/housekeeping.rs",
        "../gensee-crate-rules/src/policy.rs",
        "../gensee-crate-core/src/path.rs",
    ] {
        println!("cargo:rerun-if-changed={path}");
        hash.update(std::fs::read(path).expect("classifier source"));
    }
    println!(
        "cargo:rustc-env=GENSEE_CLASSIFIER_FINGERPRINT={:x}",
        hash.finalize()
    );
}
