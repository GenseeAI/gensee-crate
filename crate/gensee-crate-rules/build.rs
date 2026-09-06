use sha2::{Digest, Sha256};
use std::path::Path;
fn sources(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(path).expect("crate sources") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else {
            out.push(path);
        }
    }
}
fn main() {
    let mut files = vec!["Cargo.toml".into(), "build.rs".into()];
    sources(Path::new("src"), &mut files);
    files.sort();
    let mut hash = Sha256::new();
    println!("cargo:rerun-if-changed=src");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        hash.update(path.to_string_lossy().as_bytes());
        let bytes = std::fs::read(path).expect("crate source");
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    println!(
        "cargo:rustc-env=GENSEE_SOURCE_FINGERPRINT={:x}",
        hash.finalize()
    );
}
