use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const MAX_TEXT_FILE_BYTES: u64 = 256 * 1024;

pub(crate) fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn read_limited_text(path: &Path) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} exceeds the {} byte audit limit",
                path.display(),
                MAX_TEXT_FILE_BYTES
            ),
        ));
    }
    fs::read_to_string(path)
}
