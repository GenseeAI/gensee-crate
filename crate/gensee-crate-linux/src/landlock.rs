#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::io;
use std::path::Path;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const READ_EXECUTE_ACCESS: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
const BASE_WRITE_ACCESS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM;
// The operation contract supplies every writable root. Adding ambient paths
// such as /tmp would silently make an original workspace beneath that path
// writable, while special descriptors such as /dev/stdout are not valid
// Landlock path-beneath parents. Already-open standard descriptors remain
// usable without any pathname mutation grant.
const RUNTIME_WRITE_PATHS: &[&str] = &[];

#[cfg(target_os = "linux")]
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    reserved: u32,
}

#[cfg(target_os = "linux")]
pub fn apply_landlock_write_sandbox(write_paths: &[String]) -> io::Result<()> {
    apply_landlock_sandbox(write_paths, true)
}

/// Gives a verifier read/execute access to the host filesystem while denying
/// every pathname-based mutation. Output must travel over an already-open
/// pipe or another non-filesystem channel.
#[cfg(target_os = "linux")]
pub fn apply_landlock_read_only_sandbox() -> io::Result<()> {
    apply_landlock_sandbox(&[], false)
}

#[cfg(target_os = "linux")]
fn apply_landlock_sandbox(write_paths: &[String], include_runtime_paths: bool) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: u32 = 1;

    // SAFETY: A null attribute with the documented VERSION flag queries the
    // Landlock ABI and does not dereference userspace memory.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Landlock is unavailable: {}", io::Error::last_os_error()),
        ));
    }
    let mut write_access = BASE_WRITE_ACCESS;
    if abi >= 2 {
        write_access |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        write_access |= ACCESS_FS_TRUNCATE;
    }
    let handled_access = READ_EXECUTE_ACCESS | write_access;
    let attr = RulesetAttr {
        handled_access_fs: handled_access,
    };
    // SAFETY: `attr` is a valid ruleset structure for the supplied size.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The syscall returned an owned descriptor on success.
    let ruleset_fd = unsafe { OwnedFd::from_raw_fd(ruleset_fd as i32) };

    add_path_rule(&ruleset_fd, Path::new("/"), READ_EXECUTE_ACCESS)?;
    let mut paths = write_paths.to_vec();
    if include_runtime_paths {
        paths.extend(RUNTIME_WRITE_PATHS.iter().map(|path| (*path).to_string()));
    }
    paths.sort();
    paths.dedup();
    for path in paths {
        let path = Path::new(&path);
        if !path.exists() {
            continue;
        }
        let allowed_access = if path.is_dir() {
            READ_EXECUTE_ACCESS | write_access
        } else {
            ACCESS_FS_EXECUTE
                | ACCESS_FS_READ_FILE
                | ACCESS_FS_WRITE_FILE
                | (write_access & ACCESS_FS_TRUNCATE)
        };
        add_path_rule(&ruleset_fd, path, allowed_access)?;
    }

    // SAFETY: PR_SET_NO_NEW_PRIVS accepts the documented scalar arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `ruleset_fd` is a valid Landlock ruleset descriptor.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd.as_raw_fd(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fn add_path_rule(
        ruleset_fd: &std::os::fd::OwnedFd,
        path: &Path,
        allowed_access: u64,
    ) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Landlock path contains NUL")
        })?;
        // SAFETY: `path` is NUL-terminated and the flags request an O_PATH fd.
        let path_fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if path_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned an owned descriptor on success.
        let path_fd = unsafe { OwnedFd::from_raw_fd(path_fd) };
        let rule = PathBeneathAttr {
            allowed_access,
            parent_fd: path_fd.as_raw_fd(),
            reserved: 0,
        };
        // SAFETY: Both descriptors and the path-beneath attribute are valid for
        // the duration of the syscall.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &rule,
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_write_sandbox(_write_paths: &[String]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Landlock is only available on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_read_only_sandbox() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Landlock is only available on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_rights_separate_read_execute_from_mutation() {
        assert_eq!(READ_EXECUTE_ACCESS & BASE_WRITE_ACCESS, 0);
        assert_ne!(BASE_WRITE_ACCESS & ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(BASE_WRITE_ACCESS & ACCESS_FS_REMOVE_FILE, 0);
        assert_ne!(BASE_WRITE_ACCESS & ACCESS_FS_MAKE_REG, 0);
    }

    #[test]
    fn write_sandbox_has_no_implicit_host_mutation_roots() {
        assert!(RUNTIME_WRITE_PATHS.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn write_sandbox_does_not_expand_a_declared_tmp_subtree() {
        let root = std::env::temp_dir().join(format!(
            "gensee-landlock-scope-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let original = root.join("original");
        let staged = root.join("staged");
        std::fs::create_dir_all(&original).unwrap();
        std::fs::create_dir_all(&staged).unwrap();

        // Run in a disposable child because Landlock restriction is
        // irreversible for the calling thread and its descendants.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
        if child == 0 {
            let result = apply_landlock_write_sandbox(&[staged.to_string_lossy().into_owned()])
                .and_then(|()| {
                    std::fs::write(staged.join("allowed"), b"ok")?;
                    match std::fs::write(original.join("denied"), b"bad") {
                        Err(error)
                            if matches!(error.raw_os_error(), Some(code) if code == libc::EACCES || code == libc::EPERM) => {
                            Ok(())
                        }
                        Err(error) => Err(error),
                        Ok(()) => Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "undeclared sibling beneath /tmp remained writable",
                        )),
                    }
                });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        let _ = std::fs::remove_dir_all(&root);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
