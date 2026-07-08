use crate::enforcement::{LinuxEnforcementDecision, LinuxEnforcementRequest};
use crate::policy::LinuxPolicy;
use crate::session::LinuxSessionTarget;

#[derive(Debug, Clone)]
pub struct LinuxFanotifyConfig {
    pub policy: LinuxPolicy,
    pub session: Option<LinuxSessionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxFanotifyStatus {
    pub enforcing: bool,
    pub marked_paths: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxFanotifyEvent {
    pub request: LinuxEnforcementRequest,
    pub decision: LinuxEnforcementDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxFanotifyMarkPlan {
    pub marks: Vec<LinuxFanotifyMark>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxFanotifyMark {
    pub path: String,
    pub include_children: bool,
}

impl LinuxFanotifyConfig {
    pub fn new(policy: LinuxPolicy) -> Self {
        Self {
            policy,
            session: None,
        }
    }

    pub fn with_session(policy: LinuxPolicy, session: LinuxSessionTarget) -> Self {
        Self {
            policy,
            session: Some(session),
        }
    }
}

pub fn plan_fanotify_marks(policy: &LinuxPolicy) -> LinuxFanotifyMarkPlan {
    let mut marks = Vec::new();
    let mut warnings = Vec::new();
    for rule in &policy.sensitive_paths {
        match mark_from_pattern(&rule.pattern) {
            Some(mark) => marks.push(mark),
            None => warnings.push(format!(
                "fanotify cannot directly mark pattern `{}` yet; use an exact path or /path/** prefix",
                rule.pattern
            )),
        }
    }
    marks.sort_by(|left, right| left.path.cmp(&right.path));
    marks.dedup();
    LinuxFanotifyMarkPlan { marks, warnings }
}

fn mark_from_pattern(pattern: &str) -> Option<LinuxFanotifyMark> {
    let expanded = expand_home(pattern);
    if expanded.contains('*') {
        let prefix = expanded.strip_suffix("/**")?;
        if prefix.contains('*') {
            return None;
        }
        return Some(LinuxFanotifyMark {
            path: prefix.to_string(),
            include_children: true,
        });
    }
    Some(LinuxFanotifyMark {
        path: expanded,
        include_children: false,
    })
}

fn expand_home(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    pattern.to_string()
}

#[cfg(target_os = "linux")]
fn path_from_fd(fd: i32) -> Option<String> {
    std::fs::read_link(std::path::PathBuf::from("/proc/self/fd").join(fd.to_string()))
        .ok()
        .map(|path| path.to_string_lossy().to_string())
}

#[cfg(target_os = "linux")]
fn process_fields(pid: u32) -> (Option<String>, Option<String>) {
    let proc_root = std::path::PathBuf::from("/proc").join(pid.to_string());
    let process_name = std::fs::read_to_string(proc_root.join("comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let command_line = std::fs::read(proc_root.join("cmdline"))
        .ok()
        .map(|data| {
            data.split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|value| !value.is_empty());
    (process_name, command_line)
}

#[cfg(target_os = "linux")]
fn request_from_event(
    fd: i32,
    pid: u32,
    operation: crate::enforcement::LinuxAccessOperation,
) -> LinuxEnforcementRequest {
    let (process_name, command_line) = process_fields(pid);
    LinuxEnforcementRequest {
        operation,
        path: path_from_fd(fd),
        network_dest: None,
        syscall: None,
        pid: Some(pid),
        process_name,
        command_line,
    }
}

#[cfg(any(target_os = "linux", test))]
fn fanotify_response_for_verdict(verdict: LinuxEnforcementVerdict) -> u32 {
    match verdict {
        LinuxEnforcementVerdict::Deny => FAN_DENY,
        LinuxEnforcementVerdict::Ask => FAN_DENY,
        LinuxEnforcementVerdict::Speculate => FAN_DENY,
        LinuxEnforcementVerdict::Allow | LinuxEnforcementVerdict::Warn => FAN_ALLOW,
    }
}

#[cfg(any(target_os = "linux", test))]
use crate::enforcement::LinuxEnforcementVerdict;

#[cfg(any(target_os = "linux", test))]
const FAN_ALLOW: u32 = 0x01;
#[cfg(any(target_os = "linux", test))]
const FAN_DENY: u32 = 0x02;

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::mem;
    use std::os::fd::RawFd;
    use std::path::Path;

    use crate::capabilities::LinuxCapabilityReport;
    use crate::enforcement::LinuxAccessOperation;
    use crate::fanotify::{
        fanotify_response_for_verdict, plan_fanotify_marks, request_from_event,
        LinuxFanotifyConfig, LinuxFanotifyEvent, LinuxFanotifyStatus,
    };

    pub struct LinuxFanotifyEnforcer {
        fd: RawFd,
        config: LinuxFanotifyConfig,
        capabilities: LinuxCapabilityReport,
        marked_paths: Vec<String>,
        setup_warnings: Vec<String>,
    }

    impl LinuxFanotifyEnforcer {
        pub fn new(config: LinuxFanotifyConfig) -> io::Result<Self> {
            let capabilities = LinuxCapabilityReport::detect();
            if !capabilities.supports_dynamic_file_enforcement() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fanotify permission enforcement requires Linux fanotify and root",
                ));
            }

            let fd = fanotify_init(
                FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                libc::O_RDONLY,
            )?;
            let mark_plan = plan_fanotify_marks(&config.policy);
            let mut marked_paths = Vec::new();
            let mut setup_warnings = mark_plan.warnings;
            for mark in mark_plan.marks {
                let path = Path::new(&mark.path);
                if !path.exists() {
                    setup_warnings.push(format!(
                        "fanotify mark skipped because path does not exist: {}",
                        mark.path
                    ));
                    continue;
                }
                match add_mark(fd, path, mark.include_children) {
                    Ok(()) => marked_paths.push(mark.path),
                    Err(error) => setup_warnings
                        .push(format!("fanotify mark failed for {}: {error}", mark.path)),
                }
            }

            Ok(Self {
                fd,
                config,
                capabilities,
                marked_paths,
                setup_warnings,
            })
        }

        pub fn status(&self) -> LinuxFanotifyStatus {
            LinuxFanotifyStatus {
                enforcing: true,
                marked_paths: self.marked_paths.clone(),
                warnings: self.setup_warnings.clone(),
            }
        }

        pub fn handle_events_once(&mut self) -> io::Result<Vec<LinuxFanotifyEvent>> {
            let mut buffer = [0u8; 64 * 1024];
            let read_len = read_fanotify(self.fd, &mut buffer)?;
            let mut offset = 0usize;
            let mut handled = Vec::new();

            while offset + mem::size_of::<FanotifyEventMetadata>() <= read_len {
                let metadata =
                    unsafe { &*(buffer[offset..].as_ptr() as *const FanotifyEventMetadata) };
                if metadata.event_len == 0 {
                    break;
                }
                let event_len = metadata.event_len as usize;
                if offset + event_len > read_len {
                    break;
                }
                if metadata.fd >= 0 {
                    let operation = operation_from_event(metadata.mask, metadata.fd);
                    let request = request_from_event(metadata.fd, metadata.pid as u32, operation);
                    let decision = self
                        .config
                        .policy
                        .evaluate_access(&request, &self.capabilities);
                    write_response(
                        self.fd,
                        metadata.fd,
                        fanotify_response_for_verdict(decision.verdict),
                    )?;
                    close_fd(metadata.fd);
                    handled.push(LinuxFanotifyEvent { request, decision });
                }
                offset += event_len;
            }

            Ok(handled)
        }
    }

    impl Drop for LinuxFanotifyEnforcer {
        fn drop(&mut self) {
            close_fd(self.fd);
        }
    }

    fn fanotify_init(flags: u32, event_f_flags: i32) -> io::Result<RawFd> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fanotify_init,
                flags as libc::c_uint,
                event_f_flags as libc::c_uint,
            ) as RawFd
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    fn add_mark(fd: RawFd, path: &Path, include_children: bool) -> io::Result<()> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "fanotify path contains NUL")
        })?;
        let mut flags = FAN_MARK_ADD;
        let mut mask = FAN_OPEN_PERM | FAN_ACCESS_PERM;
        if include_children {
            flags |= FAN_MARK_ONLYDIR;
            mask |= FAN_EVENT_ON_CHILD;
        }
        let result = unsafe {
            libc::syscall(
                libc::SYS_fanotify_mark,
                fd,
                flags as libc::c_uint,
                mask as u64,
                libc::AT_FDCWD,
                path.as_ptr(),
            ) as libc::c_int
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn read_fanotify(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(error)
            }
        } else {
            Ok(result as usize)
        }
    }

    fn write_response(fd: RawFd, event_fd: RawFd, response: u32) -> io::Result<()> {
        let response = FanotifyResponse {
            fd: event_fd,
            response,
        };
        let result = unsafe {
            libc::write(
                fd,
                &response as *const FanotifyResponse as *const libc::c_void,
                mem::size_of::<FanotifyResponse>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn operation_from_event(mask: u64, fd: RawFd) -> LinuxAccessOperation {
        if mask & FAN_ACCESS_PERM != 0 {
            return LinuxAccessOperation::FileRead;
        }
        access_mode_from_fd(fd)
    }

    fn access_mode_from_fd(fd: RawFd) -> LinuxAccessOperation {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return LinuxAccessOperation::FileRead;
        }
        match flags & libc::O_ACCMODE {
            libc::O_WRONLY | libc::O_RDWR => LinuxAccessOperation::FileWrite,
            _ => LinuxAccessOperation::FileRead,
        }
    }

    fn close_fd(fd: RawFd) {
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }

    #[repr(C)]
    struct FanotifyEventMetadata {
        event_len: u32,
        vers: u8,
        reserved: u8,
        metadata_len: u16,
        mask: u64,
        fd: i32,
        pid: i32,
    }

    #[repr(C)]
    struct FanotifyResponse {
        fd: i32,
        response: u32,
    }

    const FAN_ACCESS_PERM: u64 = 0x0002_0000;
    const FAN_OPEN_PERM: u64 = 0x0001_0000;
    const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
    const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
    const FAN_CLOEXEC: u32 = 0x0000_0001;
    const FAN_NONBLOCK: u32 = 0x0000_0002;
    const FAN_MARK_ADD: u32 = 0x0000_0001;
    const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;

    use crate::fanotify::{LinuxFanotifyConfig, LinuxFanotifyEvent, LinuxFanotifyStatus};

    pub struct LinuxFanotifyEnforcer {
        _config: LinuxFanotifyConfig,
    }

    impl LinuxFanotifyEnforcer {
        pub fn new(config: LinuxFanotifyConfig) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "fanotify permission enforcement is only available on Linux ({} sensitive rules configured)",
                    config.policy.sensitive_paths.len()
                ),
            ))
        }

        pub fn status(&self) -> LinuxFanotifyStatus {
            LinuxFanotifyStatus {
                enforcing: false,
                marked_paths: Vec::new(),
                warnings: vec![
                    "fanotify permission enforcement is only available on Linux".to_string()
                ],
            }
        }

        pub fn handle_events_once(&mut self) -> io::Result<Vec<LinuxFanotifyEvent>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fanotify permission enforcement is only available on Linux",
            ))
        }
    }
}

pub use platform::LinuxFanotifyEnforcer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{SensitivePathAccess, SensitivePathRule};

    #[test]
    fn plans_exact_and_prefix_marks() {
        let mut policy = LinuxPolicy::default();
        policy.sensitive_paths = vec![
            SensitivePathRule {
                pattern: "/tmp/secret/**".to_string(),
                access: SensitivePathAccess::ReadWrite,
                action: crate::policy::LinuxPolicyAction::Deny,
            },
            SensitivePathRule {
                pattern: "/tmp/token".to_string(),
                access: SensitivePathAccess::Read,
                action: crate::policy::LinuxPolicyAction::Ask,
            },
        ];

        let plan = plan_fanotify_marks(&policy);

        assert_eq!(
            plan.marks,
            vec![
                LinuxFanotifyMark {
                    path: "/tmp/secret".to_string(),
                    include_children: true,
                },
                LinuxFanotifyMark {
                    path: "/tmp/token".to_string(),
                    include_children: false,
                },
            ]
        );
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn warns_for_suffix_glob_marks() {
        let mut policy = LinuxPolicy::default();
        policy.sensitive_paths = vec![SensitivePathRule {
            pattern: "**/.env".to_string(),
            access: SensitivePathAccess::ReadWrite,
            action: crate::policy::LinuxPolicyAction::Ask,
        }];

        let plan = plan_fanotify_marks(&policy);

        assert!(plan.marks.is_empty());
        assert_eq!(plan.warnings.len(), 1);
    }

    #[test]
    fn denies_speculative_fanotify_events_until_backend_can_stage() {
        assert_eq!(
            fanotify_response_for_verdict(LinuxEnforcementVerdict::Speculate),
            FAN_DENY
        );
    }

    #[test]
    fn denies_ask_fanotify_events_until_prompt_broker_exists() {
        assert_eq!(
            fanotify_response_for_verdict(LinuxEnforcementVerdict::Ask),
            FAN_DENY
        );
    }
}
