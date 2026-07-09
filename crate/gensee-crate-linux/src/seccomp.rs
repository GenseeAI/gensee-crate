use std::io;

use crate::policy::DangerousSyscallPolicy;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxSeccompProfile {
    pub default_action: LinuxSeccompAction,
    pub denied_syscalls: Vec<LinuxSeccompDeniedSyscall>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxSeccompAction {
    Allow,
    Errno,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxSeccompDeniedSyscall {
    pub name: String,
    pub group: LinuxSeccompSyscallGroup,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxSeccompSyscallGroup {
    Ptrace,
    Bpf,
    KernelModule,
    Mount,
    Namespace,
}

impl Default for LinuxSeccompProfile {
    fn default() -> Self {
        Self::from_policy(&DangerousSyscallPolicy {
            deny_mount_namespace_changes: true,
            deny_ptrace: true,
            deny_bpf: true,
            deny_kernel_module_loading: true,
        })
    }
}

impl LinuxSeccompProfile {
    pub fn from_policy(policy: &DangerousSyscallPolicy) -> Self {
        let mut denied_syscalls = Vec::new();
        if policy.deny_ptrace {
            denied_syscalls.extend([
                denied(
                    "ptrace",
                    LinuxSeccompSyscallGroup::Ptrace,
                    "debug or control another process",
                ),
                denied(
                    "process_vm_readv",
                    LinuxSeccompSyscallGroup::Ptrace,
                    "read another process memory",
                ),
                denied(
                    "process_vm_writev",
                    LinuxSeccompSyscallGroup::Ptrace,
                    "write another process memory",
                ),
            ]);
        }
        if policy.deny_bpf {
            denied_syscalls.push(denied(
                "bpf",
                LinuxSeccompSyscallGroup::Bpf,
                "load or manage kernel BPF programs",
            ));
        }
        if policy.deny_kernel_module_loading {
            denied_syscalls.extend([
                denied(
                    "init_module",
                    LinuxSeccompSyscallGroup::KernelModule,
                    "load a kernel module",
                ),
                denied(
                    "finit_module",
                    LinuxSeccompSyscallGroup::KernelModule,
                    "load a kernel module from fd",
                ),
                denied(
                    "delete_module",
                    LinuxSeccompSyscallGroup::KernelModule,
                    "remove a kernel module",
                ),
            ]);
        }
        if policy.deny_mount_namespace_changes {
            denied_syscalls.extend([
                denied(
                    "mount",
                    LinuxSeccompSyscallGroup::Mount,
                    "mount or remount filesystems",
                ),
                denied(
                    "umount2",
                    LinuxSeccompSyscallGroup::Mount,
                    "unmount filesystems",
                ),
                denied(
                    "pivot_root",
                    LinuxSeccompSyscallGroup::Mount,
                    "change process root filesystem",
                ),
                denied(
                    "unshare",
                    LinuxSeccompSyscallGroup::Namespace,
                    "create new namespaces",
                ),
                denied(
                    "setns",
                    LinuxSeccompSyscallGroup::Namespace,
                    "join another namespace",
                ),
                denied(
                    "fsopen",
                    LinuxSeccompSyscallGroup::Mount,
                    "start new mount API filesystem context",
                ),
                denied(
                    "fsconfig",
                    LinuxSeccompSyscallGroup::Mount,
                    "configure new mount API filesystem context",
                ),
                denied(
                    "fsmount",
                    LinuxSeccompSyscallGroup::Mount,
                    "create mount object with new mount API",
                ),
                denied(
                    "move_mount",
                    LinuxSeccompSyscallGroup::Mount,
                    "move mounts with new mount API",
                ),
                denied(
                    "open_tree",
                    LinuxSeccompSyscallGroup::Mount,
                    "open mount tree with new mount API",
                ),
                denied(
                    "mount_setattr",
                    LinuxSeccompSyscallGroup::Mount,
                    "change mount attributes",
                ),
            ]);
        }
        denied_syscalls.sort_by(|left, right| left.name.cmp(&right.name));
        denied_syscalls.dedup_by(|left, right| left.name == right.name);
        Self {
            default_action: LinuxSeccompAction::Allow,
            denied_syscalls,
        }
    }

    pub fn denied_names(&self) -> Vec<&str> {
        self.denied_syscalls
            .iter()
            .map(|syscall| syscall.name.as_str())
            .collect()
    }
}

fn denied(name: &str, group: LinuxSeccompSyscallGroup, reason: &str) -> LinuxSeccompDeniedSyscall {
    LinuxSeccompDeniedSyscall {
        name: name.to_string(),
        group,
        reason: reason.to_string(),
    }
}

#[cfg(target_os = "linux")]
pub fn install_seccomp_filter(profile: &LinuxSeccompProfile) -> io::Result<()> {
    platform::install_seccomp_filter(profile)
}

#[cfg(not(target_os = "linux"))]
pub fn install_seccomp_filter(_profile: &LinuxSeccompProfile) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seccomp launcher profiles are only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    use crate::seccomp::LinuxSeccompProfile;

    pub fn install_seccomp_filter(profile: &LinuxSeccompProfile) -> io::Result<()> {
        let blocked_syscalls = resolve_syscalls(profile)?;
        let mut filter = build_filter(current_audit_arch()?, &blocked_syscalls);
        let mut program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };

        prctl_set_no_new_privs()?;
        prctl_set_seccomp_filter(&mut program)
    }

    fn resolve_syscalls(profile: &LinuxSeccompProfile) -> io::Result<Vec<i64>> {
        let mut resolved = Vec::with_capacity(profile.denied_syscalls.len());
        let mut unresolved = Vec::new();
        for syscall in &profile.denied_syscalls {
            match syscall_number(&syscall.name) {
                Some(number) => resolved.push(number),
                None => unresolved.push(syscall.name.clone()),
            }
        }
        if unresolved.is_empty() {
            Ok(resolved)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "seccomp profile contains syscall names unsupported on this build target: {}",
                    unresolved.join(", ")
                ),
            ))
        }
    }

    fn build_filter(audit_arch: u32, syscalls: &[i64]) -> Vec<libc::sock_filter> {
        let mut filter = Vec::with_capacity((syscalls.len() * 2) + 5);
        filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0));
        filter.push(stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
        filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        for syscall in syscalls {
            filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *syscall as u32, 0, 1));
            filter.push(stmt(
                BPF_RET | BPF_K,
                SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ));
        }
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        filter
    }

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn current_audit_arch() -> io::Result<u32> {
        audit_arch_for_target().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "seccomp arch gate is not defined for {}",
                    std::env::consts::ARCH
                ),
            )
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn audit_arch_for_target() -> Option<u32> {
        Some(0xc000_003e)
    }

    #[cfg(target_arch = "x86")]
    fn audit_arch_for_target() -> Option<u32> {
        Some(0x4000_0003)
    }

    #[cfg(target_arch = "aarch64")]
    fn audit_arch_for_target() -> Option<u32> {
        Some(0xc000_00b7)
    }

    #[cfg(target_arch = "riscv64")]
    fn audit_arch_for_target() -> Option<u32> {
        Some(0xc000_00f3)
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    fn audit_arch_for_target() -> Option<u32> {
        None
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn prctl_set_no_new_privs() -> io::Result<()> {
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn prctl_set_seccomp_filter(program: &mut libc::sock_fprog) -> io::Result<()> {
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                program as *mut libc::sock_fprog,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn syscall_number(name: &str) -> Option<i64> {
        match name {
            "bpf" => Some(libc::SYS_bpf),
            "delete_module" => Some(libc::SYS_delete_module),
            "finit_module" => Some(libc::SYS_finit_module),
            "fsconfig" => Some(libc::SYS_fsconfig),
            "fsmount" => Some(libc::SYS_fsmount),
            "fsopen" => Some(libc::SYS_fsopen),
            "init_module" => Some(libc::SYS_init_module),
            "mount" => Some(libc::SYS_mount),
            "mount_setattr" => Some(libc::SYS_mount_setattr),
            "move_mount" => Some(libc::SYS_move_mount),
            "open_tree" => Some(libc::SYS_open_tree),
            "pivot_root" => Some(libc::SYS_pivot_root),
            "process_vm_readv" => Some(libc::SYS_process_vm_readv),
            "process_vm_writev" => Some(libc::SYS_process_vm_writev),
            "ptrace" => Some(libc::SYS_ptrace),
            "setns" => Some(libc::SYS_setns),
            "umount2" => Some(libc::SYS_umount2),
            "unshare" => Some(libc::SYS_unshare),
            _ => None,
        }
    }

    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::seccomp::LinuxSeccompProfile;

        #[test]
        fn builds_allow_default_filter_with_errno_denies() {
            let filter = build_filter(
                current_audit_arch().unwrap(),
                &resolve_syscalls(&LinuxSeccompProfile::default()).unwrap(),
            );
            assert!(filter.len() > 3);
            assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
            assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);
            assert_eq!(filter[3].k, SECCOMP_DATA_NR_OFFSET);
            assert_eq!(filter.last().unwrap().k, SECCOMP_RET_ALLOW);
        }

        #[test]
        fn unresolved_syscalls_fail_closed() {
            let mut profile = LinuxSeccompProfile::default();
            profile
                .denied_syscalls
                .push(crate::seccomp::LinuxSeccompDeniedSyscall {
                    name: "definitely_not_a_syscall".to_string(),
                    group: crate::seccomp::LinuxSeccompSyscallGroup::Mount,
                    reason: "test".to_string(),
                });

            let error = resolve_syscalls(&profile).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("definitely_not_a_syscall"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_includes_dangerous_syscall_groups() {
        let profile = LinuxSeccompProfile::default();
        let names = profile.denied_names();

        for name in [
            "ptrace",
            "bpf",
            "init_module",
            "finit_module",
            "delete_module",
            "mount",
            "umount2",
            "pivot_root",
            "unshare",
            "setns",
        ] {
            assert!(names.contains(&name), "missing {name}");
        }
    }

    #[test]
    fn profile_respects_policy_toggles() {
        let profile = LinuxSeccompProfile::from_policy(&DangerousSyscallPolicy {
            deny_mount_namespace_changes: false,
            deny_ptrace: true,
            deny_bpf: false,
            deny_kernel_module_loading: false,
        });
        let names = profile.denied_names();

        assert!(names.contains(&"ptrace"));
        assert!(!names.contains(&"bpf"));
        assert!(!names.contains(&"mount"));
        assert!(!names.contains(&"init_module"));
    }
}
