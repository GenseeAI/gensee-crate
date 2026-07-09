use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxCapabilityReport {
    pub apparmor_enabled: bool,
    pub selinux_enabled: bool,
    pub landlock_available: bool,
    pub bpf_fs_mounted: bool,
    pub bpf_lsm_enabled: bool,
    pub cgroup_v2_mounted: bool,
    pub fanotify_available: bool,
    pub seccomp_filter_available: bool,
    pub nft_available: bool,
    pub running_as_root: bool,
    pub speculation_backends: Vec<LinuxSpeculationBackend>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxSpeculationBackend {
    FileStaging,
    OverlayFs,
    BtrfsSnapshot,
    Tclone,
}

impl LinuxCapabilityReport {
    pub fn detect() -> Self {
        let lsm_stack = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        let running_as_root = current_euid_is_root();
        Self {
            apparmor_enabled: read_trimmed("/sys/module/apparmor/parameters/enabled")
                .is_some_and(|value| value.eq_ignore_ascii_case("y")),
            selinux_enabled: read_trimmed("/sys/fs/selinux/enforce")
                .is_some_and(|value| value != "0"),
            landlock_available: Path::new("/sys/kernel/security/landlock").exists()
                || lsm_stack.split(',').any(|item| item.trim() == "landlock"),
            bpf_fs_mounted: mountinfo_contains_fs("bpf"),
            bpf_lsm_enabled: lsm_stack.split(',').any(|item| item.trim() == "bpf"),
            cgroup_v2_mounted: fs::read_to_string("/proc/filesystems")
                .unwrap_or_default()
                .lines()
                .any(|line| line.split_whitespace().last() == Some("cgroup2"))
                && Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            fanotify_available: Path::new("/proc/sys/fs/fanotify/max_user_marks").exists(),
            seccomp_filter_available: Path::new("/proc/sys/kernel/seccomp/actions_avail").exists(),
            nft_available: find_executable("nft").is_some(),
            running_as_root,
            speculation_backends: detect_speculation_backends(running_as_root),
        }
    }

    pub fn supports_dynamic_file_enforcement(&self) -> bool {
        self.fanotify_available && self.running_as_root
    }

    pub fn supports_bpf_telemetry(&self) -> bool {
        self.bpf_fs_mounted && self.running_as_root
    }

    pub fn supports_cgroup_network_controls(&self) -> bool {
        self.cgroup_v2_mounted && self.nft_available && self.running_as_root
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn mountinfo_contains_fs(fs_name: &str) -> bool {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|line| {
            let mut fields = line.split_whitespace();
            let _source = fields.next();
            let _target = fields.next();
            fields.next() == Some(fs_name)
        })
}

fn find_executable(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

fn detect_speculation_backends(running_as_root: bool) -> Vec<LinuxSpeculationBackend> {
    let mut backends = Vec::new();
    if Path::new("/proc/self").exists() {
        backends.push(LinuxSpeculationBackend::FileStaging);
    }
    if running_as_root && filesystem_available("overlay") {
        backends.push(LinuxSpeculationBackend::OverlayFs);
    }
    if running_as_root && mounted_filesystem_exists("btrfs") && find_executable("btrfs").is_some() {
        backends.push(LinuxSpeculationBackend::BtrfsSnapshot);
    }
    if kernel_release_contains("pgcachecow")
        || env::var_os("GENSEE_TCLONE_ROOT").is_some()
        || env::var_os("TCLONE_ROOT").is_some()
    {
        backends.push(LinuxSpeculationBackend::Tclone);
    }
    backends
}

fn filesystem_available(fs_name: &str) -> bool {
    fs::read_to_string("/proc/filesystems")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split_whitespace().last() == Some(fs_name))
}

fn mounted_filesystem_exists(fs_name: &str) -> bool {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some(fs_name))
}

fn kernel_release_contains(needle: &str) -> bool {
    read_trimmed("/proc/sys/kernel/osrelease").is_some_and(|release| release.contains(needle))
}

fn current_euid_is_root() -> bool {
    read_trimmed("/proc/self/status").and_then(|status| {
        status.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "Uid:" {
                return None;
            }
            fields.nth(1)?.parse::<u32>().ok()
        })
    }) == Some(0)
}
