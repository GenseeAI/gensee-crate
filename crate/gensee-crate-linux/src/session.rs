use std::fs;
use std::io;
use std::path::PathBuf;

use crate::network::collect_process_tree;
use crate::procfs::{read_proc_cmdline, read_proc_stat};

pub const MAX_PROCESS_LINEAGE_IDENTITIES: usize = 4096;
const MAX_PROCESS_IDENTITY_TEXT_CHARS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_time_ticks: u64,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
}

pub fn collect_process_lineage(root_pid: u32) -> io::Result<Vec<LinuxProcessIdentity>> {
    let mut identities = Vec::new();
    let mut process_ids = collect_process_tree(root_pid)?;
    process_ids.sort_unstable_by_key(|pid| (*pid != root_pid, *pid));
    process_ids.truncate(MAX_PROCESS_LINEAGE_IDENTITIES);
    for pid in process_ids {
        let Ok(stat) = read_proc_stat(pid) else {
            continue;
        };
        let proc_root = PathBuf::from("/proc").join(pid.to_string());
        identities.push(LinuxProcessIdentity {
            pid,
            parent_pid: stat.ppid,
            start_time_ticks: stat.start_time_ticks,
            executable_path: fs::read_link(proc_root.join("exe"))
                .ok()
                .map(|path| bounded_identity_text(&path.to_string_lossy())),
            command_line: read_proc_cmdline(pid)
                .ok()
                .map(|command| bounded_identity_text(&command)),
        });
    }
    identities.sort_by_key(|identity| (identity.start_time_ticks, identity.pid));
    Ok(identities)
}

fn bounded_identity_text(value: &str) -> String {
    value
        .chars()
        .take(MAX_PROCESS_IDENTITY_TEXT_CHARS)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxSessionTarget {
    pub session_id: String,
    pub root_pid: u32,
    pub parent_pid: Option<u32>,
    pub process_group_id: Option<u32>,
    pub login_session_id: Option<u32>,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub cwd: Option<String>,
    pub cgroup_path: Option<String>,
}

impl LinuxSessionTarget {
    pub fn from_pid(session_id: impl Into<String>, root_pid: u32) -> io::Result<Self> {
        let proc_root = PathBuf::from("/proc").join(root_pid.to_string());
        let stat = read_proc_stat(root_pid).ok();
        Ok(Self {
            session_id: session_id.into(),
            root_pid,
            parent_pid: stat.as_ref().map(|stat| stat.ppid),
            process_group_id: stat.as_ref().map(|stat| stat.process_group_id),
            login_session_id: stat.as_ref().map(|stat| stat.session_id),
            executable_path: fs::read_link(proc_root.join("exe"))
                .ok()
                .map(|path| path.to_string_lossy().to_string()),
            command_line: read_proc_cmdline(root_pid).ok(),
            cwd: fs::read_link(proc_root.join("cwd"))
                .ok()
                .map(|path| path.to_string_lossy().to_string()),
            cgroup_path: read_proc_cgroup(root_pid).ok().flatten(),
        })
    }

    pub fn current(session_id: impl Into<String>) -> io::Result<Self> {
        Self::from_pid(session_id, std::process::id())
    }
}

fn read_proc_cgroup(pid: u32) -> io::Result<Option<String>> {
    let data = fs::read_to_string(PathBuf::from("/proc").join(pid.to_string()).join("cgroup"))?;
    Ok(data.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next();
        let controllers = parts.next()?;
        let path = parts.next()?;
        if controllers.is_empty() {
            Some(path.to_string())
        } else {
            None
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_session_target_is_readable_on_procfs_hosts() {
        if !std::path::Path::new("/proc/self").exists() {
            return;
        }

        let target = LinuxSessionTarget::current("test-session").unwrap();
        assert_eq!(target.root_pid, std::process::id());
        assert_eq!(target.session_id, "test-session");
    }

    #[test]
    fn current_process_lineage_has_pid_reuse_identity() {
        if !std::path::Path::new("/proc/self").exists() {
            return;
        }
        let identities = collect_process_lineage(std::process::id()).unwrap();
        let current = identities
            .iter()
            .find(|identity| identity.pid == std::process::id())
            .unwrap();
        assert!(current.start_time_ticks > 0);
    }

    #[test]
    fn process_identity_text_is_bounded() {
        let bounded = bounded_identity_text(&"x".repeat(MAX_PROCESS_IDENTITY_TEXT_CHARS + 100));
        assert_eq!(bounded.chars().count(), MAX_PROCESS_IDENTITY_TEXT_CHARS);
    }
}
