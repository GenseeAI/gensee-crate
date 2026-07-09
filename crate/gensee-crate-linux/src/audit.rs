use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use gensee_crate_core::SystemEvent;

use crate::capabilities::LinuxCapabilityReport;
use crate::procfs::{is_descendant_or_self, read_proc_cmdline, read_proc_stat};
use crate::session::LinuxSessionTarget;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxMonitorConfig {
    pub session: Option<LinuxSessionTarget>,
    pub enable_exec_events: bool,
    pub enable_file_events: bool,
    pub enable_network_events: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxMonitorStatus {
    pub capabilities: LinuxCapabilityReport,
    pub requested_event_kinds: Vec<LinuxKernelEventKind>,
    pub active: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxKernelEventKind {
    Exec,
    FileOpen,
    FileWrite,
    FileDelete,
    NetworkConnect,
    PrivilegeSensitiveSyscall,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxKernelEvent {
    pub kind: LinuxKernelEventKind,
    pub observed_at_ms: u64,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub file_path: Option<String>,
    pub network_dest: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinuxAuditMonitor {
    config: LinuxMonitorConfig,
    seen_pids: HashSet<u32>,
}

impl LinuxAuditMonitor {
    pub fn new() -> Self {
        Self {
            config: LinuxMonitorConfig::default(),
            seen_pids: HashSet::new(),
        }
    }

    pub fn with_config(config: LinuxMonitorConfig) -> Self {
        Self {
            config,
            seen_pids: HashSet::new(),
        }
    }

    pub fn start_monitoring(&self) -> LinuxMonitorStatus {
        let capabilities = LinuxCapabilityReport::detect();
        let mut requested_event_kinds = Vec::new();
        if self.config.enable_exec_events {
            requested_event_kinds.push(LinuxKernelEventKind::Exec);
        }
        if self.config.enable_file_events {
            requested_event_kinds.extend([
                LinuxKernelEventKind::FileOpen,
                LinuxKernelEventKind::FileWrite,
                LinuxKernelEventKind::FileDelete,
            ]);
        }
        if self.config.enable_network_events {
            requested_event_kinds.push(LinuxKernelEventKind::NetworkConnect);
        }

        let mut warnings = Vec::new();
        if !capabilities.supports_bpf_telemetry() {
            warnings.push(
                "eBPF telemetry is not active; run the future daemon as root with bpffs mounted"
                    .to_string(),
            );
        }
        if self.config.enable_file_events && !capabilities.supports_dynamic_file_enforcement() {
            warnings.push(
                "fanotify permission enforcement is not active; file events are plan-only"
                    .to_string(),
            );
        }

        LinuxMonitorStatus {
            capabilities,
            requested_event_kinds,
            active: false,
            warnings,
        }
    }

    pub fn config(&self) -> &LinuxMonitorConfig {
        &self.config
    }

    pub fn prime_process_snapshot(&mut self) -> io::Result<()> {
        self.seen_pids.extend(
            self.session_processes()?
                .into_iter()
                .map(|process| process.pid),
        );
        Ok(())
    }

    pub fn poll_events(&mut self) -> io::Result<Vec<LinuxKernelEvent>> {
        let mut events = Vec::new();
        if !self.config.enable_exec_events {
            return Ok(events);
        }

        for process in self.session_processes()? {
            if self.seen_pids.insert(process.pid) {
                events.push(
                    process.into_exec_event(
                        now_ms(),
                        self.config
                            .session
                            .as_ref()
                            .map(|session| session.session_id.clone()),
                    ),
                );
            }
        }
        Ok(events)
    }

    fn session_processes(&self) -> io::Result<Vec<LinuxProcessInfo>> {
        let Some(session) = &self.config.session else {
            return Ok(Vec::new());
        };
        let processes = read_proc_processes()?;
        let parent_by_pid = processes
            .iter()
            .map(|process| (process.pid, process.ppid))
            .collect::<HashMap<_, _>>();
        Ok(processes
            .into_iter()
            .filter(|process| is_descendant_or_self(process.pid, session.root_pid, &parent_by_pid))
            .collect())
    }
}

impl Default for LinuxAuditMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for LinuxMonitorConfig {
    fn default() -> Self {
        Self {
            session: None,
            enable_exec_events: true,
            enable_file_events: true,
            enable_network_events: true,
        }
    }
}

impl LinuxKernelEvent {
    pub fn to_system_event(&self) -> SystemEvent {
        let raw_json = serde_json::json!({
            "session_id": self.session_id,
            "network_dest": self.network_dest,
        })
        .to_string();

        SystemEvent {
            source: "linux".to_string(),
            event_type: "kernel".to_string(),
            event_kind: format!("{:?}", self.kind),
            observed_at_ms: self.observed_at_ms,
            pid: self.pid,
            ppid: self.ppid,
            process_name: self.process_name.clone(),
            executable_path: self.executable_path.clone(),
            file_path: self.file_path.clone(),
            command_line: self.command_line.clone(),
            raw_json,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxProcessInfo {
    pid: u32,
    ppid: u32,
    process_name: String,
    executable_path: Option<String>,
    command_line: Option<String>,
}

impl LinuxProcessInfo {
    fn into_exec_event(self, observed_at_ms: u64, session_id: Option<String>) -> LinuxKernelEvent {
        LinuxKernelEvent {
            kind: LinuxKernelEventKind::Exec,
            observed_at_ms,
            pid: Some(self.pid),
            ppid: Some(self.ppid),
            process_name: Some(self.process_name),
            executable_path: self.executable_path,
            command_line: self.command_line,
            file_path: None,
            network_dest: None,
            session_id,
        }
    }
}

fn read_proc_processes() -> io::Result<Vec<LinuxProcessInfo>> {
    let mut processes = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(processes),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(process) = read_proc_process(pid) {
            processes.push(process);
        }
    }
    Ok(processes)
}

fn read_proc_process(pid: u32) -> Option<LinuxProcessInfo> {
    let proc_root = PathBuf::from("/proc").join(pid.to_string());
    let stat = read_proc_stat(pid).ok()?;
    Some(LinuxProcessInfo {
        pid,
        ppid: stat.ppid,
        process_name: stat.comm,
        executable_path: fs::read_link(proc_root.join("exe"))
            .ok()
            .map(|path| path.to_string_lossy().to_string()),
        command_line: read_proc_cmdline(pid)
            .ok()
            .filter(|value| !value.is_empty()),
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_descendant_processes() {
        let parent_by_pid = HashMap::from([(10, 1), (11, 10), (12, 11), (20, 1)]);
        assert!(is_descendant_or_self(10, 10, &parent_by_pid));
        assert!(is_descendant_or_self(12, 10, &parent_by_pid));
        assert!(!is_descendant_or_self(20, 10, &parent_by_pid));
    }

    #[test]
    fn priming_suppresses_existing_process_exec_events() {
        if !std::path::Path::new("/proc/self").exists() {
            return;
        }

        let target = LinuxSessionTarget::current("test-session").unwrap();
        let mut monitor = LinuxAuditMonitor::with_config(LinuxMonitorConfig {
            session: Some(target),
            enable_exec_events: true,
            enable_file_events: false,
            enable_network_events: false,
        });

        monitor.prime_process_snapshot().unwrap();
        let events = monitor.poll_events().unwrap();

        assert!(events.is_empty());
    }
}
