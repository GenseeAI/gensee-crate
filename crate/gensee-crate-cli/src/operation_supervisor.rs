use crate::*;
use gensee_crate_rules::capability::Capability;
use gensee_crate_rules::capability_policy::MediationBoundary;
use gensee_crate_rules::network_boundary::{
    NetworkBoundaryDecision, NetworkBoundaryDisposition, NetworkBoundaryEvent,
    NetworkCapabilityEnvelope,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const OPERATION_RECORD_SCHEMA_VERSION: u32 = 2;
const OPERATION_POLL_INTERVAL_MS: u64 = 100;
#[cfg(target_os = "linux")]
const LINEAGE_LAST_SEEN_PERSIST_INTERVAL_MS: u64 = 5_000;
#[cfg(any(target_os = "linux", test))]
const MAX_RETAINED_INACTIVE_PROCESS_IDENTITIES: usize = 4_096;
const MAX_OPERATION_VIOLATION_KINDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationState {
    Preparing,
    Running,
    Succeeded,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationCgroupState {
    Attached,
    Prepared,
    Unavailable,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationCgroupRecord {
    pub path: String,
    pub state: OperationCgroupState,
    pub owned_by_supervisor: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_time_ticks: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationLeaseBinding {
    pub lease_id: String,
    pub capabilities: Vec<Capability>,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationCapabilityEnvelope {
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub active_mediators: Vec<MediationBoundary>,
    #[serde(default)]
    pub leases: Vec<OperationLeaseBinding>,
    #[serde(default)]
    pub network: NetworkCapabilityEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationViolation {
    pub kind: String,
    pub detail: String,
    pub observed_at_ms: u64,
    #[serde(default = "default_violation_occurrences")]
    pub occurrences: u64,
}

fn default_violation_occurrences() -> u64 {
    1
}

#[derive(Debug, Clone)]
pub(crate) struct OperationAttestation {
    pub operation_id: String,
    pub source_run_id: String,
    pub state: OperationState,
    pub root_pid: Option<u32>,
    pub root_start_time_ticks: Option<u64>,
    pub root_identity_active: bool,
    pub cgroup_state: OperationCgroupState,
    pub envelope: OperationCapabilityEnvelope,
    pub boundary_effect_count: u64,
    pub denied_boundary_effect_count: u64,
    pub violations: Vec<OperationViolation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationNetworkUsage {
    pub allowed_packets: u64,
    pub allowed_bytes: u64,
    pub blocked_packets: u64,
    pub blocked_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedOperationRecord {
    pub schema_version: u32,
    pub operation_id: String,
    pub source_run_id: String,
    pub action_class: String,
    pub state: OperationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_start_time_ticks: Option<u64>,
    pub cgroup: OperationCgroupRecord,
    pub envelope: OperationCapabilityEnvelope,
    #[serde(default)]
    pub process_lineage: Vec<OperationProcessIdentity>,
    #[serde(default)]
    pub boundary_effect_count: u64,
    /// Boundary observations that were denied before the effect occurred.
    /// Keeping this separate lets same-authority continuation distinguish a
    /// harmless blocked attempt from a completed or authority-changing effect.
    #[serde(default)]
    pub denied_boundary_effect_count: u64,
    #[serde(default)]
    pub network_usage: OperationNetworkUsage,
    #[serde(default)]
    pub violations: Vec<OperationViolation>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

pub(crate) struct OperationSupervisor {
    record: ManagedOperationRecord,
    record_path: PathBuf,
    lock_path: PathBuf,
}

impl Drop for OperationSupervisor {
    fn drop(&mut self) {
        let Ok(_lock) = OperationRecordLock::acquire(&self.lock_path) else {
            return;
        };
        if self.reload().is_err() || self.record.state != OperationState::Preparing {
            return;
        }
        let now = unix_millis().unwrap_or(self.record.updated_at_ms);
        self.record.state = OperationState::Failed;
        self.record.finished_at_ms = Some(now);
        self.record.updated_at_ms = now;
        self.record_violation_at(
            "abandoned_before_activation",
            "operation supervisor dropped before its subject was activated",
            now,
        );
        if self.record.cgroup.owned_by_supervisor
            && self.record.cgroup.state == OperationCgroupState::Prepared
        {
            match gensee_crate_linux::remove_agent_cgroup(Path::new(&self.record.cgroup.path)) {
                Ok(()) => self.record.cgroup.state = OperationCgroupState::Released,
                Err(error) => self.record.cgroup.error = Some(error.to_string()),
            }
        }
        let _ = self.persist();
    }
}

#[cfg(unix)]
struct OperationRecordLock(fs::File);

#[cfg(unix)]
impl OperationRecordLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        let file = options.open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

#[cfg(unix)]
impl Drop for OperationRecordLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
struct OperationRecordLock;

#[cfg(not(unix))]
impl OperationRecordLock {
    fn acquire(_path: &Path) -> io::Result<Self> {
        Ok(Self)
    }
}

impl OperationSupervisor {
    pub(crate) fn prepare(
        operation_id: impl Into<String>,
        source_run_id: impl Into<String>,
        action_class: impl Into<String>,
        envelope: OperationCapabilityEnvelope,
        adopted_cgroup_path: Option<&Path>,
    ) -> io::Result<Self> {
        let state_root = default_root()?;
        Self::prepare_at(
            &state_root,
            operation_id,
            source_run_id,
            action_class,
            envelope,
            adopted_cgroup_path,
        )
    }

    pub(crate) fn prepare_at(
        state_root: &Path,
        operation_id: impl Into<String>,
        source_run_id: impl Into<String>,
        action_class: impl Into<String>,
        envelope: OperationCapabilityEnvelope,
        adopted_cgroup_path: Option<&Path>,
    ) -> io::Result<Self> {
        Self::prepare_inner(
            state_root,
            operation_id,
            source_run_id,
            action_class,
            envelope,
            adopted_cgroup_path,
            true,
        )
    }

    pub(crate) fn prepare_external_subject(
        operation_id: impl Into<String>,
        source_run_id: impl Into<String>,
        action_class: impl Into<String>,
        envelope: OperationCapabilityEnvelope,
    ) -> io::Result<Self> {
        let state_root = default_root()?;
        Self::prepare_inner(
            &state_root,
            operation_id,
            source_run_id,
            action_class,
            envelope,
            None,
            false,
        )
    }

    #[cfg(test)]
    pub(crate) fn prepare_external_subject_at(
        state_root: &Path,
        operation_id: impl Into<String>,
        source_run_id: impl Into<String>,
        action_class: impl Into<String>,
        envelope: OperationCapabilityEnvelope,
    ) -> io::Result<Self> {
        Self::prepare_inner(
            state_root,
            operation_id,
            source_run_id,
            action_class,
            envelope,
            None,
            false,
        )
    }

    fn prepare_inner(
        state_root: &Path,
        operation_id: impl Into<String>,
        source_run_id: impl Into<String>,
        action_class: impl Into<String>,
        envelope: OperationCapabilityEnvelope,
        adopted_cgroup_path: Option<&Path>,
        manage_local_cgroup: bool,
    ) -> io::Result<Self> {
        let operation_id = operation_id.into();
        let source_run_id = source_run_id.into();
        let action_class = action_class.into();
        if !safe_operation_token(&operation_id)
            || !safe_operation_token(&source_run_id)
            || !safe_operation_token(&action_class)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operation identity and action class must be bounded tokens",
            ));
        }
        let root = operation_record_root_at(state_root, &operation_id)?;
        create_restrictive_dir_all(&root)?;
        let record_path = root.join("record.json");
        let lock_path = root.join("record.lock");
        let _lock = OperationRecordLock::acquire(&lock_path)?;
        if record_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "managed operation id already exists",
            ));
        }
        let (path, owned_by_supervisor) = if !manage_local_cgroup {
            (PathBuf::new(), false)
        } else {
            adopted_cgroup_path
                .map(|path| (path.to_path_buf(), false))
                .unwrap_or_else(|| {
                    (
                        gensee_crate_linux::default_agent_cgroup_path(&operation_id),
                        true,
                    )
                })
        };
        let mut cgroup = OperationCgroupRecord {
            path: path.to_string_lossy().to_string(),
            state: OperationCgroupState::Unavailable,
            owned_by_supervisor,
            error: None,
        };
        #[cfg(target_os = "linux")]
        {
            if manage_local_cgroup {
                match gensee_crate_linux::create_agent_cgroup(&path) {
                    Ok(()) => cgroup.state = OperationCgroupState::Prepared,
                    Err(error) => cgroup.error = Some(error.to_string()),
                }
            } else {
                cgroup.error = Some("operation subject is not a local process tree".to_string());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            cgroup.error = Some(if manage_local_cgroup {
                "cgroup v2 is available only on Linux".to_string()
            } else {
                "operation subject is not a local process tree".to_string()
            });
        }
        let now = unix_millis()?;
        let supervisor = Self {
            record: ManagedOperationRecord {
                schema_version: OPERATION_RECORD_SCHEMA_VERSION,
                operation_id,
                source_run_id,
                action_class,
                state: OperationState::Preparing,
                root_pid: None,
                root_start_time_ticks: None,
                cgroup,
                envelope: normalize_envelope(envelope),
                process_lineage: Vec::new(),
                boundary_effect_count: 0,
                denied_boundary_effect_count: 0,
                network_usage: OperationNetworkUsage::default(),
                violations: Vec::new(),
                started_at_ms: now,
                updated_at_ms: now,
                finished_at_ms: None,
                exit_code: None,
            },
            record_path,
            lock_path,
        };
        supervisor.persist()?;
        Ok(supervisor)
    }

    pub(crate) fn open(operation_id: &str, expected_source_run_id: &str) -> io::Result<Self> {
        let state_root = default_root()?;
        Self::open_at(&state_root, operation_id, expected_source_run_id)
    }

    pub(crate) fn open_at(
        state_root: &Path,
        operation_id: &str,
        expected_source_run_id: &str,
    ) -> io::Result<Self> {
        let root = operation_record_root_at(state_root, operation_id)?;
        let record_path = root.join("record.json");
        let lock_path = root.join("record.lock");
        let _lock = OperationRecordLock::acquire(&lock_path)?;
        let record = read_operation_record(&record_path)?;
        if record.operation_id != operation_id || record.source_run_id != expected_source_run_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed operation record identity does not match the caller",
            ));
        }
        if matches!(
            record.state,
            OperationState::Succeeded | OperationState::Failed | OperationState::TimedOut
        ) {
            drop(_lock);
            #[cfg(target_os = "linux")]
            {
                // Terminal records remain single-use, but reopening one is a
                // safe opportunity to retry an interrupted exact cleanup.
                // Release the operation lock before the helper reacquires it
                // and before network cleanup takes its own operation lock.
                if retry_terminal_operation_subject_release_at(
                    state_root,
                    operation_id,
                    expected_source_run_id,
                )? {
                    let _ = crate::network_boundary::reap_terminal_network_boundary_for_operation(
                        state_root,
                        operation_id,
                        expected_source_run_id,
                    )?;
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "terminal managed operation cannot be reopened",
            ));
        }
        Ok(Self {
            record,
            record_path,
            lock_path,
        })
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.record.operation_id
    }

    pub(crate) fn envelope_snapshot(&mut self) -> io::Result<OperationCapabilityEnvelope> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        let now = unix_millis()?;
        self.record
            .envelope
            .leases
            .retain(|lease| lease.expires_at_ms > now);
        self.record.updated_at_ms = now;
        self.persist()?;
        Ok(self.record.envelope.clone())
    }

    pub(crate) fn attestation(&mut self) -> io::Result<OperationAttestation> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        self.refresh_lineage_in_memory()?;
        let now = unix_millis()?;
        self.record
            .envelope
            .leases
            .retain(|lease| lease.expires_at_ms > now);
        self.record.updated_at_ms = now;
        self.persist()?;
        let root_identity_active = self
            .record
            .root_pid
            .zip(self.record.root_start_time_ticks)
            .is_some_and(|(root_pid, root_start_time_ticks)| {
                self.record.process_lineage.iter().any(|identity| {
                    identity.pid == root_pid
                        && identity.start_time_ticks == root_start_time_ticks
                        && identity.active
                })
            });
        Ok(OperationAttestation {
            operation_id: self.record.operation_id.clone(),
            source_run_id: self.record.source_run_id.clone(),
            state: self.record.state,
            root_pid: self.record.root_pid,
            root_start_time_ticks: self.record.root_start_time_ticks,
            root_identity_active,
            cgroup_state: self.record.cgroup.state,
            envelope: self.record.envelope.clone(),
            boundary_effect_count: self.record.boundary_effect_count,
            denied_boundary_effect_count: self.record.denied_boundary_effect_count,
            violations: self.record.violations.clone(),
        })
    }

    pub(crate) fn cgroup_path(&self) -> Option<&Path> {
        matches!(
            self.record.cgroup.state,
            OperationCgroupState::Prepared | OperationCgroupState::Attached
        )
        .then(|| Path::new(&self.record.cgroup.path))
    }

    pub(crate) fn activate(&mut self, root_pid: u32) -> io::Result<()> {
        if root_pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed operation root PID must be nonzero",
            ));
        }
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        if self.record.root_pid.is_some_and(|pid| pid != root_pid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed operation is already bound to another root process",
            ));
        }
        self.record.root_pid = Some(root_pid);
        #[cfg(target_os = "linux")]
        if let Some(path) = self.cgroup_path().map(Path::to_path_buf) {
            match gensee_crate_linux::attach_process_tree_to_cgroup(root_pid, &path) {
                Ok(attached) if attached.contains(&root_pid) => {
                    self.record.cgroup.state = OperationCgroupState::Attached;
                    self.record.cgroup.error = None;
                    self.record
                        .envelope
                        .active_mediators
                        .push(MediationBoundary::ProcessCgroup);
                    self.record.envelope.active_mediators.sort();
                    self.record.envelope.active_mediators.dedup();
                }
                Ok(_) => self.record_violation(
                    "root_cgroup_attachment_missing",
                    "root process was not returned by cgroup attachment",
                )?,
                Err(error) => {
                    self.record.cgroup.state = OperationCgroupState::Unavailable;
                    self.record.cgroup.error = Some(error.to_string());
                    self.record_violation("cgroup_attachment_failed", &error.to_string())?;
                }
            }
        }
        self.record.state = OperationState::Running;
        self.refresh_lineage_in_memory()?;
        self.persist()
    }

    pub(crate) fn activate_external_subject(&mut self) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        if self.record.root_pid.is_some()
            || self.record.cgroup.state != OperationCgroupState::Unavailable
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only an operation without a local process tree can activate an external subject",
            ));
        }
        self.record.state = OperationState::Running;
        self.record.updated_at_ms = unix_millis()?;
        self.persist()
    }

    pub(crate) fn refresh_lineage(&mut self) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        if self.refresh_lineage_in_memory()? {
            self.persist()?;
        }
        Ok(())
    }

    pub(crate) fn validates_local_process_identity(
        &mut self,
        pid: u32,
        start_time_ticks: u64,
    ) -> io::Result<bool> {
        if pid == 0 || start_time_ticks == 0 {
            return Ok(false);
        }
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        let changed = self.refresh_lineage_in_memory()?;
        let matches = self.record.process_lineage.iter().any(|identity| {
            identity.pid == pid && identity.start_time_ticks == start_time_ticks && identity.active
        });
        if changed {
            self.persist()?;
        }
        Ok(matches)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn root_process_identity(&mut self) -> io::Result<Option<(u32, u64)>> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        let changed = self.refresh_lineage_in_memory()?;
        let identity = self.record.root_pid.and_then(|root_pid| {
            self.record
                .process_lineage
                .iter()
                .find(|identity| identity.pid == root_pid && identity.active)
                .map(|identity| (identity.pid, identity.start_time_ticks))
        });
        if changed {
            self.persist()?;
        }
        Ok(identity)
    }

    pub(crate) fn record_boundary_violation(&mut self, kind: &str, detail: &str) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        self.record_violation(kind, detail)?;
        self.record.updated_at_ms = unix_millis()?;
        self.persist()
    }

    fn refresh_lineage_in_memory(&mut self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let Some(root_pid) = self.record.root_pid else {
                return Ok(false);
            };
            let mut changed = false;
            let now = unix_millis()?;
            let observed = gensee_crate_linux::collect_process_lineage(root_pid)?;
            if observed.len() == gensee_crate_linux::MAX_PROCESS_LINEAGE_IDENTITIES
                && !self
                    .record
                    .violations
                    .iter()
                    .any(|violation| violation.kind == "process_lineage_limit_reached")
            {
                self.record_violation(
                    "process_lineage_limit_reached",
                    "process lineage evidence reached its bounded identity limit",
                )?;
                changed = true;
            }
            let observed_keys = observed
                .iter()
                .map(|identity| (identity.pid, identity.start_time_ticks))
                .collect::<BTreeSet<_>>();
            for existing in &mut self.record.process_lineage {
                let active = observed_keys.contains(&(existing.pid, existing.start_time_ticks));
                changed |= existing.active != active;
                existing.active = active;
                if existing.active
                    && now.saturating_sub(existing.last_seen_at_ms)
                        >= LINEAGE_LAST_SEEN_PERSIST_INTERVAL_MS
                {
                    changed = true;
                    existing.last_seen_at_ms = now;
                }
            }
            let mut existing_by_identity = self
                .record
                .process_lineage
                .iter()
                .enumerate()
                .map(|(index, identity)| ((identity.pid, identity.start_time_ticks), index))
                .collect::<BTreeMap<_, _>>();
            for identity in observed {
                if let Some(index) = existing_by_identity
                    .get(&(identity.pid, identity.start_time_ticks))
                    .copied()
                {
                    let existing = &mut self.record.process_lineage[index];
                    changed |= existing.parent_pid != identity.parent_pid
                        || existing.executable_path != identity.executable_path
                        || existing.command_line != identity.command_line;
                    existing.parent_pid = identity.parent_pid;
                    existing.executable_path = identity.executable_path;
                    existing.command_line = identity.command_line;
                    continue;
                }
                let index = self.record.process_lineage.len();
                existing_by_identity.insert((identity.pid, identity.start_time_ticks), index);
                self.record.process_lineage.push(OperationProcessIdentity {
                    pid: identity.pid,
                    parent_pid: identity.parent_pid,
                    start_time_ticks: identity.start_time_ticks,
                    executable_path: identity.executable_path,
                    command_line: identity.command_line,
                    first_seen_at_ms: now,
                    last_seen_at_ms: now,
                    active: true,
                });
                changed = true;
            }
            self.record
                .process_lineage
                .sort_by_key(|identity| (identity.start_time_ticks, identity.pid));
            let root_identity = self
                .record
                .process_lineage
                .iter()
                .find(|identity| identity.pid == root_pid && identity.active);
            if let Some(identity) = root_identity {
                match self.record.root_start_time_ticks {
                    None => {
                        self.record.root_start_time_ticks = Some(identity.start_time_ticks);
                        changed = true;
                    }
                    Some(expected) if expected != identity.start_time_ticks => {
                        self.record_violation(
                            "root_pid_reused",
                            "root PID start time changed while operation was active",
                        )?;
                        changed = true;
                    }
                    Some(_) => {}
                }
            }
            changed |= self.bound_process_lineage_history()?;
            if changed {
                self.record.updated_at_ms = now;
            }
            Ok(changed)
        }
        #[cfg(not(target_os = "linux"))]
        Ok(false)
    }

    #[cfg(any(target_os = "linux", test))]
    fn bound_process_lineage_history(&mut self) -> io::Result<bool> {
        let inactive_count = self
            .record
            .process_lineage
            .iter()
            .filter(|identity| !identity.active)
            .count();
        if inactive_count <= MAX_RETAINED_INACTIVE_PROCESS_IDENTITIES {
            return Ok(false);
        }
        let mut inactive = self
            .record
            .process_lineage
            .iter()
            .filter(|identity| !identity.active)
            .map(|identity| {
                (
                    identity.last_seen_at_ms,
                    identity.pid,
                    identity.start_time_ticks,
                )
            })
            .collect::<Vec<_>>();
        inactive.sort_unstable_by(|left, right| right.cmp(left));
        let retained = inactive
            .into_iter()
            .take(MAX_RETAINED_INACTIVE_PROCESS_IDENTITIES)
            .map(|(_, pid, start_time_ticks)| (pid, start_time_ticks))
            .collect::<std::collections::BTreeSet<_>>();
        self.record.process_lineage.retain(|identity| {
            identity.active || retained.contains(&(identity.pid, identity.start_time_ticks))
        });
        self.record_violation(
            "process_lineage_history_truncated",
            "inactive process lineage exceeded its retained-history bound",
        )?;
        Ok(true)
    }

    pub(crate) fn update_network_envelope(
        &mut self,
        envelope: NetworkCapabilityEnvelope,
    ) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        self.record.envelope.network = envelope;
        let now = unix_millis()?;
        self.record
            .envelope
            .leases
            .retain(|binding| binding.expires_at_ms > now);
        self.record.updated_at_ms = now;
        self.persist()
    }

    pub(crate) fn record_network_effect(
        &mut self,
        event: &NetworkBoundaryEvent,
        decision: &NetworkBoundaryDecision,
    ) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        self.record.boundary_effect_count = self.record.boundary_effect_count.saturating_add(1);
        if decision.disposition == NetworkBoundaryDisposition::Deny {
            self.record.denied_boundary_effect_count =
                self.record.denied_boundary_effect_count.saturating_add(1);
        }
        if let Some(lease) = decision.lease.as_ref() {
            if let (Some(lease_id), Some(expires_at_ms)) =
                (lease.lease_id.as_ref(), lease.expires_at_ms)
            {
                self.record.envelope.leases.retain(|binding| {
                    binding.lease_id != *lease_id && binding.expires_at_ms > event.observed_at_ms
                });
                self.record.envelope.leases.push(OperationLeaseBinding {
                    lease_id: lease_id.clone(),
                    capabilities: vec![Capability::NetworkEgress],
                    expires_at_ms,
                });
            }
        }
        self.record.updated_at_ms = unix_millis()?;
        self.persist()
    }

    pub(crate) fn record_network_usage(
        &mut self,
        allowed_packets: u64,
        allowed_bytes: u64,
        blocked_packets: u64,
        blocked_bytes: u64,
    ) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        self.record.network_usage.allowed_packets = self
            .record
            .network_usage
            .allowed_packets
            .saturating_add(allowed_packets);
        self.record.network_usage.allowed_bytes = self
            .record
            .network_usage
            .allowed_bytes
            .saturating_add(allowed_bytes);
        self.record.network_usage.blocked_packets = self
            .record
            .network_usage
            .blocked_packets
            .saturating_add(blocked_packets);
        self.record.network_usage.blocked_bytes = self
            .record
            .network_usage
            .blocked_bytes
            .saturating_add(blocked_bytes);
        self.record.updated_at_ms = unix_millis()?;
        self.persist()
    }

    pub(crate) fn wait_for_child(
        &mut self,
        child: &mut std::process::Child,
        max_runtime_seconds: Option<u64>,
    ) -> io::Result<(std::process::ExitStatus, bool)> {
        let started = Instant::now();
        let timeout = max_runtime_seconds.map(Duration::from_secs);
        loop {
            if let Some(status) = child.try_wait()? {
                self.refresh_lineage()?;
                return Ok((status, false));
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                child.kill()?;
                let status = child.wait()?;
                self.refresh_lineage()?;
                return Ok((status, true));
            }
            self.refresh_lineage()?;
            thread::sleep(Duration::from_millis(OPERATION_POLL_INTERVAL_MS));
        }
    }

    pub(crate) fn finish(&mut self, exit_code: Option<i32>, timed_out: bool) -> io::Result<()> {
        let _lock = OperationRecordLock::acquire(&self.lock_path)?;
        self.reload()?;
        let now = unix_millis()?;
        self.record.state = if timed_out {
            OperationState::TimedOut
        } else if exit_code == Some(0) {
            OperationState::Succeeded
        } else {
            OperationState::Failed
        };
        self.record.exit_code = exit_code;
        self.record.finished_at_ms = Some(now);
        self.record.updated_at_ms = now;
        if let Err(error) = attempt_terminal_subject_release_with(
            &mut self.record,
            gensee_crate_linux::remove_agent_cgroup,
        ) {
            self.record.cgroup.error = Some(error.to_string());
            let kind = if self.record.cgroup.owned_by_supervisor {
                "cgroup_release_failed"
            } else {
                "adopted_cgroup_release_check_failed"
            };
            self.record_violation_at(kind, &error.to_string(), now);
        }
        self.persist()?;
        drop(_lock);
        let state_root = default_root()?;
        let _ = crate::network_boundary::reap_terminal_network_boundary_for_operation(
            &state_root,
            &self.record.operation_id,
            &self.record.source_run_id,
        )?;
        Ok(())
    }

    fn record_violation(&mut self, kind: &str, detail: &str) -> io::Result<()> {
        let now = unix_millis()?;
        self.record_violation_at(kind, detail, now);
        Ok(())
    }

    fn record_violation_at(&mut self, kind: &str, detail: &str, now: u64) {
        if let Some(existing) = self
            .record
            .violations
            .iter_mut()
            .find(|violation| violation.kind == kind && violation.detail == detail)
        {
            existing.observed_at_ms = now;
            existing.occurrences = existing.occurrences.saturating_add(1);
            return;
        }
        if self.record.violations.len() < MAX_OPERATION_VIOLATION_KINDS {
            self.record.violations.push(OperationViolation {
                kind: kind.to_string(),
                detail: detail.to_string(),
                observed_at_ms: now,
                occurrences: 1,
            });
            return;
        }
        const TRUNCATED_KIND: &str = "violation_evidence_truncated";
        if let Some(existing) = self
            .record
            .violations
            .iter_mut()
            .find(|violation| violation.kind == TRUNCATED_KIND)
        {
            existing.observed_at_ms = now;
            existing.occurrences = existing.occurrences.saturating_add(1);
        } else {
            let oldest = self
                .record
                .violations
                .iter()
                .enumerate()
                .min_by_key(|(_, violation)| violation.observed_at_ms)
                .map(|(index, _)| index)
                .unwrap_or(0);
            self.record.violations[oldest] = OperationViolation {
                kind: TRUNCATED_KIND.to_string(),
                detail: "additional distinct operation violations exceeded the evidence bound"
                    .to_string(),
                observed_at_ms: now,
                occurrences: 1,
            };
        }
    }

    fn persist(&self) -> io::Result<()> {
        write_atomic_nofollow(
            &self.record_path,
            &serde_json::to_vec_pretty(&self.record)?,
            0o600,
        )
    }

    fn reload(&mut self) -> io::Result<()> {
        self.record = read_operation_record(&self.record_path)?;
        Ok(())
    }
}

fn attempt_terminal_subject_release_with(
    record: &mut ManagedOperationRecord,
    remove_owned_cgroup: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<bool> {
    if !matches!(
        record.state,
        OperationState::Succeeded | OperationState::Failed | OperationState::TimedOut
    ) {
        return Ok(false);
    }
    if record.cgroup.path.is_empty() || record.cgroup.state == OperationCgroupState::Released {
        return Ok(true);
    }
    if record.cgroup.owned_by_supervisor {
        if !matches!(
            record.cgroup.state,
            OperationCgroupState::Prepared
                | OperationCgroupState::Attached
                | OperationCgroupState::Unavailable
        ) {
            return Ok(false);
        }
        match remove_owned_cgroup(Path::new(&record.cgroup.path)) {
            Ok(()) => {
                record.cgroup.state = OperationCgroupState::Released;
                record.cgroup.error = None;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                record.cgroup.state = OperationCgroupState::Released;
                record.cgroup.error = None;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    } else {
        if !matches!(
            record.cgroup.state,
            OperationCgroupState::Prepared | OperationCgroupState::Attached
        ) {
            return Ok(false);
        }
        match fs::symlink_metadata(&record.cgroup.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // The runner that adopted this cgroup tears it down before
                // finishing the operation. Reflect that observed release in
                // the durable record so exact boundary cleanup can proceed.
                record.cgroup.state = OperationCgroupState::Released;
                record.cgroup.error = None;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Returns true only after a terminal operation has already released its
/// enforceable local subject. This is intentionally read-only: boundary
/// cleanup may verify lifecycle completion, but must not release a subject on
/// behalf of an active or incompletely terminated operation.
#[cfg(any(target_os = "linux", test))]
fn terminal_operation_subject_is_released(record: &ManagedOperationRecord) -> bool {
    matches!(
        record.state,
        OperationState::Succeeded | OperationState::Failed | OperationState::TimedOut
    ) && (record.cgroup.path.is_empty() || record.cgroup.state == OperationCgroupState::Released)
}

#[cfg(any(target_os = "linux", test))]
fn retry_terminal_operation_subject_release_at_with(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
    remove_owned_cgroup: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<bool> {
    let root = operation_record_root_at(state_root, operation_id)?;
    let record_path = root.join("record.json");
    if !record_path.exists() {
        return Ok(false);
    }
    let lock_path = root.join("record.lock");
    let _lock = OperationRecordLock::acquire(&lock_path)?;
    let record = read_operation_record(&record_path)?;
    if record.operation_id != operation_id || record.source_run_id != expected_source_run_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "terminal cleanup identity does not match the operation record",
        ));
    }
    if !matches!(
        record.state,
        OperationState::Succeeded | OperationState::Failed | OperationState::TimedOut
    ) {
        return Ok(false);
    }
    let now = unix_millis()?;
    let mut supervisor = OperationSupervisor {
        record,
        record_path,
        lock_path,
    };
    let released =
        match attempt_terminal_subject_release_with(&mut supervisor.record, remove_owned_cgroup) {
            Ok(released) => released,
            Err(error) => {
                supervisor.record.cgroup.error = Some(error.to_string());
                let kind = if supervisor.record.cgroup.owned_by_supervisor {
                    "cgroup_release_retry_failed"
                } else {
                    "adopted_cgroup_release_retry_failed"
                };
                supervisor.record_violation_at(kind, &error.to_string(), now);
                false
            }
        };
    supervisor.record.updated_at_ms = now;
    let persist_result = supervisor.persist();
    drop(_lock);
    persist_result?;
    Ok(released)
}

#[cfg(target_os = "linux")]
pub(crate) fn retry_terminal_operation_subject_release_at(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    retry_terminal_operation_subject_release_at_with(
        state_root,
        operation_id,
        expected_source_run_id,
        gensee_crate_linux::remove_agent_cgroup,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn terminal_operation_subject_is_released_at(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    let root = operation_record_root_at(state_root, operation_id)?;
    let record_path = root.join("record.json");
    let lock_path = root.join("record.lock");
    let _lock = OperationRecordLock::acquire(&lock_path)?;
    let record = read_operation_record(&record_path)?;
    if record.operation_id != operation_id || record.source_run_id != expected_source_run_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "terminal operation identity does not match the boundary record",
        ));
    }
    Ok(terminal_operation_subject_is_released(&record))
}

fn read_operation_record(path: &Path) -> io::Result<ManagedOperationRecord> {
    let record: ManagedOperationRecord = serde_json::from_str(&read_nofollow_to_string(path)?)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid managed operation record: {error}"),
            )
        })?;
    if record.schema_version != OPERATION_RECORD_SCHEMA_VERSION
        || !safe_operation_token(&record.operation_id)
        || !safe_operation_token(&record.source_run_id)
        || !safe_operation_token(&record.action_class)
        || record.root_pid == Some(0)
        || record
            .root_start_time_ticks
            .is_some_and(|_| record.root_pid.is_none())
        || record
            .process_lineage
            .iter()
            .any(|identity| identity.pid == 0)
        || record
            .envelope
            .leases
            .iter()
            .any(|lease| !safe_operation_token(&lease.lease_id))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed operation record has an invalid schema or identity",
        ));
    }
    let expected_cgroup = gensee_crate_linux::default_agent_cgroup_path(&record.operation_id);
    if !record.cgroup.path.is_empty() && Path::new(&record.cgroup.path) != expected_cgroup {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed operation record contains an unexpected cgroup path",
        ));
    }
    Ok(record)
}

fn normalize_envelope(mut envelope: OperationCapabilityEnvelope) -> OperationCapabilityEnvelope {
    envelope.capabilities.sort_by_key(|capability| {
        serde_json::to_string(capability).unwrap_or_else(|_| "unknown".to_string())
    });
    envelope.capabilities.dedup();
    envelope.active_mediators.sort();
    envelope.active_mediators.dedup();
    envelope
}

fn operation_record_root_at(state_root: &Path, operation_id: &str) -> io::Result<PathBuf> {
    if !safe_operation_token(operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe operation id",
        ));
    }
    Ok(state_root.join("operations").join(operation_id))
}

fn safe_operation_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_boundary_cleanup_requires_terminal_and_released_subject() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let mut supervisor = OperationSupervisor::prepare_external_subject(
            "op_cleanup_gate",
            "run_cleanup_gate",
            "test",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();

        assert!(!terminal_operation_subject_is_released(&supervisor.record));
        supervisor.record.state = OperationState::Succeeded;
        assert!(terminal_operation_subject_is_released(&supervisor.record));

        supervisor.record.cgroup.path = "/sys/fs/cgroup/gensee/op_cleanup_gate".to_string();
        supervisor.record.cgroup.state = OperationCgroupState::Attached;
        assert!(!terminal_operation_subject_is_released(&supervisor.record));
        supervisor.record.cgroup.state = OperationCgroupState::Released;
        assert!(terminal_operation_subject_is_released(&supervisor.record));

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn absent_adopted_cgroup_transitions_to_released() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        let adopted = root.join("adopted-cgroup");
        fs::create_dir_all(&adopted).unwrap();
        env::set_var("GENSEE_HOME", &root);
        let mut supervisor = OperationSupervisor::prepare_external_subject(
            "op_adopted_release",
            "run_adopted_release",
            "test",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();
        supervisor.activate_external_subject().unwrap();
        supervisor.record.cgroup.path = adopted.to_string_lossy().to_string();
        supervisor.record.cgroup.state = OperationCgroupState::Attached;
        supervisor.record.state = OperationState::Failed;
        assert!(
            !attempt_terminal_subject_release_with(&mut supervisor.record, |_| Ok(())).unwrap()
        );
        assert_eq!(
            supervisor.record.cgroup.state,
            OperationCgroupState::Attached
        );
        fs::remove_dir_all(&adopted).unwrap();

        assert!(attempt_terminal_subject_release_with(&mut supervisor.record, |_| Ok(())).unwrap());
        assert_eq!(
            supervisor.record.cgroup.state,
            OperationCgroupState::Released
        );
        assert!(supervisor.record.cgroup.error.is_none());

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn owned_cgroup_release_failure_can_be_retried_after_terminalization() {
        let root = env::temp_dir().join(format!(
            "gensee-operation-release-retry-test-{}",
            uuid::Uuid::new_v4()
        ));
        let mut supervisor = OperationSupervisor::prepare_external_subject_at(
            &root,
            "op_release_retry",
            "run_release_retry",
            "test",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();
        supervisor.record.state = OperationState::Failed;
        supervisor.record.finished_at_ms = Some(1);
        supervisor.record.exit_code = Some(1);
        supervisor.record.cgroup = OperationCgroupRecord {
            path: "/sys/fs/cgroup/gensee/op_release_retry".to_string(),
            state: OperationCgroupState::Attached,
            owned_by_supervisor: true,
            error: None,
        };
        supervisor.persist().unwrap();
        drop(supervisor);

        assert!(!retry_terminal_operation_subject_release_at_with(
            &root,
            "op_release_retry",
            "run_release_retry",
            |_| Err(io::Error::from_raw_os_error(libc::EBUSY)),
        )
        .unwrap());
        let record =
            read_operation_record(&root.join("operations/op_release_retry/record.json")).unwrap();
        assert_eq!(record.cgroup.state, OperationCgroupState::Attached);
        assert!(!terminal_operation_subject_is_released(&record));
        assert!(record
            .violations
            .iter()
            .any(|violation| violation.kind == "cgroup_release_retry_failed"));

        assert!(retry_terminal_operation_subject_release_at_with(
            &root,
            "op_release_retry",
            "run_release_retry",
            |_| Ok(()),
        )
        .unwrap());
        let record =
            read_operation_record(&root.join("operations/op_release_retry/record.json")).unwrap();
        assert_eq!(record.cgroup.state, OperationCgroupState::Released);
        assert!(terminal_operation_subject_is_released(&record));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn unavailable_owned_cgroup_is_still_removed_during_terminal_recovery() {
        let mut record = ManagedOperationRecord {
            schema_version: OPERATION_RECORD_SCHEMA_VERSION,
            operation_id: "op_unavailable_release".to_string(),
            source_run_id: "run_unavailable_release".to_string(),
            action_class: "test".to_string(),
            state: OperationState::Failed,
            root_pid: None,
            root_start_time_ticks: None,
            cgroup: OperationCgroupRecord {
                path: "/sys/fs/cgroup/gensee/op_unavailable_release".to_string(),
                state: OperationCgroupState::Unavailable,
                owned_by_supervisor: true,
                error: Some("creation or attachment failed".to_string()),
            },
            envelope: OperationCapabilityEnvelope::default(),
            process_lineage: Vec::new(),
            boundary_effect_count: 0,
            denied_boundary_effect_count: 0,
            network_usage: OperationNetworkUsage::default(),
            violations: Vec::new(),
            started_at_ms: 1,
            updated_at_ms: 1,
            finished_at_ms: Some(1),
            exit_code: None,
        };

        assert!(attempt_terminal_subject_release_with(&mut record, |_| Ok(())).unwrap());
        assert_eq!(record.cgroup.state, OperationCgroupState::Released);
        assert!(record.cgroup.error.is_none());
    }

    #[test]
    fn supervisor_persists_envelope_lineage_and_completion() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let envelope = OperationCapabilityEnvelope {
            capabilities: vec![Capability::ProcessExecution, Capability::ProcessExecution],
            active_mediators: vec![MediationBoundary::ProcessCgroup],
            ..OperationCapabilityEnvelope::default()
        };
        let mut supervisor =
            OperationSupervisor::prepare("op_test", "run_test", "managed_test", envelope, None)
                .unwrap();
        supervisor.activate(std::process::id()).unwrap();
        supervisor.finish(Some(0), false).unwrap();

        let record: ManagedOperationRecord = serde_json::from_str(
            &fs::read_to_string(root.join("operations/op_test/record.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record.state, OperationState::Succeeded);
        assert_eq!(record.envelope.capabilities.len(), 1);
        if cfg!(target_os = "linux") {
            assert!(record
                .process_lineage
                .iter()
                .any(|identity| identity.pid == std::process::id()));
        }
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn operation_identity_is_path_safe_and_single_use() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        assert!(OperationSupervisor::prepare(
            "../escape",
            "run_test",
            "test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .is_err());
        OperationSupervisor::prepare(
            "op_once",
            "run_test",
            "test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        assert!(OperationSupervisor::prepare(
            "op_once",
            "run_test",
            "test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .is_err());
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn terminal_operation_cannot_be_reopened() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let mut supervisor = OperationSupervisor::prepare(
            "op_terminal",
            "run_terminal",
            "test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        supervisor.activate(std::process::id()).unwrap();
        supervisor.finish(Some(0), false).unwrap();
        let error = OperationSupervisor::open_at(&root, "op_terminal", "run_terminal")
            .err()
            .expect("terminal operation must stay terminal");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("cannot be reopened"));
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn lineage_and_violation_history_are_bounded_with_explicit_truncation() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let mut supervisor = OperationSupervisor::prepare(
            "op_bounded",
            "run_bounded",
            "test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        for index in 0..(MAX_RETAINED_INACTIVE_PROCESS_IDENTITIES + 17) {
            supervisor
                .record
                .process_lineage
                .push(OperationProcessIdentity {
                    pid: (index + 1) as u32,
                    parent_pid: 1,
                    start_time_ticks: (index + 1) as u64,
                    executable_path: None,
                    command_line: None,
                    first_seen_at_ms: index as u64,
                    last_seen_at_ms: index as u64,
                    active: false,
                });
        }
        supervisor
            .record
            .process_lineage
            .push(OperationProcessIdentity {
                pid: 99_999,
                parent_pid: 1,
                start_time_ticks: 99_999,
                executable_path: None,
                command_line: None,
                first_seen_at_ms: 1,
                last_seen_at_ms: 1,
                active: true,
            });
        assert!(supervisor.bound_process_lineage_history().unwrap());
        assert_eq!(
            supervisor
                .record
                .process_lineage
                .iter()
                .filter(|identity| !identity.active)
                .count(),
            MAX_RETAINED_INACTIVE_PROCESS_IDENTITIES
        );
        assert!(supervisor
            .record
            .process_lineage
            .iter()
            .any(|identity| identity.pid == 99_999 && identity.active));

        for index in 0..(MAX_OPERATION_VIOLATION_KINDS + 20) {
            supervisor
                .record_violation(&format!("kind_{index}"), "distinct")
                .unwrap();
        }
        assert_eq!(
            supervisor.record.violations.len(),
            MAX_OPERATION_VIOLATION_KINDS
        );
        assert!(supervisor.record.violations.iter().any(|violation| {
            violation.kind == "violation_evidence_truncated" && violation.occurrences > 1
        }));
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_supervisor_handles_reload_before_each_update() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let mut runner = OperationSupervisor::prepare_external_subject(
            "op_shared",
            "run_shared",
            "managed_test",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();
        let mut boundary = OperationSupervisor::open("op_shared", "run_shared").unwrap();
        let envelope = NetworkCapabilityEnvelope {
            grants: vec![gensee_crate_rules::network_boundary::NetworkEndpointGrant {
                destination: "203.0.113.10".to_string(),
                protocol: gensee_crate_rules::network_boundary::NetworkProtocol::Tcp,
                ports: vec![443],
                expires_at_ms: None,
                lease_id: None,
            }],
        };
        boundary.update_network_envelope(envelope).unwrap();
        runner.finish(Some(0), false).unwrap();
        let event = NetworkBoundaryEvent {
            schema_version: gensee_crate_rules::network_boundary::NETWORK_BOUNDARY_SCHEMA_VERSION,
            operation_id: "op_shared".to_string(),
            source_run_id: "run_shared".to_string(),
            process_id: 1,
            destination: "203.0.113.10".to_string(),
            protocol: gensee_crate_rules::network_boundary::NetworkProtocol::Tcp,
            port: 443,
            effect: gensee_crate_rules::network_boundary::NetworkEffectKind::DirectConnect,
            observed_at_ms: unix_millis().unwrap(),
            requested_ttl_seconds: None,
        };
        let decision = NetworkBoundaryDecision {
            disposition: gensee_crate_rules::network_boundary::NetworkBoundaryDisposition::AllowWithinEnvelope,
            reason_code: "within_envelope".to_string(),
            lease: None,
        };
        boundary.record_network_effect(&event, &decision).unwrap();
        boundary.record_network_usage(2, 200, 1, 80).unwrap();

        let record = read_operation_record(&root.join("operations/op_shared/record.json")).unwrap();
        assert_eq!(record.state, OperationState::Succeeded);
        assert_eq!(record.boundary_effect_count, 1);
        assert_eq!(record.envelope.network.grants.len(), 1);
        assert_eq!(record.network_usage.allowed_packets, 2);
        assert_eq!(record.network_usage.blocked_bytes, 80);
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn operation_record_reader_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-operation-test-{}", uuid::Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let mut supervisor = OperationSupervisor::prepare_external_subject(
            "op_symlink",
            "run_symlink",
            "test",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();
        supervisor.activate_external_subject().unwrap();
        drop(supervisor);
        let record_path = root.join("operations/op_symlink/record.json");
        let target_path = root.join("record-target.json");
        fs::rename(&record_path, &target_path).unwrap();
        symlink(&target_path, &record_path).unwrap();
        assert!(OperationSupervisor::open("op_symlink", "run_symlink").is_err());
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }
}
