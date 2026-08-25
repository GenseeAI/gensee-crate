use super::*;
use gensee_crate_rules::capability::{
    Capability, CapabilityRequest, EffectManifest, EffectTelemetryCoverage, EffectViolation,
    FileChangeEffect, FileChangeKind, FileEntryKind, FileOperationKind, FilesystemReadCoverage,
    ProcessEffect, PromotionOutput, PromotionReceipt, TelemetryCoverage,
    CAPABILITY_REQUEST_SCHEMA_VERSION, EFFECT_MANIFEST_SCHEMA_VERSION,
};
use gensee_crate_rules::capability_broker::BrokerResourceKind;
use gensee_crate_rules::capability_broker::{BrokerDelivery, BrokerGatewayEffectKind, BrokerLease};
use gensee_crate_rules::capability_policy::{
    ApprovalRequirement, CapabilityDecision, CapabilityExecutor, CapabilityPolicyDecision,
    CapabilityPolicyEngine, MediationBoundary, PolicyEvaluationContext, PromotionRequirement,
};
use std::collections::{BTreeMap, BTreeSet};

const CELL_LEASE_SCHEMA_VERSION: u32 = 2;
const CELL_FORENSICS_SCHEMA_VERSION: u32 = 2;
const CELL_FORENSICS_SIGNATURE_DOMAIN: &str = "capability-cell-forensics-v1";
const CELL_PROMOTION_SIGNATURE_DOMAIN: &str = "capability-cell-promotion-v1";
// Leave time for the host-control bridge to return the result and reap the
// container before its own hard command timeout.
const CELL_LEASE_MAX_TTL_SECONDS: u64 = TCLONE_HOST_CONTROL_COMMAND_TIMEOUT_SECS - 60;
const CELL_POLL_INTERVAL_MS: u64 = 25;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CapabilityCellLease {
    schema_version: u32,
    lease_id: String,
    operation_id: String,
    cell_id: String,
    source_run_id: String,
    request: CapabilityRequest,
    policy_decision: CapabilityDecision,
    command: Vec<String>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at_ms: Option<u64>,
    #[serde(default)]
    broker_lease_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_of_cell_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_input_snapshot_digest: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCellReplayPlan {
    schema_version: u32,
    original_cell_id: String,
    original_operation_id: String,
    original_source_run_id: String,
    request: CapabilityRequest,
    command: Vec<String>,
    input_snapshot_digest: String,
    manifest_digest: String,
    required_broker_resources: Vec<BrokerResourceKind>,
    created_at_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCellForensicsClaims {
    schema_version: u32,
    operation_id: String,
    cell_id: String,
    lease_id: String,
    source_run_id: String,
    request_digest: String,
    policy_decision_digest: String,
    command_digest: String,
    input_snapshot_digest: String,
    output_snapshot_digest: String,
    manifest_digest: String,
    replay_plan_digest: String,
    created_at_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCellForensicsEvidence {
    claims: CapabilityCellForensicsClaims,
    signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPromotionReceipt {
    claims: CapabilityCellPromotionClaims,
    signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCellPromotionClaims {
    schema_version: u32,
    cell_id: String,
    receipt: PromotionReceipt,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CapabilityCellRecord {
    schema_version: u32,
    operation_id: String,
    cell_id: String,
    lease_id: String,
    source_run_id: String,
    request: CapabilityRequest,
    policy_decision: CapabilityDecision,
    command: Vec<String>,
    #[serde(default)]
    broker_lease_ids: Vec<String>,
    container_name: String,
    input_snapshot: String,
    workspace_snapshot: String,
    effect_manifest: String,
    started_at_ms: u64,
    finished_at_ms: u64,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCellCleanupJournal {
    schema_version: u32,
    cell_id: String,
    container_name: String,
    broker_lease_ids: Vec<String>,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nftables_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cgroup_path: Option<String>,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleaned_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Debug)]
struct CellNetworkPlan {
    enforcement: gensee_crate_linux::LinuxNetworkEnforcementPlan,
}

#[derive(Debug, Default)]
struct CellNetworkEvidence {
    allowed: Vec<gensee_crate_linux::LinuxNetworkEndpointEvent>,
    blocked: Vec<gensee_crate_linux::LinuxNetworkBlockEvent>,
    collection_error: Option<String>,
}

#[derive(Debug, Default)]
struct CellRuntimeEvidence {
    files_read: BTreeSet<String>,
    processes_started: Vec<ProcessEffect>,
    covered_read_mounts: Vec<String>,
    expected_read_mounts: Vec<String>,
    filesystem_collection_error: Option<String>,
    process_collection_error: Option<String>,
    process_telemetry_complete: bool,
}

#[derive(Debug, Default)]
struct CellRuntimeWorkerResult {
    filesystem_events: Vec<gensee_crate_linux::LinuxFanotifyEvent>,
    processes_started: Vec<ProcessEffect>,
    filesystem_collection_error: Option<String>,
    process_collection_error: Option<String>,
    process_telemetry_complete: bool,
}

#[derive(Debug)]
struct CellProcessTracker {
    tracked_pids: BTreeSet<u32>,
    active_processes: BTreeMap<u32, Option<u64>>,
    processes_started: Vec<ProcessEffect>,
}

struct CellRuntimeSensor {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<CellRuntimeWorkerResult>>,
    evidence: CellRuntimeEvidence,
    input_snapshot: PathBuf,
    output_snapshot: PathBuf,
    container_workspace: String,
}

struct CellNetworkGuard {
    plan: CellNetworkPlan,
    table_applied: bool,
    cleaned: bool,
}

struct CellCgroupGuard {
    path: PathBuf,
    cleaned: bool,
}

impl CellCgroupGuard {
    fn activate(cell_id: &str) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cell_id;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "capability cells require Linux cgroup v2",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let path = gensee_crate_linux::default_agent_cgroup_path(cell_id);
            gensee_crate_linux::create_agent_cgroup(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot create capability-cell cgroup: {error}"),
                )
            })?;
            Ok(Self {
                path,
                cleaned: false,
            })
        }
    }

    fn attach(&self, pid: u32) -> io::Result<()> {
        let attached = gensee_crate_linux::attach_process_tree_to_cgroup(pid, &self.path)?;
        if attached.contains(&pid) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capability-cell process was not attached to its cgroup",
            ))
        }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.cleaned {
            gensee_crate_linux::remove_agent_cgroup(&self.path)?;
            self.cleaned = true;
        }
        Ok(())
    }
}

impl Drop for CellCgroupGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl CellRuntimeSensor {
    fn start(
        cell_id: &str,
        root_pid: u32,
        input_snapshot: &Path,
        output_snapshot: &Path,
        container_workspace: &str,
        read_mounts: &[String],
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let mut sensor = Self {
            stop: Arc::clone(&stop),
            worker: None,
            evidence: CellRuntimeEvidence::default(),
            input_snapshot: input_snapshot.to_path_buf(),
            output_snapshot: output_snapshot.to_path_buf(),
            container_workspace: container_workspace.to_string(),
        };
        sensor.evidence.expected_read_mounts = read_mounts.to_vec();
        sensor.evidence.expected_read_mounts.sort();
        sensor.evidence.expected_read_mounts.dedup();
        let result =
            (|| -> io::Result<(gensee_crate_linux::LinuxFanotifyEnforcer, Vec<String>, Option<String>)> {
                let process_root = PathBuf::from("/proc")
                    .join(root_pid.to_string())
                    .join("root");
                if !process_root.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "gated capability-cell process root is not inspectable",
                    ));
                }
                let mount_marks = read_mounts
                    .iter()
                    .map(|mount| {
                        if mount == "/" {
                            process_root.clone()
                        } else {
                            process_root.join(mount.trim_start_matches('/'))
                        }
                    })
                    .map(|path| path.to_string_lossy().to_string())
                    .collect::<Vec<_>>();
                let session = gensee_crate_linux::LinuxSessionTarget::from_pid(cell_id, root_pid)?;
                let config = gensee_crate_linux::LinuxFanotifyConfig::with_session_filesystem_audit(
                    gensee_crate_linux::LinuxPolicy::default(),
                    session,
                    mount_marks.clone(),
                );
                let enforcer = gensee_crate_linux::LinuxFanotifyEnforcer::new(config)?;
                let status = enforcer.status();
                let covered_read_mounts = read_mounts
                    .iter()
                    .zip(mount_marks.iter())
                    .filter(|(_, host)| status.marked_paths.contains(host))
                    .map(|(mount, _)| mount.clone())
                    .collect::<Vec<_>>();
                let missing_read_mounts = read_mounts
                    .iter()
                    .filter(|mount| !covered_read_mounts.contains(*mount))
                    .cloned()
                    .collect::<Vec<_>>();
                let setup_error = if status.warnings.is_empty()
                    && missing_read_mounts.is_empty()
                {
                    None
                } else {
                    Some(format!(
                        "fanotify did not establish every declared cell mount; missing [{}]; {}",
                        missing_read_mounts.join(", "),
                        status.warnings.join("; "),
                    ))
                };
                Ok((enforcer, covered_read_mounts, setup_error))
            })();
        let (fanotify, filesystem_setup_error) = match result {
            Ok((enforcer, covered_read_mounts, setup_error)) => {
                sensor.evidence.covered_read_mounts = covered_read_mounts;
                (Some(enforcer), setup_error)
            }
            Err(error) => (None, Some(error.to_string())),
        };
        sensor.evidence.filesystem_collection_error = filesystem_setup_error.clone();

        let process_setup = gensee_crate_linux::LinuxProcessEventSensor::new()
            .and_then(|sensor| CellProcessTracker::new(root_pid).map(|tracker| (sensor, tracker)));
        let (process_sensor, process_tracker, process_setup_error) = match process_setup {
            Ok((process_sensor, process_tracker)) => {
                (Some(process_sensor), Some(process_tracker), None)
            }
            Err(error) => (None, None, Some(error.to_string())),
        };
        sensor.evidence.process_collection_error = process_setup_error.clone();

        if fanotify.is_some() || process_sensor.is_some() {
            sensor.worker = Some(thread::spawn(move || {
                run_cell_runtime_sensors(
                    stop,
                    fanotify,
                    process_sensor,
                    process_tracker,
                    filesystem_setup_error,
                    process_setup_error,
                )
            }));
        }
        sensor
    }

    fn record_events(
        &mut self,
        events: Vec<gensee_crate_linux::LinuxFanotifyEvent>,
        record_process_fallback: bool,
    ) {
        for event in events {
            let path = event.request.path.as_deref().map(|path| {
                cell_effect_path(
                    path,
                    &self.input_snapshot,
                    &self.output_snapshot,
                    &self.container_workspace,
                )
            });
            if matches!(
                event.request.operation,
                gensee_crate_linux::LinuxAccessOperation::FileRead
            ) {
                if let Some(path) = path.clone() {
                    self.evidence.files_read.insert(path);
                }
            }
            if record_process_fallback && event.executable_open {
                let command_line = event.request.command_line.unwrap_or_default();
                let argv_digest = format!("sha256:{:x}", Sha256::digest(command_line.as_bytes()));
                let process = ProcessEffect {
                    executable: path.unwrap_or_else(|| "unknown".to_string()),
                    argv_digest,
                    pid: event.request.pid,
                    parent_pid: None,
                    start_time_ticks: None,
                    started_at_ms: unix_millis().unwrap_or_default(),
                    finished_at_ms: None,
                    exit_code: None,
                };
                if !self.evidence.processes_started.iter().any(|observed| {
                    observed.pid == process.pid
                        && observed.executable == process.executable
                        && observed.argv_digest == process.argv_digest
                }) {
                    self.evidence.processes_started.push(process);
                }
            }
        }
    }

    fn finish(mut self) -> CellRuntimeEvidence {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(result) => {
                    self.record_events(
                        result.filesystem_events,
                        !result.process_telemetry_complete,
                    );
                    self.evidence
                        .processes_started
                        .extend(result.processes_started);
                    append_collection_error(
                        &mut self.evidence.filesystem_collection_error,
                        result.filesystem_collection_error,
                    );
                    append_collection_error(
                        &mut self.evidence.process_collection_error,
                        result.process_collection_error,
                    );
                    self.evidence.process_telemetry_complete = result.process_telemetry_complete
                        && self.evidence.process_collection_error.is_none();
                }
                Err(_) => {
                    let error = Some("cell runtime sensor thread panicked".to_string());
                    append_collection_error(
                        &mut self.evidence.filesystem_collection_error,
                        error.clone(),
                    );
                    append_collection_error(&mut self.evidence.process_collection_error, error);
                }
            }
        }
        self.evidence
    }
}

impl CellProcessTracker {
    fn new(root_pid: u32) -> io::Result<Self> {
        let identities = gensee_crate_linux::collect_process_lineage(root_pid)?;
        if identities.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "capability-cell root process identity is unavailable",
            ));
        }
        let started_at_ms = unix_millis()?;
        let tracked_pids = identities.iter().map(|identity| identity.pid).collect();
        let active_processes = identities
            .iter()
            .map(|identity| (identity.pid, Some(identity.start_time_ticks)))
            .collect();
        let processes_started = identities
            .iter()
            .map(|identity| process_effect_from_identity(identity, started_at_ms))
            .collect();
        Ok(Self {
            tracked_pids,
            active_processes,
            processes_started,
        })
    }

    fn record(&mut self, event: gensee_crate_linux::LinuxProcessEvent) -> io::Result<()> {
        let observed_at_ms = unix_millis()?;
        match event {
            gensee_crate_linux::LinuxProcessEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
                ..
            } if self.tracked_pids.contains(&parent_pid)
                || self.tracked_pids.contains(&parent_tgid) =>
            {
                self.tracked_pids.insert(child_pid);
                self.tracked_pids.insert(child_tgid);
                if child_pid == child_tgid {
                    let effect = match gensee_crate_linux::inspect_process_identity(child_tgid) {
                        Ok(identity) => process_effect_from_identity(&identity, observed_at_ms),
                        Err(_) => {
                            self.inherited_process_effect(parent_tgid, child_tgid, observed_at_ms)?
                        }
                    };
                    self.active_processes
                        .insert(child_tgid, effect.start_time_ticks);
                    self.processes_started.push(effect);
                }
            }
            gensee_crate_linux::LinuxProcessEvent::Exec {
                process_pid,
                process_tgid,
                ..
            } if self.tracked_pids.contains(&process_pid)
                || self.tracked_pids.contains(&process_tgid) =>
            {
                self.tracked_pids.insert(process_pid);
                self.tracked_pids.insert(process_tgid);
                let identity = gensee_crate_linux::inspect_process_identity(process_tgid)?;
                let effect = process_effect_from_identity(&identity, observed_at_ms);
                self.active_processes
                    .insert(process_tgid, effect.start_time_ticks);
                if !self.processes_started.iter().any(|observed| {
                    observed.pid == effect.pid
                        && observed.start_time_ticks == effect.start_time_ticks
                        && observed.executable == effect.executable
                        && observed.argv_digest == effect.argv_digest
                }) {
                    self.processes_started.push(effect);
                }
            }
            gensee_crate_linux::LinuxProcessEvent::Exit {
                process_pid,
                process_tgid,
                exit_code,
                exit_signal,
                ..
            } if self.tracked_pids.contains(&process_pid)
                || self.tracked_pids.contains(&process_tgid) =>
            {
                self.tracked_pids.remove(&process_pid);
                if process_pid == process_tgid {
                    self.tracked_pids.remove(&process_tgid);
                    let exit_code = decode_process_exit(exit_code, exit_signal);
                    let active_start_time = self.active_processes.remove(&process_tgid);
                    for process in self.processes_started.iter_mut().filter(|process| {
                        process.pid == Some(process_tgid)
                            && process.finished_at_ms.is_none()
                            && active_start_time
                                .is_some_and(|start| process.start_time_ticks == start)
                    }) {
                        process.finished_at_ms = Some(observed_at_ms);
                        process.exit_code = Some(exit_code);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn inherited_process_effect(
        &self,
        parent_pid: u32,
        child_pid: u32,
        started_at_ms: u64,
    ) -> io::Result<ProcessEffect> {
        let parent = self
            .processes_started
            .iter()
            .rev()
            .find(|process| process.pid == Some(parent_pid))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fork event parent was not present in process evidence",
                )
            })?;
        Ok(ProcessEffect {
            executable: parent.executable.clone(),
            argv_digest: parent.argv_digest.clone(),
            pid: Some(child_pid),
            parent_pid: Some(parent_pid),
            start_time_ticks: None,
            started_at_ms,
            finished_at_ms: None,
            exit_code: None,
        })
    }
}

fn process_effect_from_identity(
    identity: &gensee_crate_linux::LinuxProcessIdentity,
    started_at_ms: u64,
) -> ProcessEffect {
    let command_line = identity.command_line.as_deref().unwrap_or_default();
    ProcessEffect {
        executable: identity
            .executable_path
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        argv_digest: format!("sha256:{:x}", Sha256::digest(command_line.as_bytes())),
        pid: Some(identity.pid),
        parent_pid: Some(identity.parent_pid),
        start_time_ticks: Some(identity.start_time_ticks),
        started_at_ms,
        finished_at_ms: None,
        exit_code: None,
    }
}

fn decode_process_exit(exit_code: u32, exit_signal: u32) -> i32 {
    if exit_signal != 0 {
        128_i32.saturating_add(exit_signal.min(i32::MAX as u32) as i32)
    } else {
        ((exit_code >> 8) & 0xff) as i32
    }
}

fn run_cell_runtime_sensors(
    stop: Arc<AtomicBool>,
    mut fanotify: Option<gensee_crate_linux::LinuxFanotifyEnforcer>,
    mut process_sensor: Option<gensee_crate_linux::LinuxProcessEventSensor>,
    mut process_tracker: Option<CellProcessTracker>,
    mut filesystem_collection_error: Option<String>,
    mut process_collection_error: Option<String>,
) -> CellRuntimeWorkerResult {
    let mut filesystem_events = Vec::new();
    loop {
        let mut filesystem_empty = true;
        if let Some(enforcer) = fanotify.as_mut() {
            match enforcer.handle_events_once() {
                Ok(events) => {
                    filesystem_empty = events.is_empty();
                    filesystem_events.extend(events);
                }
                Err(error) => {
                    append_collection_error(
                        &mut filesystem_collection_error,
                        Some(error.to_string()),
                    );
                    fanotify = None;
                }
            }
        }

        let mut process_empty = true;
        if let Some(sensor) = process_sensor.as_mut() {
            match sensor.handle_events_once() {
                Ok(events) => {
                    process_empty = events.is_empty();
                    if let Some(tracker) = process_tracker.as_mut() {
                        for event in events {
                            if let Err(error) = tracker.record(event) {
                                append_collection_error(
                                    &mut process_collection_error,
                                    Some(error.to_string()),
                                );
                            }
                        }
                    }
                }
                Err(error) => {
                    append_collection_error(&mut process_collection_error, Some(error.to_string()));
                    process_sensor = None;
                }
            }
        }

        if stop.load(Ordering::Acquire) && filesystem_empty && process_empty {
            return CellRuntimeWorkerResult {
                filesystem_events,
                processes_started: process_tracker
                    .map(|tracker| tracker.processes_started)
                    .unwrap_or_default(),
                filesystem_collection_error,
                process_telemetry_complete: process_sensor.is_some()
                    && process_collection_error.is_none(),
                process_collection_error,
            };
        }
        if filesystem_empty && process_empty {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn append_collection_error(target: &mut Option<String>, error: Option<String>) {
    let Some(error) = error.filter(|error| !error.is_empty()) else {
        return;
    };
    match target {
        Some(existing) if !existing.contains(&error) => {
            existing.push_str("; ");
            existing.push_str(&error);
        }
        None => *target = Some(error),
        _ => {}
    }
}

fn cell_effect_path(
    observed: &str,
    input_snapshot: &Path,
    output_snapshot: &Path,
    container_workspace: &str,
) -> String {
    let path = Path::new(observed);
    for root in [input_snapshot, output_snapshot] {
        if let Ok(relative) = path.strip_prefix(root) {
            return relative.to_string_lossy().to_string();
        }
    }
    let workspace = container_workspace.trim_end_matches('/');
    if let Some((_, relative)) = observed.split_once(&format!("{workspace}/")) {
        return relative.to_string();
    }
    observed.to_string()
}

pub(crate) fn tclone_capability_lease(args: Vec<OsString>) -> io::Result<()> {
    recover_expired_capability_cells(unix_millis()?)?;
    if args.first().and_then(|arg| arg.to_str()) != Some("issue") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run lease issue <source-run-id> --request <request.json> -- <command> [args...]",
        ));
    }
    if env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).is_some()
        || env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).is_some()
        || env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability leases are host-issued; run this command from the trusted host terminal",
        ));
    }

    let separator = args.iter().position(|arg| arg == "--").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability lease issuance requires an exact command after --",
        )
    })?;
    let options = &args[1..separator];
    let command = args[separator + 1..]
        .iter()
        .map(|arg| {
            arg.to_str().map(ToString::to_string).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command arguments must be UTF-8",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability lease command cannot be empty",
        ));
    }
    let source_run_id = tclone_target_arg(
        options,
        "usage: gensee run lease issue <source-run-id> --request <request.json> -- <command> [args...]",
    )?;
    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability leases require a running tclone source",
        ));
    }
    let request_path = arg_value(options, "--request")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --request file"))?;
    let request: CapabilityRequest = serde_json::from_str(&read_nofollow_to_string(&request_path)?)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid capability request: {error}"),
            )
        })?;
    let mut policy_decision = validate_cell_request_for_issue(&request)?;
    let ttl_seconds = arg_value(options, "--ttl-seconds")
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid --ttl-seconds value")
            })
        })
        .transpose()?
        .unwrap_or(request.lease_ttl_seconds)
        .min(request.lease_ttl_seconds)
        .min(CELL_LEASE_MAX_TTL_SECONDS);
    if ttl_seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("lease TTL must be between 1 and {CELL_LEASE_MAX_TTL_SECONDS} seconds"),
        ));
    }
    policy_decision.lease_delta.ttl_seconds = ttl_seconds;

    let issued_at_ms = unix_millis()?;
    let lease_id = format!("lease_{}", Uuid::new_v4().simple());
    let cell_id = format!("cell_{}", Uuid::new_v4().simple());
    let lease = CapabilityCellLease {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        lease_id: lease_id.clone(),
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        cell_id: cell_id.clone(),
        source_run_id,
        request,
        policy_decision,
        command,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        consumed_at_ms: None,
        broker_lease_ids: Vec::new(),
        replay_of_cell_id: None,
        expected_input_snapshot_digest: None,
    };
    let path = capability_lease_path(&lease_id)?;
    if let Some(parent) = path.parent() {
        create_restrictive_dir_all(parent)?;
    }
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    write_atomic_nofollow(
        &capability_cell_binding_path(&cell_id)?,
        format!("{lease_id}\n").as_bytes(),
        0o600,
    )?;

    if options.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "lease_id": lease.lease_id,
                "operation_id": lease.operation_id,
                "cell_id": lease.cell_id,
                "source_run_id": lease.source_run_id,
                "expires_at_ms": lease.expires_at_ms,
                "policy_decision": lease.policy_decision,
                "authorization_state": "planned",
            }))?
        );
    } else {
        println!("issued one-use capability lease reservation {lease_id}");
        println!("reserved capability cell {cell_id}");
        println!("authorization remains pending until required mediators are attached");
        println!(
            "execute with: gensee run cell {} --lease {lease_id}",
            lease.source_run_id
        );
    }
    Ok(())
}

pub(crate) fn tclone_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    let recovery = recover_expired_capability_cells(unix_millis()?);
    if args.first().and_then(|arg| arg.to_str()) == Some("inspect") {
        if let Err(error) = recovery {
            eprintln!("gensee: warning: capability-cell recovery incomplete: {error}");
        }
        return inspect_capability_cell(args[1..].to_vec());
    }
    recovery?;
    if args.first().and_then(|arg| arg.to_str()) == Some("promote") {
        return promote_capability_cell(args[1..].to_vec());
    }
    if args.first().and_then(|arg| arg.to_str()) == Some("replay") {
        return replay_capability_cell(args[1..].to_vec());
    }
    let source_run_id = tclone_target_arg(
        &args,
        "usage: gensee run cell <source-run-id> --lease <lease-id> [--json]",
    )?;
    if let Some(caller) = env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER") {
        if caller != OsString::from(&source_run_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a tclone source may execute only its own capability lease",
            ));
        }
    }
    let lease_id = arg_value(&args, "--lease")
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing valid --lease id"))?;
    let lease = consume_capability_lease(&lease_id, &source_run_id, unix_millis()?)?;
    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability cells require a running tclone source",
        ));
    }
    let record = execute_capability_cell(&source, &lease)?;

    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!(
            "capability cell {} finished with exit code {:?}; inspect retained snapshot at {}",
            record.cell_id, record.exit_code, record.workspace_snapshot
        );
    }
    if record.exit_code == Some(0) {
        Ok(())
    } else {
        Err(io::Error::other(if record.timed_out {
            "capability cell lease expired during execution".to_string()
        } else {
            format!("capability cell exited with status {:?}", record.exit_code)
        }))
    }
}

fn validate_cell_request_for_issue(request: &CapabilityRequest) -> io::Result<CapabilityDecision> {
    if request.schema_version != CAPABILITY_REQUEST_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported capability request schema version",
        ));
    }
    if request.capabilities.is_empty()
        || !request.capabilities.contains(&Capability::ProcessExecution)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell requests must include process_execution",
        ));
    }
    let read_paths = effective_read_paths(request);
    let write_paths = effective_write_paths(request);
    if !read_paths.is_empty() && !request.capabilities.contains(&Capability::FilesystemRead) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read_paths require filesystem_read capability",
        ));
    }
    if !write_paths.is_empty() && !request.capabilities.contains(&Capability::FilesystemWrite) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "write_paths require filesystem_write capability",
        ));
    }
    for unsupported in [
        Capability::Syscall,
        Capability::LinuxCapability,
        Capability::PrivilegedExecution,
        Capability::IrreversibleEffect,
        Capability::OutputPromotion,
        Capability::ExternalMutation,
    ] {
        if request.capabilities.contains(&unsupported) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "capability {unsupported:?} requires approval or kernel authority that is not available to fresh cells"
                ),
            ));
        }
    }
    validate_scope_paths(&read_paths)?;
    validate_scope_paths(&write_paths)?;
    if read_paths
        .iter()
        .any(|read| write_paths.iter().any(|write| read == write))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the same path cannot be mounted both read-only and writable",
        ));
    }
    // Issuance reserves an operation before broker leases can be attached.
    // Declare only boundaries enforced by every fresh cell; execution derives
    // broker-backed mediators from leases actually attached to this cell.
    let active_issue_mediators = vec![
        MediationBoundary::ProcessCgroup,
        MediationBoundary::FilesystemBoundary,
        MediationBoundary::KernelBoundary,
    ];
    let decision = CapabilityPolicyEngine::default().evaluate(
        request,
        &PolicyEvaluationContext {
            active_mediators: active_issue_mediators,
            attachable_mediators: vec![
                MediationBoundary::NetworkBoundary,
                MediationBoundary::SecretBroker,
                MediationBoundary::WorkloadIdentityBroker,
                MediationBoundary::CloudApiGateway,
                MediationBoundary::ExternalApiGateway,
                MediationBoundary::BrowserAutomationGateway,
                MediationBoundary::DatabaseProxy,
                MediationBoundary::OutputPromotionTransaction,
            ],
            locally_authorized_capabilities: Vec::new(),
            locally_leaseable_capabilities: Vec::new(),
            trusted_mediator_available: false,
            fresh_cell_available: true,
            live_fork_available: false,
            approval_staging_available: false,
            effect_brokerable: false,
            requires_staged_effects: true,
            effects_inseparable_from_runtime: false,
        },
    );
    if decision.decision != CapabilityPolicyDecision::Plan
        || decision.executor != Some(CapabilityExecutor::FreshCell)
        || decision.approval != ApprovalRequirement::None
        || (cell_request_requires_attested_promotion(request)
            && decision.promotion != PromotionRequirement::TransactionalPromotion)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "capability policy denied cell request structure: {}",
                decision.reason_codes.join(", ")
            ),
        ));
    }
    Ok(decision)
}

fn validate_cell_request_for_execution(
    lease: &CapabilityCellLease,
    now_ms: u64,
) -> io::Result<Vec<BrokerLease>> {
    let issued_decision = validate_cell_request_for_issue(&lease.request)?;
    if issued_decision.executor != lease.policy_decision.executor
        || issued_decision.approval != lease.policy_decision.approval
        || issued_decision.promotion != lease.policy_decision.promotion
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stored cell execution plan does not match current trusted policy",
        ));
    }
    let broker_leases = super::capability_broker::active_attached_broker_leases(
        &lease.broker_lease_ids,
        &lease.source_run_id,
        &lease.operation_id,
        &lease.cell_id,
        now_ms,
    )?;
    let mut active_mediators = vec![
        MediationBoundary::ProcessCgroup,
        MediationBoundary::FilesystemBoundary,
        MediationBoundary::KernelBoundary,
    ];
    for broker_lease in &broker_leases {
        validate_broker_scope_against_request(&lease.request, broker_lease)?;
        match broker_lease.resource_kind {
            BrokerResourceKind::ServiceCredential
            | BrokerResourceKind::LegacyServiceCredentialV1A
            | BrokerResourceKind::LegacyServiceCredentialV1B => {
                active_mediators.push(MediationBoundary::SecretBroker);
                active_mediators.push(MediationBoundary::NetworkBoundary);
                add_gateway_kind_mediator(&mut active_mediators, broker_lease)?;
            }
            BrokerResourceKind::WorkloadIdentity | BrokerResourceKind::MtlsCertificate => {
                active_mediators.push(MediationBoundary::WorkloadIdentityBroker);
                active_mediators.push(MediationBoundary::SecretBroker);
                active_mediators.push(MediationBoundary::NetworkBoundary);
            }
            BrokerResourceKind::FilesystemHandle => {
                active_mediators.push(MediationBoundary::FilesystemBoundary);
            }
            BrokerResourceKind::DatabaseRole => {
                active_mediators.push(MediationBoundary::DatabaseProxy);
                active_mediators.push(MediationBoundary::NetworkBoundary);
            }
            BrokerResourceKind::NetworkLease => {
                active_mediators.push(MediationBoundary::NetworkBoundary);
            }
            BrokerResourceKind::ExternalActionCommitToken => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "external-action commit tokens are consumed by a host gateway, never inside a cell",
                ));
            }
        }
    }
    active_mediators.sort();
    active_mediators.dedup();
    let decision = CapabilityPolicyEngine::default().evaluate(
        &lease.request,
        &PolicyEvaluationContext {
            active_mediators,
            attachable_mediators: Vec::new(),
            locally_authorized_capabilities: Vec::new(),
            locally_leaseable_capabilities: Vec::new(),
            trusted_mediator_available: false,
            fresh_cell_available: true,
            live_fork_available: false,
            approval_staging_available: false,
            effect_brokerable: false,
            requires_staged_effects: true,
            effects_inseparable_from_runtime: false,
        },
    );
    if decision.decision != CapabilityPolicyDecision::Plan
        || decision.executor != Some(CapabilityExecutor::FreshCell)
        || !decision.lease_delta.mediators.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "capability policy denied cell execution: {}",
                decision.reason_codes.join(", ")
            ),
        ));
    }
    Ok(broker_leases)
}

fn validate_broker_scope_against_request(
    request: &CapabilityRequest,
    lease: &BrokerLease,
) -> io::Result<()> {
    let scope = &request.scope;
    let allowed_audiences = scope
        .network_hosts
        .iter()
        .cloned()
        .chain(
            scope
                .network_destinations
                .iter()
                .map(|network| network.destination.clone()),
        )
        .chain(scope.external_targets.iter().cloned())
        .chain(
            scope
                .external_applications
                .iter()
                .map(|application| application.target.clone()),
        )
        .chain(scope.cloud_iam.iter().flat_map(|cloud| {
            [Some(cloud.resource.clone()), cloud.assume_role.clone()]
                .into_iter()
                .flatten()
        }))
        .chain(
            scope
                .secret_identities
                .iter()
                .flat_map(|secret| [secret.handle.clone(), secret.identity.clone()]),
        )
        .chain(scope.databases.iter().flat_map(|database| {
            [
                database.service.clone(),
                format!("{}/{}", database.service, database.database),
            ]
        }))
        .collect::<BTreeSet<_>>();
    let matched = match lease.resource_kind {
        BrokerResourceKind::FilesystemHandle => {
            let path = lease
                .constraints
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let access = lease
                .constraints
                .get("access")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let read = effective_read_paths(request);
            let write = effective_write_paths(request);
            match access {
                "read" => path_is_in_scopes(path, &read),
                "write" => path_is_in_scopes(path, &write),
                "read_write" => path_is_in_scopes(path, &read) && path_is_in_scopes(path, &write),
                _ => false,
            }
        }
        BrokerResourceKind::NetworkLease => {
            let destination = lease.constraints.get("destination").and_then(Value::as_str);
            let protocol = lease.constraints.get("protocol").and_then(Value::as_str);
            let ports = lease.constraints.get("ports").and_then(Value::as_array);
            destination
                .zip(protocol)
                .zip(ports)
                .is_some_and(|((destination, protocol), ports)| {
                    scope.network_destinations.iter().any(|requested| {
                        requested.destination == destination
                            && requested.protocol == protocol
                            && ports.iter().all(|port| {
                                port.as_u64().is_some_and(|port| {
                                    u16::try_from(port)
                                        .ok()
                                        .is_some_and(|port| requested.ports.contains(&port))
                                })
                            })
                    })
                })
        }
        BrokerResourceKind::ExternalActionCommitToken => false,
        _ => allowed_audiences.contains(&lease.audience),
    };
    if !matched {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "broker lease audience or resource is outside the capability request: {}",
                lease.lease_id
            ),
        ));
    }
    Ok(())
}

fn cell_network_plan(
    cell_id: &str,
    broker_leases: &[BrokerLease],
) -> io::Result<Option<CellNetworkPlan>> {
    let mut endpoints = Vec::new();
    for lease in broker_leases
        .iter()
        .filter(|lease| lease.resource_kind == BrokerResourceKind::NetworkLease)
    {
        if !matches!(lease.delivery, BrokerDelivery::NetworkLease { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "network authority must be delivered as a built-in network lease",
            ));
        }
        let destination = lease
            .constraints
            .get("destination")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "network destination missing")
            })?;
        let protocol = match lease.constraints.get("protocol").and_then(Value::as_str) {
            Some("tcp") => gensee_crate_linux::LinuxNetworkProtocol::Tcp,
            Some("udp") => gensee_crate_linux::LinuxNetworkProtocol::Udp,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "network protocol must be tcp or udp",
                ));
            }
        };
        let ports = lease
            .constraints
            .get("ports")
            .and_then(Value::as_array)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "network ports missing"))?;
        for port in ports {
            let port = port
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid network port")
                })?;
            endpoints.push(gensee_crate_linux::LinuxNetworkEndpoint {
                destination: destination.to_string(),
                protocol,
                ports: vec![port],
            });
        }
    }
    if endpoints.is_empty() {
        return Ok(None);
    }
    endpoints.sort_by(|left, right| {
        (
            left.destination.as_str(),
            format!("{:?}", left.protocol),
            left.ports.as_slice(),
        )
            .cmp(&(
                right.destination.as_str(),
                format!("{:?}", right.protocol),
                right.ports.as_slice(),
            ))
    });
    endpoints.dedup();
    let config = gensee_crate_linux::LinuxNetworkEnforcementConfig::new(
        cell_id,
        gensee_crate_linux::LinuxNetworkPolicy {
            mode: gensee_crate_linux::LinuxNetworkMode::AllowListed,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_endpoints: endpoints,
        },
    );
    let enforcement = gensee_crate_linux::plan_nftables_policy(&config);
    gensee_crate_linux::validate_nftables_plan_for_apply(&enforcement.nftables)?;
    Ok(Some(CellNetworkPlan { enforcement }))
}

impl CellNetworkGuard {
    fn activate(plan: CellNetworkPlan) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = plan;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "direct network capability cells require Linux cgroup v2 and nftables",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let guard = Self {
                plan,
                table_applied: false,
                cleaned: false,
            };
            Ok(guard)
        }
    }

    fn attach(&mut self, podman: &OsString, container_name: &str) -> io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (podman, container_name);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "direct network capability cells require Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let source_address = inspect_capability_cell_ip(podman, container_name)?;
            gensee_crate_linux::bind_nftables_plan_to_source_address(
                &mut self.plan.enforcement.nftables,
                source_address,
            );
            gensee_crate_linux::apply_nftables_script(&self.plan.enforcement.nftables.script)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("cannot apply capability-cell nftables policy: {error}"),
                    )
                })?;
            self.table_applied = true;
            Ok(())
        }
    }

    fn collect_and_cleanup(&mut self) -> CellNetworkEvidence {
        let mut evidence = CellNetworkEvidence::default();
        if self.table_applied {
            match gensee_crate_linux::read_nftables_endpoint_events(&self.plan.enforcement.nftables)
            {
                Ok(events) => evidence.allowed = events,
                Err(error) => evidence.collection_error = Some(error.to_string()),
            }
            match gensee_crate_linux::read_nftables_block_events(&self.plan.enforcement.nftables) {
                Ok(events) => evidence.blocked = events,
                Err(error) if evidence.collection_error.is_none() => {
                    evidence.collection_error = Some(error.to_string());
                }
                Err(_) => {}
            }
        }
        if let Err(error) = self.cleanup() {
            evidence.collection_error = Some(match evidence.collection_error.take() {
                Some(existing) => format!("{existing}; cleanup failed: {error}"),
                None => format!("network cleanup failed: {error}"),
            });
        }
        evidence
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        if self.table_applied {
            gensee_crate_linux::delete_nftables_table_if_exists(
                &self.plan.enforcement.nftables.table_name,
            )?;
            self.table_applied = false;
        }
        self.cleaned = true;
        Ok(())
    }
}

fn wait_for_capability_cell_pid(
    podman: &OsString,
    container_name: &str,
    child: &mut std::process::Child,
) -> io::Result<u32> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match super::inspect_container_pid(podman, container_name) {
            Ok(pid) if pid != 0 => return Ok(pid),
            Ok(_) | Err(_) if Instant::now() < deadline => {
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "capability-cell runtime exited before gated startup with {status}"
                    )));
                }
                thread::sleep(Duration::from_millis(CELL_POLL_INTERVAL_MS));
            }
            Ok(_) | Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out locating gated capability-cell process",
                ));
            }
        }
    }
}

impl Drop for CellNetworkGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(target_os = "linux")]
fn inspect_capability_cell_ip(
    podman: &OsString,
    container_name: &str,
) -> io::Result<std::net::IpAddr> {
    let output = run_command_capture(
        podman,
        &[OsString::from("inspect"), OsString::from(container_name)],
    )?;
    let value: Value = serde_json::from_str(&output)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    value
        .as_array()
        .and_then(|containers| containers.first())
        .and_then(|container| container.get("NetworkSettings"))
        .and_then(|settings| settings.get("Networks"))
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|networks| networks.values())
        .filter_map(|network| network.get("IPAddress").and_then(Value::as_str))
        .find_map(|address| address.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "gated capability cell has no inspectable private-network address",
            )
        })
}

fn add_gateway_kind_mediator(
    active_mediators: &mut Vec<MediationBoundary>,
    lease: &BrokerLease,
) -> io::Result<()> {
    let gateway_kind = lease
        .constraints
        .get("gateway_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cell-bound API broker lease is missing gateway_kind",
            )
        })?;
    let mediator = match gateway_kind {
        "service_gateway" | "secret" => MediationBoundary::ExternalApiGateway,
        // Read compatibility for leases created before service gateways were
        // represented by one generic kind.
        "repository_api" | "external_api" => MediationBoundary::ExternalApiGateway,
        "cloud_api" => MediationBoundary::CloudApiGateway,
        "browser_automation" => MediationBoundary::BrowserAutomationGateway,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported cell gateway kind: {gateway_kind}"),
            ));
        }
    };
    active_mediators.push(mediator);
    Ok(())
}

fn effective_read_paths(request: &CapabilityRequest) -> Vec<String> {
    request
        .scope
        .read_paths
        .iter()
        .cloned()
        .chain(
            request
                .scope
                .file_operations
                .iter()
                .filter(|operation| {
                    matches!(
                        operation.operation,
                        gensee_crate_rules::capability::FileOperationKind::Read
                            | gensee_crate_rules::capability::FileOperationKind::Execute
                    )
                })
                .map(|operation| operation.path.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn effective_write_paths(request: &CapabilityRequest) -> Vec<String> {
    request
        .scope
        .write_paths
        .iter()
        .cloned()
        .chain(
            request
                .scope
                .file_operations
                .iter()
                .filter(|operation| {
                    matches!(
                        operation.operation,
                        gensee_crate_rules::capability::FileOperationKind::Create
                            | gensee_crate_rules::capability::FileOperationKind::Write
                            | gensee_crate_rules::capability::FileOperationKind::Rename
                            | gensee_crate_rules::capability::FileOperationKind::Delete
                            | gensee_crate_rules::capability::FileOperationKind::Metadata
                    )
                })
                .map(|operation| operation.path.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn validate_scope_paths(paths: &[String]) -> io::Result<()> {
    for value in paths {
        let path = Path::new(value);
        if value.is_empty()
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("capability path must be workspace-relative without traversal: {value}"),
            ));
        }
    }
    Ok(())
}

fn consume_capability_lease(
    lease_id: &str,
    source_run_id: &str,
    now_ms: u64,
) -> io::Result<CapabilityCellLease> {
    let path = capability_lease_path(lease_id)?;
    let _lock = TcloneStateLock::acquire(&path)?;
    let mut lease: CapabilityCellLease = serde_json::from_str(&read_nofollow_to_string(&path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lease.schema_version != CELL_LEASE_SCHEMA_VERSION
        || lease.lease_id != lease_id
        || lease.source_run_id != source_run_id
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability lease does not match this source",
        ));
    }
    if lease.consumed_at_ms.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability lease has already been consumed",
        ));
    }
    if now_ms < lease.issued_at_ms || now_ms >= lease.expires_at_ms {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "capability lease has expired",
        ));
    }
    validate_cell_request_for_execution(&lease, now_ms)?;
    lease.consumed_at_ms = Some(now_ms);
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    Ok(lease)
}

fn execute_capability_cell(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
) -> io::Result<CapabilityCellRecord> {
    let mut broker_cleanup = AttachedBrokerLeaseCleanup::new(&lease.broker_lease_ids);
    let broker_leases = validate_cell_request_for_execution(lease, unix_millis()?)?;
    let cell_id = lease.cell_id.clone();
    let container_name = format!("gensee-tclone-{cell_id}");
    let cell_root = capability_cell_path(&cell_id)?;
    let input_snapshot = cell_root.join("input");
    let snapshot = cell_root.join("output");
    let startup_gate = cell_root.join("startup-gate");
    create_restrictive_dir_all(&input_snapshot)?;
    create_restrictive_dir_all(&startup_gate)?;
    let _cleanup_journal_lock =
        TcloneStateLock::acquire(&capability_cell_cleanup_journal_path(&cell_id)?)?;
    let seccomp_profile = write_cell_seccomp_profile(&cell_root)?;
    let network_plan = cell_network_plan(&cell_id, &broker_leases)?;
    let mut cgroup_guard = CellCgroupGuard::activate(&cell_id)?;
    let mut cleanup_journal = CapabilityCellCleanupJournal {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        cell_id: cell_id.clone(),
        container_name: container_name.clone(),
        broker_lease_ids: lease.broker_lease_ids.clone(),
        expires_at_ms: lease.expires_at_ms,
        nftables_table: network_plan
            .as_ref()
            .map(|plan| plan.enforcement.nftables.table_name.clone()),
        cgroup_path: Some(cgroup_guard.path.to_string_lossy().to_string()),
        state: "active".to_string(),
        cleaned_at_ms: None,
        last_error: None,
    };
    persist_cell_cleanup_journal(&cleanup_journal)?;
    let mut network_guard = network_plan.map(CellNetworkGuard::activate).transpose()?;
    let podman = tclone_podman();
    let cell_supervisor = copy_cell_supervisor(&podman, source, &cell_root)?;
    let declared_creates = copy_capability_scope(&podman, source, lease, &input_snapshot)?;
    if let Some(expected) = lease.expected_input_snapshot_digest.as_deref() {
        let actual = digest_cell_snapshot(&input_snapshot)?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "replay input does not match the signed original snapshot: expected {expected}, observed {actual}"
                ),
            ));
        }
    }
    copy_path_all(&input_snapshot, &snapshot)?;
    materialize_declared_create_paths(&snapshot, &declared_creates)?;

    let mut run_args = capability_cell_run_args(
        source,
        lease,
        &container_name,
        &input_snapshot,
        &snapshot,
        &broker_leases,
        network_guard.as_ref().map(|guard| &guard.plan),
        &startup_gate,
        &cell_supervisor,
        &seccomp_profile,
        unix_millis()?,
    )?;
    run_args.extend(lease.command.iter().skip(1).map(OsString::from));
    let cleanup = TcloneContainerCleanup::new(&podman, &container_name);
    let started_at_ms = unix_millis()?;
    let mut child = Command::new(&podman).args(&run_args).spawn()?;
    let root_pid = wait_for_capability_cell_pid(&podman, &container_name, &mut child)?;
    let sensor_mounts = capability_cell_read_mounts(lease, &source.container_workspace);
    let runtime_sensor = CellRuntimeSensor::start(
        &cell_id,
        root_pid,
        &input_snapshot,
        &snapshot,
        &source.container_workspace,
        &sensor_mounts,
    );
    cgroup_guard.attach(root_pid)?;
    if let Some(guard) = network_guard.as_mut() {
        if let Err(error) = guard.attach(&podman, &container_name) {
            let _ = Command::new(&podman)
                .args(["kill", &container_name])
                .status();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    write_atomic_nofollow(&startup_gate.join("open"), b"open\n", 0o600)?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if unix_millis()? >= lease.expires_at_ms {
            timed_out = true;
            let _ = Command::new(&podman)
                .args(["kill", &container_name])
                .status();
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(CELL_POLL_INTERVAL_MS));
    };
    let runtime_evidence = runtime_sensor.finish();
    drop(cleanup);
    verify_capability_cell_terminated(&podman, &container_name)?;
    let cgroup_cleanup_error = cgroup_guard.cleanup().err();
    let network_evidence = network_guard
        .as_mut()
        .map(CellNetworkGuard::collect_and_cleanup);
    let finished_at_ms = unix_millis()?;
    let (broker_effect_leases, broker_revocation_error) = match broker_cleanup.revoke() {
        Ok(leases) => (leases, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let network_cleanup_complete = network_guard.as_ref().is_none_or(|guard| guard.cleaned);
    if network_cleanup_complete
        && broker_revocation_error.is_none()
        && cgroup_cleanup_error.is_none()
    {
        cleanup_journal.state = "cleaned".to_string();
        cleanup_journal.cleaned_at_ms = Some(finished_at_ms);
        cleanup_journal.last_error = None;
    } else {
        cleanup_journal.last_error = Some(
            broker_revocation_error
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| cgroup_cleanup_error.as_ref().map(ToString::to_string))
                .unwrap_or_else(|| "network cleanup incomplete".to_string()),
        );
    }
    persist_cell_cleanup_journal(&cleanup_journal)?;
    let mut manifest = build_effect_manifest(
        source,
        lease,
        &cell_id,
        &input_snapshot,
        &snapshot,
        started_at_ms,
        finished_at_ms,
        status.code(),
        timed_out,
        &broker_effect_leases,
        network_evidence.as_ref(),
        Some(&runtime_evidence),
    )?;
    if let Some(error) = broker_revocation_error {
        manifest.violations.push(EffectViolation {
            kind: "broker_lease_revocation_failed".to_string(),
            resource: lease.broker_lease_ids.join(","),
            detail: error.to_string(),
            observed_at_ms: finished_at_ms,
        });
    }
    if let Some(error) = cgroup_cleanup_error {
        manifest.violations.push(EffectViolation {
            kind: "cgroup_cleanup_failed".to_string(),
            resource: cgroup_guard.path.to_string_lossy().to_string(),
            detail: error.to_string(),
            observed_at_ms: finished_at_ms,
        });
    }
    let manifest_path = cell_root.join("effect-manifest.json");
    write_atomic_nofollow(
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest)?,
        0o600,
    )?;
    persist_capability_cell_forensics(
        source,
        lease,
        &cell_root,
        &input_snapshot,
        &snapshot,
        &manifest,
        &broker_leases,
        finished_at_ms,
    )?;
    let record = CapabilityCellRecord {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        operation_id: lease.operation_id.clone(),
        cell_id,
        lease_id: lease.lease_id.clone(),
        source_run_id: source.run_id.clone(),
        request: lease.request.clone(),
        policy_decision: lease.policy_decision.clone(),
        command: lease.command.clone(),
        broker_lease_ids: lease.broker_lease_ids.clone(),
        container_name,
        input_snapshot: input_snapshot.to_string_lossy().to_string(),
        workspace_snapshot: snapshot.to_string_lossy().to_string(),
        effect_manifest: manifest_path.to_string_lossy().to_string(),
        started_at_ms,
        finished_at_ms,
        exit_code: status.code(),
        timed_out,
    };
    write_atomic_nofollow(
        &cell_root.join("record.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
    )?;
    Ok(record)
}

fn verify_capability_cell_terminated(podman: &OsString, container_name: &str) -> io::Result<()> {
    let status = Command::new(podman)
        .args(["container", "exists", container_name])
        .status()?;
    match status.code() {
        Some(1) => Ok(()),
        Some(0) => Err(io::Error::other(
            "capability-cell container still exists after process-tree termination",
        )),
        _ => Err(io::Error::other(format!(
            "could not verify capability-cell process-tree termination: {status}"
        ))),
    }
}

struct AttachedBrokerLeaseCleanup {
    lease_ids: Vec<String>,
    armed: bool,
}

impl AttachedBrokerLeaseCleanup {
    fn new(lease_ids: &[String]) -> Self {
        Self {
            lease_ids: lease_ids.to_vec(),
            armed: !lease_ids.is_empty(),
        }
    }

    fn revoke(&mut self) -> io::Result<Vec<BrokerLease>> {
        if !self.armed {
            return Ok(Vec::new());
        }
        let result = super::capability_broker::revoke_attached_broker_leases(&self.lease_ids);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for AttachedBrokerLeaseCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = super::capability_broker::revoke_attached_broker_leases(&self.lease_ids);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn capability_cell_run_args(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    container_name: &str,
    input_snapshot: &Path,
    output_snapshot: &Path,
    broker_leases: &[BrokerLease],
    network_plan: Option<&CellNetworkPlan>,
    startup_gate: &Path,
    cell_supervisor: &Path,
    seccomp_profile: &Path,
    now_ms: u64,
) -> io::Result<Vec<OsString>> {
    let remaining_ms = lease.expires_at_ms.saturating_sub(now_ms);
    if remaining_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "capability lease expired while preparing the cell",
        ));
    }
    let remaining_seconds = remaining_ms.saturating_add(999) / 1_000;
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--name"),
        OsString::from(container_name),
        OsString::from("--timeout"),
        OsString::from(remaining_seconds.to_string()),
        OsString::from("--network"),
        OsString::from(if network_plan.is_some() {
            "bridge"
        } else {
            "none"
        }),
        OsString::from("--read-only"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--security-opt"),
        OsString::from("no-new-privileges"),
        OsString::from("--security-opt"),
        OsString::from(format!("seccomp={}", seccomp_profile.display())),
        OsString::from("--security-opt"),
        OsString::from(format!("apparmor={}", capability_cell_apparmor_profile()?)),
        OsString::from("--pids-limit"),
        OsString::from("256"),
        OsString::from("--cpus"),
        OsString::from("2"),
        OsString::from("--memory"),
        OsString::from("2g"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp:rw,noexec,nosuid,nodev,size=512m"),
        OsString::from("--tmpfs"),
        OsString::from("/run:rw,noexec,nosuid,nodev,size=64m"),
        OsString::from("--workdir"),
        OsString::from(&source.container_workspace),
        OsString::from("-e"),
        OsString::from("HOME=/tmp"),
        OsString::from("-e"),
        OsString::from(format!("GENSEE_CAPABILITY_LEASE_ID={}", lease.lease_id)),
    ];
    if !lease.broker_lease_ids.is_empty() {
        args.push(OsString::from("-e"));
        args.push(OsString::from(format!(
            "GENSEE_BROKER_LEASE_IDS={}",
            lease.broker_lease_ids.join(",")
        )));
        args.push(OsString::from("-e"));
        args.push(OsString::from(
            "GENSEE_BROKER_SOCKET_DIR=/run/gensee-broker",
        ));
    }
    args.push(OsString::from("--entrypoint"));
    args.push(OsString::from("/run/gensee-cell-supervisor"));
    for path in effective_read_paths(&lease.request) {
        add_scope_mount(
            &mut args,
            input_snapshot,
            &source.container_workspace,
            &path,
            "ro",
        )?;
    }
    for path in effective_write_paths(&lease.request) {
        add_scope_mount(
            &mut args,
            output_snapshot,
            &source.container_workspace,
            &path,
            "rw",
        )?;
    }
    for broker_lease in broker_leases {
        if let BrokerDelivery::Gateway {
            gateway_endpoint, ..
        } = &broker_lease.delivery
        {
            let host_socket = gateway_endpoint.strip_prefix("unix://").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "cell gateways must use Unix sockets",
                )
            })?;
            if host_socket.contains(',') || host_socket.contains('\n') || host_socket.contains('\r')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gateway socket path contains an unsafe mount character",
                ));
            }
            let target = format!("/run/gensee-broker/{}.sock", broker_lease.lease_id);
            args.push(OsString::from("--mount"));
            args.push(OsString::from(format!(
                "type=bind,source={host_socket},destination={target}"
            )));
        }
    }
    args.push(OsString::from("--mount"));
    args.push(OsString::from(format!(
        "type=bind,source={},destination=/run/gensee-startup-gate,ro",
        startup_gate.display()
    )));
    let supervisor_path = cell_supervisor.to_string_lossy();
    if supervisor_path.contains(',')
        || supervisor_path.contains('\n')
        || supervisor_path.contains('\r')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell supervisor path contains an unsafe mount character",
        ));
    }
    args.push(OsString::from("--mount"));
    args.push(OsString::from(format!(
        "type=bind,source={},destination=/run/gensee-cell-supervisor,ro",
        supervisor_path
    )));
    args.push(OsString::from(&source.image));
    args.push(OsString::from("__cell-landlock-exec"));
    args.push(OsString::from("--gate"));
    args.push(OsString::from("/run/gensee-startup-gate/open"));
    for path in effective_write_paths(&lease.request) {
        args.push(OsString::from("--write-path"));
        args.push(OsString::from(container_scope_path(
            &source.container_workspace,
            &path,
        )));
    }
    args.push(OsString::from("--"));
    args.push(OsString::from(&lease.command[0]));
    Ok(args)
}

fn copy_cell_supervisor(
    podman: &OsString,
    source: &TcloneRunRecord,
    cell_root: &Path,
) -> io::Result<PathBuf> {
    let destination = cell_root.join("gensee-cell-supervisor");
    run_command_status(
        podman,
        &[
            OsString::from("cp"),
            OsString::from(format!("{}:/usr/local/bin/gensee", source.container_name)),
            OsString::from(&destination),
        ],
    )?;
    let metadata = fs::symlink_metadata(&destination)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell supervisor must be a copied regular file",
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o500))?;
    Ok(destination)
}

fn container_scope_path(workspace: &str, relative: &str) -> String {
    if relative == "." {
        workspace.to_string()
    } else {
        format!("{}/{}", workspace.trim_end_matches('/'), relative)
    }
}

fn capability_cell_apparmor_profile() -> io::Result<String> {
    let profile = env::var("GENSEE_TCLONE_CELL_APPARMOR_PROFILE")
        .unwrap_or_else(|_| "gensee-capability-cell".to_string());
    if !tclone_is_safe_token(&profile) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid capability-cell AppArmor profile name",
        ));
    }
    Ok(profile)
}

fn write_cell_seccomp_profile(cell_root: &Path) -> io::Result<PathBuf> {
    let denied = gensee_crate_linux::LinuxSeccompProfile::default()
        .denied_names()
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let profile = json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{
            "names": denied,
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }]
    });
    let path = cell_root.join("seccomp.json");
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&profile)?, 0o600)?;
    Ok(path)
}

fn copy_capability_scope(
    podman: &OsString,
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    snapshot: &Path,
) -> io::Result<Vec<(String, FileEntryKind)>> {
    let write_paths = effective_write_paths(&lease.request)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let paths = effective_read_paths(&lease.request)
        .into_iter()
        .chain(write_paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut declared_creates = Vec::new();
    for relative in paths {
        let destination = snapshot.join(&relative);
        if relative == "." {
            run_command_status(
                podman,
                &[
                    OsString::from("cp"),
                    OsString::from(format!(
                        "{}:{}/.",
                        source.container_name, source.container_workspace
                    )),
                    OsString::from(snapshot),
                ],
            )?;
            continue;
        }
        if destination.exists() {
            continue;
        }
        if !capability_source_path_exists(podman, source, &relative)? {
            if write_paths.contains(&relative) {
                if let Some(kind) = declared_create_kind(&lease.request, &relative) {
                    declared_creates.push((relative, kind));
                    continue;
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "capability path does not exist in the source; declare an exact create operation to materialize it: {relative}"
                ),
            ));
        }
        if let Some(parent) = destination.parent() {
            create_restrictive_dir_all(parent)?;
        }
        run_command_status(
            podman,
            &[
                OsString::from("cp"),
                OsString::from(format!(
                    "{}:{}/{}",
                    source.container_name, source.container_workspace, relative
                )),
                OsString::from(&destination),
            ],
        )?;
    }
    Ok(declared_creates)
}

fn capability_source_path_exists(
    podman: &OsString,
    source: &TcloneRunRecord,
    relative: &str,
) -> io::Result<bool> {
    let target = Path::new(&source.container_workspace).join(relative);
    let status = Command::new(podman)
        .args([
            OsString::from("exec"),
            OsString::from(&source.container_name),
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("test -e \"$1\" || test -L \"$1\""),
            OsString::from("gensee-path-check"),
            target.into_os_string(),
        ])
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(io::Error::other(format!(
            "could not inspect capability path in source container: {relative}"
        ))),
    }
}

fn declared_create_kind(request: &CapabilityRequest, relative: &str) -> Option<FileEntryKind> {
    request
        .scope
        .file_operations
        .iter()
        .find(|scope| scope.path == relative && scope.operation == FileOperationKind::Create)
        .map(|scope| scope.entry_kind.unwrap_or(FileEntryKind::File))
}

fn materialize_declared_create_paths(
    snapshot: &Path,
    creates: &[(String, FileEntryKind)],
) -> io::Result<()> {
    for (relative, _) in creates
        .iter()
        .filter(|(_, kind)| *kind == FileEntryKind::Directory)
    {
        create_restrictive_dir_all(&snapshot.join(relative))?;
    }
    for (relative, kind) in creates {
        let destination = snapshot.join(relative);
        match kind {
            FileEntryKind::File => {
                if let Some(parent) = destination.parent() {
                    create_restrictive_dir_all(parent)?;
                }
                write_atomic_nofollow(&destination, b"", 0o600)?;
            }
            FileEntryKind::Directory => {}
            FileEntryKind::Symlink => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "declared symlink creation is not a safe capability mount target: {relative}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn add_scope_mount(
    args: &mut Vec<OsString>,
    snapshot: &Path,
    container_workspace: &str,
    relative: &str,
    mode: &str,
) -> io::Result<()> {
    let host_path = snapshot.join(relative);
    let canonical = fs::canonicalize(&host_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("capability path does not exist in source snapshot: {relative}"),
        )
    })?;
    let canonical_snapshot = fs::canonicalize(snapshot)?;
    if !canonical.starts_with(&canonical_snapshot) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("capability path resolves outside source snapshot: {relative}"),
        ));
    }
    let target = Path::new(container_workspace).join(relative);
    args.push(OsString::from("-v"));
    args.push(OsString::from(format!(
        "{}:{}:{mode},Z",
        canonical.display(),
        target.display()
    )));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CellSnapshotEntry {
    kind: FileEntryKind,
    digest: Option<String>,
    size: Option<u64>,
    mode: Option<u32>,
}

#[allow(clippy::too_many_arguments)]
fn build_effect_manifest(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    cell_id: &str,
    input_snapshot: &Path,
    output_snapshot: &Path,
    started_at_ms: u64,
    finished_at_ms: u64,
    exit_code: Option<i32>,
    timed_out: bool,
    broker_leases: &[BrokerLease],
    network_evidence: Option<&CellNetworkEvidence>,
    runtime_evidence: Option<&CellRuntimeEvidence>,
) -> io::Result<EffectManifest> {
    let before = collect_cell_snapshot(input_snapshot)?;
    let after = collect_cell_snapshot(output_snapshot)?;
    let files_changed = diff_cell_snapshots(&before, &after);
    let mut outputs = Vec::new();
    let mut violations = Vec::new();
    for effect in &files_changed {
        if effect.change != FileChangeKind::Deleted && effect.entry_kind == FileEntryKind::Symlink {
            let target = fs::read_link(output_snapshot.join(&effect.path))?;
            if target.is_absolute()
                || target.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                violations.push(EffectViolation {
                    kind: "unsafe_symlink_output".to_string(),
                    resource: effect.path.clone(),
                    detail: format!(
                        "symlink output has an absolute or parent-traversing target: {}",
                        target.display()
                    ),
                    observed_at_ms: finished_at_ms,
                });
            }
        }
        if path_is_in_scopes(&effect.path, &effective_write_paths(&lease.request)) {
            outputs.push(PromotionOutput {
                path: effect.path.clone(),
                change: effect.change,
                entry_kind: effect.entry_kind,
                digest: effect.after_digest.clone(),
            });
        } else {
            violations.push(EffectViolation {
                kind: "filesystem_write_outside_scope".to_string(),
                resource: effect.path.clone(),
                detail: "observed output differs from the immutable input but is not covered by a write selector".to_string(),
                observed_at_ms: finished_at_ms,
            });
        }
    }
    let mut capabilities_used = vec![Capability::ProcessExecution];
    if !files_changed.is_empty() {
        capabilities_used.push(Capability::FilesystemWrite);
    }
    let mut network_connections = Vec::new();
    let mut external_requests = Vec::new();
    let mut secrets_accessed = Vec::new();
    let mut broker_telemetry_required = false;
    let mut broker_telemetry_complete = true;
    for broker_lease in broker_leases {
        if matches!(broker_lease.delivery, BrokerDelivery::Gateway { .. }) {
            broker_telemetry_required = true;
            broker_telemetry_complete &= broker_lease.effect_telemetry_complete;
        }
        for effect in &broker_lease.gateway_effects {
            match effect.kind {
                BrokerGatewayEffectKind::NetworkConnection
                | BrokerGatewayEffectKind::MtlsConnection => {
                    network_connections.push(
                        gensee_crate_rules::capability::NetworkConnectionEffect {
                            protocol: effect
                                .protocol
                                .clone()
                                .unwrap_or_else(|| "brokered".to_string()),
                            destination: effect.target.clone(),
                            port: effect.port,
                            broker_lease_id: broker_lease.lease_id.clone(),
                        },
                    );
                }
                BrokerGatewayEffectKind::SecretAccess
                | BrokerGatewayEffectKind::IdentityExchange => {
                    let handle_id = effect
                        .broker_handle_id
                        .clone()
                        .or_else(|| match &broker_lease.delivery {
                            BrokerDelivery::Gateway {
                                provider_handle, ..
                            } => Some(provider_handle.clone()),
                            _ => None,
                        })
                        .unwrap_or_else(|| broker_lease.lease_id.clone());
                    secrets_accessed.push(gensee_crate_rules::capability::SecretAccessEffect {
                        broker: broker_lease.adapter_id.clone(),
                        handle_id,
                        identity: broker_lease.audience.clone(),
                        purpose: effect.action.clone(),
                    });
                }
                BrokerGatewayEffectKind::ServiceRequest
                | BrokerGatewayEffectKind::LegacyServiceRequestV1A
                | BrokerGatewayEffectKind::LegacyServiceRequestV1B
                | BrokerGatewayEffectKind::DatabaseRequest
                | BrokerGatewayEffectKind::BrowserAction
                | BrokerGatewayEffectKind::CloudAction => {
                    external_requests.push(gensee_crate_rules::capability::ExternalRequestEffect {
                        gateway: broker_lease.adapter_id.clone(),
                        target: effect.target.clone(),
                        action: effect.action.clone(),
                        request_digest: effect.request_digest.clone(),
                        response_status: effect.response_status,
                        commit_token_id: None,
                    });
                }
            }
        }
    }
    if let Some(evidence) = network_evidence {
        for event in &evidence.allowed {
            let protocol = match event.protocol {
                gensee_crate_linux::LinuxNetworkProtocol::Tcp => "tcp",
                gensee_crate_linux::LinuxNetworkProtocol::Udp => "udp",
            };
            let port = event.ports.first().copied();
            let broker_lease_id = broker_leases
                .iter()
                .find(|broker_lease| {
                    broker_lease.resource_kind == BrokerResourceKind::NetworkLease
                        && broker_lease
                            .constraints
                            .get("destination")
                            .and_then(Value::as_str)
                            == Some(event.destination.as_str())
                        && broker_lease
                            .constraints
                            .get("protocol")
                            .and_then(Value::as_str)
                            == Some(protocol)
                        && port.is_some_and(|port| {
                            broker_lease
                                .constraints
                                .get("ports")
                                .and_then(Value::as_array)
                                .is_some_and(|ports| {
                                    ports
                                        .iter()
                                        .any(|allowed| allowed.as_u64() == Some(port.into()))
                                })
                        })
                })
                .map(|broker_lease| broker_lease.lease_id.clone())
                .unwrap_or_else(|| "unmatched_network_lease".to_string());
            network_connections.push(gensee_crate_rules::capability::NetworkConnectionEffect {
                protocol: protocol.to_string(),
                destination: event.destination.clone(),
                port,
                broker_lease_id,
            });
        }
        for event in &evidence.blocked {
            violations.push(EffectViolation {
                kind: "network_policy_block".to_string(),
                resource: event
                    .destination
                    .clone()
                    .unwrap_or_else(|| "unlisted_destination".to_string()),
                detail: format!(
                    "nftables blocked {} packets ({} bytes): {:?}",
                    event.packets, event.bytes, event.reason
                ),
                observed_at_ms: finished_at_ms,
            });
        }
        if let Some(error) = &evidence.collection_error {
            violations.push(EffectViolation {
                kind: "network_effect_telemetry_incomplete".to_string(),
                resource: cell_id.to_string(),
                detail: error.clone(),
                observed_at_ms: finished_at_ms,
            });
        }
    }
    if broker_telemetry_required && !broker_telemetry_complete {
        violations.push(EffectViolation {
            kind: "broker_effect_telemetry_incomplete".to_string(),
            resource: broker_leases
                .iter()
                .map(|lease| lease.lease_id.as_str())
                .collect::<Vec<_>>()
                .join(","),
            detail: "one or more mediated gateways did not attest complete effect coverage at revocation".to_string(),
            observed_at_ms: finished_at_ms,
        });
    }
    if let Some(error) =
        runtime_evidence.and_then(|evidence| evidence.filesystem_collection_error.as_ref())
    {
        violations.push(EffectViolation {
            kind: "filesystem_read_telemetry_incomplete".to_string(),
            resource: cell_id.to_string(),
            detail: error.clone(),
            observed_at_ms: finished_at_ms,
        });
    }
    if let Some(error) =
        runtime_evidence.and_then(|evidence| evidence.process_collection_error.as_ref())
    {
        violations.push(EffectViolation {
            kind: "process_lifecycle_telemetry_incomplete".to_string(),
            resource: cell_id.to_string(),
            detail: error.clone(),
            observed_at_ms: finished_at_ms,
        });
    }
    if !network_connections.is_empty()
        && lease
            .request
            .capabilities
            .contains(&Capability::NetworkEgress)
    {
        capabilities_used.push(Capability::NetworkEgress);
    }
    if !secrets_accessed.is_empty() {
        for capability in [
            Capability::SecretUse,
            Capability::IdentityUse,
            Capability::WorkloadIdentity,
        ] {
            if lease.request.capabilities.contains(&capability)
                && !capabilities_used.contains(&capability)
            {
                capabilities_used.push(capability);
            }
        }
    }
    if !external_requests.is_empty() {
        for capability in [
            Capability::ExternalApplication,
            Capability::CloudIam,
            Capability::DatabaseAccess,
        ] {
            if lease.request.capabilities.contains(&capability)
                && !capabilities_used.contains(&capability)
            {
                capabilities_used.push(capability);
            }
        }
    }
    let argv = serde_json::to_vec(&lease.command)?;
    let argv_digest = format!("sha256:{:x}", Sha256::digest(argv));
    let files_read = runtime_evidence
        .map(|evidence| evidence.files_read.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if !files_read.is_empty() && !capabilities_used.contains(&Capability::FilesystemRead) {
        capabilities_used.push(Capability::FilesystemRead);
    }
    let mut processes_started = runtime_evidence
        .map(|evidence| evidence.processes_started.clone())
        .unwrap_or_default();
    if !processes_started
        .iter()
        .any(|process| process.executable == lease.command[0] && process.argv_digest == argv_digest)
    {
        processes_started.insert(
            0,
            ProcessEffect {
                executable: lease.command[0].clone(),
                argv_digest,
                pid: None,
                parent_pid: None,
                start_time_ticks: None,
                started_at_ms,
                finished_at_ms: Some(finished_at_ms),
                exit_code,
            },
        );
    }
    if runtime_evidence.is_some_and(|evidence| !evidence.processes_started.is_empty()) {
        for capability in [
            Capability::ProcessExecution,
            Capability::PrivilegedExecution,
            Capability::UntrustedCodeExecution,
        ] {
            if lease.request.capabilities.contains(&capability)
                && !capabilities_used.contains(&capability)
            {
                capabilities_used.push(capability);
            }
        }
    }
    let filesystem_read_coverage_status = match runtime_evidence {
        Some(evidence)
            if evidence.filesystem_collection_error.is_none()
                && !evidence.expected_read_mounts.is_empty()
                && evidence.covered_read_mounts.len() == evidence.expected_read_mounts.len() =>
        {
            TelemetryCoverage::Complete
        }
        Some(evidence) if !evidence.covered_read_mounts.is_empty() => TelemetryCoverage::Partial,
        None => TelemetryCoverage::Unavailable,
        Some(_) => TelemetryCoverage::Unavailable,
    };
    let process_coverage = match runtime_evidence {
        Some(evidence) if evidence.process_telemetry_complete => TelemetryCoverage::Complete,
        Some(evidence) if !evidence.processes_started.is_empty() => TelemetryCoverage::Partial,
        None => TelemetryCoverage::Unavailable,
        Some(_) => TelemetryCoverage::Unavailable,
    };
    let filesystem_read_coverage = runtime_evidence.map(|evidence| {
        let covered = evidence
            .covered_read_mounts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        FilesystemReadCoverage {
            covered_mounts: covered.iter().cloned().collect(),
            uncovered_mounts: evidence
                .expected_read_mounts
                .iter()
                .filter(|mount| !covered.contains(*mount))
                .cloned()
                .collect(),
        }
    });

    let network_coverage = match network_evidence {
        Some(evidence) if evidence.collection_error.is_none() => TelemetryCoverage::Complete,
        Some(_) => TelemetryCoverage::Partial,
        None => broker_coverage_for_capabilities(
            &lease.request,
            &[Capability::NetworkEgress, Capability::NetworkListen],
            broker_telemetry_required,
            broker_telemetry_complete,
        ),
    };

    Ok(EffectManifest {
        schema_version: EFFECT_MANIFEST_SCHEMA_VERSION,
        operation_id: lease.operation_id.clone(),
        source_run_id: source.run_id.clone(),
        cell_id: cell_id.to_string(),
        requested_capabilities: lease.request.capabilities.clone(),
        capabilities_used,
        files_read,
        files_changed,
        network_connections,
        external_requests,
        secrets_accessed,
        processes_started,
        outputs_proposed_for_promotion: outputs,
        promotions: Vec::new(),
        violations,
        telemetry_coverage: EffectTelemetryCoverage {
            filesystem_reads: filesystem_read_coverage_status,
            filesystem_writes: TelemetryCoverage::Complete,
            network_connections: network_coverage,
            external_requests: broker_coverage_for_capabilities(
                &lease.request,
                &[
                    Capability::ExternalApplication,
                    Capability::CloudIam,
                    Capability::DatabaseAccess,
                ],
                broker_telemetry_required,
                broker_telemetry_complete,
            ),
            secret_accesses: broker_coverage_for_capabilities(
                &lease.request,
                &[
                    Capability::SecretUse,
                    Capability::IdentityUse,
                    Capability::WorkloadIdentity,
                ],
                broker_telemetry_required,
                broker_telemetry_complete,
            ),
            process_tree: process_coverage,
        },
        filesystem_read_coverage,
        started_at_ms,
        finished_at_ms,
        exit_code,
        timed_out,
    })
}

fn capability_cell_read_mounts(
    lease: &CapabilityCellLease,
    container_workspace: &str,
) -> Vec<String> {
    let mut mounts = vec![
        "/".to_string(),
        "/tmp".to_string(),
        "/run".to_string(),
        "/run/gensee-startup-gate".to_string(),
        "/run/gensee-cell-supervisor".to_string(),
    ];
    mounts.extend(
        lease
            .broker_lease_ids
            .iter()
            .map(|lease_id| format!("/run/gensee-broker/{lease_id}.sock")),
    );
    mounts.extend(
        effective_read_paths(&lease.request)
            .into_iter()
            .chain(effective_write_paths(&lease.request))
            .map(|path| container_scope_path(container_workspace, &path)),
    );
    mounts.sort();
    mounts.dedup();
    mounts
}

fn broker_coverage_for_capabilities(
    request: &CapabilityRequest,
    capabilities: &[Capability],
    telemetry_required: bool,
    telemetry_complete: bool,
) -> TelemetryCoverage {
    if !request
        .capabilities
        .iter()
        .any(|capability| capabilities.contains(capability))
    {
        TelemetryCoverage::NotApplicable
    } else if telemetry_required && telemetry_complete {
        TelemetryCoverage::Complete
    } else if telemetry_required {
        TelemetryCoverage::Partial
    } else {
        TelemetryCoverage::Unavailable
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_capability_cell_forensics(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    cell_root: &Path,
    input_snapshot: &Path,
    output_snapshot: &Path,
    manifest: &EffectManifest,
    broker_leases: &[BrokerLease],
    created_at_ms: u64,
) -> io::Result<()> {
    let input_snapshot_digest = digest_cell_snapshot(input_snapshot)?;
    let output_snapshot_digest = digest_cell_snapshot(output_snapshot)?;
    let manifest_digest = effect_manifest_evidence_digest(manifest)?;
    let mut required_broker_resources = Vec::new();
    for lease in broker_leases {
        if !required_broker_resources.contains(&lease.resource_kind) {
            required_broker_resources.push(lease.resource_kind);
        }
    }
    let replay_plan = CapabilityCellReplayPlan {
        schema_version: CELL_FORENSICS_SCHEMA_VERSION,
        original_cell_id: lease.cell_id.clone(),
        original_operation_id: lease.operation_id.clone(),
        original_source_run_id: source.run_id.clone(),
        request: lease.request.clone(),
        command: lease.command.clone(),
        input_snapshot_digest: input_snapshot_digest.clone(),
        manifest_digest: manifest_digest.clone(),
        required_broker_resources,
        created_at_ms,
    };
    let replay_path = cell_root.join("replay-plan.json");
    write_atomic_nofollow(
        &replay_path,
        &serde_json::to_vec_pretty(&replay_plan)?,
        0o600,
    )?;
    let claims = CapabilityCellForensicsClaims {
        schema_version: CELL_FORENSICS_SCHEMA_VERSION,
        operation_id: lease.operation_id.clone(),
        cell_id: lease.cell_id.clone(),
        lease_id: lease.lease_id.clone(),
        source_run_id: source.run_id.clone(),
        request_digest: digest_serialized(&lease.request)?,
        policy_decision_digest: digest_serialized(&lease.policy_decision)?,
        command_digest: digest_serialized(&lease.command)?,
        input_snapshot_digest,
        output_snapshot_digest,
        manifest_digest,
        replay_plan_digest: digest_serialized(&replay_plan)?,
        created_at_ms,
    };
    let signature = super::capability_broker::sign_host_evidence(
        CELL_FORENSICS_SIGNATURE_DOMAIN,
        &serde_json::to_vec(&claims)?,
    )?;
    let evidence = CapabilityCellForensicsEvidence { claims, signature };
    write_atomic_nofollow(
        &cell_root.join("forensics-evidence.json"),
        &serde_json::to_vec_pretty(&evidence)?,
        0o600,
    )?;
    write_atomic_nofollow(
        &cell_root.join("promotion-ledger.json"),
        &serde_json::to_vec_pretty(&Vec::<SignedPromotionReceipt>::new())?,
        0o600,
    )
}

fn verify_capability_cell_forensics(
    record: &CapabilityCellRecord,
    manifest: &EffectManifest,
    cell_root: &Path,
) -> io::Result<(CapabilityCellForensicsEvidence, CapabilityCellReplayPlan)> {
    let evidence: CapabilityCellForensicsEvidence = serde_json::from_str(&read_nofollow_to_string(
        &cell_root.join("forensics-evidence.json"),
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let replay_plan: CapabilityCellReplayPlan = serde_json::from_str(&read_nofollow_to_string(
        &cell_root.join("replay-plan.json"),
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    super::capability_broker::verify_host_evidence(
        CELL_FORENSICS_SIGNATURE_DOMAIN,
        &serde_json::to_vec(&evidence.claims)?,
        &evidence.signature,
    )?;
    let claims = &evidence.claims;
    if record.schema_version != CELL_LEASE_SCHEMA_VERSION
        || manifest.schema_version != EFFECT_MANIFEST_SCHEMA_VERSION
        || claims.schema_version != CELL_FORENSICS_SCHEMA_VERSION
        || replay_plan.schema_version != CELL_FORENSICS_SCHEMA_VERSION
        || claims.operation_id != record.operation_id
        || claims.cell_id != record.cell_id
        || claims.lease_id != record.lease_id
        || claims.source_run_id != record.source_run_id
        || replay_plan.original_cell_id != record.cell_id
        || replay_plan.original_operation_id != record.operation_id
        || replay_plan.original_source_run_id != record.source_run_id
        || replay_plan.request != record.request
        || replay_plan.command != record.command
        || claims.request_digest != digest_serialized(&record.request)?
        || claims.policy_decision_digest != digest_serialized(&record.policy_decision)?
        || claims.command_digest != digest_serialized(&record.command)?
        || claims.input_snapshot_digest != digest_cell_snapshot(&cell_root.join("input"))?
        || claims.output_snapshot_digest != digest_cell_snapshot(&cell_root.join("output"))?
        || claims.manifest_digest != effect_manifest_evidence_digest(manifest)?
        || claims.replay_plan_digest != digest_serialized(&replay_plan)?
        || replay_plan.input_snapshot_digest != claims.input_snapshot_digest
        || replay_plan.manifest_digest != claims.manifest_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability-cell forensic evidence does not match its signed record, snapshots, manifest, or replay plan",
        ));
    }
    Ok((evidence, replay_plan))
}

fn diff_cell_snapshots(
    before: &BTreeMap<String, CellSnapshotEntry>,
    after: &BTreeMap<String, CellSnapshotEntry>,
) -> Vec<FileChangeEffect> {
    let paths = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    paths
        .into_iter()
        .filter_map(|path| {
            let before_entry = before.get(&path);
            let after_entry = after.get(&path);
            if before_entry == after_entry {
                return None;
            }
            let change = match (before_entry, after_entry) {
                (None, Some(_)) => FileChangeKind::Created,
                (Some(_), None) => FileChangeKind::Deleted,
                (Some(_), Some(_)) => FileChangeKind::Modified,
                (None, None) => return None,
            };
            let entry_kind = after_entry
                .or(before_entry)
                .expect("changed entry exists")
                .kind;
            Some(FileChangeEffect {
                path,
                change,
                entry_kind,
                before_digest: before_entry.and_then(|entry| entry.digest.clone()),
                after_digest: after_entry.and_then(|entry| entry.digest.clone()),
                before_size: before_entry.and_then(|entry| entry.size),
                after_size: after_entry.and_then(|entry| entry.size),
                before_mode: before_entry.and_then(|entry| entry.mode),
                after_mode: after_entry.and_then(|entry| entry.mode),
            })
        })
        .collect()
}

fn collect_cell_snapshot(root: &Path) -> io::Result<BTreeMap<String, CellSnapshotEntry>> {
    let mut entries = BTreeMap::new();
    collect_cell_snapshot_inner(root, root, &mut entries)?;
    Ok(entries)
}

fn collect_cell_snapshot_inner(
    root: &Path,
    current: &Path,
    entries: &mut BTreeMap<String, CellSnapshotEntry>,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let relative = relative.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cell snapshots require UTF-8 workspace paths",
            )
        })?;
        let metadata = fs::symlink_metadata(&path)?;
        let state = if metadata.is_dir() {
            CellSnapshotEntry {
                kind: FileEntryKind::Directory,
                digest: None,
                size: None,
                mode: cell_metadata_mode(&metadata),
            }
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            CellSnapshotEntry {
                kind: FileEntryKind::Symlink,
                digest: Some(format!(
                    "sha256:{:x}",
                    Sha256::digest(target.to_string_lossy().as_bytes())
                )),
                size: None,
                mode: None,
            }
        } else if metadata.is_file() {
            CellSnapshotEntry {
                kind: FileEntryKind::File,
                digest: Some(digest_cell_file(&path)?),
                size: Some(metadata.len()),
                mode: cell_metadata_mode(&metadata),
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("special filesystem entry is not allowed in a cell output: {relative}"),
            ));
        };
        entries.insert(relative.to_string(), state);
        if metadata.is_dir() {
            collect_cell_snapshot_inner(root, &path, entries)?;
        }
    }
    Ok(())
}

fn digest_cell_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn digest_serialized<T: serde::Serialize>(value: &T) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value)?)
    ))
}

fn digest_cell_snapshot(root: &Path) -> io::Result<String> {
    digest_serialized(&collect_cell_snapshot(root)?)
}

fn effect_manifest_evidence_digest(manifest: &EffectManifest) -> io::Result<String> {
    let mut immutable = manifest.clone();
    immutable.promotions.clear();
    digest_serialized(&immutable)
}

fn path_is_in_scopes(path: &str, scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|scope| scope == "." || path == scope || path.starts_with(&format!("{scope}/")))
}

fn replay_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    if env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some()
        || env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).is_some()
        || env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell replay is host-only and cannot be requested through the agent bridge",
        ));
    }
    let usage = "usage: gensee run cell replay <cell-id> --source <running-source-id> [--ttl-seconds N] [--json]";
    let original_cell_id = tclone_target_arg(&args, usage)?;
    let source_run_id = arg_value(&args, "--source")
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell replay requires a running tclone source",
        ));
    }
    let original_root = capability_cell_path(&original_cell_id)?;
    let original_record: CapabilityCellRecord = serde_json::from_str(&read_nofollow_to_string(
        &original_root.join("record.json"),
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let original_manifest: EffectManifest = serde_json::from_str(&read_nofollow_to_string(
        &original_root.join("effect-manifest.json"),
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (_, replay_plan) =
        verify_capability_cell_forensics(&original_record, &original_manifest, &original_root)?;
    let mut policy_decision = validate_cell_request_for_issue(&replay_plan.request)?;
    let ttl_seconds = arg_value(&args, "--ttl-seconds")
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid --ttl-seconds value")
            })
        })
        .transpose()?
        .unwrap_or(replay_plan.request.lease_ttl_seconds)
        .min(replay_plan.request.lease_ttl_seconds)
        .min(CELL_LEASE_MAX_TTL_SECONDS);
    if ttl_seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "replay lease TTL must be positive",
        ));
    }
    policy_decision.lease_delta.ttl_seconds = ttl_seconds;
    let issued_at_ms = unix_millis()?;
    let lease_id = format!("lease_{}", Uuid::new_v4().simple());
    let cell_id = format!("cell_{}", Uuid::new_v4().simple());
    let lease = CapabilityCellLease {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        lease_id: lease_id.clone(),
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        cell_id: cell_id.clone(),
        source_run_id: source.run_id.clone(),
        request: replay_plan.request.clone(),
        policy_decision,
        command: replay_plan.command.clone(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        consumed_at_ms: None,
        broker_lease_ids: Vec::new(),
        replay_of_cell_id: Some(original_cell_id.clone()),
        expected_input_snapshot_digest: Some(replay_plan.input_snapshot_digest.clone()),
    };
    let path = capability_lease_path(&lease_id)?;
    if let Some(parent) = path.parent() {
        create_restrictive_dir_all(parent)?;
    }
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    write_atomic_nofollow(
        &capability_cell_binding_path(&cell_id)?,
        format!("{lease_id}\n").as_bytes(),
        0o600,
    )?;
    let result = json!({
        "lease_id": lease_id,
        "operation_id": lease.operation_id,
        "cell_id": cell_id,
        "source_run_id": source.run_id,
        "replay_of_cell_id": original_cell_id,
        "expected_input_snapshot_digest": replay_plan.input_snapshot_digest,
        "required_broker_resources": replay_plan.required_broker_resources,
        "expires_at_ms": lease.expires_at_ms,
    });
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "issued replay lease {} for cell {}",
            lease.lease_id, lease.cell_id
        );
        println!("the source snapshot must match the signed original input exactly");
        if !replay_plan.required_broker_resources.is_empty() {
            println!(
                "attach fresh broker leases for: {:?}",
                replay_plan.required_broker_resources
            );
        }
        println!(
            "execute with: gensee run cell {} --lease {}",
            lease.source_run_id, lease.lease_id
        );
    }
    Ok(())
}

fn load_verified_promotion_ledger(
    cell_root: &Path,
    cell_id: &str,
) -> io::Result<Vec<SignedPromotionReceipt>> {
    let ledger: Vec<SignedPromotionReceipt> = serde_json::from_str(&read_nofollow_to_string(
        &cell_root.join("promotion-ledger.json"),
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    for signed in &ledger {
        if signed.claims.schema_version != CELL_FORENSICS_SCHEMA_VERSION
            || signed.claims.cell_id != cell_id
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "promotion ledger contains a receipt for another cell or schema",
            ));
        }
        super::capability_broker::verify_host_evidence(
            CELL_PROMOTION_SIGNATURE_DOMAIN,
            &serde_json::to_vec(&signed.claims)?,
            &signed.signature,
        )?;
    }
    Ok(ledger)
}

fn append_signed_promotion_receipt(
    cell_root: &Path,
    cell_id: &str,
    receipt: PromotionReceipt,
) -> io::Result<()> {
    let mut ledger = load_verified_promotion_ledger(cell_root, cell_id)?;
    let claims = CapabilityCellPromotionClaims {
        schema_version: CELL_FORENSICS_SCHEMA_VERSION,
        cell_id: cell_id.to_string(),
        receipt,
    };
    let signature = super::capability_broker::sign_host_evidence(
        CELL_PROMOTION_SIGNATURE_DOMAIN,
        &serde_json::to_vec(&claims)?,
    )?;
    ledger.push(SignedPromotionReceipt { claims, signature });
    write_atomic_nofollow(
        &cell_root.join("promotion-ledger.json"),
        &serde_json::to_vec_pretty(&ledger)?,
        0o600,
    )
}

fn promote_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    if env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some()
        || env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).is_some()
        || env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell promotion is host-only and cannot be requested through the agent bridge",
        ));
    }
    let usage = "usage: gensee run cell promote <cell-id> --into <source-run-id> --path <workspace-relative-path> [--path <path>...] [--dry-run] [--json]";
    let cell_id = tclone_target_arg(&args, usage)?;
    let source_run_id = arg_value(&args, "--into")
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, usage))?;
    let selectors = repeated_arg_values(&args, "--path")?;
    if selectors.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "promotion requires at least one explicit --path selector",
        ));
    }
    validate_scope_paths(&selectors)?;

    let cell_root = capability_cell_path(&cell_id)?;
    let record: CapabilityCellRecord =
        serde_json::from_str(&read_nofollow_to_string(&cell_root.join("record.json"))?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let manifest_path = cell_root.join("effect-manifest.json");
    let mut manifest: EffectManifest =
        serde_json::from_str(&read_nofollow_to_string(&manifest_path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_promotion_evidence(&record, &manifest, &cell_id, &source_run_id, &cell_root)?;
    let promotion_ledger = load_verified_promotion_ledger(&cell_root, &cell_id)?;

    let mut selected = manifest
        .outputs_proposed_for_promotion
        .iter()
        .filter(|output| path_is_in_scopes(&output.path, &selectors))
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.path.cmp(&right.path));
    selected.dedup_by(|left, right| left.path == right.path);
    for selector in &selectors {
        if !selected
            .iter()
            .any(|output| path_is_in_scopes(&output.path, std::slice::from_ref(selector)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("promotion selector has no proposed output: {selector}"),
            ));
        }
    }
    if promotion_ledger.iter().any(|signed| {
        signed.claims.receipt.paths.iter().any(|promoted| {
            selected.iter().any(|output| {
                promoted == &output.path
                    || promoted.starts_with(&format!("{}/", output.path))
                    || output.path.starts_with(&format!("{promoted}/"))
            })
        })
    }) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "one or more selected outputs have already been promoted",
        ));
    }

    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell outputs can be promoted only into their running source",
        ));
    }
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &source)?;
    let plan = build_cell_promotion_plan(&podman, &source, &cell_root, &selected)?;
    if !plan.conflicts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "source changed since the cell snapshot; refusing promotion for: {}",
                plan.conflicts.join(", ")
            ),
        ));
    }

    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let promotion_id = format!("promotion_{}", Uuid::new_v4().simple());
    if !dry_run {
        apply_tclone_overlay_merge(&podman, &source, &plan)?;
        let receipt = PromotionReceipt {
            promotion_id: promotion_id.clone(),
            source_run_id: source.run_id.clone(),
            paths: selected.iter().map(|output| output.path.clone()).collect(),
            promoted_at_ms: unix_millis()?,
            approval_token_id: None,
        };
        append_signed_promotion_receipt(&cell_root, &cell_id, receipt.clone())?;
        manifest.promotions.push(receipt);
        write_atomic_nofollow(
            &manifest_path,
            &serde_json::to_vec_pretty(&manifest)?,
            0o600,
        )?;
    }

    let result = json!({
        "promotion_id": promotion_id,
        "cell_id": cell_id,
        "source_run_id": source_run_id,
        "dry_run": dry_run,
        "paths": selected.iter().map(|output| &output.path).collect::<Vec<_>>(),
        "conflicts": plan.conflicts,
    });
    if option_flag(&args, "--json") {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if dry_run {
        println!(
            "validated promotion of {} output(s) from {} into {}; no changes applied",
            selected.len(),
            cell_id,
            source_run_id
        );
    } else {
        println!(
            "transactionally promoted {} output(s) from {} into {} ({promotion_id})",
            selected.len(),
            cell_id,
            source_run_id
        );
    }
    Ok(())
}

fn repeated_arg_values(args: &[OsString], flag: &str) -> io::Result<Vec<String>> {
    let prefix = format!("{flag}=");
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} must be UTF-8"))
        })?;
        if value == "--" {
            break;
        }
        if value == flag {
            let next = args
                .get(index + 1)
                .and_then(|arg| arg.to_str())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("missing {flag} value"))
                })?;
            values.push(next.to_string());
            index += 2;
            continue;
        }
        if let Some(value) = value.strip_prefix(&prefix) {
            if value.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("missing {flag} value"),
                ));
            }
            values.push(value.to_string());
        }
        index += 1;
    }
    Ok(values)
}

fn option_flag(args: &[OsString], flag: &str) -> bool {
    args.iter()
        .take_while(|arg| arg.as_os_str() != "--")
        .any(|arg| arg == flag)
}

fn validate_promotion_evidence(
    record: &CapabilityCellRecord,
    manifest: &EffectManifest,
    cell_id: &str,
    source_run_id: &str,
    cell_root: &Path,
) -> io::Result<()> {
    verify_capability_cell_forensics(record, manifest, cell_root)?;
    if record.cell_id != cell_id
        || manifest.cell_id != cell_id
        || record.operation_id != manifest.operation_id
        || record.source_run_id != source_run_id
        || manifest.source_run_id != source_run_id
        || record.exit_code != Some(0)
        || manifest.exit_code != Some(0)
        || record.timed_out
        || manifest.timed_out
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell identity, source, or successful completion evidence does not match",
        ));
    }
    if !cell_request_requires_attested_promotion(&record.request)
        || !promotion_telemetry_is_complete(&record.request, &manifest.telemetry_coverage)
        || !manifest.violations.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "promotion requires a policy-derived cell promotion plan, complete relevant effect telemetry, authenticated evidence, and zero violations",
        ));
    }
    let actual_before = collect_cell_snapshot(&cell_root.join("input"))?;
    let actual_after = collect_cell_snapshot(&cell_root.join("output"))?;
    if diff_cell_snapshots(&actual_before, &actual_after) != manifest.files_changed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cell snapshots no longer match the recorded effect evidence",
        ));
    }
    let expected_outputs = manifest
        .files_changed
        .iter()
        .filter(|effect| path_is_in_scopes(&effect.path, &effective_write_paths(&record.request)))
        .map(|effect| PromotionOutput {
            path: effect.path.clone(),
            change: effect.change,
            entry_kind: effect.entry_kind,
            digest: effect.after_digest.clone(),
        })
        .collect::<Vec<_>>();
    if expected_outputs != manifest.outputs_proposed_for_promotion {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "promotion proposals do not match the observed filesystem diff",
        ));
    }
    Ok(())
}

fn cell_request_requires_attested_promotion(request: &CapabilityRequest) -> bool {
    request.effect_scope != gensee_crate_rules::capability::EffectScope::ReadOnly
        && request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::FilesystemWrite
                    | Capability::FilesystemMetadata
                    | Capability::DestructiveFilesystem
                    | Capability::OutputPromotion
            )
        })
}

fn promotion_telemetry_is_complete(
    request: &CapabilityRequest,
    coverage: &EffectTelemetryCoverage,
) -> bool {
    (!request.capabilities.contains(&Capability::FilesystemRead)
        || coverage.filesystem_reads == TelemetryCoverage::Complete)
        && (!request.capabilities.contains(&Capability::FilesystemWrite)
            || coverage.filesystem_writes == TelemetryCoverage::Complete)
        && (!request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::ProcessExecution
                    | Capability::PrivilegedExecution
                    | Capability::UntrustedCodeExecution
            )
        }) || coverage.process_tree == TelemetryCoverage::Complete)
        && (!request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::NetworkEgress | Capability::NetworkListen
            )
        }) || coverage.network_connections == TelemetryCoverage::Complete)
        && (!request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::ExternalApplication | Capability::CloudIam | Capability::DatabaseAccess
            )
        }) || coverage.external_requests == TelemetryCoverage::Complete)
        && (!request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::SecretUse | Capability::IdentityUse | Capability::WorkloadIdentity
            )
        }) || coverage.secret_accesses == TelemetryCoverage::Complete)
}

fn build_cell_promotion_plan(
    podman: &OsString,
    source: &TcloneRunRecord,
    cell_root: &Path,
    selected: &[PromotionOutput],
) -> io::Result<TcloneOverlayMergePlan> {
    let current_root = cell_root.join(format!(".promotion-current-{}", Uuid::new_v4().simple()));
    let cleanup = CapabilityCellDirectoryCleanup(current_root.clone());
    create_restrictive_dir_all(&current_root)?;
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();
    for output in selected {
        let input = cell_root.join("input").join(&output.path);
        let current = current_root.join(&output.path);
        let container_path = Path::new(&source.container_workspace).join(&output.path);
        ensure_source_path_has_no_symlink_ancestor(podman, source, &container_path)?;
        capture_source_path(podman, source, &container_path, &current)?;
        if snapshot_cell_path(&input)? != snapshot_cell_path(&current)? {
            conflicts.push(output.path.clone());
            continue;
        }
        let path =
            normalize_tclone_workspace_merge_path(&output.path, &source.container_workspace)?;
        let (op, source_path) = match output.change {
            FileChangeKind::Deleted => (TcloneOverlayMergeOp::Delete, None),
            FileChangeKind::Created | FileChangeKind::Modified
                if output.entry_kind == FileEntryKind::Directory =>
            {
                (
                    TcloneOverlayMergeOp::CreateDir,
                    Some(cell_root.join("output").join(&output.path)),
                )
            }
            FileChangeKind::Created | FileChangeKind::Modified => (
                TcloneOverlayMergeOp::UpsertFile,
                Some(cell_root.join("output").join(&output.path)),
            ),
        };
        if let Some(path) = source_path.as_deref() {
            ensure_cell_path_has_no_symlink_ancestor(&cell_root.join("output"), path)?;
        }
        changes.push(TcloneOverlayMergeChange {
            path,
            op,
            source: source_path,
        });
    }
    drop(cleanup);
    Ok(TcloneOverlayMergePlan { changes, conflicts })
}

fn capture_source_path(
    podman: &OsString,
    source: &TcloneRunRecord,
    container_path: &Path,
    destination: &Path,
) -> io::Result<()> {
    if let Some(parent) = destination.parent() {
        create_restrictive_dir_all(parent)?;
    }
    let status = Command::new(podman)
        .args([
            OsString::from("cp"),
            OsString::from(format!(
                "{}:{}",
                source.container_name,
                container_path.display()
            )),
            destination.as_os_str().to_os_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        return Ok(());
    }
    let path = container_path.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "container path must be UTF-8")
    })?;
    let missing = Command::new(podman)
        .args([
            OsString::from("exec"),
            OsString::from(&source.container_name),
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from("[ ! -e \"$1\" ] && [ ! -L \"$1\" ]"),
            OsString::from("sh"),
            OsString::from(path),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if missing.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "failed to capture source path for conflict detection: {path}"
        )))
    }
}

fn ensure_source_path_has_no_symlink_ancestor(
    podman: &OsString,
    source: &TcloneRunRecord,
    container_path: &Path,
) -> io::Result<()> {
    let path = container_path.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "container path must be UTF-8")
    })?;
    tclone_exec(
        podman,
        &source.container_name,
        &[
            "sh",
            "-c",
            "p=$1; while [ \"$p\" != / ]; do p=${p%/*}; [ -z \"$p\" ] && p=/; [ ! -L \"$p\" ] || exit 42; done",
            "sh",
            path,
        ],
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("source path has a symlink ancestor: {path}"),
        )
    })
}

fn ensure_cell_path_has_no_symlink_ancestor(root: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell output escaped its root",
        )
    })?;
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("cell output has a symlink ancestor: {}", current.display()),
            ));
        }
    }
    Ok(())
}

fn snapshot_cell_path(path: &Path) -> io::Result<Option<CellSnapshotEntry>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.is_dir() {
        return Ok(Some(CellSnapshotEntry {
            kind: FileEntryKind::Directory,
            digest: None,
            size: None,
            mode: cell_metadata_mode(&metadata),
        }));
    }
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        return Ok(Some(CellSnapshotEntry {
            kind: FileEntryKind::Symlink,
            digest: Some(format!(
                "sha256:{:x}",
                Sha256::digest(target.to_string_lossy().as_bytes())
            )),
            size: None,
            mode: None,
        }));
    }
    if metadata.is_file() {
        return Ok(Some(CellSnapshotEntry {
            kind: FileEntryKind::File,
            digest: Some(digest_cell_file(path)?),
            size: Some(metadata.len()),
            mode: cell_metadata_mode(&metadata),
        }));
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "special filesystem entry cannot be promoted: {}",
            path.display()
        ),
    ))
}

#[cfg(unix)]
fn cell_metadata_mode(metadata: &fs::Metadata) -> Option<u32> {
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn cell_metadata_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

struct CapabilityCellDirectoryCleanup(PathBuf);

impl Drop for CapabilityCellDirectoryCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn inspect_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    if env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell inspection is host-only",
        ));
    }
    let cell_id = tclone_target_arg(&args, "usage: gensee run cell inspect <cell-id> [--json]")?;
    let cell_path = capability_cell_path(&cell_id)?;
    let record = read_nofollow_to_string(&cell_path.join("record.json"))?;
    let manifest = read_nofollow_to_string(&cell_path.join("effect-manifest.json"))?;
    let parsed_record: CapabilityCellRecord = serde_json::from_str(&record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let parsed_manifest: EffectManifest = serde_json::from_str(&manifest)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (forensics, replay_plan) =
        verify_capability_cell_forensics(&parsed_record, &parsed_manifest, &cell_path)?;
    let promotion_ledger = load_verified_promotion_ledger(&cell_path, &cell_id)?;
    if args.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "record": parsed_record,
                "effect_manifest": parsed_manifest,
                "forensics_evidence": forensics,
                "replay_plan": replay_plan,
                "promotion_ledger": promotion_ledger,
            }))?
        );
    } else {
        println!("cell: {}", parsed_record.cell_id);
        println!("source: {}", parsed_record.source_run_id);
        println!("lease: {}", parsed_record.lease_id);
        println!(
            "exit: {:?} timed_out={}",
            parsed_record.exit_code, parsed_record.timed_out
        );
        println!("snapshot: {}", parsed_record.workspace_snapshot);
        println!("manifest: {}", parsed_record.effect_manifest);
        println!("forensics signature: verified");
        println!(
            "effects: {} changed path(s), {} promotion proposal(s), {} violation(s)",
            parsed_manifest.files_changed.len(),
            parsed_manifest.outputs_proposed_for_promotion.len(),
            parsed_manifest.violations.len()
        );
        println!("signed promotions: {}", promotion_ledger.len());
    }
    Ok(())
}

fn capability_lease_path(lease_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(lease_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid lease id",
        ));
    }
    Ok(default_root()?
        .join("tclone-capability-leases")
        .join(format!("{lease_id}.json")))
}

fn capability_cell_path(cell_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(cell_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cell id",
        ));
    }
    Ok(default_root()?
        .join("tclone-capability-cells")
        .join(cell_id))
}

fn capability_cell_cleanup_journal_path(cell_id: &str) -> io::Result<PathBuf> {
    Ok(capability_cell_path(cell_id)?.join("cleanup-journal.json"))
}

fn persist_cell_cleanup_journal(journal: &CapabilityCellCleanupJournal) -> io::Result<()> {
    write_atomic_nofollow(
        &capability_cell_cleanup_journal_path(&journal.cell_id)?,
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

pub(super) fn recover_expired_capability_cells(now_ms: u64) -> io::Result<()> {
    let cells_dir = default_root()?.join("tclone-capability-cells");
    if !cells_dir.exists() {
        return Ok(());
    }
    let podman = tclone_podman();
    let mut failures = Vec::new();
    for entry in fs::read_dir(&cells_dir)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let journal_path = entry.path().join("cleanup-journal.json");
        if !journal_path.exists() {
            continue;
        }
        let _lock = match TcloneStateLock::acquire(&journal_path) {
            Ok(lock) => lock,
            Err(error) => {
                failures.push(format!("{}: {error}", journal_path.display()));
                continue;
            }
        };
        let mut journal: CapabilityCellCleanupJournal =
            match serde_json::from_str(&read_nofollow_to_string(&journal_path)?) {
                Ok(journal) => journal,
                Err(error) => {
                    failures.push(format!(
                        "{}: invalid journal: {error}",
                        journal_path.display()
                    ));
                    continue;
                }
            };
        if journal.state == "cleaned" || now_ms < journal.expires_at_ms {
            continue;
        }
        let result = recover_one_capability_cell(&podman, &journal);
        match result {
            Ok(()) => {
                journal.state = "cleaned".to_string();
                journal.cleaned_at_ms = Some(now_ms);
                journal.last_error = None;
            }
            Err(error) => {
                journal.last_error = Some(error.to_string());
                failures.push(format!("{}: {error}", journal.cell_id));
            }
        }
        write_atomic_nofollow(&journal_path, &serde_json::to_vec_pretty(&journal)?, 0o600)?;
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "capability-cell crash recovery incomplete: {}",
            failures.join("; ")
        )))
    }
}

fn recover_one_capability_cell(
    podman: &OsString,
    journal: &CapabilityCellCleanupJournal,
) -> io::Result<()> {
    if !tclone_is_safe_token(&journal.cell_id)
        || journal.container_name != format!("gensee-tclone-{}", journal.cell_id)
        || journal
            .broker_lease_ids
            .iter()
            .any(|lease_id| !tclone_is_safe_token(lease_id))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cleanup journal contains an unsafe target",
        ));
    }
    let _ = Command::new(podman)
        .args(["rm", "--force", &journal.container_name])
        .status();
    if let Some(table) = journal.nftables_table.as_deref() {
        if !tclone_is_safe_token(table) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cleanup journal contains an unsafe nftables table",
            ));
        }
        gensee_crate_linux::delete_nftables_table_if_exists(table)?;
    }
    if let Some(cgroup_path) = journal.cgroup_path.as_deref() {
        let expected = gensee_crate_linux::default_agent_cgroup_path(&journal.cell_id);
        if Path::new(cgroup_path) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cleanup journal cgroup does not match its cell",
            ));
        }
        if Path::new(cgroup_path).exists() {
            gensee_crate_linux::remove_agent_cgroup(Path::new(cgroup_path))?;
        }
    }
    super::capability_broker::revoke_attached_broker_leases(&journal.broker_lease_ids)?;
    Ok(())
}

fn capability_cell_binding_path(cell_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(cell_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cell id",
        ));
    }
    Ok(default_root()?
        .join("tclone-capability-cell-bindings")
        .join(format!("{cell_id}.lease")))
}

pub(super) fn validate_broker_cell_binding(
    cell_id: &str,
    source_run_id: &str,
    operation_id: &str,
    now_ms: u64,
) -> io::Result<u64> {
    let lease_id = read_nofollow_to_string(&capability_cell_binding_path(cell_id)?)?
        .trim()
        .to_string();
    let path = capability_lease_path(&lease_id)?;
    let _lock = TcloneStateLock::acquire(&path)?;
    let lease: CapabilityCellLease = serde_json::from_str(&read_nofollow_to_string(&path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lease.cell_id != cell_id
        || lease.source_run_id != source_run_id
        || lease.operation_id != operation_id
        || lease.consumed_at_ms.is_some()
        || now_ms < lease.issued_at_ms
        || now_ms >= lease.expires_at_ms
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker lease does not match an unconsumed live capability cell lease",
        ));
    }
    Ok(lease.expires_at_ms)
}

pub(super) fn attach_broker_lease_to_cell(
    cell_id: &str,
    source_run_id: &str,
    operation_id: &str,
    broker_lease_id: &str,
    resource_kind: BrokerResourceKind,
    now_ms: u64,
) -> io::Result<()> {
    if !tclone_is_safe_token(broker_lease_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker lease id",
        ));
    }
    let lease_id = read_nofollow_to_string(&capability_cell_binding_path(cell_id)?)?
        .trim()
        .to_string();
    let path = capability_lease_path(&lease_id)?;
    let _lock = TcloneStateLock::acquire(&path)?;
    let mut lease: CapabilityCellLease = serde_json::from_str(&read_nofollow_to_string(&path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lease.cell_id != cell_id
        || lease.source_run_id != source_run_id
        || lease.operation_id != operation_id
        || lease.consumed_at_ms.is_some()
        || now_ms < lease.issued_at_ms
        || now_ms >= lease.expires_at_ms
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability cell lease changed before broker attachment",
        ));
    }
    let requested = match resource_kind {
        BrokerResourceKind::ServiceCredential
        | BrokerResourceKind::LegacyServiceCredentialV1A
        | BrokerResourceKind::LegacyServiceCredentialV1B => {
            lease.request.capabilities.iter().any(|capability| {
                matches!(capability, Capability::SecretUse | Capability::IdentityUse)
            })
        }
        BrokerResourceKind::WorkloadIdentity => lease
            .request
            .capabilities
            .contains(&Capability::WorkloadIdentity),
        BrokerResourceKind::MtlsCertificate => lease
            .request
            .capabilities
            .contains(&Capability::IdentityUse),
        BrokerResourceKind::FilesystemHandle => {
            lease.request.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::FilesystemRead | Capability::FilesystemWrite
                )
            })
        }
        BrokerResourceKind::NetworkLease => lease.request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::NetworkEgress | Capability::NetworkListen
            )
        }),
        BrokerResourceKind::DatabaseRole => lease
            .request
            .capabilities
            .contains(&Capability::DatabaseAccess),
        BrokerResourceKind::ExternalActionCommitToken => {
            lease.request.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::ExternalMutation
                        | Capability::IrreversibleEffect
                        | Capability::OutputPromotion
                )
            })
        }
    };
    if !requested {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker resource kind was not declared by the capability cell request",
        ));
    }
    if !lease
        .broker_lease_ids
        .iter()
        .any(|lease_id| lease_id == broker_lease_id)
    {
        lease.broker_lease_ids.push(broker_lease_id.to_string());
        lease.broker_lease_ids.sort();
        write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gensee_crate_rules::capability::{
        CapabilityScope, EffectScope, NetworkDestinationScope, SecretIdentityScope,
    };
    use gensee_crate_rules::capability_broker::{BrokerGatewayEffect, BrokerLeaseStatus};

    fn request() -> CapabilityRequest {
        CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
            operation_class: "workspace_mutation".to_string(),
            effect_scope: EffectScope::ReversibleLocal,
            capabilities: vec![
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
                Capability::ProcessExecution,
            ],
            scope: CapabilityScope {
                read_paths: vec!["Cargo.toml".to_string()],
                write_paths: vec!["Cargo.lock".to_string()],
                ..CapabilityScope::default()
            },
            lease_ttl_seconds: 300,
        }
    }

    fn policy_decision_for(request: &CapabilityRequest) -> CapabilityDecision {
        validate_cell_request_for_issue(request).unwrap()
    }

    fn source_record() -> TcloneRunRecord {
        TcloneRunRecord {
            run_id: "run_1".to_string(),
            observe_only: false,
            operation_id: None,
            operation_state_root: None,
            capability_lifecycle: None,
            parent_run_id: None,
            role: "source".to_string(),
            status: "running".to_string(),
            container_name: "source".to_string(),
            container_id: None,
            source_container: None,
            host_control_owner_run_id: None,
            fork_prefix: None,
            fork_group_id: None,
            fork_index: None,
            fork_count: None,
            fork_approach: None,
            image: "image".to_string(),
            workspace: "/repo".to_string(),
            container_workspace: "/workspace".to_string(),
            container_home: "/home/gensee".to_string(),
            agent_cmd: vec![],
            path_prefixes: Vec::new(),
            fork_base_git_head: None,
            fork_base_overlay_lowerdir: None,
            fork_overlay_upperdir: None,
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        }
    }

    #[test]
    fn cell_request_rejects_unscoped_or_unexecutable_authority() {
        for capability in [
            Capability::FilesystemMetadata,
            Capability::NetworkEgress,
            Capability::NetworkListen,
            Capability::SecretUse,
            Capability::IdentityUse,
            Capability::WorkloadIdentity,
            Capability::CloudIam,
            Capability::Syscall,
            Capability::LinuxCapability,
            Capability::PrivilegedExecution,
            Capability::ExternalApplication,
            Capability::DatabaseAccess,
            Capability::IrreversibleEffect,
            Capability::OutputPromotion,
            Capability::ExternalMutation,
        ] {
            let mut request = request();
            request.capabilities.push(capability);
            assert!(matches!(
                validate_cell_request_for_issue(&request)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported | io::ErrorKind::PermissionDenied
            ));
        }
    }

    #[test]
    fn cell_request_rejects_path_traversal() {
        let mut request = request();
        request.scope.write_paths = vec!["../outside".to_string()];
        assert_eq!(
            validate_cell_request_for_issue(&request)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn destructive_filesystem_request_accepts_typed_delete_scope() {
        let mut request = request();
        request.capabilities.push(Capability::DestructiveFilesystem);
        request.scope.file_operations = vec![gensee_crate_rules::capability::FileOperationScope {
            path: "target/cache".to_string(),
            operation: gensee_crate_rules::capability::FileOperationKind::Delete,
            entry_kind: None,
        }];

        validate_cell_request_for_issue(&request).unwrap();
        assert!(effective_write_paths(&request).contains(&"target/cache".to_string()));
    }

    #[test]
    fn irreversible_local_request_is_issuable_when_the_cell_contains_the_effect() {
        let mut request = request();
        request.effect_scope = EffectScope::IrreversibleLocal;
        request.capabilities.push(Capability::DestructiveFilesystem);
        request.scope.file_operations = vec![gensee_crate_rules::capability::FileOperationScope {
            path: "target/cache".to_string(),
            operation: gensee_crate_rules::capability::FileOperationKind::Delete,
            entry_kind: None,
        }];

        validate_cell_request_for_issue(&request).unwrap();
    }

    #[test]
    fn cell_issue_marks_broker_mediation_as_pending_without_claiming_it_is_active() {
        let mut request = request();
        request.capabilities.push(Capability::NetworkEgress);
        request.scope.network_destinations =
            vec![gensee_crate_rules::capability::NetworkDestinationScope {
                destination: "10.20.30.40/32".to_string(),
                protocol: "tcp".to_string(),
                ports: vec![443],
            }];

        validate_cell_request_for_issue(&request).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn whole_workspace_selector_copies_contents_even_when_snapshot_root_exists() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("gensee-cell-dot-scope-{}", Uuid::new_v4()));
        let snapshot = root.join("snapshot");
        fs::create_dir_all(&snapshot).unwrap();
        let fake_podman = root.join("podman");
        fs::write(
            &fake_podman,
            "#!/bin/sh\nif [ \"$1\" = cp ]; then printf copied > \"$3/copied.txt\"; fi\n",
        )
        .unwrap();
        fs::set_permissions(&fake_podman, fs::Permissions::from_mode(0o700)).unwrap();
        let mut request = request();
        request.scope.read_paths = vec![".".to_string()];
        request.scope.write_paths.clear();
        request
            .capabilities
            .retain(|capability| *capability != Capability::FilesystemWrite);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_dot".to_string(),
            operation_id: "op_dot".to_string(),
            cell_id: "cell_dot".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&request),
            request,
            command: vec!["true".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };

        copy_capability_scope(
            &fake_podman.into_os_string(),
            &source_record(),
            &lease,
            &snapshot,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(snapshot.join("copied.txt")).unwrap(),
            "copied"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn declared_create_paths_materialize_only_in_the_output_snapshot() {
        let root = env::temp_dir().join(format!("gensee-cell-create-{}", Uuid::new_v4()));
        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        copy_path_all(&input, &output).unwrap();
        let mut request = request();
        request.scope.write_paths = vec!["generated/report.txt".to_string()];
        request
            .scope
            .file_operations
            .push(gensee_crate_rules::capability::FileOperationScope {
                path: "generated/report.txt".to_string(),
                operation: FileOperationKind::Create,
                entry_kind: Some(FileEntryKind::File),
            });

        let kind = declared_create_kind(&request, "generated/report.txt").unwrap();
        materialize_declared_create_paths(&output, &[("generated/report.txt".to_string(), kind)])
            .unwrap();

        assert!(!input.join("generated/report.txt").exists());
        assert!(output.join("generated/report.txt").is_file());
        let before = collect_cell_snapshot(&input).unwrap();
        let after = collect_cell_snapshot(&output).unwrap();
        assert_eq!(
            diff_cell_snapshots(&before, &after)[0].change,
            FileChangeKind::Created
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn declared_create_paths_support_directories_but_reject_symlink_mounts() {
        let root = env::temp_dir().join(format!("gensee-cell-create-kind-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();

        materialize_declared_create_paths(
            &root,
            &[("generated".to_string(), FileEntryKind::Directory)],
        )
        .unwrap();
        assert!(root.join("generated").is_dir());
        assert_eq!(
            materialize_declared_create_paths(
                &root,
                &[("link".to_string(), FileEntryKind::Symlink)],
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_lease_is_source_bound_expiring_and_single_use() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-lease-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_one".to_string(),
            operation_id: "op_one".to_string(),
            cell_id: "cell_one".to_string(),
            source_run_id: "run_one".to_string(),
            policy_decision: policy_decision_for(&request()),
            request: request(),
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 200,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let path = capability_lease_path(&lease.lease_id).unwrap();
        create_restrictive_dir_all(path.parent().unwrap()).unwrap();
        write_atomic_nofollow(&path, &serde_json::to_vec(&lease).unwrap(), 0o600).unwrap();

        let consumed = consume_capability_lease("lease_one", "run_one", 150).unwrap();
        assert_eq!(consumed.consumed_at_ms, Some(150));
        assert_eq!(
            consume_capability_lease("lease_one", "run_one", 151)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn broker_attachment_is_cell_bound_and_capability_matched() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-broker-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_one".to_string(),
            operation_id: "op_one".to_string(),
            cell_id: "cell_one".to_string(),
            source_run_id: "run_one".to_string(),
            policy_decision: policy_decision_for(&request()),
            request: request(),
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 200,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let path = capability_lease_path(&lease.lease_id).unwrap();
        create_restrictive_dir_all(path.parent().unwrap()).unwrap();
        write_atomic_nofollow(&path, &serde_json::to_vec(&lease).unwrap(), 0o600).unwrap();
        write_atomic_nofollow(
            &capability_cell_binding_path(&lease.cell_id).unwrap(),
            b"lease_one\n",
            0o600,
        )
        .unwrap();

        assert_eq!(
            validate_broker_cell_binding("cell_one", "run_one", "op_one", 150).unwrap(),
            200
        );
        attach_broker_lease_to_cell(
            "cell_one",
            "run_one",
            "op_one",
            "broker_lease_one",
            BrokerResourceKind::FilesystemHandle,
            150,
        )
        .unwrap();
        let attached: CapabilityCellLease =
            serde_json::from_str(&read_nofollow_to_string(&path).unwrap()).unwrap();
        assert_eq!(attached.broker_lease_ids, vec!["broker_lease_one"]);
        assert_eq!(
            attach_broker_lease_to_cell(
                "cell_one",
                "run_one",
                "op_one",
                "broker_lease_network",
                BrokerResourceKind::NetworkLease,
                151,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn gateway_broker_must_be_active_and_complete_effect_telemetry() {
        let _guard = crate::cli_test_env_lock();
        let suffix = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from("/tmp").join(format!("gcm-{}", &suffix[..8]));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("GENSEE_HOME", &root);
        let socket = root.join("api.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let mut gateway_request = CapabilityRequest::new(
            "read_service_records",
            EffectScope::ReadOnly,
            vec![
                Capability::NetworkEgress,
                Capability::SecretUse,
                Capability::ProcessExecution,
            ],
        );
        gateway_request.scope.network_destinations = vec![NetworkDestinationScope {
            destination: "records.example.test".to_string(),
            protocol: "https".to_string(),
            ports: vec![443],
        }];
        gateway_request.scope.secret_identities = vec![SecretIdentityScope {
            handle: "records_reader".to_string(),
            identity: "records-reader".to_string(),
            purpose: "read service records".to_string(),
        }];
        let cell_lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_gateway".to_string(),
            operation_id: "op_gateway".to_string(),
            cell_id: "cell_gateway".to_string(),
            source_run_id: "run_gateway".to_string(),
            policy_decision: policy_decision_for(&gateway_request),
            request: gateway_request,
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 300,
            consumed_at_ms: None,
            broker_lease_ids: vec!["broker_gateway".to_string()],
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let broker_lease = BrokerLease {
            protocol_version: gensee_crate_rules::capability_broker::BROKER_PROTOCOL_VERSION,
            lease_id: "broker_gateway".to_string(),
            operation_id: "op_gateway".to_string(),
            source_run_id: "run_gateway".to_string(),
            cell_id: Some("cell_gateway".to_string()),
            resource_kind: BrokerResourceKind::ServiceCredential,
            adapter_id: "records_adapter".to_string(),
            audience: "records.example.test".to_string(),
            scopes: vec!["records:read".to_string()],
            constraints: json!({ "gateway_kind": "service_gateway" }),
            issued_at_ms: 100,
            expires_at_ms: 250,
            status: BrokerLeaseStatus::Active,
            delivery: BrokerDelivery::Gateway {
                gateway_endpoint: format!("unix://{}", socket.display()),
                provider_handle: "opaque_gateway".to_string(),
            },
            public_metadata: Value::Null,
            gateway_effects: Vec::new(),
            effect_telemetry_complete: false,
            revoked_at_ms: None,
            consumed_at_ms: None,
        };
        let broker_path = root.join("capability-broker/leases/broker_gateway.json");
        write_atomic_nofollow(
            &broker_path,
            &serde_json::to_vec_pretty(&broker_lease).unwrap(),
            0o600,
        )
        .unwrap();

        assert_eq!(
            validate_cell_request_for_execution(&cell_lease, 150)
                .unwrap()
                .len(),
            1
        );
        let args = capability_cell_run_args(
            &source_record(),
            &cell_lease,
            "cell-gateway",
            &root,
            &root,
            std::slice::from_ref(&broker_lease),
            None,
            &root,
            &root,
            &root.join("seccomp.json"),
            150,
        )
        .unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(rendered.iter().any(|arg| {
            arg.contains(&format!("source={}", socket.display()))
                && arg.contains("destination=/run/gensee-broker/broker_gateway.sock")
        }));

        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        let mut revoked = broker_lease;
        revoked.status = BrokerLeaseStatus::Revoked;
        revoked.gateway_effects = vec![BrokerGatewayEffect {
            kind: BrokerGatewayEffectKind::SecretAccess,
            occurred_at_ms: 160,
            target: "records.example.test".to_string(),
            action: "read_records".to_string(),
            request_digest: format!("sha256:{}", "b".repeat(64)),
            protocol: None,
            port: None,
            response_status: Some(200),
            broker_handle_id: Some("records_reader".to_string()),
        }];
        let manifest = build_effect_manifest(
            &source_record(),
            &cell_lease,
            "cell_gateway",
            &input,
            &output,
            150,
            170,
            Some(0),
            false,
            &[revoked],
            None,
            None,
        )
        .unwrap();
        assert!(manifest
            .violations
            .iter()
            .any(|violation| violation.kind == "broker_effect_telemetry_incomplete"));
        assert_eq!(manifest.secrets_accessed.len(), 1);
        assert_eq!(
            manifest.telemetry_coverage.secret_accesses,
            TelemetryCoverage::Partial
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_plan_is_fresh_confined_and_scope_mounted() {
        let root = env::temp_dir().join(format!("gensee-cell-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        let request = request();
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&request),
            request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let source = source_record();

        let args = capability_cell_run_args(
            &source,
            &lease,
            "cell",
            &root,
            &root,
            &[],
            None,
            &root,
            &root,
            &root,
            1,
        )
        .unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--network", "none"]));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("--rm")));
        assert!(rendered.windows(2).any(|pair| pair == ["--timeout", "1"]));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("--read-only")));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("ALL")));
        assert!(rendered.iter().any(|arg| arg.starts_with("seccomp=")));
        assert!(rendered
            .iter()
            .any(|arg| arg == "apparmor=gensee-capability-cell"));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--entrypoint", "/run/gensee-cell-supervisor"]));
        assert!(rendered.iter().any(|arg| arg == "__cell-landlock-exec"));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--gate", "/run/gensee-startup-gate/open"]));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--write-path", "/workspace/Cargo.lock"]));
        assert!(!rendered.iter().any(|arg| arg.contains("unconfined")));
        assert!(rendered.iter().any(|arg| arg.ends_with("/Cargo.toml:ro,Z")));
        assert!(rendered.iter().any(|arg| arg.ends_with("/Cargo.lock:rw,Z")));
        assert!(!rendered.iter().any(|arg| arg.contains(".codex")));
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn recursive_snapshot_copy_preserves_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("gensee-cell-dir-mode-{}", Uuid::new_v4()));
        let input = root.join("input");
        let nested = input.join("private");
        let output = root.join("output");
        fs::create_dir_all(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o2710)).unwrap();
        fs::write(nested.join("value"), "x").unwrap();

        copy_path_all(&input, &output).unwrap();

        let source_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o7777;
        let output_mode = fs::metadata(output.join("private"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(output_mode, source_mode);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_cli_paths_accept_equals_and_stop_at_command_separator() {
        let promotion_args = vec![
            OsString::from("--path=src"),
            OsString::from("--path"),
            OsString::from("Cargo.lock"),
            OsString::from("--"),
            OsString::from("--path=ignored"),
        ];
        assert_eq!(
            repeated_arg_values(&promotion_args, "--path").unwrap(),
            vec!["src", "Cargo.lock"]
        );
        assert!(repeated_arg_values(&[OsString::from("--path")], "--path").is_err());
    }

    #[test]
    fn direct_network_lease_builds_a_gated_exact_endpoint_plan() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-network-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        env::set_var("GENSEE_HOME", &root);
        fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        let mut request = request();
        request.capabilities.push(Capability::NetworkEgress);
        request.scope.network_destinations = vec![NetworkDestinationScope {
            destination: "10.20.30.40/32".to_string(),
            protocol: "tcp".to_string(),
            ports: vec![443],
        }];
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_network".to_string(),
            operation_id: "op_network".to_string(),
            cell_id: "cell_network".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&request),
            request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: vec!["broker_network".to_string()],
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let broker = BrokerLease {
            protocol_version: gensee_crate_rules::capability_broker::BROKER_PROTOCOL_VERSION,
            lease_id: "broker_network".to_string(),
            operation_id: "op_network".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: Some("cell_network".to_string()),
            resource_kind: BrokerResourceKind::NetworkLease,
            adapter_id: super::super::capability_broker::BUILTIN_NETWORK_ADAPTER.to_string(),
            audience: "service-pinned-endpoint".to_string(),
            scopes: vec!["connect".to_string()],
            constraints: json!({
                "destination": "10.20.30.40/32",
                "protocol": "tcp",
                "ports": [443]
            }),
            issued_at_ms: 1,
            expires_at_ms: 2,
            status: BrokerLeaseStatus::Active,
            delivery: BrokerDelivery::NetworkLease {
                network_lease_id: "net_1".to_string(),
            },
            public_metadata: Value::Null,
            gateway_effects: Vec::new(),
            effect_telemetry_complete: false,
            revoked_at_ms: None,
            consumed_at_ms: None,
        };

        validate_broker_scope_against_request(&lease.request, &broker).unwrap();
        write_atomic_nofollow(
            &root.join("capability-broker/leases/broker_network.json"),
            &serde_json::to_vec_pretty(&broker).unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(
            validate_cell_request_for_execution(&lease, 1)
                .unwrap()
                .len(),
            1
        );
        let mut plan = cell_network_plan("cell_network", std::slice::from_ref(&broker))
            .unwrap()
            .unwrap();
        gensee_crate_linux::bind_nftables_plan_to_source_address(
            &mut plan.enforcement.nftables,
            "10.88.0.2".parse().unwrap(),
        );
        assert_eq!(plan.enforcement.nftables.endpoint_counters.len(), 1);
        assert!(plan.enforcement.nftables.script.contains(
            "ip saddr 10.88.0.2 ip daddr 10.20.30.40/32 meta l4proto tcp tcp dport 443 counter name allow_0 accept"
        ));
        assert!(plan.enforcement.nftables.script.contains("hook forward"));
        let args = capability_cell_run_args(
            &source_record(),
            &lease,
            "cell-network",
            &root,
            &root,
            std::slice::from_ref(&broker),
            Some(&plan),
            &root,
            &root,
            &root.join("seccomp.json"),
            1,
        )
        .unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--network", "bridge"]));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--entrypoint", "/run/gensee-cell-supervisor"]));
        assert!(rendered
            .iter()
            .any(|arg| { arg.contains("destination=/run/gensee-startup-gate,ro") }));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--gate", "/run/gensee-startup-gate/open"]));

        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        let evidence = CellNetworkEvidence {
            allowed: vec![gensee_crate_linux::LinuxNetworkEndpointEvent {
                table_name: plan.enforcement.nftables.table_name.clone(),
                counter_name: "allow_0".to_string(),
                destination: "10.20.30.40/32".to_string(),
                protocol: gensee_crate_linux::LinuxNetworkProtocol::Tcp,
                ports: vec![443],
                packets: 4,
                bytes: 512,
            }],
            blocked: Vec::new(),
            collection_error: None,
        };
        let manifest = build_effect_manifest(
            &source_record(),
            &lease,
            "cell_network",
            &input,
            &output,
            1,
            2,
            Some(0),
            false,
            std::slice::from_ref(&broker),
            Some(&evidence),
            None,
        )
        .unwrap();
        assert_eq!(manifest.network_connections.len(), 1);
        assert_eq!(manifest.network_connections[0].port, Some(443));
        assert_eq!(
            manifest.telemetry_coverage.network_connections,
            TelemetryCoverage::Complete
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_seccomp_profile_denies_kernel_escape_primitives() {
        let root = env::temp_dir().join(format!("gensee-cell-seccomp-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();

        let path = write_cell_seccomp_profile(&root).unwrap();
        let value: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["defaultAction"], "SCMP_ACT_ALLOW");
        assert_eq!(value["syscalls"][0]["action"], "SCMP_ACT_ERRNO");
        let names = value["syscalls"][0]["names"].as_array().unwrap();
        for denied in [
            "ptrace",
            "process_vm_writev",
            "bpf",
            "mount",
            "unshare",
            "init_module",
        ] {
            assert!(names.iter().any(|name| name == denied), "missing {denied}");
        }
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn expired_cell_journal_is_recovered_and_marked_clean() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-recovery-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let fake_podman = root.join("podman");
        fs::write(&fake_podman, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_podman, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("GENSEE_HOME", &root);
        env::set_var("GENSEE_TCLONE_PODMAN", &fake_podman);
        let journal = CapabilityCellCleanupJournal {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            cell_id: "cell_recovery".to_string(),
            container_name: "gensee-tclone-cell_recovery".to_string(),
            broker_lease_ids: Vec::new(),
            expires_at_ms: 10,
            nftables_table: None,
            cgroup_path: None,
            state: "active".to_string(),
            cleaned_at_ms: None,
            last_error: None,
        };
        persist_cell_cleanup_journal(&journal).unwrap();

        recover_expired_capability_cells(11).unwrap();

        let recovered: CapabilityCellCleanupJournal = serde_json::from_str(
            &read_nofollow_to_string(
                &capability_cell_cleanup_journal_path("cell_recovery").unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.state, "cleaned");
        assert_eq!(recovered.cleaned_at_ms, Some(11));
        env::remove_var("GENSEE_TCLONE_PODMAN");
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn manifest_uses_actual_diff_and_flags_out_of_scope_changes() {
        let root = env::temp_dir().join(format!("gensee-cell-manifest-{}", Uuid::new_v4()));
        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(input.join("src")).unwrap();
        fs::create_dir_all(output.join("src")).unwrap();
        fs::write(input.join("Cargo.lock"), "before").unwrap();
        fs::write(output.join("Cargo.lock"), "after").unwrap();
        fs::write(input.join("src/lib.rs"), "same").unwrap();
        fs::write(output.join("src/lib.rs"), "changed outside scope").unwrap();
        let mut manifest_request = request();
        manifest_request
            .capabilities
            .push(Capability::UntrustedCodeExecution);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&manifest_request),
            request: manifest_request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };

        let manifest = build_effect_manifest(
            &source_record(),
            &lease,
            "cell_1",
            &input,
            &output,
            10,
            20,
            Some(0),
            false,
            &[],
            None,
            None,
        )
        .unwrap();

        assert_eq!(manifest.operation_id, "op_1");
        assert!(manifest
            .requested_capabilities
            .contains(&Capability::UntrustedCodeExecution));
        assert!(!manifest
            .capabilities_used
            .contains(&Capability::UntrustedCodeExecution));
        assert_eq!(manifest.files_changed.len(), 2);
        assert_eq!(manifest.outputs_proposed_for_promotion.len(), 1);
        assert_eq!(
            manifest.outputs_proposed_for_promotion[0].path,
            "Cargo.lock"
        );
        assert_eq!(manifest.violations.len(), 1);
        assert_eq!(manifest.violations[0].resource, "src/lib.rs");
        assert_eq!(
            manifest.telemetry_coverage.filesystem_writes,
            TelemetryCoverage::Complete
        );
        assert_eq!(
            manifest.telemetry_coverage.filesystem_reads,
            TelemetryCoverage::Unavailable
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn manifest_records_runtime_evidence_with_explicit_partial_mount_coverage() {
        let root = env::temp_dir().join(format!("gensee-cell-runtime-{}", Uuid::new_v4()));
        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        fs::write(input.join("Cargo.toml"), "[package]").unwrap();
        fs::write(output.join("Cargo.toml"), "[package]").unwrap();
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_runtime".to_string(),
            operation_id: "op_runtime".to_string(),
            cell_id: "cell_runtime".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&request()),
            request: request(),
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let mut runtime = CellRuntimeEvidence::default();
        runtime.files_read.insert("Cargo.toml".to_string());
        runtime.covered_read_mounts = vec!["/".to_string()];
        runtime.expected_read_mounts =
            vec!["/".to_string(), "/run".to_string(), "/tmp".to_string()];
        runtime.processes_started.push(ProcessEffect {
            executable: "/usr/bin/cargo".to_string(),
            argv_digest: format!("sha256:{}", "a".repeat(64)),
            pid: Some(42),
            parent_pid: Some(1),
            start_time_ticks: Some(100),
            started_at_ms: 10,
            finished_at_ms: None,
            exit_code: None,
        });
        let manifest = build_effect_manifest(
            &source_record(),
            &lease,
            "cell_runtime",
            &input,
            &output,
            10,
            20,
            Some(0),
            false,
            &[],
            None,
            Some(&runtime),
        )
        .unwrap();
        assert_eq!(manifest.files_read, vec!["Cargo.toml"]);
        assert!(manifest
            .processes_started
            .iter()
            .any(|process| process.pid == Some(42)));
        assert_eq!(
            manifest.telemetry_coverage.filesystem_reads,
            TelemetryCoverage::Partial
        );
        assert_eq!(
            manifest.telemetry_coverage.process_tree,
            TelemetryCoverage::Partial
        );
        let coverage = manifest.filesystem_read_coverage.as_ref().unwrap();
        assert_eq!(coverage.covered_mounts, vec!["/"]);
        assert!(coverage.uncovered_mounts.contains(&"/tmp".to_string()));
        assert!(coverage.uncovered_mounts.contains(&"/run".to_string()));
        assert!(!manifest
            .violations
            .iter()
            .any(|violation| violation.kind == "filesystem_read_coverage_partial"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn process_tracker_records_inherited_forks_and_exit_status() {
        let parent_pid = std::process::id();
        let parent_effect = ProcessEffect {
            executable: "/bin/test-parent".to_string(),
            argv_digest: format!("sha256:{}", "c".repeat(64)),
            pid: Some(parent_pid),
            parent_pid: None,
            start_time_ticks: Some(1),
            started_at_ms: 10,
            finished_at_ms: None,
            exit_code: None,
        };
        let mut tracker = CellProcessTracker {
            tracked_pids: BTreeSet::from([parent_pid]),
            active_processes: BTreeMap::from([(parent_pid, Some(1))]),
            processes_started: vec![parent_effect.clone()],
        };
        let child_pid = u32::MAX - 1;
        tracker
            .record(gensee_crate_linux::LinuxProcessEvent::Fork {
                parent_pid,
                parent_tgid: parent_pid,
                child_pid,
                child_tgid: child_pid,
                timestamp_ns: 1,
            })
            .unwrap();
        let child = tracker
            .processes_started
            .iter()
            .find(|process| process.pid == Some(child_pid))
            .unwrap();
        assert_eq!(child.parent_pid, Some(parent_pid));
        assert_eq!(child.executable, parent_effect.executable);

        tracker
            .record(gensee_crate_linux::LinuxProcessEvent::Exit {
                process_pid: child_pid,
                process_tgid: child_pid,
                exit_code: 7 << 8,
                exit_signal: 0,
                parent_pid,
                parent_tgid: parent_pid,
                timestamp_ns: 2,
            })
            .unwrap();
        let child = tracker
            .processes_started
            .iter()
            .find(|process| process.pid == Some(child_pid))
            .unwrap();
        assert_eq!(child.exit_code, Some(7));
        assert!(child.finished_at_ms.is_some());
    }

    #[test]
    fn process_exit_updates_only_the_active_pid_generation() {
        let pid = u32::MAX - 2;
        let effect = |start_time_ticks, finished_at_ms, exit_code| ProcessEffect {
            executable: "/bin/process".to_string(),
            argv_digest: format!("sha256:{}", "d".repeat(64)),
            pid: Some(pid),
            parent_pid: Some(1),
            start_time_ticks: Some(start_time_ticks),
            started_at_ms: start_time_ticks,
            finished_at_ms,
            exit_code,
        };
        let mut tracker = CellProcessTracker {
            tracked_pids: BTreeSet::from([pid]),
            active_processes: BTreeMap::from([(pid, Some(30))]),
            processes_started: vec![effect(10, Some(20), Some(0)), effect(30, None, None)],
        };
        tracker
            .record(gensee_crate_linux::LinuxProcessEvent::Exit {
                process_pid: pid,
                process_tgid: pid,
                exit_code: 7 << 8,
                exit_signal: 0,
                parent_pid: 1,
                parent_tgid: 1,
                timestamp_ns: 40,
            })
            .unwrap();
        assert_eq!(tracker.processes_started[0].finished_at_ms, Some(20));
        assert_eq!(tracker.processes_started[0].exit_code, Some(0));
        assert!(tracker.processes_started[1].finished_at_ms.is_some());
        assert_eq!(tracker.processes_started[1].exit_code, Some(7));
    }

    #[test]
    fn cell_read_mount_plan_covers_every_separate_effect_mount() {
        let mut lease_request = request();
        lease_request
            .scope
            .write_paths
            .push("generated".to_string());
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_mounts".to_string(),
            operation_id: "op_mounts".to_string(),
            cell_id: "cell_mounts".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&lease_request),
            request: lease_request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: vec!["broker_1".to_string()],
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let mounts = capability_cell_read_mounts(&lease, "/workspace");
        for required in [
            "/",
            "/tmp",
            "/run",
            "/run/gensee-startup-gate",
            "/run/gensee-cell-supervisor",
            "/run/gensee-broker/broker_1.sock",
            "/workspace/Cargo.toml",
            "/workspace/Cargo.lock",
            "/workspace/generated",
        ] {
            assert!(mounts.contains(&required.to_string()), "missing {required}");
        }
    }

    #[test]
    fn promotion_evidence_rejects_tampering_and_incomplete_telemetry() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-promotion-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", root.join("state"));
        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        fs::write(input.join("Cargo.lock"), "before").unwrap();
        fs::write(output.join("Cargo.lock"), "after").unwrap();
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&request()),
            request: request(),
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let mut runtime = CellRuntimeEvidence::default();
        runtime.files_read.insert("Cargo.toml".to_string());
        runtime.covered_read_mounts = vec!["/".to_string(), "/tmp".to_string()];
        runtime.expected_read_mounts = runtime.covered_read_mounts.clone();
        runtime.process_telemetry_complete = true;
        runtime.processes_started.push(ProcessEffect {
            executable: "/usr/bin/cargo".to_string(),
            argv_digest: format!("sha256:{}", "b".repeat(64)),
            pid: Some(42),
            parent_pid: Some(1),
            start_time_ticks: Some(101),
            started_at_ms: 10,
            finished_at_ms: Some(20),
            exit_code: Some(0),
        });
        let manifest = build_effect_manifest(
            &source_record(),
            &lease,
            "cell_1",
            &input,
            &output,
            10,
            20,
            Some(0),
            false,
            &[],
            None,
            Some(&runtime),
        )
        .unwrap();
        assert_eq!(
            manifest.telemetry_coverage.filesystem_reads,
            TelemetryCoverage::Complete
        );
        assert_eq!(
            manifest.telemetry_coverage.process_tree,
            TelemetryCoverage::Complete
        );
        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &manifest,
            &[],
            20,
        )
        .unwrap();
        let record = CapabilityCellRecord {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            lease_id: "lease_1".to_string(),
            source_run_id: "run_1".to_string(),
            request: lease.request.clone(),
            policy_decision: lease.policy_decision.clone(),
            command: lease.command.clone(),
            broker_lease_ids: Vec::new(),
            container_name: "cell".to_string(),
            input_snapshot: input.to_string_lossy().to_string(),
            workspace_snapshot: output.to_string_lossy().to_string(),
            effect_manifest: root
                .join("effect-manifest.json")
                .to_string_lossy()
                .to_string(),
            started_at_ms: 10,
            finished_at_ms: 20,
            exit_code: Some(0),
            timed_out: false,
        };

        validate_promotion_evidence(&record, &manifest, "cell_1", "run_1", &root).unwrap();

        let mut incomplete = manifest.clone();
        incomplete.telemetry_coverage.filesystem_writes = TelemetryCoverage::Partial;
        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &incomplete,
            &[],
            20,
        )
        .unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &incomplete, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut incomplete_reads = manifest.clone();
        incomplete_reads.telemetry_coverage.filesystem_reads = TelemetryCoverage::Partial;
        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &incomplete_reads,
            &[],
            20,
        )
        .unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &incomplete_reads, "cell_1", "run_1", &root,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut incomplete_process = manifest.clone();
        incomplete_process.telemetry_coverage.process_tree = TelemetryCoverage::Partial;
        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &incomplete_process,
            &[],
            20,
        )
        .unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &incomplete_process, "cell_1", "run_1", &root,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &manifest,
            &[],
            20,
        )
        .unwrap();
        let mut altered_manifest = manifest.clone();
        altered_manifest.files_read.push("invented.txt".to_string());
        assert_eq!(
            validate_promotion_evidence(&record, &altered_manifest, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut replay: CapabilityCellReplayPlan =
            serde_json::from_str(&fs::read_to_string(root.join("replay-plan.json")).unwrap())
                .unwrap();
        replay.command.push("--tampered".to_string());
        write_atomic_nofollow(
            &root.join("replay-plan.json"),
            &serde_json::to_vec_pretty(&replay).unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &manifest, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        persist_capability_cell_forensics(
            &source_record(),
            &lease,
            &root,
            &input,
            &output,
            &manifest,
            &[],
            20,
        )
        .unwrap();
        append_signed_promotion_receipt(
            &root,
            "cell_1",
            PromotionReceipt {
                promotion_id: "promotion_1".to_string(),
                source_run_id: "run_1".to_string(),
                paths: vec!["Cargo.lock".to_string()],
                promoted_at_ms: 21,
                approval_token_id: None,
            },
        )
        .unwrap();
        assert_eq!(
            load_verified_promotion_ledger(&root, "cell_1")
                .unwrap()
                .len(),
            1
        );

        fs::write(output.join("Cargo.lock"), "tampered").unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &manifest, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn manifest_blocks_escaping_symlink_outputs() {
        let root = env::temp_dir().join(format!("gensee-cell-symlink-{}", Uuid::new_v4()));
        let input = root.join("input");
        let output = root.join("output");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&output).unwrap();
        std::os::unix::fs::symlink("../../outside", output.join("escape")).unwrap();
        let mut cell_request = request();
        cell_request.scope.read_paths.clear();
        cell_request
            .capabilities
            .retain(|capability| *capability != Capability::FilesystemRead);
        cell_request.scope.write_paths = vec![".".to_string()];
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            source_run_id: "run_1".to_string(),
            policy_decision: policy_decision_for(&cell_request),
            request: cell_request,
            command: vec!["true".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
            replay_of_cell_id: None,
            expected_input_snapshot_digest: None,
        };
        let manifest = build_effect_manifest(
            &source_record(),
            &lease,
            "cell_1",
            &input,
            &output,
            10,
            20,
            Some(0),
            false,
            &[],
            None,
            None,
        )
        .unwrap();

        assert!(manifest
            .violations
            .iter()
            .any(|violation| violation.kind == "unsafe_symlink_output"));
        fs::remove_dir_all(root).ok();
    }
}
