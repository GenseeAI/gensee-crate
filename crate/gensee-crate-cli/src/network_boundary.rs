use crate::*;
use gensee_crate_rules::capability_fault::{
    BoundaryEffectObservation, CapabilityFault, CapabilityFaultAction, CapabilityFaultResolution,
    CapabilityFaultSubject,
};
use gensee_crate_rules::capability_policy::CapabilityExecutor;
use gensee_crate_rules::capability_policy::MediationBoundary;
use gensee_crate_rules::network_boundary::{
    decide_network_boundary, NetworkBoundaryDecision, NetworkBoundaryDisposition,
    NetworkBoundaryEvent, NetworkBoundaryPolicy, NetworkCapabilityEnvelope, NetworkEffectKind,
    NetworkProtocol, NETWORK_BOUNDARY_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::sync::{Arc, Mutex};
use url::Url;
use uuid::Uuid;

const NETWORK_SUPERVISOR_SCHEMA_VERSION: u32 = 2;
const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;
const MAX_SUPERVISOR_MESSAGE_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const NETWORK_POLL_INTERVAL_MS: u64 = 100;
const NETWORK_USAGE_POLL_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkOperationConfig {
    schema_version: u32,
    operation_id: String,
    source_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_address: Option<String>,
    #[serde(default)]
    envelope: NetworkCapabilityEnvelope,
    policy: NetworkBoundaryPolicy,
    proxy: HttpGatewayConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpGatewayConfig {
    listen: String,
    /// Exact client IP allowed to use the gateway. Loopback is not assumed.
    client_address: String,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: u64,
    connect_timeout_seconds: u64,
    io_timeout_seconds: u64,
}

fn default_max_response_bytes() -> u64 {
    DEFAULT_MAX_RESPONSE_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkOperationRecord {
    schema_version: u32,
    operation_id: String,
    source_run_id: String,
    root_pid: Option<u32>,
    source_address: Option<String>,
    envelope: NetworkCapabilityEnvelope,
    policy: NetworkBoundaryPolicy,
    active_table_name: Option<String>,
    generation: u64,
    #[serde(default)]
    usage: OperationNetworkUsage,
    #[serde(default)]
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    started_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NetworkSupervisorRequest {
    Event { event: NetworkBoundaryEvent },
    Fault { fault: CapabilityFault },
    Inspect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSupervisorResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<NetworkBoundaryDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolution: Option<CapabilityFaultResolution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record: Option<NetworkOperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkEffectRecord {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fault_id: Option<String>,
    event: NetworkBoundaryEvent,
    decision: NetworkBoundaryDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    bytes_from_client: u64,
    bytes_to_client: u64,
    completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkCounterEvidenceRecord {
    schema_version: u32,
    operation_id: String,
    generation: u64,
    table_name: String,
    #[serde(default)]
    allowed: Vec<gensee_crate_linux::LinuxNetworkEndpointEvent>,
    #[serde(default)]
    blocked: Vec<gensee_crate_linux::LinuxNetworkBlockEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection_error: Option<String>,
    observed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFaultEvidenceRecord {
    schema_version: u32,
    fault: CapabilityFault,
    resolution: CapabilityFaultResolution,
    received_at_ms: u64,
}

struct NetworkSupervisor {
    record: NetworkOperationRecord,
    record_path: PathBuf,
    event_log_path: PathBuf,
    counter_log_path: PathBuf,
    fault_log_path: PathBuf,
    dry_run: bool,
    operation: Option<OperationSupervisor>,
    active_plan: Option<gensee_crate_linux::LinuxNftablesPlan>,
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    next_usage_sample_at_ms: u64,
    last_counter_error: Option<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct NetworkRuntimeCleanup {
    table_names: Arc<Mutex<Vec<String>>>,
    cgroup_path: Option<PathBuf>,
}

#[cfg(unix)]
struct NetworkOperationLock(fs::File);

#[cfg(unix)]
impl NetworkOperationLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        let file = options.open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "another network supervisor owns this operation",
            ));
        }
        Ok(Self(file))
    }
}

#[cfg(unix)]
impl Drop for NetworkOperationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl Drop for NetworkRuntimeCleanup {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(names) = self.table_names.lock() {
                for name in names.iter() {
                    let _ = gensee_crate_linux::delete_nftables_table_if_exists(name);
                }
            }
            if let Some(path) = self.cgroup_path.as_deref() {
                let _ = gensee_crate_linux::remove_agent_cgroup(path);
            }
        }
    }
}

pub(crate) fn handle_c0_network(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("serve") => serve_network_supervisor(&args[1..]),
        Some("event") => send_network_supervisor_event(&args[1..]),
        Some("fault") => send_capability_fault(&args[1..]),
        Some("inspect") => inspect_network_supervisor(&args[1..]),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: gensee run network <serve --config FILE [--dry-run]|event --socket PATH --event FILE|fault --socket PATH --fault FILE|inspect --socket PATH>",
        )),
    }
}

pub(crate) fn handle_capability_fault(args: Vec<OsString>) -> io::Result<()> {
    send_capability_fault(&args)
}

fn serve_network_supervisor(args: &[OsString]) -> io::Result<()> {
    let config_path = network_arg_value(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --config"))?;
    let config: NetworkOperationConfig =
        serde_json::from_str(&read_nofollow_to_string(&config_path)?).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid network operation config: {error}"),
            )
        })?;
    validate_network_operation_config(&config)?;
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    if !dry_run && std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "C0 network enforcement requires Linux; use --dry-run only for parser tests",
        ));
    }

    let root = network_operation_root(&config.operation_id)?;
    create_restrictive_dir_all(&root)?;
    #[cfg(unix)]
    let _operation_lock = NetworkOperationLock::acquire(&root.join("supervisor.lock"))?;
    let socket_path = root.join("supervisor.sock");
    let record_path = root.join("record.json");
    let event_log_path = root.join("effects.jsonl");
    let counter_log_path = root.join("counters.jsonl");
    let fault_log_path = root.join("faults.jsonl");
    let previous = if record_path.exists() {
        let previous: NetworkOperationRecord =
            serde_json::from_str(&read_nofollow_to_string(&record_path)?).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("cannot reconcile prior network operation record: {error}"),
                )
            })?;
        if previous.schema_version != NETWORK_SUPERVISOR_SCHEMA_VERSION
            || previous.operation_id != config.operation_id
            || previous.source_run_id != config.source_run_id
            || previous.root_pid != config.root_pid
            || previous.source_address != config.source_address
            || previous
                .active_table_name
                .as_deref()
                .is_some_and(|name| !safe_nft_table_name(name))
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "prior network operation record is not safe to reconcile",
            ));
        }
        Some(previous)
    } else {
        None
    };
    let now_ms = unix_millis()?;
    let started_at_ms = previous
        .as_ref()
        .map_or(now_ms, |record| record.started_at_ms);
    let record = NetworkOperationRecord {
        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
        operation_id: config.operation_id.clone(),
        source_run_id: config.source_run_id.clone(),
        root_pid: config.root_pid,
        source_address: config.source_address.clone(),
        envelope: config.envelope.clone(),
        policy: config.policy.clone(),
        active_table_name: previous
            .as_ref()
            .and_then(|record| record.active_table_name.clone()),
        generation: previous.as_ref().map_or(0, |record| record.generation),
        usage: previous
            .as_ref()
            .map_or_else(OperationNetworkUsage::default, |record| {
                record.usage.clone()
            }),
        counter_snapshot: previous
            .as_ref()
            .map_or_else(BTreeMap::new, |record| record.counter_snapshot.clone()),
        started_at_ms,
        updated_at_ms: now_ms,
    };
    let table_names = Arc::new(Mutex::new(Vec::new()));
    if let Some(table) = record.active_table_name.as_ref() {
        table_names
            .lock()
            .map_err(|_| io::Error::other("network table registry lock poisoned"))?
            .push(table.clone());
    }
    let active_plan = if record.active_table_name.is_some() {
        let plan = network_plan_for_record(&record)?;
        if plan.nftables.table_name != record.active_table_name.as_deref().unwrap_or_default() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "prior network operation table does not match its recorded generation",
            ));
        }
        Some(plan.nftables)
    } else {
        None
    };
    let counter_snapshot = record.counter_snapshot.clone();
    let cgroup_path = if let Some(root_pid) = config.root_pid {
        let path = gensee_crate_linux::default_agent_cgroup_path(&config.operation_id);
        if !dry_run {
            gensee_crate_linux::create_agent_cgroup(&path)?;
            let attached = gensee_crate_linux::attach_process_tree_to_cgroup(root_pid, &path)?;
            if !attached.contains(&root_pid) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "network supervisor could not attach the operation root to its cgroup",
                ));
            }
        }
        Some(path)
    } else {
        None
    };
    let operation_envelope = OperationCapabilityEnvelope {
        capabilities: Vec::new(),
        active_mediators: if config.root_pid.is_some() {
            vec![
                MediationBoundary::NetworkBoundary,
                MediationBoundary::ProcessCgroup,
            ]
        } else {
            vec![MediationBoundary::NetworkBoundary]
        },
        network: config.envelope.clone(),
        ..OperationCapabilityEnvelope::default()
    };
    let mut operation = match OperationSupervisor::open(&config.operation_id, &config.source_run_id)
    {
        Ok(operation) => operation,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if let Some(path) = cgroup_path.as_deref() {
                OperationSupervisor::prepare(
                    &config.operation_id,
                    &config.source_run_id,
                    "network_boundary",
                    operation_envelope,
                    Some(path),
                )?
            } else {
                OperationSupervisor::prepare_external_subject(
                    &config.operation_id,
                    &config.source_run_id,
                    "network_boundary",
                    operation_envelope,
                )?
            }
        }
        Err(error) => return Err(error),
    };
    if let Some(root_pid) = config.root_pid {
        operation.activate(root_pid)?;
    } else {
        operation.update_network_envelope(config.envelope.clone())?;
        operation.activate_external_subject()?;
    }
    let supervisor = Arc::new(Mutex::new(NetworkSupervisor {
        record,
        record_path,
        event_log_path,
        counter_log_path,
        fault_log_path,
        dry_run,
        operation: Some(operation),
        active_plan,
        counter_snapshot,
        next_usage_sample_at_ms: now_ms.saturating_add(NETWORK_USAGE_POLL_INTERVAL_MS),
        last_counter_error: None,
    }));
    let _cleanup = NetworkRuntimeCleanup {
        table_names: Arc::clone(&table_names),
        cgroup_path,
    };
    {
        let mut state = lock_supervisor(&supervisor)?;
        state.reconcile_expired_and_apply(&table_names)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (socket_path, supervisor, table_names, config);
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "network supervisor control requires Unix sockets",
        ));
    }
    #[cfg(unix)]
    {
        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }
        let unix_listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        unix_listener.set_nonblocking(true)?;

        let proxy_listener = TcpListener::bind(&config.proxy.listen)?;
        proxy_listener.set_nonblocking(true)?;
        let local_proxy = proxy_listener.local_addr()?;
        eprintln!(
            "gensee: C0 network supervisor operation={} socket={} proxy={} dry_run={dry_run}",
            config.operation_id,
            socket_path.display(),
            local_proxy
        );

        loop {
            match unix_listener.accept() {
                Ok((stream, _)) => {
                    let supervisor = Arc::clone(&supervisor);
                    let tables = Arc::clone(&table_names);
                    thread::spawn(move || {
                        if let Err(error) = handle_supervisor_stream(stream, supervisor, tables) {
                            eprintln!("gensee: network supervisor request failed: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            match proxy_listener.accept() {
                Ok((stream, peer)) => {
                    let supervisor = Arc::clone(&supervisor);
                    let tables = Arc::clone(&table_names);
                    let proxy = config.proxy.clone();
                    thread::spawn(move || {
                        if let Err(error) =
                            handle_http_proxy_connection(stream, peer, supervisor, tables, proxy)
                        {
                            eprintln!("gensee: HTTP capability gateway request failed: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            {
                let mut state = lock_supervisor(&supervisor)?;
                let now_ms = unix_millis()?;
                if state.has_expired_leases(now_ms) {
                    state.reconcile_expired_and_apply(&table_names)?;
                }
                if now_ms >= state.next_usage_sample_at_ms {
                    state.sample_usage()?;
                    state.next_usage_sample_at_ms =
                        now_ms.saturating_add(NETWORK_USAGE_POLL_INTERVAL_MS);
                }
            }
            thread::sleep(Duration::from_millis(NETWORK_POLL_INTERVAL_MS));
        }
    }
}

fn validate_network_operation_config(config: &NetworkOperationConfig) -> io::Result<()> {
    if config.schema_version != NETWORK_SUPERVISOR_SCHEMA_VERSION
        || config.policy.schema_version != NETWORK_BOUNDARY_SCHEMA_VERSION
        || !safe_network_token(&config.operation_id)
        || !safe_network_token(&config.source_run_id)
        || config.root_pid.is_some() == config.source_address.is_some()
        || config.proxy.max_response_bytes == 0
        || config.proxy.connect_timeout_seconds == 0
        || config.proxy.io_timeout_seconds == 0
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "network operation requires one exact subject, bounded proxy limits, and valid identifiers",
        ));
    }
    let client = config.proxy.client_address.parse::<IpAddr>().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "proxy client_address must be an IP",
        )
    })?;
    let _ = config.proxy.listen.parse::<SocketAddr>().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "proxy listen must be an IP socket address",
        )
    })?;
    if config
        .source_address
        .as_deref()
        .is_some_and(|address| address.parse::<IpAddr>().is_err())
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "source_address must be an exact IP",
        ));
    }
    if client.is_unspecified() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "proxy client_address cannot be unspecified",
        ));
    }
    Ok(())
}

impl NetworkSupervisor {
    fn decide(&mut self, event: &mut NetworkBoundaryEvent) -> io::Result<NetworkBoundaryDecision> {
        // Boundary clients report what happened, but the privileged supervisor
        // owns time. Lease duration must never derive from an attacker-supplied
        // clock value.
        event.observed_at_ms = unix_millis()?;
        if event.operation_id != self.record.operation_id
            || event.source_run_id != self.record.source_run_id
            || self
                .record
                .root_pid
                .is_some_and(|pid| event.process_id != pid)
        {
            return Ok(NetworkBoundaryDecision {
                disposition: NetworkBoundaryDisposition::Deny,
                reason_code: "event_is_not_bound_to_this_operation".to_string(),
                lease: None,
            });
        }
        Ok(decide_network_boundary(
            event,
            &self.record.envelope,
            &self.record.policy,
        ))
    }

    fn resolve_fault(
        &mut self,
        fault: &CapabilityFault,
        table_names: &Arc<Mutex<Vec<String>>>,
    ) -> io::Result<(CapabilityFaultResolution, Option<NetworkEffectRecord>)> {
        let mut reasons = fault.validation_reasons();
        if fault.operation_id != self.record.operation_id
            || fault.source_run_id != self.record.source_run_id
        {
            reasons.push("fault_is_not_bound_to_this_operation".to_string());
        }
        let subject_matches = match &fault.subject {
            CapabilityFaultSubject::LocalProcess {
                pid,
                start_time_ticks,
            } => {
                if self.record.root_pid.is_none() {
                    false
                } else if let Some(operation) = self.operation.as_mut() {
                    operation.validates_local_process_identity(*pid, *start_time_ticks)?
                } else {
                    false
                }
            }
            CapabilityFaultSubject::NetworkPeer { source_address } => self
                .record
                .source_address
                .as_deref()
                .is_some_and(|expected| expected == source_address),
        };
        if !subject_matches {
            reasons.push("fault_subject_is_not_in_the_operation".to_string());
        }
        if !reasons.is_empty() {
            return Ok((denied_fault_resolution(fault, reasons), None));
        }

        let BoundaryEffectObservation::NetworkConnect {
            destination,
            protocol,
            port,
        } = &fault.effect
        else {
            return Ok((
                denied_fault_resolution(
                    fault,
                    vec!["capability_fault_backend_unavailable".to_string()],
                ),
                None,
            ));
        };
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "tcp" => NetworkProtocol::Tcp,
            "udp" => NetworkProtocol::Udp,
            _ => {
                return Ok((
                    denied_fault_resolution(
                        fault,
                        vec!["invalid_network_connect_effect".to_string()],
                    ),
                    None,
                ));
            }
        };
        let mut event = NetworkBoundaryEvent {
            schema_version: NETWORK_BOUNDARY_SCHEMA_VERSION,
            operation_id: fault.operation_id.clone(),
            source_run_id: fault.source_run_id.clone(),
            process_id: self.record.root_pid.unwrap_or(1),
            destination: destination.clone(),
            protocol,
            port: *port,
            effect: NetworkEffectKind::DirectConnect,
            observed_at_ms: fault.observed_at_ms,
            requested_ttl_seconds: Some(fault.requested_ttl_seconds),
        };
        let decision = self.decide(&mut event)?;
        let decision = self.apply_decision(&event, decision, table_names)?;
        let (action, executor, retry_allowed) = match decision.disposition {
            NetworkBoundaryDisposition::AllowWithinEnvelope => (
                CapabilityFaultAction::ContinueAlreadyAuthorized,
                Some(CapabilityExecutor::CurrentOperation),
                true,
            ),
            NetworkBoundaryDisposition::AttachInPlaceLease => (
                CapabilityFaultAction::RetryAfterLease,
                Some(CapabilityExecutor::CurrentOperation),
                true,
            ),
            NetworkBoundaryDisposition::BrokerHttp => (
                CapabilityFaultAction::Delegate,
                Some(CapabilityExecutor::TrustedMediator),
                false,
            ),
            NetworkBoundaryDisposition::Deny => (CapabilityFaultAction::Deny, None, false),
        };
        let resolution = CapabilityFaultResolution {
            fault_id: fault.fault_id.clone(),
            action,
            executor,
            lease_id: decision
                .lease
                .as_ref()
                .and_then(|lease| lease.lease_id.clone()),
            expires_at_ms: decision
                .lease
                .as_ref()
                .and_then(|lease| lease.expires_at_ms),
            retry_allowed,
            reason_codes: vec![decision.reason_code.clone()],
        };
        let effect = NetworkEffectRecord {
            schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
            fault_id: Some(fault.fault_id.clone()),
            event,
            lease_id: resolution.lease_id.clone(),
            decision,
            response_status: None,
            bytes_from_client: 0,
            bytes_to_client: 0,
            completed_at_ms: unix_millis()?,
        };
        Ok((resolution, Some(effect)))
    }

    fn apply_decision(
        &mut self,
        event: &NetworkBoundaryEvent,
        mut decision: NetworkBoundaryDecision,
        table_names: &Arc<Mutex<Vec<String>>>,
    ) -> io::Result<NetworkBoundaryDecision> {
        if decision.disposition == NetworkBoundaryDisposition::AttachInPlaceLease {
            let mut lease = decision.lease.take().ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "lease decision omitted its scope")
            })?;
            let lease_id = format!("net_lease_{}", Uuid::new_v4().simple());
            lease.lease_id = Some(lease_id);
            self.record.envelope.grants.push(lease.clone());
            decision.lease = Some(lease);
            if let Err(error) = self.reconcile_expired_and_apply(table_names) {
                let failed_id = decision
                    .lease
                    .as_ref()
                    .and_then(|lease| lease.lease_id.as_deref());
                self.record
                    .envelope
                    .grants
                    .retain(|grant| grant.lease_id.as_deref() != failed_id);
                self.record.updated_at_ms = unix_millis()?;
                if let Err(persist_error) = self.persist() {
                    return Err(io::Error::other(format!(
                        "network lease activation failed: {error}; rollback evidence could not be persisted: {persist_error}"
                    )));
                }
                return Err(error);
            }
        }
        self.record.updated_at_ms = event.observed_at_ms;
        self.persist()?;
        Ok(decision)
    }

    fn has_expired_leases(&self, now_ms: u64) -> bool {
        self.record
            .envelope
            .grants
            .iter()
            .any(|grant| grant.expires_at_ms.is_some_and(|expiry| now_ms >= expiry))
    }

    fn reconcile_expired_and_apply(
        &mut self,
        table_names: &Arc<Mutex<Vec<String>>>,
    ) -> io::Result<()> {
        let now_ms = unix_millis()?;
        self.record
            .envelope
            .grants
            .retain(|grant| grant.expires_at_ms.is_none_or(|expiry| now_ms < expiry));
        self.record.generation = self.record.generation.saturating_add(1);
        if let Some(pid) = self.record.root_pid {
            if !self.dry_run {
                gensee_crate_linux::attach_process_tree_to_cgroup(
                    pid,
                    &gensee_crate_linux::default_agent_cgroup_path(&self.record.operation_id),
                )?;
            }
        }
        let plan = network_plan_for_record(&self.record)?;
        if !plan.warnings.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported network envelope: {}", plan.warnings.join("; ")),
            ));
        }
        let new_table = plan.nftables.table_name.clone();
        if !self.dry_run {
            // Install the next policy before deleting the previous one. While
            // both base chains exist, their intersection is enforced; changes
            // therefore fail closed during both grant and revocation.
            gensee_crate_linux::apply_nftables_script(&plan.nftables.script)?;
            table_names
                .lock()
                .map_err(|_| io::Error::other("network table registry lock poisoned"))?
                .push(new_table.clone());
            self.sample_usage()?;
            let new_snapshot = match read_counter_snapshot(&plan.nftables) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let _ = gensee_crate_linux::delete_nftables_table_if_exists(&new_table);
                    return Err(io::Error::new(
                        error.kind(),
                        format!("cannot establish network usage counter baseline: {error}"),
                    ));
                }
            };
            if let Some(old_table) = self.record.active_table_name.as_deref() {
                gensee_crate_linux::delete_nftables_table_if_exists(old_table)?;
            }
            self.counter_snapshot = new_snapshot;
            self.record.counter_snapshot = self.counter_snapshot.clone();
        }
        if self.dry_run {
            let mut names = table_names
                .lock()
                .map_err(|_| io::Error::other("network table registry lock poisoned"))?;
            names.push(new_table.clone());
            if let Some(old) = self.record.active_table_name.as_deref() {
                names.retain(|name| name != old);
            }
            self.counter_snapshot.clear();
            self.record.counter_snapshot.clear();
        } else {
            let mut names = table_names
                .lock()
                .map_err(|_| io::Error::other("network table registry lock poisoned"))?;
            if let Some(old) = self.record.active_table_name.as_deref() {
                names.retain(|name| name != old);
            }
        }
        self.record.active_table_name = Some(new_table);
        self.active_plan = Some(plan.nftables);
        self.record.updated_at_ms = now_ms;
        self.persist()?;
        if let Some(operation) = self.operation.as_mut() {
            operation.update_network_envelope(self.record.envelope.clone())?;
        }
        Ok(())
    }

    fn sample_usage(&mut self) -> io::Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let Some(plan) = self.active_plan.clone() else {
            return Ok(());
        };
        let observed_at_ms = unix_millis()?;
        let (allowed, blocked) = match read_counter_events(&plan) {
            Ok(events) => {
                self.last_counter_error = None;
                events
            }
            Err(error) => {
                let message = error.to_string();
                if self.last_counter_error.as_deref() != Some(&message) {
                    self.append_counter_evidence(&NetworkCounterEvidenceRecord {
                        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                        operation_id: self.record.operation_id.clone(),
                        generation: self.record.generation,
                        table_name: plan.table_name.clone(),
                        allowed: Vec::new(),
                        blocked: Vec::new(),
                        collection_error: Some(message.clone()),
                        observed_at_ms,
                    })?;
                    self.last_counter_error = Some(message);
                }
                return Ok(());
            }
        };
        let allowed = endpoint_counter_deltas(&mut self.counter_snapshot, allowed);
        let blocked = block_counter_deltas(&mut self.counter_snapshot, blocked);
        if allowed.is_empty() && blocked.is_empty() {
            return Ok(());
        }
        let allowed_packets = allowed
            .iter()
            .fold(0u64, |total, event| total.saturating_add(event.packets));
        let allowed_bytes = allowed
            .iter()
            .fold(0u64, |total, event| total.saturating_add(event.bytes));
        let blocked_packets = blocked
            .iter()
            .fold(0u64, |total, event| total.saturating_add(event.packets));
        let blocked_bytes = blocked
            .iter()
            .fold(0u64, |total, event| total.saturating_add(event.bytes));
        self.record.usage.allowed_packets = self
            .record
            .usage
            .allowed_packets
            .saturating_add(allowed_packets);
        self.record.usage.allowed_bytes = self
            .record
            .usage
            .allowed_bytes
            .saturating_add(allowed_bytes);
        self.record.usage.blocked_packets = self
            .record
            .usage
            .blocked_packets
            .saturating_add(blocked_packets);
        self.record.usage.blocked_bytes = self
            .record
            .usage
            .blocked_bytes
            .saturating_add(blocked_bytes);
        self.record.counter_snapshot = self.counter_snapshot.clone();
        self.record.updated_at_ms = observed_at_ms;
        self.persist()?;
        self.append_counter_evidence(&NetworkCounterEvidenceRecord {
            schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
            operation_id: self.record.operation_id.clone(),
            generation: self.record.generation,
            table_name: plan.table_name.clone(),
            allowed,
            blocked,
            collection_error: None,
            observed_at_ms,
        })?;
        if let Some(operation) = self.operation.as_mut() {
            operation.record_network_usage(
                allowed_packets,
                allowed_bytes,
                blocked_packets,
                blocked_bytes,
            )?;
        }
        Ok(())
    }

    fn append_counter_evidence(&self, evidence: &NetworkCounterEvidenceRecord) -> io::Result<()> {
        let mut file = open_owner_append_nofollow(&self.counter_log_path)?;
        serde_json::to_writer(&mut file, evidence)?;
        file.write_all(b"\n")?;
        file.sync_data()
    }

    fn append_fault_evidence(
        &self,
        fault: &CapabilityFault,
        resolution: &CapabilityFaultResolution,
    ) -> io::Result<()> {
        let mut file = open_owner_append_nofollow(&self.fault_log_path)?;
        serde_json::to_writer(
            &mut file,
            &CapabilityFaultEvidenceRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                fault: fault.clone(),
                resolution: resolution.clone(),
                received_at_ms: unix_millis()?,
            },
        )?;
        file.write_all(b"\n")?;
        file.sync_data()
    }

    fn append_effect(&mut self, effect: &NetworkEffectRecord) -> io::Result<()> {
        let mut file = open_owner_append_nofollow(&self.event_log_path)?;
        serde_json::to_writer(&mut file, effect)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        if let Some(operation) = self.operation.as_mut() {
            operation.record_network_effect(&effect.event, &effect.decision)?;
        }
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        write_atomic_nofollow(
            &self.record_path,
            &serde_json::to_vec_pretty(&self.record)?,
            0o600,
        )
    }
}

#[cfg(unix)]
fn handle_supervisor_stream(
    mut stream: UnixStream,
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    table_names: Arc<Mutex<Vec<String>>>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let line = read_bounded_supervisor_line(BufReader::new(stream.try_clone()?))?;
    let request: NetworkSupervisorRequest = serde_json::from_str(&line)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    let response = match request {
        NetworkSupervisorRequest::Inspect => {
            let mut state = lock_supervisor(&supervisor)?;
            state.sample_usage()?;
            NetworkSupervisorResponse {
                ok: true,
                decision: None,
                resolution: None,
                record: Some(state.record.clone()),
                error: None,
            }
        }
        NetworkSupervisorRequest::Fault { fault } => {
            let mut state = lock_supervisor(&supervisor)?;
            match state.resolve_fault(&fault, &table_names) {
                Ok((resolution, effect)) => {
                    state.append_fault_evidence(&fault, &resolution)?;
                    if let Some(effect) = effect.as_ref() {
                        state.append_effect(effect)?;
                    }
                    NetworkSupervisorResponse {
                        ok: true,
                        decision: None,
                        resolution: Some(resolution),
                        record: None,
                        error: None,
                    }
                }
                Err(error) => {
                    let resolution = denied_fault_resolution(
                        &fault,
                        vec!["capability_fault_backend_error".to_string()],
                    );
                    state.append_fault_evidence(&fault, &resolution)?;
                    NetworkSupervisorResponse {
                        ok: false,
                        decision: None,
                        resolution: Some(resolution),
                        record: None,
                        error: Some(error.to_string()),
                    }
                }
            }
        }
        NetworkSupervisorRequest::Event { mut event } => {
            let mut state = lock_supervisor(&supervisor)?;
            let decision = state.decide(&mut event)?;
            match state.apply_decision(&event, decision, &table_names) {
                Ok(decision) => {
                    let effect = NetworkEffectRecord {
                        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                        fault_id: None,
                        event,
                        lease_id: decision
                            .lease
                            .as_ref()
                            .and_then(|lease| lease.lease_id.clone()),
                        decision: decision.clone(),
                        response_status: None,
                        bytes_from_client: 0,
                        bytes_to_client: 0,
                        completed_at_ms: unix_millis()?,
                    };
                    state.append_effect(&effect)?;
                    NetworkSupervisorResponse {
                        ok: true,
                        decision: Some(decision),
                        resolution: None,
                        record: None,
                        error: None,
                    }
                }
                Err(error) => NetworkSupervisorResponse {
                    ok: false,
                    decision: None,
                    resolution: None,
                    record: None,
                    error: Some(error.to_string()),
                },
            }
        }
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")
}

fn handle_http_proxy_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    table_names: Arc<Mutex<Vec<String>>>,
    config: HttpGatewayConfig,
) -> io::Result<()> {
    let allowed_client = config
        .client_address
        .parse::<IpAddr>()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid proxy client address"))?;
    if peer.ip() != allowed_client {
        write_proxy_error(&mut client, 403, "client is outside the gateway audience")?;
        return Ok(());
    }
    client.set_read_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;
    client.set_write_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;
    let request = read_proxy_request(&mut client)?;
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        write_proxy_error(&mut client, 405, "gateway permits read-only HTTP effects")?;
        return Ok(());
    }
    let addresses = resolve_authority(&request.host, request.port)?;
    if addresses.is_empty() {
        write_proxy_error(&mut client, 502, "authority did not resolve")?;
        return Ok(());
    }

    let now = unix_millis()?;
    let state = lock_supervisor(&supervisor)?;
    let operation_id = state.record.operation_id.clone();
    let source_run_id = state.record.source_run_id.clone();
    let process_id = state.record.root_pid.unwrap_or(1);
    drop(state);
    let mut chosen = None;
    let mut decisions = Vec::new();
    for address in addresses {
        let mut event = NetworkBoundaryEvent {
            schema_version: NETWORK_BOUNDARY_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            source_run_id: source_run_id.clone(),
            process_id,
            destination: address.ip().to_string(),
            protocol: NetworkProtocol::Tcp,
            port: address.port(),
            effect: NetworkEffectKind::Http {
                method: request.method.clone(),
                authority: request.authority.clone(),
            },
            observed_at_ms: now,
            requested_ttl_seconds: None,
        };
        let decision = lock_supervisor(&supervisor)?.decide(&mut event)?;
        if matches!(
            decision.disposition,
            NetworkBoundaryDisposition::BrokerHttp
                | NetworkBoundaryDisposition::AllowWithinEnvelope
        ) && chosen.is_none()
        {
            chosen = Some((address, event.clone(), decision.clone()));
        }
        decisions.push((event, decision));
    }
    // A mixed public/private answer is denied as a whole. The gateway pins the
    // actual upstream socket to the already evaluated address.
    if decisions
        .iter()
        .any(|(_, decision)| decision.disposition == NetworkBoundaryDisposition::Deny)
    {
        for (event, decision) in decisions {
            let effect = NetworkEffectRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                fault_id: None,
                event,
                decision,
                lease_id: None,
                response_status: Some(403),
                bytes_from_client: 0,
                bytes_to_client: 0,
                completed_at_ms: unix_millis()?,
            };
            lock_supervisor(&supervisor)?.append_effect(&effect)?;
        }
        write_proxy_error(
            &mut client,
            403,
            "resolved destination is outside the operation envelope",
        )?;
        return Ok(());
    }
    let Some((address, event, decision)) = chosen else {
        write_proxy_error(&mut client, 403, "HTTP effect is not brokerable")?;
        return Ok(());
    };

    // No in-place lease is attached for a brokered effect.
    let _ = table_names;
    let upstream = TcpStream::connect_timeout(
        &address,
        Duration::from_secs(config.connect_timeout_seconds),
    );
    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            write_proxy_error(&mut client, 502, "upstream connection failed")?;
            let effect = NetworkEffectRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                fault_id: None,
                event,
                decision,
                lease_id: None,
                response_status: Some(502),
                bytes_from_client: 0,
                bytes_to_client: 0,
                completed_at_ms: unix_millis()?,
            };
            lock_supervisor(&supervisor)?.append_effect(&effect)?;
            return Err(error);
        }
    };
    upstream.set_read_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;

    let forwarded = request.forward_bytes()?;
    upstream.write_all(&forwarded)?;
    upstream.flush()?;
    let status = copy_http_response_bounded(&mut upstream, &mut client, config.max_response_bytes)?;
    let (bytes_from_client, bytes_to_client, status) = (forwarded.len() as u64, status.1, status.0);
    let effect = NetworkEffectRecord {
        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
        fault_id: None,
        event,
        decision,
        lease_id: None,
        response_status: status,
        bytes_from_client,
        bytes_to_client,
        completed_at_ms: unix_millis()?,
    };
    lock_supervisor(&supervisor)?.append_effect(&effect)
}

#[derive(Debug)]
struct ParsedProxyRequest {
    method: String,
    authority: String,
    host: String,
    port: u16,
    path_and_query: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl ParsedProxyRequest {
    fn forward_bytes(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        write!(
            output,
            "{} {} {}\r\n",
            self.method, self.path_and_query, self.version
        )?;
        for (name, value) in &self.headers {
            if proxy_hop_header(name) || name.eq_ignore_ascii_case("host") {
                continue;
            }
            write!(output, "{name}: {value}\r\n")?;
        }
        write!(output, "Host: {}\r\n", self.authority)?;
        output.extend_from_slice(b"Connection: close\r\n\r\n");
        Ok(output)
    }
}

fn read_proxy_request(stream: &mut TcpStream) -> io::Result<ParsedProxyRequest> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < MAX_PROXY_HEADER_BYTES {
        let count = stream.read(&mut byte)?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "proxy request ended early",
            ));
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "proxy request headers exceeded the limit",
        ));
    }
    parse_proxy_request_bytes(&bytes)
}

fn parse_proxy_request_bytes(bytes: &[u8]) -> io::Result<ParsedProxyRequest> {
    if bytes.len() > MAX_PROXY_HEADER_BYTES || !bytes.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "proxy request headers are incomplete or exceed the limit",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "proxy headers are not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "missing proxy request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default().to_string();
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid proxy request line",
        ));
    }
    let url = Url::parse(target).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "forward proxy requests must use an absolute HTTP URL",
        )
    })?;
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "gateway accepts credential-free absolute HTTP URLs; HTTPS requires a separately approved mediator",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "HTTP host missing"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let authority = if url.port().is_some() {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path_and_query = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "invalid proxy request header")
        })?;
        if name.trim().is_empty() || name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unsafe proxy header",
            ));
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    if headers.iter().any(|(name, value)| {
        (name.eq_ignore_ascii_case("content-length") && value != "0")
            || name.eq_ignore_ascii_case("transfer-encoding")
    }) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "read-only gateway requests cannot carry a body",
        ));
    }
    Ok(ParsedProxyRequest {
        method,
        authority,
        host: host.to_string(),
        port,
        path_and_query,
        version,
        headers,
    })
}

fn proxy_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "authorization"
            | "cookie"
    )
}

fn resolve_authority(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let mut addresses = (host, port).to_socket_addrs()?.collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

fn copy_http_response_bounded(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    limit: u64,
) -> io::Result<(Option<u16>, u64)> {
    let mut total = 0u64;
    let mut status = None;
    let mut first = true;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = upstream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > limit {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "HTTP gateway response exceeded its byte budget",
            ));
        }
        if first {
            first = false;
            status = parse_http_status(&buffer[..count]);
        }
        client.write_all(&buffer[..count])?;
    }
    client.flush()?;
    Ok((status, total))
}

fn parse_http_status(bytes: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn write_proxy_error(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        403 => "Forbidden",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        _ => "Denied",
    };
    let body = format!("gensee network boundary: {message}\n");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn send_network_supervisor_event(args: &[OsString]) -> io::Result<()> {
    let event_path = network_arg_value(args, "--event")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --event"))?;
    let event: NetworkBoundaryEvent = serde_json::from_str(&read_nofollow_to_string(&event_path)?)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    send_supervisor_request(args, &NetworkSupervisorRequest::Event { event })
}

fn send_capability_fault(args: &[OsString]) -> io::Result<()> {
    let fault_path = network_arg_value(args, "--fault")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --fault"))?;
    let fault: CapabilityFault = serde_json::from_str(&read_nofollow_to_string(&fault_path)?)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    send_supervisor_request(args, &NetworkSupervisorRequest::Fault { fault })
}

fn inspect_network_supervisor(args: &[OsString]) -> io::Result<()> {
    send_supervisor_request(args, &NetworkSupervisorRequest::Inspect)
}

#[cfg(unix)]
fn send_supervisor_request(
    args: &[OsString],
    request: &NetworkSupervisorRequest,
) -> io::Result<()> {
    let socket = network_arg_value(args, "--socket")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --socket"))?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let response = read_bounded_supervisor_line(BufReader::new(stream))?;
    let parsed: NetworkSupervisorResponse = serde_json::from_str(&response)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    println!("{}", serde_json::to_string_pretty(&parsed)?);
    if parsed.ok {
        Ok(())
    } else {
        Err(io::Error::other(
            parsed
                .error
                .unwrap_or_else(|| "network request failed".to_string()),
        ))
    }
}

#[cfg(not(unix))]
fn send_supervisor_request(
    _args: &[OsString],
    _request: &NetworkSupervisorRequest,
) -> io::Result<()> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "network supervisor client requires Unix sockets",
    ))
}

fn network_operation_root(operation_id: &str) -> io::Result<PathBuf> {
    if !safe_network_token(operation_id) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid network operation id",
        ));
    }
    Ok(default_root()?
        .join("network-operations")
        .join(operation_id))
}

fn safe_network_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn safe_nft_table_name(value: &str) -> bool {
    value.starts_with("gensee_")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn network_arg_value<'a>(args: &'a [OsString], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then(|| pair[1].to_str()).flatten())
}

fn read_bounded_supervisor_line(reader: impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    reader
        .take(MAX_SUPERVISOR_MESSAGE_BYTES + 1)
        .read_line(&mut line)?;
    if line.len() as u64 > MAX_SUPERVISOR_MESSAGE_BYTES || !line.ends_with('\n') {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "network supervisor message is incomplete or exceeds its byte limit",
        ));
    }
    Ok(line)
}

fn open_owner_append_nofollow(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "network evidence destination is not a regular file",
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn network_plan_for_record(
    record: &NetworkOperationRecord,
) -> io::Result<gensee_crate_linux::LinuxNetworkEnforcementPlan> {
    let session = format!("{}_{}", record.operation_id, record.generation);
    let mut config = gensee_crate_linux::LinuxNetworkEnforcementConfig::new(
        session,
        gensee_crate_linux::LinuxNetworkPolicy {
            mode: gensee_crate_linux::LinuxNetworkMode::AllowListed,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_endpoints: record
                .envelope
                .grants
                .iter()
                .flat_map(|grant| {
                    grant
                        .ports
                        .iter()
                        .map(move |port| gensee_crate_linux::LinuxNetworkEndpoint {
                            destination: grant.destination.clone(),
                            protocol: match grant.protocol {
                                NetworkProtocol::Tcp => {
                                    gensee_crate_linux::LinuxNetworkProtocol::Tcp
                                }
                                NetworkProtocol::Udp => {
                                    gensee_crate_linux::LinuxNetworkProtocol::Udp
                                }
                            },
                            ports: vec![*port],
                        })
                })
                .collect(),
        },
    );
    config.root_pid = record.root_pid;
    if record.root_pid.is_some() {
        config.cgroup_path = gensee_crate_linux::default_agent_cgroup_path(&record.operation_id)
            .to_string_lossy()
            .to_string();
    }
    let mut plan = gensee_crate_linux::plan_nftables_policy(&config);
    if let Some(address) = record.source_address.as_deref() {
        gensee_crate_linux::bind_nftables_plan_to_source_address(
            &mut plan.nftables,
            address.parse().map_err(|_| {
                io::Error::new(ErrorKind::InvalidData, "invalid stored source address")
            })?,
        );
    }
    Ok(plan)
}

fn read_counter_events(
    plan: &gensee_crate_linux::LinuxNftablesPlan,
) -> io::Result<(
    Vec<gensee_crate_linux::LinuxNetworkEndpointEvent>,
    Vec<gensee_crate_linux::LinuxNetworkBlockEvent>,
)> {
    Ok((
        gensee_crate_linux::read_nftables_endpoint_events(plan)?,
        gensee_crate_linux::read_nftables_block_events(plan)?,
    ))
}

fn read_counter_snapshot(
    plan: &gensee_crate_linux::LinuxNftablesPlan,
) -> io::Result<BTreeMap<String, (u64, u64)>> {
    let (allowed, blocked) = read_counter_events(plan)?;
    let mut snapshot = BTreeMap::new();
    for event in allowed {
        snapshot.insert(
            counter_snapshot_key("allow", &event.table_name, &event.counter_name),
            (event.packets, event.bytes),
        );
    }
    for event in blocked {
        snapshot.insert(
            counter_snapshot_key("block", &event.table_name, &event.counter_name),
            (event.packets, event.bytes),
        );
    }
    Ok(snapshot)
}

fn endpoint_counter_deltas(
    snapshot: &mut BTreeMap<String, (u64, u64)>,
    events: Vec<gensee_crate_linux::LinuxNetworkEndpointEvent>,
) -> Vec<gensee_crate_linux::LinuxNetworkEndpointEvent> {
    events
        .into_iter()
        .filter_map(|mut event| {
            let key = counter_snapshot_key("allow", &event.table_name, &event.counter_name);
            let (packets, bytes) = counter_delta(
                snapshot.insert(key, (event.packets, event.bytes)),
                (event.packets, event.bytes),
            );
            event.packets = packets;
            event.bytes = bytes;
            (packets > 0 || bytes > 0).then_some(event)
        })
        .collect()
}

fn block_counter_deltas(
    snapshot: &mut BTreeMap<String, (u64, u64)>,
    events: Vec<gensee_crate_linux::LinuxNetworkBlockEvent>,
) -> Vec<gensee_crate_linux::LinuxNetworkBlockEvent> {
    events
        .into_iter()
        .filter_map(|mut event| {
            let key = counter_snapshot_key("block", &event.table_name, &event.counter_name);
            let (packets, bytes) = counter_delta(
                snapshot.insert(key, (event.packets, event.bytes)),
                (event.packets, event.bytes),
            );
            event.packets = packets;
            event.bytes = bytes;
            (packets > 0 || bytes > 0).then_some(event)
        })
        .collect()
}

fn counter_delta(previous: Option<(u64, u64)>, current: (u64, u64)) -> (u64, u64) {
    let Some(previous) = previous else {
        return current;
    };
    (
        if current.0 >= previous.0 {
            current.0 - previous.0
        } else {
            current.0
        },
        if current.1 >= previous.1 {
            current.1 - previous.1
        } else {
            current.1
        },
    )
}

fn counter_snapshot_key(kind: &str, table: &str, counter: &str) -> String {
    format!("{kind}:{table}:{counter}")
}

fn lock_supervisor(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
) -> io::Result<std::sync::MutexGuard<'_, NetworkSupervisor>> {
    supervisor
        .lock()
        .map_err(|_| io::Error::other("network supervisor lock poisoned"))
}

fn denied_fault_resolution(
    fault: &CapabilityFault,
    reason_codes: Vec<String>,
) -> CapabilityFaultResolution {
    CapabilityFaultResolution {
        fault_id: fault.fault_id.clone(),
        action: CapabilityFaultAction::Deny,
        executor: None,
        lease_id: None,
        expires_at_ms: None,
        retry_allowed: false,
        reason_codes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_supervisor(
        root: &Path,
        policy: NetworkBoundaryPolicy,
    ) -> Arc<Mutex<NetworkSupervisor>> {
        fs::create_dir_all(root).unwrap();
        Arc::new(Mutex::new(NetworkSupervisor {
            record: NetworkOperationRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                operation_id: "op_1".to_string(),
                source_run_id: "run_1".to_string(),
                root_pid: Some(42),
                source_address: None,
                envelope: NetworkCapabilityEnvelope::default(),
                policy,
                active_table_name: None,
                generation: 0,
                usage: OperationNetworkUsage::default(),
                counter_snapshot: BTreeMap::new(),
                started_at_ms: 1,
                updated_at_ms: 1,
            },
            record_path: root.join("record.json"),
            event_log_path: root.join("effects.jsonl"),
            counter_log_path: root.join("counters.jsonl"),
            fault_log_path: root.join("faults.jsonl"),
            dry_run: true,
            operation: None,
            active_plan: None,
            counter_snapshot: BTreeMap::new(),
            next_usage_sample_at_ms: u64::MAX,
            last_counter_error: None,
        }))
    }

    #[test]
    fn proxy_parser_rewrites_absolute_get_and_strips_proxy_headers() {
        let request = parse_proxy_request_bytes(
            b"GET http://example.test:8080/a?b=1 HTTP/1.1\r\nHost: attacker.test\r\nProxy-Authorization: secret\r\nAuthorization: bearer-secret\r\nCookie: secret=value\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.host, "example.test");
        assert_eq!(request.port, 8080);
        let forwarded = String::from_utf8(request.forward_bytes().unwrap()).unwrap();
        assert!(forwarded.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Host: example.test:8080\r\n"));
        assert!(!forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization"));
        assert!(!forwarded.contains("attacker.test"));
        assert!(!forwarded.to_ascii_lowercase().contains("authorization"));
        assert!(!forwarded.to_ascii_lowercase().contains("cookie"));
    }

    #[test]
    fn supervisor_messages_are_newline_terminated_and_bounded() {
        assert_eq!(
            read_bounded_supervisor_line(io::Cursor::new(b"{}\n")).unwrap(),
            "{}\n"
        );
        assert!(read_bounded_supervisor_line(io::Cursor::new(b"{}".as_slice())).is_err());
        let mut oversized = vec![b'x'; MAX_SUPERVISOR_MESSAGE_BYTES as usize + 1];
        oversized.push(b'\n');
        assert!(read_bounded_supervisor_line(io::Cursor::new(oversized)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn network_evidence_append_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        fs::write(&target, b"unchanged").unwrap();
        let link = root.join("effects.jsonl");
        symlink(&target, &link).unwrap();
        assert!(open_owner_append_nofollow(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn proxy_parser_rejects_embedded_url_credentials_and_non_http_urls() {
        for target in ["http://user:password@example.test/a", "file:///etc/passwd"] {
            let request = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn proxy_parser_rejects_read_requests_with_bodies() {
        for request in [
            "GET http://example.test/a HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            "GET http://example.test/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn config_requires_exactly_one_enforcement_subject() {
        let config = NetworkOperationConfig {
            schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            root_pid: None,
            source_address: None,
            envelope: NetworkCapabilityEnvelope::default(),
            policy: NetworkBoundaryPolicy::default(),
            proxy: HttpGatewayConfig {
                listen: "127.0.0.1:0".to_string(),
                client_address: "127.0.0.1".to_string(),
                max_response_bytes: 1024,
                connect_timeout_seconds: 1,
                io_timeout_seconds: 1,
            },
        };
        assert!(validate_network_operation_config(&config).is_err());
        let mut local = config.clone();
        local.root_pid = Some(42);
        assert!(validate_network_operation_config(&local).is_ok());
        local.source_address = Some("10.0.0.2".to_string());
        assert!(validate_network_operation_config(&local).is_err());
    }

    #[test]
    fn in_place_lease_is_attached_then_removed_on_expiry() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            in_place_lease_destinations: vec!["8.8.8.8".to_string()],
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let tables = Arc::new(Mutex::new(Vec::new()));
        let forged_future = unix_millis().unwrap().saturating_add(86_400_000);
        let mut event = NetworkBoundaryEvent {
            schema_version: NETWORK_BOUNDARY_SCHEMA_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            process_id: 42,
            destination: "8.8.8.8".to_string(),
            protocol: NetworkProtocol::Tcp,
            port: 443,
            effect: NetworkEffectKind::DirectConnect,
            observed_at_ms: forged_future,
            requested_ttl_seconds: Some(1),
        };
        let mut state = supervisor.lock().unwrap();
        let decision = state.decide(&mut event).unwrap();
        assert!(event.observed_at_ms < forged_future);
        let decision = state.apply_decision(&event, decision, &tables).unwrap();
        assert_eq!(
            decision.disposition,
            NetworkBoundaryDisposition::AttachInPlaceLease
        );
        assert_eq!(state.record.envelope.grants.len(), 1);
        state.record.envelope.grants[0].expires_at_ms = Some(1);
        state.reconcile_expired_and_apply(&tables).unwrap();
        assert!(state.record.envelope.grants.is_empty());
        assert!(state.record.generation >= 2);
    }

    #[test]
    fn generic_network_fault_retries_only_after_a_scoped_lease_is_active() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            in_place_lease_destinations: vec!["8.8.8.8".to_string()],
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let tables = Arc::new(Mutex::new(Vec::new()));
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        let fault = CapabilityFault {
            schema_version: gensee_crate_rules::capability_fault::CAPABILITY_FAULT_SCHEMA_VERSION,
            fault_id: "fault_network_1".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            subject: CapabilityFaultSubject::NetworkPeer {
                source_address: "10.88.0.12".to_string(),
            },
            effect: BoundaryEffectObservation::NetworkConnect {
                destination: "8.8.8.8".to_string(),
                protocol: "tcp".to_string(),
                port: 443,
            },
            requested_ttl_seconds: 5,
            observed_at_ms: 1,
        };
        let (resolution, effect) = state.resolve_fault(&fault, &tables).unwrap();
        assert_eq!(resolution.action, CapabilityFaultAction::RetryAfterLease);
        assert!(resolution.retry_allowed);
        assert!(resolution.lease_id.is_some());
        assert_eq!(state.record.envelope.grants.len(), 1);
        assert_eq!(effect.unwrap().fault_id.as_deref(), Some("fault_network_1"));
    }

    #[test]
    fn generic_fault_with_the_wrong_subject_fails_closed() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        let fault = CapabilityFault {
            schema_version: gensee_crate_rules::capability_fault::CAPABILITY_FAULT_SCHEMA_VERSION,
            fault_id: "fault_network_2".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            subject: CapabilityFaultSubject::NetworkPeer {
                source_address: "10.88.0.99".to_string(),
            },
            effect: BoundaryEffectObservation::NetworkConnect {
                destination: "8.8.8.8".to_string(),
                protocol: "tcp".to_string(),
                port: 443,
            },
            requested_ttl_seconds: 5,
            observed_at_ms: 1,
        };
        let (resolution, effect) = state
            .resolve_fault(&fault, &Arc::new(Mutex::new(Vec::new())))
            .unwrap();
        assert_eq!(resolution.action, CapabilityFaultAction::Deny);
        assert!(!resolution.retry_allowed);
        assert!(effect.is_none());
        assert!(resolution
            .reason_codes
            .contains(&"fault_subject_is_not_in_the_operation".to_string()));
    }

    #[test]
    fn counter_snapshots_emit_only_new_usage_and_survive_counter_reset() {
        let mut snapshot = BTreeMap::from([(
            counter_snapshot_key("allow", "table_1", "counter_1"),
            (10, 1000),
        )]);
        let event = gensee_crate_linux::LinuxNetworkEndpointEvent {
            table_name: "table_1".to_string(),
            counter_name: "counter_1".to_string(),
            destination: "8.8.8.8".to_string(),
            protocol: gensee_crate_linux::LinuxNetworkProtocol::Tcp,
            ports: vec![443],
            packets: 13,
            bytes: 1600,
        };
        let deltas = endpoint_counter_deltas(&mut snapshot, vec![event.clone()]);
        assert_eq!(deltas[0].packets, 3);
        assert_eq!(deltas[0].bytes, 600);

        let mut reset = event;
        reset.packets = 2;
        reset.bytes = 120;
        let reset_deltas = endpoint_counter_deltas(&mut snapshot, vec![reset]);
        assert_eq!(reset_deltas[0].packets, 2);
        assert_eq!(reset_deltas[0].bytes, 120);
    }

    #[test]
    fn post_is_not_a_read_mediator_effect() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            restricted_destinations: Vec::new(),
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let proxy = HttpGatewayConfig {
            listen: "127.0.0.1:0".to_string(),
            client_address: "127.0.0.1".to_string(),
            max_response_bytes: 1024,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(b"POST http://example.test/upload HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, peer) = listener.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            supervisor,
            Arc::new(Mutex::new(Vec::new())),
            proxy,
        )
        .unwrap();
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 405"));
    }

    #[test]
    fn public_http_hop_succeeds_and_private_redirect_is_denied_before_connect() {
        let challenge = TcpListener::bind("[::1]:0").unwrap();
        challenge.set_nonblocking(true).unwrap();
        let challenge_address = challenge.local_addr().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_worker = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{challenge_address}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        supervisor.lock().unwrap().record.envelope.grants.push(
            gensee_crate_rules::network_boundary::NetworkEndpointGrant {
                destination: origin_address.ip().to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![origin_address.port()],
                expires_at_ms: None,
                lease_id: None,
            },
        );
        let proxy_config = HttpGatewayConfig {
            listen: "127.0.0.1:0".to_string(),
            client_address: "127.0.0.1".to_string(),
            max_response_bytes: 64 * 1024,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
        };

        let first_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_proxy_address = first_proxy.local_addr().unwrap();
        let first_client = thread::spawn(move || {
            let mut stream = TcpStream::connect(first_proxy_address).unwrap();
            write!(
                stream,
                "GET http://{origin_address}/artifact HTTP/1.1\r\nHost: ignored.test\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, peer) = first_proxy.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            Arc::clone(&supervisor),
            Arc::new(Mutex::new(Vec::new())),
            proxy_config.clone(),
        )
        .unwrap();
        let first_response = first_client.join().unwrap();
        origin_worker.join().unwrap();
        assert!(first_response.starts_with("HTTP/1.1 302"));
        assert!(first_response.contains(&format!("Location: http://{challenge_address}/secret")));

        let second_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let second_proxy_address = second_proxy.local_addr().unwrap();
        let second_client = thread::spawn(move || {
            let mut stream = TcpStream::connect(second_proxy_address).unwrap();
            write!(
                stream,
                "GET http://{challenge_address}/secret HTTP/1.1\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, peer) = second_proxy.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            Arc::clone(&supervisor),
            Arc::new(Mutex::new(Vec::new())),
            proxy_config,
        )
        .unwrap();
        let second_response = second_client.join().unwrap();
        assert!(second_response.starts_with("HTTP/1.1 403"));
        assert!(matches!(
            challenge.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));

        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert!(effects.contains("\"response_status\":302"));
        assert!(effects.contains("\"reason_code\":\"restricted_destination\""));
        assert!(effects.contains("\"response_status\":403"));
    }
}
