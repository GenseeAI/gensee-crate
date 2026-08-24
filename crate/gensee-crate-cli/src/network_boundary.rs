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
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", test))]
use std::collections::VecDeque;
use std::io::{BufReader, ErrorKind};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const NETWORK_SUPERVISOR_SCHEMA_VERSION: u32 = 3;
const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;
const MAX_SUPERVISOR_MESSAGE_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CREDENTIAL_HEADER_BYTES: u64 = 16 * 1024;
const NETWORK_POLL_INTERVAL_MS: u64 = 100;
const NETWORK_USAGE_POLL_INTERVAL_MS: u64 = 1_000;
const MAX_IN_FLIGHT_CONTROL_CONNECTIONS: usize = 64;
const MAX_IN_FLIGHT_HTTP_CONNECTIONS: usize = 128;
const PROXY_BODY_READ_CHUNK_BYTES: usize = 16 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_OBSERVED_ATTEMPT_TRACES: usize = 4_096;
#[cfg(any(target_os = "linux", test))]
const MAX_DETAILED_FAULTS_PER_SECOND: u32 = 64;
const MAX_NETWORK_EVIDENCE_LOG_BYTES: u64 = 64 * 1024 * 1024;

struct ConnectionPermit {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection(in_flight: &Arc<AtomicUsize>, limit: usize) -> Option<ConnectionPermit> {
    in_flight
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < limit).then_some(current + 1)
        })
        .ok()?;
    Some(ConnectionPermit {
        in_flight: Arc::clone(in_flight),
    })
}

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
    #[serde(default = "default_max_request_bytes")]
    max_request_bytes: u64,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: u64,
    #[serde(default)]
    max_redirects: u32,
    connect_timeout_seconds: u64,
    io_timeout_seconds: u64,
    /// A mediator lease is required for credentials or mutating HTTP methods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<HttpCredentialInjection>,
    /// Mutating methods additionally consume one exact, signed host-broker
    /// commit token immediately before the upstream effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_token_id: Option<String>,
    /// Optional inactive-by-default transaction policy for a narrowly scoped
    /// HTTP effect. This policy is installed from the
    /// root-owned operation config; lifecycle requests can select an operation
    /// and TTL, but can never add destinations or raise a budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction: Option<HttpTransactionPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransactionPolicy {
    effect: String,
    scopes: Vec<HttpTransactionScope>,
    max_ttl_seconds: u64,
    max_requests: u64,
    max_request_bytes: u64,
    max_response_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransactionScope {
    /// Canonical lowercase `http` or `https`.
    scheme: String,
    /// Canonical URL authority, including a non-default port when present.
    authority: String,
    /// Absolute path segment prefix. `/repo` matches `/repo` and `/repo/...`,
    /// never `/v1/data`.
    path_prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HttpTransactionStatus {
    Prepared,
    Active,
    Revoked,
    Ended,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransactionRecord {
    transaction_id: String,
    operation_id: String,
    effect: String,
    status: HttpTransactionStatus,
    ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activated_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
    requests: u64,
    request_bytes: u64,
    response_bytes: u64,
    /// A durable single-hop claim on the remaining response budget. A daemon
    /// crash intentionally leaves this populated so recovery cannot issue a
    /// second upstream request without an explicit terminal transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_reservation: Option<HttpResponseReservation>,
    #[serde(default)]
    generation: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpResponseReservation {
    reservation_id: String,
    transaction_generation: u64,
    max_response_bytes: u64,
    created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpCredentialInjection {
    handle_id: String,
    header_name: String,
    value_file: String,
    allowed_url_prefixes: Vec<String>,
}

fn default_max_request_bytes() -> u64 {
    DEFAULT_MAX_REQUEST_BYTES
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
    suppressed_fault_count: u64,
    #[serde(default)]
    evidence_rotation_count: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_boundary_reaped_at_ms: Option<u64>,
    #[serde(default)]
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    #[serde(default)]
    revoked_http_mediator_leases: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_mediator_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_mediator_expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_transaction_policy: Option<HttpTransactionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_transaction: Option<HttpTransactionRecord>,
    #[serde(default)]
    used_http_transaction_ids: BTreeSet<String>,
    started_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NetworkSupervisorRequest {
    Event {
        event: NetworkBoundaryEvent,
    },
    Fault {
        fault: CapabilityFault,
    },
    RevokeHttpMediator {
        lease_id: String,
    },
    BeginHttpTransaction {
        transaction_id: String,
        operation_id: String,
        effect: String,
        ttl_seconds: u64,
    },
    ActivateHttpTransaction {
        transaction_id: String,
        operation_id: String,
    },
    RevokeHttpTransaction {
        transaction_id: String,
        operation_id: String,
    },
    EndHttpTransaction {
        transaction_id: String,
        operation_id: String,
    },
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
    operation_recovery_health: Option<OperationRecoveryHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecoveryHealth {
    network_entries_skipped: u64,
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
    transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_handle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_target: Option<String>,
    bytes_from_client: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytes_from_upstream: Option<u64>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpMediatorAuditRecord {
    schema_version: u32,
    operation_id: String,
    source_run_id: String,
    method: String,
    target: String,
    request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_id: Option<String>,
    disposition: String,
    reason_code: String,
    observed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransactionAuditRecord {
    schema_version: u32,
    operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_id: Option<String>,
    action: String,
    disposition: String,
    reason_code: String,
    observed_at_ms: u64,
}

struct NetworkSupervisor {
    record: NetworkOperationRecord,
    record_path: PathBuf,
    event_log_path: PathBuf,
    counter_log_path: PathBuf,
    fault_log_path: PathBuf,
    mediator_log_path: PathBuf,
    transaction_log_path: PathBuf,
    dry_run: bool,
    operation: Option<OperationSupervisor>,
    active_plan: Option<gensee_crate_linux::LinuxNftablesPlan>,
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    next_usage_sample_at_ms: u64,
    last_counter_error: Option<String>,
    http_mediator_lease_id: Option<String>,
    http_transaction_policy: Option<HttpTransactionPolicy>,
    active_http_transports: BTreeMap<u64, TcpStream>,
    next_http_transport_id: u64,
    #[cfg(target_os = "linux")]
    attempt_monitor: Option<gensee_crate_linux::LinuxNetworkAttemptMonitor>,
    #[cfg(any(target_os = "linux", test))]
    observed_attempt_traces: BTreeSet<String>,
    #[cfg(any(target_os = "linux", test))]
    observed_attempt_trace_order: VecDeque<String>,
    #[cfg(any(target_os = "linux", test))]
    fault_rate_window_started_at_ms: u64,
    #[cfg(any(target_os = "linux", test))]
    detailed_faults_in_window: u32,
    #[cfg(any(target_os = "linux", test))]
    fault_rate_violation_recorded_in_window: bool,
    #[cfg(any(target_os = "linux", test))]
    dedupe_eviction_recorded: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct NetworkRuntimeCleanup {
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    owns_operation_lifecycle: bool,
    table_names: Arc<Mutex<Vec<String>>>,
    terminal_deny_plan: gensee_crate_linux::LinuxNftablesPlan,
    state_root: PathBuf,
    record_path: PathBuf,
    operation_id: String,
    source_run_id: String,
    dry_run: bool,
}

struct HttpTransportGuard {
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    transport_id: u64,
}

impl Drop for HttpTransportGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.supervisor.lock() {
            state.active_http_transports.remove(&self.transport_id);
        }
    }
}

#[cfg(unix)]
struct NetworkOperationLock(fs::File);

#[cfg(unix)]
struct NetworkOperationLocks {
    _identity: NetworkOperationLock,
    _legacy: NetworkOperationLock,
}

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
impl NetworkOperationLocks {
    fn acquire(state_root: &Path, operation_root: &Path, operation_id: &str) -> io::Result<Self> {
        // The order is part of the migration protocol. The stable lock keeps
        // the operation identity exclusive across directory renames; the
        // legacy lock excludes supervisors launched before stable locks were
        // introduced. Do not remove the legacy half until a versioned state-
        // root migration can prove those supervisors no longer exist.
        let identity = NetworkOperationLock::acquire(&network_operation_identity_lock_path(
            state_root,
            operation_id,
        )?)?;
        let legacy = NetworkOperationLock::acquire(&operation_root.join("supervisor.lock"))?;
        Ok(Self {
            _identity: identity,
            _legacy: legacy,
        })
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
        // A standalone boundary daemon creates the operation record itself,
        // so it must also make that lifecycle terminal. When the record was
        // opened from an existing runner, that runner remains the only owner
        // allowed to finish the operation. An implicit daemon teardown has no
        // authenticated success handshake, so fail closed without inventing a
        // child-process exit code.
        if self.owns_operation_lifecycle {
            if let Ok(mut state) = self.supervisor.lock() {
                if let Some(operation) = state.operation.as_mut() {
                    let _ = operation.finish(None, false);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if self.dry_run {
                return;
            }
            // Never tear down the only enforcement generation while the
            // operation may still be running. A deterministic terminal deny
            // generation permits old normal generations to be removed. If
            // installing it fails, retain the normal generations unless the
            // durable operation record proves the subject is already released.
            let terminal_installed =
                gensee_crate_linux::apply_nftables_script(&self.terminal_deny_plan.script).is_ok();
            let subject_released =
                crate::operation_supervisor::terminal_operation_subject_is_released_at(
                    &self.state_root,
                    &self.operation_id,
                    &self.source_run_id,
                )
                .unwrap_or(false);
            if terminal_installed || subject_released {
                let mut exact_tables_deleted = true;
                if let Ok(names) = self.table_names.lock() {
                    for name in names.iter() {
                        exact_tables_deleted &=
                            gensee_crate_linux::delete_nftables_table_if_exists(name).is_ok();
                    }
                } else {
                    exact_tables_deleted = false;
                }
                if subject_released {
                    exact_tables_deleted &= gensee_crate_linux::delete_nftables_table_if_exists(
                        &self.terminal_deny_plan.table_name,
                    )
                    .is_ok();
                    if exact_tables_deleted {
                        let _ = mark_terminal_network_boundary_reaped(
                            &self.record_path,
                            &self.operation_id,
                            &self.source_run_id,
                        );
                    }
                }
            }
        }
    }
}

pub(crate) fn handle_c0_network(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("serve") => serve_network_supervisor(&args[1..]),
        Some("event") => send_network_supervisor_event(&args[1..]),
        Some("fault") => send_capability_fault(&args[1..]),
        Some("revoke-http") => revoke_http_mediator(&args[1..]),
        Some("transaction-begin") => begin_http_transaction(&args[1..]),
        Some("transaction-activate") => activate_http_transaction(&args[1..]),
        Some("transaction-revoke") => revoke_http_transaction(&args[1..]),
        Some("transaction-end") => end_http_transaction(&args[1..]),
        Some("inspect") => inspect_network_supervisor(&args[1..]),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: gensee run network <serve --state-root ROOT --config FILE [--dry-run]|event --socket PATH --event FILE|fault --socket PATH --fault FILE|revoke-http --socket PATH --lease ID|transaction-begin --socket PATH --transaction ID --operation ID --effect EFFECT --ttl-seconds N|transaction-activate|transaction-revoke|transaction-end --socket PATH --transaction ID --operation ID|inspect --socket PATH>",
        )),
    }
}

pub(crate) fn handle_capability_fault(args: Vec<OsString>) -> io::Result<()> {
    send_capability_fault(&args)
}

fn serve_network_supervisor(args: &[OsString]) -> io::Result<()> {
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let config_path = network_arg_value(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --config"))?;
    if !dry_run {
        prepare_privileged_boundary_environment(args, &config_path)?;
    }
    let config: NetworkOperationConfig =
        serde_json::from_str(&read_nofollow_to_string(&config_path)?).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid network operation config: {error}"),
            )
        })?;
    validate_network_operation_config(&config)?;
    if !dry_run && std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "C0 network enforcement requires Linux; use --dry-run only for parser tests",
        ));
    }

    let state_root = default_root()?;
    #[cfg(target_os = "linux")]
    let recovery_report = if dry_run {
        NetworkBoundaryRecoveryReport::default()
    } else {
        recover_pending_terminal_network_boundaries(&state_root)?
    };
    let root = network_operation_root(&config.operation_id)?;
    create_restrictive_dir_all(&root)?;
    #[cfg(unix)]
    let _operation_locks =
        NetworkOperationLocks::acquire(&state_root, &root, &config.operation_id)?;
    let socket_path = root.join("supervisor.sock");
    let record_path = root.join("record.json");
    let event_log_path = root.join("effects.jsonl");
    let counter_log_path = root.join("counters.jsonl");
    let fault_log_path = root.join("faults.jsonl");
    let mediator_log_path = root.join("http-mediator.jsonl");
    let transaction_log_path = root.join("http-transactions.jsonl");
    let previous = if record_path.exists() {
        let previous: NetworkOperationRecord =
            serde_json::from_str(&read_nofollow_to_string(&record_path)?).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("cannot reconcile prior network operation record: {error}"),
                )
            })?;
        validate_stored_network_record(&previous)?;
        if previous.operation_id != config.operation_id
            || previous.source_run_id != config.source_run_id
            || previous.root_pid != config.root_pid
            || previous.source_address != config.source_address
            || previous.http_mediator_lease_id != config.proxy.lease_id
            || previous.http_mediator_expires_at_ms != config.proxy.expires_at_ms
            || previous.http_transaction_policy != config.proxy.transaction
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
        suppressed_fault_count: previous
            .as_ref()
            .map_or(0, |record| record.suppressed_fault_count),
        evidence_rotation_count: previous.as_ref().map_or_else(BTreeMap::new, |record| {
            record.evidence_rotation_count.clone()
        }),
        terminal_boundary_reaped_at_ms: previous
            .as_ref()
            .and_then(|record| record.terminal_boundary_reaped_at_ms),
        counter_snapshot: previous
            .as_ref()
            .map_or_else(BTreeMap::new, |record| record.counter_snapshot.clone()),
        revoked_http_mediator_leases: previous.as_ref().map_or_else(BTreeSet::new, |record| {
            record.revoked_http_mediator_leases.clone()
        }),
        http_mediator_lease_id: config.proxy.lease_id.clone(),
        http_mediator_expires_at_ms: config.proxy.expires_at_ms,
        http_transaction_policy: config.proxy.transaction.clone(),
        http_transaction: previous
            .as_ref()
            .and_then(|record| record.http_transaction.clone()),
        used_http_transaction_ids: previous.as_ref().map_or_else(BTreeSet::new, |record| {
            record.used_http_transaction_ids.clone()
        }),
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
    let terminal_deny_plan = terminal_deny_plan_for_record(&record)?.nftables;
    #[cfg(target_os = "linux")]
    let attempt_monitor = if dry_run {
        None
    } else {
        Some(gensee_crate_linux::start_nftables_attempt_monitor(
            &network_plan_for_record(&record)?.nftables,
        )?)
    };
    let cgroup_path = if config.root_pid.is_some() {
        let path = gensee_crate_linux::default_agent_cgroup_path(&config.operation_id);
        if !dry_run {
            gensee_crate_linux::create_agent_cgroup(&path)?;
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
    let (mut operation, owns_operation_lifecycle) =
        match OperationSupervisor::open(&config.operation_id, &config.source_run_id) {
            Ok(operation) => (operation, false),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if cgroup_path.is_some() {
                    (
                        OperationSupervisor::prepare(
                            &config.operation_id,
                            &config.source_run_id,
                            "network_boundary",
                            operation_envelope,
                            None,
                        )?,
                        true,
                    )
                } else {
                    (
                        OperationSupervisor::prepare_external_subject(
                            &config.operation_id,
                            &config.source_run_id,
                            "network_boundary",
                            operation_envelope,
                        )?,
                        true,
                    )
                }
            }
            Err(error) => return Err(error),
        };
    #[cfg(target_os = "linux")]
    record_network_boundary_recovery_report(&mut operation, recovery_report)?;
    operation.update_network_envelope(config.envelope.clone())?;
    let supervisor = Arc::new(Mutex::new(NetworkSupervisor {
        record,
        record_path: record_path.clone(),
        event_log_path,
        counter_log_path,
        fault_log_path,
        mediator_log_path,
        transaction_log_path,
        dry_run,
        operation: Some(operation),
        active_plan,
        counter_snapshot,
        next_usage_sample_at_ms: now_ms.saturating_add(NETWORK_USAGE_POLL_INTERVAL_MS),
        last_counter_error: None,
        http_mediator_lease_id: config.proxy.lease_id.clone(),
        http_transaction_policy: config.proxy.transaction.clone(),
        active_http_transports: BTreeMap::new(),
        next_http_transport_id: 0,
        #[cfg(target_os = "linux")]
        attempt_monitor,
        #[cfg(any(target_os = "linux", test))]
        observed_attempt_traces: BTreeSet::new(),
        #[cfg(any(target_os = "linux", test))]
        observed_attempt_trace_order: VecDeque::new(),
        #[cfg(any(target_os = "linux", test))]
        fault_rate_window_started_at_ms: now_ms,
        #[cfg(any(target_os = "linux", test))]
        detailed_faults_in_window: 0,
        #[cfg(any(target_os = "linux", test))]
        fault_rate_violation_recorded_in_window: false,
        #[cfg(any(target_os = "linux", test))]
        dedupe_eviction_recorded: false,
    }));
    let _cleanup = NetworkRuntimeCleanup {
        supervisor: Arc::clone(&supervisor),
        owns_operation_lifecycle,
        table_names: Arc::clone(&table_names),
        terminal_deny_plan: terminal_deny_plan.clone(),
        state_root,
        record_path: record_path.clone(),
        operation_id: config.operation_id.clone(),
        source_run_id: config.source_run_id.clone(),
        dry_run,
    };
    {
        let mut state = lock_supervisor(&supervisor)?;
        state.reconcile_expired_and_apply(&table_names)?;
        if !dry_run {
            // A previous daemon exit may have left the deterministic terminal
            // deny generation behind. The new normal generation is already
            // installed, so deleting the terminal table now preserves
            // continuous enforcement without preventing supervised recovery.
            gensee_crate_linux::delete_nftables_table_if_exists(&terminal_deny_plan.table_name)?;
        }
        if let Some(root_pid) = config.root_pid {
            state
                .operation
                .as_mut()
                .ok_or_else(|| io::Error::other("operation supervisor unavailable"))?
                .activate(root_pid)?;
        } else {
            state
                .operation
                .as_mut()
                .ok_or_else(|| io::Error::other("operation supervisor unavailable"))?
                .activate_external_subject()?;
        }
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
        let control_in_flight = Arc::new(AtomicUsize::new(0));
        let http_in_flight = Arc::new(AtomicUsize::new(0));

        loop {
            for _ in 0..MAX_IN_FLIGHT_CONTROL_CONNECTIONS {
                match unix_listener.accept() {
                    Ok((stream, _)) => {
                        if !dry_run && peer_effective_uid(&stream)? != 0 {
                            eprintln!(
                                "gensee: rejected non-root boundary control peer for operation={}",
                                config.operation_id
                            );
                            continue;
                        }
                        let Some(permit) = try_acquire_connection(
                            &control_in_flight,
                            MAX_IN_FLIGHT_CONTROL_CONNECTIONS,
                        ) else {
                            eprintln!(
                                "gensee: rejected boundary control connection above in-flight limit for operation={}",
                                config.operation_id
                            );
                            continue;
                        };
                        let supervisor = Arc::clone(&supervisor);
                        let tables = Arc::clone(&table_names);
                        thread::spawn(move || {
                            let _permit = permit;
                            if let Err(error) = handle_supervisor_stream(stream, supervisor, tables)
                            {
                                eprintln!("gensee: network supervisor request failed: {error}");
                            }
                        });
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            for _ in 0..MAX_IN_FLIGHT_HTTP_CONNECTIONS {
                match proxy_listener.accept() {
                    Ok((mut stream, peer)) => {
                        let Some(permit) =
                            try_acquire_connection(&http_in_flight, MAX_IN_FLIGHT_HTTP_CONNECTIONS)
                        else {
                            let _ = write_proxy_error(
                                &mut stream,
                                503,
                                "HTTP capability gateway is at its in-flight limit",
                            );
                            continue;
                        };
                        let supervisor = Arc::clone(&supervisor);
                        let tables = Arc::clone(&table_names);
                        let proxy = config.proxy.clone();
                        thread::spawn(move || {
                            let _permit = permit;
                            if let Err(error) = handle_http_proxy_connection(
                                stream, peer, supervisor, tables, proxy,
                            ) {
                                eprintln!(
                                    "gensee: HTTP capability gateway request failed: {error}"
                                );
                            }
                        });
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            {
                let mut state = lock_supervisor(&supervisor)?;
                let now_ms = unix_millis()?;
                if state.has_expired_leases(now_ms) {
                    state.reconcile_expired_and_apply(&table_names)?;
                }
                state.expire_http_transaction_if_needed(now_ms)?;
                #[cfg(target_os = "linux")]
                state.sample_kernel_network_attempts(&table_names)?;
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
    let mediator_lease_is_complete =
        config.proxy.lease_id.is_some() == config.proxy.expires_at_ms.is_some();
    let mutating_http = config
        .policy
        .http_gateway_methods
        .iter()
        .any(|method| !matches!(method.as_str(), "GET" | "HEAD"));
    if config.schema_version != NETWORK_SUPERVISOR_SCHEMA_VERSION
        || config.policy.schema_version != NETWORK_BOUNDARY_SCHEMA_VERSION
        || !safe_network_token(&config.operation_id)
        || !safe_network_token(&config.source_run_id)
        || config.root_pid.is_some() == config.source_address.is_some()
        || config.proxy.max_request_bytes == 0
        || config.proxy.max_response_bytes == 0
        || config.proxy.max_request_bytes > 1024 * 1024 * 1024
        || config.proxy.max_response_bytes > 1024 * 1024 * 1024
        || config.proxy.max_redirects > 10
        || config.proxy.connect_timeout_seconds == 0
        || config.proxy.io_timeout_seconds == 0
        || !mediator_lease_is_complete
        || config
            .proxy
            .lease_id
            .as_deref()
            .is_some_and(|lease_id| !safe_network_token(lease_id))
        || (mutating_http || config.proxy.credential.is_some())
            && config.proxy.lease_id.is_none()
            && config.proxy.transaction.is_none()
        || mutating_http
            && (config.proxy.gateway_id.is_none() || config.proxy.commit_token_id.is_none())
        || config.proxy.gateway_id.is_some() != config.proxy.commit_token_id.is_some()
        || config
            .proxy
            .gateway_id
            .as_deref()
            .is_some_and(|gateway| !safe_network_token(gateway))
        || config
            .proxy
            .commit_token_id
            .as_deref()
            .is_some_and(|token| !safe_network_token(token))
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
    if let Some(credential) = config.proxy.credential.as_ref() {
        validate_http_credential_config(credential)?;
    }
    if let Some(transaction) = config.proxy.transaction.as_ref() {
        validate_http_transaction_policy(transaction)?;
        if config.proxy.lease_id.is_some()
            || config.proxy.expires_at_ms.is_some()
            || transaction.max_request_bytes > 1024 * 1024 * 1024 * 1024
            || transaction.max_response_bytes > 1024 * 1024 * 1024 * 1024
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "transactional HTTP mediation is inactive by default and cannot use a static mediator lease",
            ));
        }
    }
    Ok(())
}

fn validate_http_transaction_policy(policy: &HttpTransactionPolicy) -> io::Result<()> {
    if !safe_network_token(&policy.effect)
        || policy.scopes.is_empty()
        || policy.max_ttl_seconds == 0
        || policy.max_ttl_seconds > 24 * 60 * 60
        || policy.max_requests == 0
        || policy.max_requests > 1_000_000
        || policy.max_request_bytes == 0
        || policy.max_response_bytes == 0
        || policy
            .scopes
            .iter()
            .any(|scope| validate_http_transaction_scope(scope).is_err())
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "HTTP transaction requires a safe effect, canonical scopes, TTL, and bounded request/response budgets",
        ));
    }
    Ok(())
}

fn validate_http_transaction_scope(scope: &HttpTransactionScope) -> io::Result<()> {
    if !matches!(scope.scheme.as_str(), "http" | "https")
        || scope.authority.is_empty()
        || !scope.path_prefix.starts_with('/')
        || scope.path_prefix.contains(['?', '#', '\\', '%'])
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "HTTP transaction scope is not canonical",
        ));
    }
    let candidate = Url::parse(&format!(
        "{}://{}{}",
        scope.scheme, scope.authority, scope.path_prefix
    ))
    .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid HTTP transaction scope"))?;
    if candidate.scheme() != scope.scheme
        || url_authority(&candidate)? != scope.authority
        || candidate.path() != scope.path_prefix
        || candidate.query().is_some()
        || candidate.fragment().is_some()
        || !candidate.username().is_empty()
        || candidate.password().is_some()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "HTTP transaction scope must use canonical scheme, authority, and path",
        ));
    }
    Ok(())
}

fn validate_http_credential_config(config: &HttpCredentialInjection) -> io::Result<()> {
    if !safe_network_token(&config.handle_id)
        || !valid_http_header_name(&config.header_name)
        || connection_hop_header(&config.header_name)
        || matches!(
            config.header_name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "x-gensee-target"
        )
        || config.allowed_url_prefixes.is_empty()
        || config
            .allowed_url_prefixes
            .iter()
            .any(|prefix| validate_credential_url_prefix(prefix).is_err())
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "HTTP credential injection requires a safe handle, header, and exact URL audience",
        ));
    }
    let path = Path::new(&config.value_file);
    if !path.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "HTTP credential value_file must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP credential value_file must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP credential value_file must be owned by the mediator user and mode 0600 or stricter",
        ));
    }
    Ok(())
}

fn validate_credential_url_prefix(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "credential URL audience must be an absolute HTTP(S) URL",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "credential URL audience must be credential-free HTTP(S) origin/path without query or fragment",
        ));
    }
    Ok(url)
}

fn valid_http_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

impl NetworkSupervisor {
    fn append_http_transaction_audit(
        &mut self,
        transaction_id: Option<&str>,
        action: &str,
        disposition: &str,
        reason_code: &str,
    ) -> io::Result<()> {
        if append_bounded_json_line(
            &self.transaction_log_path,
            &HttpTransactionAuditRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                operation_id: self.record.operation_id.clone(),
                transaction_id: transaction_id.map(ToString::to_string),
                action: action.to_string(),
                disposition: disposition.to_string(),
                reason_code: reason_code.to_string(),
                observed_at_ms: unix_millis()?,
            },
            true,
        )? {
            self.record_evidence_rotation("http_transactions")?;
        }
        Ok(())
    }

    fn append_committed_http_transaction_audit(
        &mut self,
        transaction_id: &str,
        action: &str,
        disposition: &str,
        reason_code: &str,
    ) {
        if self
            .append_http_transaction_audit(Some(transaction_id), action, disposition, reason_code)
            .is_err()
        {
            eprintln!(
                "gensee: committed HTTP transaction state but its audit append failed operation={} transaction={transaction_id}",
                self.record.operation_id
            );
            if let Some(operation) = self.operation.as_mut() {
                let _ = operation.record_boundary_violation(
                    "http_transaction_audit_incomplete",
                    "a committed HTTP transaction transition could not be appended to its evidence log",
                );
            }
        }
    }

    fn begin_http_transaction(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
        effect: &str,
        ttl_seconds: u64,
    ) -> Result<(), String> {
        let Some(policy) = self.http_transaction_policy.as_ref() else {
            return Err("http_transaction_policy_unavailable".to_string());
        };
        if !safe_network_token(transaction_id)
            || operation_id != self.record.operation_id
            || effect != policy.effect
            || ttl_seconds == 0
            || ttl_seconds > policy.max_ttl_seconds
        {
            return Err("http_transaction_request_outside_policy".to_string());
        }
        if self
            .record
            .used_http_transaction_ids
            .contains(transaction_id)
        {
            return Err("http_transaction_id_replayed".to_string());
        }
        if self
            .record
            .http_transaction
            .as_ref()
            .is_some_and(|transaction| {
                matches!(
                    transaction.status,
                    HttpTransactionStatus::Prepared | HttpTransactionStatus::Active
                )
            })
        {
            return Err("http_transaction_already_in_progress".to_string());
        }
        let now_ms = unix_millis().map_err(|error| error.to_string())?;
        let prior_record = self.record.clone();
        self.record
            .used_http_transaction_ids
            .insert(transaction_id.to_string());
        self.record.http_transaction = Some(HttpTransactionRecord {
            transaction_id: transaction_id.to_string(),
            operation_id: operation_id.to_string(),
            effect: effect.to_string(),
            status: HttpTransactionStatus::Prepared,
            ttl_seconds,
            activated_at_ms: None,
            expires_at_ms: None,
            requests: 0,
            request_bytes: 0,
            response_bytes: 0,
            response_reservation: None,
            generation: 0,
            updated_at_ms: now_ms,
        });
        if let Some(transaction) = self.record.http_transaction.as_mut() {
            transaction.expires_at_ms =
                Some(now_ms.saturating_add(transaction.ttl_seconds.saturating_mul(1_000)));
        }
        self.record.updated_at_ms = now_ms;
        if let Err(error) = self.persist() {
            self.record = prior_record;
            return Err(error.to_string());
        }
        self.append_committed_http_transaction_audit(
            transaction_id,
            "begin",
            "allow",
            "http_transaction_prepared",
        );
        Ok(())
    }

    fn activate_http_transaction(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
    ) -> Result<(), String> {
        let now_ms = unix_millis().map_err(|error| error.to_string())?;
        self.expire_http_transaction_if_needed(now_ms)
            .map_err(|error| error.to_string())?;
        let prior_record = self.record.clone();
        let Some(transaction) = self.record.http_transaction.as_mut() else {
            return Err("http_transaction_not_prepared".to_string());
        };
        if transaction.transaction_id != transaction_id
            || transaction.operation_id != operation_id
            || operation_id != self.record.operation_id
            || transaction.status != HttpTransactionStatus::Prepared
        {
            return Err("http_transaction_activation_mismatch".to_string());
        }
        transaction.status = HttpTransactionStatus::Active;
        transaction.activated_at_ms = Some(now_ms);
        transaction.generation = transaction.generation.saturating_add(1);
        transaction.updated_at_ms = now_ms;
        self.record.updated_at_ms = now_ms;
        if let Err(error) = self.persist() {
            self.record = prior_record;
            return Err(error.to_string());
        }
        self.append_committed_http_transaction_audit(
            transaction_id,
            "activate",
            "allow",
            "http_transaction_active",
        );
        Ok(())
    }

    fn terminal_http_transaction(
        &mut self,
        transaction_id: &str,
        operation_id: &str,
        status: HttpTransactionStatus,
        action: &str,
    ) -> Result<(), String> {
        let now_ms = unix_millis().map_err(|error| error.to_string())?;
        let Some(transaction) = self.record.http_transaction.as_mut() else {
            return Err("http_transaction_not_found".to_string());
        };
        if transaction.transaction_id != transaction_id
            || transaction.operation_id != operation_id
            || operation_id != self.record.operation_id
            || !matches!(
                transaction.status,
                HttpTransactionStatus::Prepared | HttpTransactionStatus::Active
            )
        {
            return Err("http_transaction_terminal_transition_mismatch".to_string());
        }
        transaction.status = status;
        transaction.updated_at_ms = now_ms;
        self.record.updated_at_ms = now_ms;
        self.cancel_active_http_transports();
        self.persist().map_err(|error| error.to_string())?;
        self.append_committed_http_transaction_audit(
            transaction_id,
            action,
            "allow",
            if status == HttpTransactionStatus::Revoked {
                "http_transaction_revoked"
            } else {
                "http_transaction_ended"
            },
        );
        Ok(())
    }

    fn expire_http_transaction_if_needed(&mut self, now_ms: u64) -> io::Result<bool> {
        let expired_id = self
            .record
            .http_transaction
            .as_mut()
            .and_then(|transaction| {
                (matches!(
                    transaction.status,
                    HttpTransactionStatus::Prepared | HttpTransactionStatus::Active
                ) && transaction
                    .expires_at_ms
                    .is_some_and(|expires_at_ms| now_ms >= expires_at_ms))
                .then(|| {
                    transaction.status = HttpTransactionStatus::Expired;
                    transaction.updated_at_ms = now_ms;
                    transaction.transaction_id.clone()
                })
            });
        let Some(transaction_id) = expired_id else {
            return Ok(false);
        };
        self.record.updated_at_ms = now_ms;
        self.cancel_active_http_transports();
        self.persist()?;
        self.append_committed_http_transaction_audit(
            &transaction_id,
            "expire",
            "deny",
            "http_transaction_expired",
        );
        Ok(true)
    }

    fn cancel_active_http_transports(&mut self) {
        for (_, transport) in std::mem::take(&mut self.active_http_transports) {
            let _ = transport.shutdown(Shutdown::Both);
        }
    }

    fn register_http_transport(&mut self, transport: &TcpStream) -> io::Result<u64> {
        self.next_http_transport_id = self.next_http_transport_id.saturating_add(1);
        let transport_id = self.next_http_transport_id;
        self.active_http_transports
            .insert(transport_id, transport.try_clone()?);
        Ok(transport_id)
    }

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
            transaction_id: None,
            decision,
            response_status: None,
            request_digest: None,
            response_digest: None,
            credential_handle_id: None,
            redirect_target: None,
            bytes_from_client: 0,
            bytes_from_upstream: None,
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
            // On initial activation, install the empty-cgroup policy before
            // attaching the process tree. Once attached, both the root and
            // future descendants inherit enforcement without an ambient-
            // network window. On rotation, the prior table remains active.
            if let Some(pid) = self.record.root_pid {
                let attachment = gensee_crate_linux::attach_process_tree_to_cgroup(
                    pid,
                    &gensee_crate_linux::default_agent_cgroup_path(&self.record.operation_id),
                );
                if !matches!(attachment, Ok(ref attached) if attached.contains(&pid)) {
                    let _ = gensee_crate_linux::delete_nftables_table_if_exists(&new_table);
                    return Err(match attachment {
                        Err(error) => error,
                        Ok(_) => io::Error::new(
                            ErrorKind::PermissionDenied,
                            "network supervisor could not attach the operation root to its cgroup",
                        ),
                    });
                }
            }
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

    #[cfg(target_os = "linux")]
    fn sample_kernel_network_attempts(
        &mut self,
        table_names: &Arc<Mutex<Vec<String>>>,
    ) -> io::Result<()> {
        let Some(monitor) = self.attempt_monitor.as_ref() else {
            return Ok(());
        };
        let (attempts, dropped, exited) = monitor.drain();
        self.process_kernel_network_attempts(attempts, dropped, exited, table_names)
    }

    #[cfg(any(target_os = "linux", test))]
    fn process_kernel_network_attempts(
        &mut self,
        attempts: Vec<gensee_crate_linux::LinuxNetworkAttemptEvent>,
        dropped: u64,
        exited: bool,
        table_names: &Arc<Mutex<Vec<String>>>,
    ) -> io::Result<()> {
        if dropped > 0 {
            if let Some(operation) = self.operation.as_mut() {
                operation.record_boundary_violation(
                    "network_attempt_event_loss",
                    &format!("kernel network trace channel dropped {dropped} events"),
                )?;
            }
        }
        if exited {
            if let Some(operation) = self.operation.as_mut() {
                operation.record_boundary_violation(
                    "network_attempt_sensor_stopped",
                    "nftables trace monitor stopped; hard deny remains active but automatic capability-fault resolution is disabled",
                )?;
            }
            #[cfg(target_os = "linux")]
            {
                self.attempt_monitor = None;
            }
        }
        let suppressed_fault_count_before = self.record.suppressed_fault_count;
        for attempt in attempts {
            let trace_key = format!(
                "{}:{}:{}:{}:{}",
                attempt.table_name,
                attempt.trace_id,
                attempt.destination,
                match attempt.protocol {
                    gensee_crate_linux::LinuxNetworkProtocol::Tcp => "tcp",
                    gensee_crate_linux::LinuxNetworkProtocol::Udp => "udp",
                },
                attempt.port
            );
            if !self.observed_attempt_traces.insert(trace_key.clone()) {
                continue;
            }
            self.observed_attempt_trace_order
                .push_back(trace_key.clone());
            if self.observed_attempt_traces.len() > MAX_OBSERVED_ATTEMPT_TRACES {
                if let Some(evicted) = self.observed_attempt_trace_order.pop_front() {
                    self.observed_attempt_traces.remove(&evicted);
                }
                if !self.dedupe_eviction_recorded {
                    self.dedupe_eviction_recorded = true;
                    if let Some(operation) = self.operation.as_mut() {
                        operation.record_boundary_violation(
                            "network_attempt_dedupe_eviction_started",
                            "kernel network-attempt deduplication began bounded oldest-first eviction",
                        )?;
                    }
                }
            }
            let observed_at_ms = unix_millis()?;
            if observed_at_ms.saturating_sub(self.fault_rate_window_started_at_ms) >= 1_000 {
                self.record.updated_at_ms = observed_at_ms;
                self.persist()?;
                self.fault_rate_window_started_at_ms = observed_at_ms;
                self.detailed_faults_in_window = 0;
                self.fault_rate_violation_recorded_in_window = false;
            }
            if self.detailed_faults_in_window >= MAX_DETAILED_FAULTS_PER_SECOND {
                self.record.suppressed_fault_count =
                    self.record.suppressed_fault_count.saturating_add(1);
                if !self.fault_rate_violation_recorded_in_window {
                    self.fault_rate_violation_recorded_in_window = true;
                    if let Some(operation) = self.operation.as_mut() {
                        operation.record_boundary_violation(
                            "network_attempt_fault_rate_limited",
                            "additional denied network attempts were counted after the detailed evidence rate limit",
                        )?;
                    }
                }
                continue;
            }
            self.detailed_faults_in_window = self.detailed_faults_in_window.saturating_add(1);
            let subject = if let Some(source_address) = self.record.source_address.clone() {
                CapabilityFaultSubject::NetworkPeer { source_address }
            } else if let Some((pid, start_time_ticks)) = self
                .operation
                .as_mut()
                .ok_or_else(|| io::Error::other("operation supervisor unavailable"))?
                .root_process_identity()?
            {
                CapabilityFaultSubject::LocalProcess {
                    pid,
                    start_time_ticks,
                }
            } else {
                if let Some(operation) = self.operation.as_mut() {
                    operation.record_boundary_violation(
                        "network_attempt_subject_unavailable",
                        "kernel denied an endpoint but the operation subject identity was unavailable",
                    )?;
                }
                continue;
            };
            let fault_digest = format!("{:x}", Sha256::digest(trace_key.as_bytes()));
            let fault = CapabilityFault {
                schema_version:
                    gensee_crate_rules::capability_fault::CAPABILITY_FAULT_SCHEMA_VERSION,
                fault_id: format!("fault_nft_{}", &fault_digest[..24]),
                operation_id: self.record.operation_id.clone(),
                source_run_id: self.record.source_run_id.clone(),
                subject,
                effect: BoundaryEffectObservation::NetworkConnect {
                    destination: attempt.destination,
                    protocol: match attempt.protocol {
                        gensee_crate_linux::LinuxNetworkProtocol::Tcp => "tcp".to_string(),
                        gensee_crate_linux::LinuxNetworkProtocol::Udp => "udp".to_string(),
                    },
                    port: attempt.port,
                },
                requested_ttl_seconds: self.record.policy.max_in_place_lease_ttl_seconds,
                observed_at_ms,
            };
            let (resolution, effect) = self.resolve_fault(&fault, table_names)?;
            self.append_fault_evidence(&fault, &resolution)?;
            if let Some(effect) = effect.as_ref() {
                self.append_effect(effect)?;
            }
        }
        if self.record.suppressed_fault_count != suppressed_fault_count_before {
            self.record.updated_at_ms = unix_millis()?;
            self.persist()?;
        }
        Ok(())
    }

    fn append_counter_evidence(
        &mut self,
        evidence: &NetworkCounterEvidenceRecord,
    ) -> io::Result<()> {
        if append_bounded_json_line(&self.counter_log_path, evidence, true)? {
            self.record_evidence_rotation("counters")?;
        }
        Ok(())
    }

    fn append_fault_evidence(
        &mut self,
        fault: &CapabilityFault,
        resolution: &CapabilityFaultResolution,
    ) -> io::Result<()> {
        if append_bounded_json_line(
            &self.fault_log_path,
            &CapabilityFaultEvidenceRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                fault: fault.clone(),
                resolution: resolution.clone(),
                received_at_ms: unix_millis()?,
            },
            true,
        )? {
            self.record_evidence_rotation("faults")?;
        }
        Ok(())
    }

    fn append_effect(&mut self, effect: &NetworkEffectRecord) -> io::Result<()> {
        if append_bounded_json_line(&self.event_log_path, effect, true)? {
            self.record_evidence_rotation("effects")?;
        }
        if let Some(operation) = self.operation.as_mut() {
            operation.record_network_effect(&effect.event, &effect.decision)?;
        }
        Ok(())
    }

    fn append_http_mediator_audit(
        &mut self,
        request: &ParsedProxyRequest,
        disposition: &str,
        reason_code: &str,
    ) -> io::Result<()> {
        if append_bounded_json_line(
            &self.mediator_log_path,
            &HttpMediatorAuditRecord {
                schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                operation_id: self.record.operation_id.clone(),
                source_run_id: self.record.source_run_id.clone(),
                method: request.method.clone(),
                target: redacted_url_for_evidence(&request.url),
                request_digest: mediated_http_request_digest(
                    &request.method,
                    &request.url,
                    &request.headers,
                    &request.body,
                ),
                lease_id: self.http_mediator_lease_id.clone(),
                transaction_id: self
                    .record
                    .http_transaction
                    .as_ref()
                    .map(|transaction| transaction.transaction_id.clone()),
                disposition: disposition.to_string(),
                reason_code: reason_code.to_string(),
                observed_at_ms: unix_millis()?,
            },
            true,
        )? {
            self.record_evidence_rotation("http_mediator")?;
        }
        Ok(())
    }

    fn record_evidence_rotation(&mut self, log_kind: &str) -> io::Result<()> {
        // Rotation means the retained evidence is incomplete. Treat it as an
        // attestation violation intentionally so a capacity-only truncation
        // cannot be promoted or used as a clean live-fork parent.
        let count = self
            .record
            .evidence_rotation_count
            .entry(log_kind.to_string())
            .or_default();
        *count = count.saturating_add(1);
        self.record.updated_at_ms = unix_millis()?;
        self.persist()?;
        if let Some(operation) = self.operation.as_mut() {
            operation.record_boundary_violation(
                "network_evidence_log_rotated",
                &format!("{log_kind} evidence exceeded its retained log bound"),
            )?;
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
            let network_entries_skipped = state
                .operation
                .as_mut()
                .ok_or_else(|| io::Error::other("operation supervisor unavailable"))?
                .network_recovery_skipped_entry_count()?;
            NetworkSupervisorResponse {
                ok: true,
                decision: None,
                resolution: None,
                record: Some(state.record.clone()),
                operation_recovery_health: Some(OperationRecoveryHealth {
                    network_entries_skipped,
                }),
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
                        operation_recovery_health: None,
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
                        operation_recovery_health: None,
                        error: Some(error.to_string()),
                    }
                }
            }
        }
        NetworkSupervisorRequest::RevokeHttpMediator { lease_id } => {
            let mut state = lock_supervisor(&supervisor)?;
            let response = if state.http_mediator_lease_id.as_deref() == Some(&lease_id) {
                state.record.revoked_http_mediator_leases.insert(lease_id);
                state.cancel_active_http_transports();
                state.record.updated_at_ms = unix_millis()?;
                state.persist()?;
                NetworkSupervisorResponse {
                    ok: true,
                    decision: None,
                    resolution: None,
                    record: Some(state.record.clone()),
                    operation_recovery_health: None,
                    error: None,
                }
            } else {
                NetworkSupervisorResponse {
                    ok: false,
                    decision: None,
                    resolution: None,
                    record: None,
                    operation_recovery_health: None,
                    error: Some(
                        "HTTP mediator lease does not belong to this operation".to_string(),
                    ),
                }
            };
            response
        }
        NetworkSupervisorRequest::BeginHttpTransaction {
            transaction_id,
            operation_id,
            effect,
            ttl_seconds,
        } => {
            let mut state = lock_supervisor(&supervisor)?;
            let result =
                state.begin_http_transaction(&transaction_id, &operation_id, &effect, ttl_seconds);
            http_transaction_control_response(&mut state, &transaction_id, "begin", result)?
        }
        NetworkSupervisorRequest::ActivateHttpTransaction {
            transaction_id,
            operation_id,
        } => {
            let mut state = lock_supervisor(&supervisor)?;
            let result = state.activate_http_transaction(&transaction_id, &operation_id);
            http_transaction_control_response(&mut state, &transaction_id, "activate", result)?
        }
        NetworkSupervisorRequest::RevokeHttpTransaction {
            transaction_id,
            operation_id,
        } => {
            let mut state = lock_supervisor(&supervisor)?;
            let result = state.terminal_http_transaction(
                &transaction_id,
                &operation_id,
                HttpTransactionStatus::Revoked,
                "revoke",
            );
            http_transaction_control_response(&mut state, &transaction_id, "revoke", result)?
        }
        NetworkSupervisorRequest::EndHttpTransaction {
            transaction_id,
            operation_id,
        } => {
            let mut state = lock_supervisor(&supervisor)?;
            let result = state.terminal_http_transaction(
                &transaction_id,
                &operation_id,
                HttpTransactionStatus::Ended,
                "end",
            );
            http_transaction_control_response(&mut state, &transaction_id, "end", result)?
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
                        transaction_id: None,
                        decision: decision.clone(),
                        response_status: None,
                        request_digest: None,
                        response_digest: None,
                        credential_handle_id: None,
                        redirect_target: None,
                        bytes_from_client: 0,
                        bytes_from_upstream: None,
                        bytes_to_client: 0,
                        completed_at_ms: unix_millis()?,
                    };
                    state.append_effect(&effect)?;
                    NetworkSupervisorResponse {
                        ok: true,
                        decision: Some(decision),
                        resolution: None,
                        record: None,
                        operation_recovery_health: None,
                        error: None,
                    }
                }
                Err(error) => NetworkSupervisorResponse {
                    ok: false,
                    decision: None,
                    resolution: None,
                    record: None,
                    operation_recovery_health: None,
                    error: Some(error.to_string()),
                },
            }
        }
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")
}

fn http_transaction_control_response(
    state: &mut NetworkSupervisor,
    transaction_id: &str,
    action: &str,
    result: Result<(), String>,
) -> io::Result<NetworkSupervisorResponse> {
    match result {
        Ok(()) => Ok(NetworkSupervisorResponse {
            ok: true,
            decision: None,
            resolution: None,
            record: Some(state.record.clone()),
            operation_recovery_health: None,
            error: None,
        }),
        Err(reason_code) => {
            state.append_http_transaction_audit(
                Some(transaction_id),
                action,
                "deny",
                &reason_code,
            )?;
            Ok(NetworkSupervisorResponse {
                ok: false,
                decision: None,
                resolution: None,
                record: Some(state.record.clone()),
                operation_recovery_health: None,
                error: Some(reason_code),
            })
        }
    }
}

fn handle_http_proxy_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    _table_names: Arc<Mutex<Vec<String>>>,
    config: HttpGatewayConfig,
) -> io::Result<()> {
    let allowed_client = config
        .client_address
        .parse::<IpAddr>()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid proxy client address"))?;
    if peer.ip() != allowed_client {
        lock_supervisor(&supervisor)?.append_http_transaction_audit(
            None,
            "request",
            "deny",
            "http_transaction_wrong_client_identity",
        )?;
        write_proxy_error(&mut client, 403, "client is outside the gateway audience")?;
        return Ok(());
    }
    let transport_id = lock_supervisor(&supervisor)?.register_http_transport(&client)?;
    let _transport_guard = HttpTransportGuard {
        supervisor: Arc::clone(&supervisor),
        transport_id,
    };
    client.set_read_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;
    client.set_write_timeout(Some(Duration::from_secs(config.io_timeout_seconds)))?;
    let request = match read_proxy_request(&mut client, config.max_request_bytes) {
        Ok(request) => request,
        Err(error) => {
            let status = if error.to_string().contains("byte budget") {
                413
            } else {
                400
            };
            write_proxy_error(&mut client, status, "invalid mediated HTTP request")?;
            return Ok(());
        }
    };
    let now_ms = unix_millis()?;
    {
        let mut state = lock_supervisor(&supervisor)?;
        state.expire_http_transaction_if_needed(now_ms)?;
        if !http_mediator_is_active(&state, &config, now_ms) {
            state.append_http_mediator_audit(&request, "deny", "http_mediator_lease_inactive")?;
            let transaction_id = state
                .record
                .http_transaction
                .as_ref()
                .map(|transaction| transaction.transaction_id.clone());
            state.append_http_transaction_audit(
                transaction_id.as_deref(),
                "request",
                "deny",
                "http_transaction_inactive",
            )?;
            write_proxy_error(
                &mut client,
                403,
                "HTTP mediator lease is expired or revoked",
            )?;
            return Ok(());
        }
        if !state
            .record
            .policy
            .http_gateway_methods
            .contains(&request.method)
        {
            state.append_http_mediator_audit(
                &request,
                "deny",
                "http_method_outside_mediator_lease",
            )?;
            write_proxy_error(
                &mut client,
                405,
                "HTTP method is outside the mediator lease",
            )?;
            return Ok(());
        }
    }
    if matches!(request.method.as_str(), "GET" | "HEAD") && !request.body.is_empty() {
        lock_supervisor(&supervisor)?.append_http_mediator_audit(
            &request,
            "deny",
            "read_only_method_has_body",
        )?;
        write_proxy_error(
            &mut client,
            400,
            "read-only HTTP methods cannot carry a body",
        )?;
        return Ok(());
    }
    match execute_mediated_http(request, Arc::clone(&supervisor), &config) {
        Ok(response) => write_mediated_http_response(&mut client, response),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            write_proxy_error(&mut client, 403, &error.to_string())
        }
        Err(error) => {
            write_proxy_error(&mut client, 502, "mediated upstream request failed")?;
            Err(error)
        }
    }
}

#[derive(Debug)]
struct MediatedHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn http_mediator_is_active(
    supervisor: &NetworkSupervisor,
    config: &HttpGatewayConfig,
    now_ms: u64,
) -> bool {
    if config.transaction.is_some() {
        return supervisor
            .record
            .http_transaction
            .as_ref()
            .is_some_and(|transaction| {
                transaction.operation_id == supervisor.record.operation_id
                    && transaction.status == HttpTransactionStatus::Active
                    && transaction
                        .expires_at_ms
                        .is_some_and(|expires_at_ms| now_ms < expires_at_ms)
            });
    }
    match (config.lease_id.as_deref(), config.expires_at_ms) {
        (Some(lease_id), Some(expires_at_ms)) => {
            now_ms < expires_at_ms
                && !supervisor
                    .record
                    .revoked_http_mediator_leases
                    .contains(lease_id)
        }
        (None, None) => true,
        _ => false,
    }
}

fn http_transaction_scope_allows(policy: &HttpTransactionPolicy, url: &Url) -> bool {
    let lower_path = url.path().to_ascii_lowercase();
    if url.path().contains('\\')
        || ["%25", "%2f", "%5c", "%2e"]
            .iter()
            .any(|encoded| lower_path.contains(encoded))
    {
        return false;
    }
    let Ok(authority) = url_authority(url) else {
        return false;
    };
    policy.scopes.iter().any(|scope| {
        scope.scheme == url.scheme()
            && scope.authority == authority
            && (scope.path_prefix == "/"
                || url.path() == scope.path_prefix
                || (url.path().starts_with(&scope.path_prefix)
                    && (scope.path_prefix.ends_with('/')
                        || url.path().as_bytes().get(scope.path_prefix.len()).copied()
                            == Some(b'/'))))
    })
}

#[derive(Debug, Clone)]
struct HttpHopReservation {
    transaction_id: String,
    reservation_id: String,
    transaction_generation: u64,
    max_response_bytes: u64,
    expires_at_ms: u64,
}

fn check_http_transaction_hop(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    config: &HttpGatewayConfig,
    url: &Url,
) -> io::Result<()> {
    let Some(policy) = config.transaction.as_ref() else {
        return Ok(());
    };
    let mut state = lock_supervisor(supervisor)?;
    let now_ms = unix_millis()?;
    state.expire_http_transaction_if_needed(now_ms)?;
    if !http_transaction_scope_allows(policy, url) {
        let transaction_id = state
            .record
            .http_transaction
            .as_ref()
            .map(|transaction| transaction.transaction_id.clone());
        state.append_http_transaction_audit(
            transaction_id.as_deref(),
            "request",
            "deny",
            "http_transaction_url_outside_scope",
        )?;
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction target is outside its immutable scope",
        ));
    }
    if !http_mediator_is_active(&state, config, now_ms) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction is inactive",
        ));
    }
    Ok(())
}

fn reserve_http_transaction_hop(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    config: &HttpGatewayConfig,
    url: &Url,
    request_bytes: u64,
) -> io::Result<Option<HttpHopReservation>> {
    let Some(policy) = config.transaction.as_ref() else {
        return Ok(None);
    };
    let mut state = lock_supervisor(supervisor)?;
    let now_ms = unix_millis()?;
    state.expire_http_transaction_if_needed(now_ms)?;
    if !http_transaction_scope_allows(policy, url) {
        let transaction_id = state
            .record
            .http_transaction
            .as_ref()
            .map(|transaction| transaction.transaction_id.clone());
        state.append_http_transaction_audit(
            transaction_id.as_deref(),
            "request",
            "deny",
            "http_transaction_url_outside_scope",
        )?;
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction target is outside its immutable scope",
        ));
    }
    if !http_mediator_is_active(&state, config, now_ms) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction is inactive",
        ));
    }
    let transaction =
        state.record.http_transaction.as_mut().ok_or_else(|| {
            io::Error::new(ErrorKind::PermissionDenied, "HTTP transaction is absent")
        })?;
    let next_requests = transaction.requests.saturating_add(1);
    let next_request_bytes = transaction.request_bytes.saturating_add(request_bytes);
    let remaining_response_bytes = policy
        .max_response_bytes
        .saturating_sub(transaction.response_bytes);
    if transaction.response_reservation.is_some() {
        let transaction_id = transaction.transaction_id.clone();
        state.append_http_transaction_audit(
            Some(&transaction_id),
            "request",
            "deny",
            "http_transaction_response_reservation_in_flight",
        )?;
        return Err(io::Error::new(
            ErrorKind::WouldBlock,
            "HTTP transaction already has an in-flight response reservation",
        ));
    }
    if next_requests > policy.max_requests || next_request_bytes > policy.max_request_bytes {
        let transaction_id = transaction.transaction_id.clone();
        state.append_http_transaction_audit(
            Some(&transaction_id),
            "request",
            "deny",
            "http_transaction_request_budget_exhausted",
        )?;
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction request budget is exhausted",
        ));
    }
    if remaining_response_bytes == 0 {
        let transaction_id = transaction.transaction_id.clone();
        state.append_http_transaction_audit(
            Some(&transaction_id),
            "request",
            "deny",
            "http_transaction_response_budget_exhausted",
        )?;
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction response budget is exhausted",
        ));
    }
    transaction.requests = next_requests;
    transaction.request_bytes = next_request_bytes;
    transaction.updated_at_ms = now_ms;
    let transaction_id = transaction.transaction_id.clone();
    let reservation_id = format!("http_response_{}", Uuid::new_v4().simple());
    let transaction_generation = transaction.generation;
    let expires_at_ms = transaction.expires_at_ms.unwrap_or(now_ms);
    transaction.response_reservation = Some(HttpResponseReservation {
        reservation_id: reservation_id.clone(),
        transaction_generation,
        max_response_bytes: remaining_response_bytes,
        created_at_ms: now_ms,
    });
    state.record.updated_at_ms = now_ms;
    state.persist()?;
    state.append_http_transaction_audit(
        Some(&transaction_id),
        "request",
        "allow",
        "http_transaction_hop_authorized",
    )?;
    Ok(Some(HttpHopReservation {
        transaction_id,
        reservation_id,
        transaction_generation,
        max_response_bytes: remaining_response_bytes,
        expires_at_ms,
    }))
}

fn commit_http_transaction_response(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    config: &HttpGatewayConfig,
    reservation: &HttpHopReservation,
    response_bytes: u64,
) -> io::Result<()> {
    let Some(policy) = config.transaction.as_ref() else {
        return Ok(());
    };
    let mut state = lock_supervisor(supervisor)?;
    let now_ms = unix_millis()?;
    state.expire_http_transaction_if_needed(now_ms)?;
    if !http_mediator_is_active(&state, config, now_ms) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction ended before the response completed",
        ));
    }
    let transaction = state
        .record
        .http_transaction
        .as_mut()
        .filter(|transaction| transaction.transaction_id == reservation.transaction_id)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "HTTP transaction identity changed during the request",
            )
        })?;
    let reservation_matches = transaction
        .response_reservation
        .as_ref()
        .is_some_and(|active| {
            active.reservation_id == reservation.reservation_id
                && active.transaction_generation == reservation.transaction_generation
                && transaction.generation == reservation.transaction_generation
        });
    if !reservation_matches {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP response reservation is no longer active",
        ));
    }
    let next_response_bytes = transaction.response_bytes.saturating_add(response_bytes);
    if response_bytes > reservation.max_response_bytes
        || next_response_bytes > policy.max_response_bytes
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction response budget is exhausted",
        ));
    }
    let prior_record = state.record.clone();
    let transaction =
        state.record.http_transaction.as_mut().ok_or_else(|| {
            io::Error::new(ErrorKind::PermissionDenied, "HTTP transaction is absent")
        })?;
    transaction.response_bytes = next_response_bytes;
    transaction.response_reservation = None;
    transaction.updated_at_ms = now_ms;
    state.record.updated_at_ms = now_ms;
    if let Err(error) = state.persist() {
        state.record = prior_record;
        return Err(error);
    }
    Ok(())
}

fn release_http_transaction_reservation(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    reservation: &HttpHopReservation,
) -> io::Result<()> {
    let mut state = lock_supervisor(supervisor)?;
    let prior_record = state.record.clone();
    let transaction = state
        .record
        .http_transaction
        .as_mut()
        .filter(|transaction| transaction.transaction_id == reservation.transaction_id)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "HTTP transaction identity changed during reservation release",
            )
        })?;
    if !transaction
        .response_reservation
        .as_ref()
        .is_some_and(|active| {
            active.reservation_id == reservation.reservation_id
                && active.transaction_generation == reservation.transaction_generation
        })
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP response reservation is no longer owned by this request",
        ));
    }
    transaction.response_reservation = None;
    transaction.updated_at_ms = unix_millis()?;
    state.record.updated_at_ms = transaction.updated_at_ms;
    if let Err(error) = state.persist() {
        state.record = prior_record;
        return Err(error);
    }
    Ok(())
}

fn validate_http_transaction_reservation_before_upstream(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    config: &HttpGatewayConfig,
    reservation: &HttpHopReservation,
) -> io::Result<()> {
    let mut state = lock_supervisor(supervisor)?;
    let now_ms = unix_millis()?;
    state.expire_http_transaction_if_needed(now_ms)?;
    if !http_mediator_is_active(&state, config, now_ms) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP transaction was revoked before upstream connect",
        ));
    }
    let valid = state
        .record
        .http_transaction
        .as_ref()
        .is_some_and(|transaction| {
            transaction.transaction_id == reservation.transaction_id
                && transaction.generation == reservation.transaction_generation
                && transaction
                    .response_reservation
                    .as_ref()
                    .is_some_and(|active| {
                        active.reservation_id == reservation.reservation_id
                            && active.transaction_generation == reservation.transaction_generation
                    })
        });
    if !valid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP response reservation was invalidated before upstream connect",
        ));
    }
    Ok(())
}

fn execute_mediated_http(
    request: ParsedProxyRequest,
    supervisor: Arc<Mutex<NetworkSupervisor>>,
    config: &HttpGatewayConfig,
) -> io::Result<MediatedHttpResponse> {
    let mut current_url = request.url.clone();
    let method = request.method.clone();
    let mut redirects_followed = 0u32;
    loop {
        let now_ms = unix_millis()?;
        {
            let mut state = lock_supervisor(&supervisor)?;
            state.expire_http_transaction_if_needed(now_ms)?;
            if !http_mediator_is_active(&state, config, now_ms) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "HTTP mediator lease expired or was revoked before the effect completed",
                ));
            }
        }
        // Client-originated headers are scoped to the URL authority the
        // client requested. A cross-origin redirect is a new audience; only
        // mediator-owned headers (including an independently scoped brokered
        // credential) may cross it.
        let hop_headers = if same_http_origin(&request.url, &current_url) {
            request.headers.as_slice()
        } else {
            &[]
        };
        let request_digest =
            mediated_http_request_digest(&method, &current_url, hop_headers, &request.body);
        // Scope is checked independently before DNS. The single-in-flight
        // response reservation is acquired later, immediately before the
        // upstream effect, after all other preflight work succeeds.
        check_http_transaction_hop(&supervisor, config, &current_url)?;
        let transaction_id = if config.transaction.is_some() {
            lock_supervisor(&supervisor)?
                .record
                .http_transaction
                .as_ref()
                .map(|transaction| transaction.transaction_id.clone())
        } else {
            None
        };
        let (address, event, decision) = authorize_mediated_http_hop(
            &supervisor,
            &method,
            &current_url,
            &request_digest,
            config.lease_id.clone(),
        )?;
        let credential = config
            .credential
            .as_ref()
            .filter(|credential| credential_applies_to_url(credential, &current_url))
            .map(|credential| {
                load_http_credential(credential).map(|value| {
                    (
                        credential.handle_id.clone(),
                        credential.header_name.clone(),
                        value,
                    )
                })
            })
            .transpose()?;
        let credential_handle_id = credential.as_ref().map(|(handle, _, _)| handle.clone());
        if !matches!(method.as_str(), "GET" | "HEAD") {
            let mediator_active = {
                let state = lock_supervisor(&supervisor)?;
                http_mediator_is_active(&state, config, unix_millis()?)
            };
            if !mediator_active {
                lock_supervisor(&supervisor)?.append_effect(&NetworkEffectRecord {
                    schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                    fault_id: None,
                    event,
                    decision,
                    lease_id: config.lease_id.clone(),
                    transaction_id: transaction_id.clone(),
                    response_status: Some(403),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_from_upstream: None,
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                })?;
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "HTTP mediator lease expired or was revoked before commit",
                ));
            }
            let gateway = config.gateway_id.as_deref().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::PermissionDenied,
                    "mutating HTTP effect has no trusted gateway identity",
                )
            })?;
            let token_id = config.commit_token_id.as_deref().ok_or_else(|| {
                io::Error::new(
                    ErrorKind::PermissionDenied,
                    "mutating HTTP effect has no one-use commit token",
                )
            })?;
            let (operation_id, source_run_id) = {
                let state = lock_supervisor(&supervisor)?;
                (
                    state.record.operation_id.clone(),
                    state.record.source_run_id.clone(),
                )
            };
            let commit_result = crate::tclone::consume_external_commit_token_for_gateway(
                token_id,
                gateway,
                current_url.as_str(),
                &method,
                &request_digest,
                Some(&operation_id),
                Some(&source_run_id),
            );
            if let Err(error) = commit_result {
                lock_supervisor(&supervisor)?.append_effect(&NetworkEffectRecord {
                    schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                    fault_id: None,
                    event,
                    decision,
                    lease_id: config.lease_id.clone(),
                    transaction_id: transaction_id.clone(),
                    response_status: Some(403),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_from_upstream: None,
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                })?;
                return Err(io::Error::new(ErrorKind::PermissionDenied, error));
            }
        }
        let transaction_reservation = reserve_http_transaction_hop(
            &supervisor,
            config,
            &current_url,
            request.body.len() as u64,
        )?;
        let mut hop_config = config.clone();
        if let Some(reservation) = transaction_reservation.as_ref() {
            hop_config.max_response_bytes = hop_config
                .max_response_bytes
                .min(reservation.max_response_bytes);
            hop_config.expires_at_ms = Some(reservation.expires_at_ms);
            validate_http_transaction_reservation_before_upstream(
                &supervisor,
                config,
                reservation,
            )?;
        }
        let upstream = perform_pinned_http_request(
            &method,
            &current_url,
            address,
            hop_headers,
            &request.body,
            credential.as_ref(),
            &hop_config,
        );
        let response = match upstream {
            Ok(response) => response,
            Err(error) => {
                let reservation_release = transaction_reservation
                    .as_ref()
                    .map(|reservation| {
                        release_http_transaction_reservation(&supervisor, reservation)
                    })
                    .transpose();
                let effect = NetworkEffectRecord {
                    schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                    fault_id: None,
                    event,
                    decision,
                    lease_id: config.lease_id.clone(),
                    transaction_id: transaction_reservation
                        .as_ref()
                        .map(|reservation| reservation.transaction_id.clone()),
                    response_status: Some(502),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_from_upstream: None,
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                };
                lock_supervisor(&supervisor)?.append_effect(&effect)?;
                // Evidence for the attempted upstream effect must survive a
                // reservation-release failure. A failed release deliberately
                // leaves the durable reservation in place, so later requests
                // remain fail closed.
                if let Err(release_error) = reservation_release {
                    return Err(io::Error::new(
                        release_error.kind(),
                        format!(
                            "mediated upstream request failed; response reservation remained fail closed: {release_error}"
                        ),
                    ));
                }
                return Err(error);
            }
        };
        let response_digest = mediated_http_response_digest(&response);
        if let Some(reservation) = transaction_reservation.as_ref() {
            if let Err(error) = commit_http_transaction_response(
                &supervisor,
                config,
                reservation,
                response.body.len() as u64,
            ) {
                let denied_decision = NetworkBoundaryDecision {
                    disposition: NetworkBoundaryDisposition::Deny,
                    reason_code: "http_transaction_late_response_denied".to_string(),
                    lease: None,
                };
                lock_supervisor(&supervisor)?.append_effect(&NetworkEffectRecord {
                    schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                    fault_id: None,
                    event,
                    decision: denied_decision,
                    lease_id: config.lease_id.clone(),
                    transaction_id: Some(reservation.transaction_id.clone()),
                    response_status: Some(response.status),
                    request_digest: Some(request_digest),
                    response_digest: Some(response_digest),
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_from_upstream: Some(response.body.len() as u64),
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                })?;
                return Err(error);
            }
        }
        let redirect = redirect_target(&current_url, &response)?;
        let effect = NetworkEffectRecord {
            schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
            fault_id: None,
            event,
            decision,
            lease_id: config.lease_id.clone(),
            transaction_id: transaction_reservation
                .as_ref()
                .map(|reservation| reservation.transaction_id.clone()),
            response_status: Some(response.status),
            request_digest: Some(request_digest),
            response_digest: Some(response_digest),
            credential_handle_id,
            redirect_target: redirect.as_ref().map(redacted_url_for_evidence),
            bytes_from_client: request.body.len() as u64,
            bytes_from_upstream: Some(response.body.len() as u64),
            bytes_to_client: response.body.len() as u64,
            completed_at_ms: unix_millis()?,
        };
        lock_supervisor(&supervisor)?.append_effect(&effect)?;

        if let Some(target) = redirect {
            let safe_to_repeat = matches!(method.as_str(), "GET" | "HEAD");
            if safe_to_repeat && redirects_followed < config.max_redirects {
                redirects_followed = redirects_followed.saturating_add(1);
                current_url = target;
                continue;
            }
        }
        return Ok(response);
    }
}

fn authorize_mediated_http_hop(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    method: &str,
    url: &Url,
    request_digest: &str,
    lease_id: Option<String>,
) -> io::Result<(SocketAddr, NetworkBoundaryEvent, NetworkBoundaryDecision)> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "HTTP authority is missing"))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidData, "HTTP authority has no usable port")
    })?;
    let addresses = resolve_authority(host, port)?;
    if addresses.is_empty() {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            "HTTP authority did not resolve",
        ));
    }
    authorize_mediated_http_addresses(supervisor, method, url, request_digest, lease_id, addresses)
}

/// Authorize the complete resolver answer as one effect. Keeping this logic
/// separate makes the all-address fail-closed invariant directly testable
/// without relying on mutable external DNS.
fn authorize_mediated_http_addresses(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
    method: &str,
    url: &Url,
    request_digest: &str,
    lease_id: Option<String>,
    addresses: Vec<SocketAddr>,
) -> io::Result<(SocketAddr, NetworkBoundaryEvent, NetworkBoundaryDecision)> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            "HTTP authority did not resolve",
        ));
    }
    let now_ms = unix_millis()?;
    let state = lock_supervisor(supervisor)?;
    let operation_id = state.record.operation_id.clone();
    let source_run_id = state.record.source_run_id.clone();
    let process_id = state.record.root_pid.unwrap_or(1);
    let transaction_id = state
        .record
        .http_transaction
        .as_ref()
        .map(|transaction| transaction.transaction_id.clone());
    drop(state);
    let authority = url_authority(url)?;
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
                method: method.to_string(),
                authority: authority.clone(),
            },
            observed_at_ms: now_ms,
            requested_ttl_seconds: None,
        };
        let decision = lock_supervisor(supervisor)?.decide(&mut event)?;
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
                lease_id: lease_id.clone(),
                transaction_id: transaction_id.clone(),
                response_status: Some(403),
                request_digest: Some(request_digest.to_string()),
                response_digest: None,
                credential_handle_id: None,
                redirect_target: None,
                bytes_from_client: 0,
                bytes_from_upstream: None,
                bytes_to_client: 0,
                completed_at_ms: unix_millis()?,
            };
            lock_supervisor(supervisor)?.append_effect(&effect)?;
        }
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "resolved HTTP destination is outside the operation envelope",
        ));
    }
    chosen.ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP effect is not brokerable by this operation",
        )
    })
}

fn perform_pinned_http_request(
    method: &str,
    url: &Url,
    address: SocketAddr,
    headers: &[(String, String)],
    body: &[u8],
    credential: Option<&(String, String, Zeroizing<String>)>,
    config: &HttpGatewayConfig,
) -> io::Result<MediatedHttpResponse> {
    let mut connect_timeout = Duration::from_secs(config.connect_timeout_seconds);
    let mut io_timeout = Duration::from_secs(config.io_timeout_seconds);
    if let Some(expires_at_ms) = config.expires_at_ms {
        let remaining_ms = expires_at_ms.saturating_sub(unix_millis()?);
        if remaining_ms == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "HTTP mediator lease expired before the upstream effect",
            ));
        }
        let remaining = Duration::from_millis(remaining_ms);
        connect_timeout = connect_timeout.min(remaining);
        io_timeout = io_timeout.min(remaining);
    }
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        // An inherited HTTP(S)_PROXY would move the actual socket outside the
        // address we just authorized and pinned.
        .try_proxy_from_env(false)
        .timeout_connect(connect_timeout)
        .timeout_read(io_timeout)
        .timeout_write(io_timeout)
        .resolver(move |_: &str| Ok(vec![address]))
        .build();
    let mut upstream = agent.request(method, url.as_str());
    for (name, value) in headers {
        if !client_header_is_forwarded(name) {
            continue;
        }
        upstream = upstream.set(name, value);
    }
    if let Some((_, header_name, value)) = credential {
        upstream = upstream.set(header_name, value.as_str());
    }
    let result = if body.is_empty() {
        upstream.call()
    } else {
        upstream.send_bytes(body)
    };
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(error)) => {
            // Transport errors can contain the full request URL (including a
            // presigned query). Retain a correlatable digest, never the raw
            // error, in supervisor stderr or caller-visible responses.
            let detail_digest = format!("sha256:{:x}", Sha256::digest(error.to_string()));
            return Err(io::Error::other(format!(
                "mediated HTTP transport failed (detail {detail_digest})"
            )));
        }
    };
    let status = response.status();
    let headers = response
        .headers_names()
        .into_iter()
        .filter_map(|name| {
            response
                .header(&name)
                .filter(|value| safe_response_header(&name, value))
                .map(|value| (name, value.to_string()))
        })
        .collect::<Vec<_>>();
    if response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|size| size > config.max_response_bytes)
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP mediator response exceeded its byte budget",
        ));
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(config.max_response_bytes.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > config.max_response_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP mediator response exceeded its byte budget",
        ));
    }
    Ok(MediatedHttpResponse {
        status,
        headers,
        body,
    })
}

fn safe_response_header(name: &str, value: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cache-control"
            | "content-disposition"
            | "content-type"
            | "etag"
            | "last-modified"
            | "location"
            | "retry-after"
    ) && !value.contains(['\r', '\n'])
}

fn redirect_target(current: &Url, response: &MediatedHttpResponse) -> io::Result<Option<Url>> {
    if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some((_, location)) = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
    else {
        return Ok(None);
    };
    let target = current.join(location).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "upstream returned an invalid redirect",
        )
    })?;
    if !matches!(target.scheme(), "http" | "https")
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "upstream redirect is outside the HTTP mediator protocol",
        ));
    }
    Ok(Some(target))
}

fn credential_applies_to_url(credential: &HttpCredentialInjection, target: &Url) -> bool {
    credential.allowed_url_prefixes.iter().any(|prefix| {
        validate_credential_url_prefix(prefix)
            .ok()
            .is_some_and(|prefix| url_is_within_prefix(target, &prefix))
    })
}

fn same_http_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn url_is_within_prefix(target: &Url, prefix: &Url) -> bool {
    target.scheme() == prefix.scheme()
        && target.host_str() == prefix.host_str()
        && target.port_or_known_default() == prefix.port_or_known_default()
        && (prefix.path() == "/"
            || target.path() == prefix.path()
            || (target.path().starts_with(prefix.path())
                && (prefix.path().ends_with('/')
                    || target.path().as_bytes().get(prefix.path().len()).copied() == Some(b'/'))))
}

fn load_http_credential(config: &HttpCredentialInjection) -> io::Result<Zeroizing<String>> {
    validate_http_credential_config(config)?;
    let path = Path::new(&config.value_file);
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CREDENTIAL_HEADER_BYTES {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP credential handle did not resolve to a bounded regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP credential handle did not resolve to an owner-only mediator file",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CREDENTIAL_HEADER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CREDENTIAL_HEADER_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP credential header exceeded its byte budget",
        ));
    }
    let mut value =
        Zeroizing::new(String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "HTTP credential header must be UTF-8",
            )
        })?);
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte == b'\t' || (0x20..=0x7e).contains(&byte)))
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP credential header contains unsafe bytes",
        ));
    }
    Ok(value)
}

fn mediated_http_request_digest(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: &[u8],
) -> String {
    let mut safe_headers = headers
        .iter()
        .filter(|(name, _)| client_header_is_forwarded(name))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<Vec<_>>();
    safe_headers.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"gensee-http-request-v1\0");
    hasher.update(method.as_bytes());
    hasher.update(b"\0");
    hasher.update(url.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(serde_json::to_vec(&safe_headers).unwrap_or_default());
    hasher.update(b"\0");
    hasher.update(Sha256::digest(body));
    format!("sha256:{:x}", hasher.finalize())
}

fn mediated_http_response_digest(response: &MediatedHttpResponse) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gensee-http-response-v1\0");
    hasher.update(response.status.to_be_bytes());
    hasher.update(b"\0");
    hasher.update(serde_json::to_vec(&response.headers).unwrap_or_default());
    hasher.update(b"\0");
    hasher.update(Sha256::digest(&response.body));
    format!("sha256:{:x}", hasher.finalize())
}

fn redacted_url_for_evidence(url: &Url) -> String {
    let mut redacted = url.clone();
    if let Some(query) = url.query() {
        let digest = format!("sha256:{:x}", Sha256::digest(query.as_bytes()));
        redacted.set_query(Some(&digest));
    }
    redacted.to_string()
}

fn url_authority(url: &Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "HTTP authority is missing"))?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn write_mediated_http_response(
    stream: &mut TcpStream,
    response: MediatedHttpResponse,
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {} Mediated\r\n", response.status)?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    )?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[derive(Debug)]
struct ParsedProxyRequest {
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    declared_body_bytes: u64,
    body: Vec<u8>,
}

fn read_proxy_request(
    stream: &mut TcpStream,
    max_body_bytes: u64,
) -> io::Result<ParsedProxyRequest> {
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
    let mut request = parse_proxy_request_bytes(&bytes)?;
    if request.declared_body_bytes > max_body_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP mediator request exceeded its body byte budget",
        ));
    }
    let body_len = usize::try_from(request.declared_body_bytes).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "HTTP mediator body size does not fit this host",
        )
    })?;
    let mut remaining = body_len;
    while remaining > 0 {
        let mut chunk = [0u8; PROXY_BODY_READ_CHUNK_BYTES];
        let read_limit = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..read_limit])?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "proxy request body ended before its declared length",
            ));
        }
        request.body.extend_from_slice(&chunk[..count]);
        remaining -= count;
    }
    Ok(request)
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
    if parts.next().is_some()
        || !matches!(version.as_str(), "HTTP/1.0" | "HTTP/1.1")
        || !valid_http_mediator_request_method(&method)
    {
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
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "gateway accepts credential-free absolute HTTP(S) URLs without fragments",
        ));
    }
    url.host_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "HTTP host missing"))?;
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "invalid proxy request header")
        })?;
        if !valid_http_header_name(name) || name != name.trim() || value.contains(['\r', '\n']) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unsafe proxy header",
            ));
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "HTTP mediator does not accept transfer-encoded request bodies",
        ));
    }
    let content_lengths = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid Content-Length"))?;
    if content_lengths
        .windows(2)
        .any(|values| values[0] != values[1])
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "conflicting Content-Length headers",
        ));
    }
    let declared_body_bytes = content_lengths.first().copied().unwrap_or(0);
    Ok(ParsedProxyRequest {
        method,
        url,
        headers,
        declared_body_bytes,
        body: Vec::new(),
    })
}

fn valid_http_mediator_request_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && method != "CONNECT"
        && method != "TRACE"
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn connection_hop_header(name: &str) -> bool {
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
    )
}

fn client_header_is_forwarded(name: &str) -> bool {
    !connection_hop_header(name)
        && !name.eq_ignore_ascii_case("host")
        && !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("authorization")
        && !name.eq_ignore_ascii_case("cookie")
        && !name.to_ascii_lowercase().starts_with("x-gensee-")
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

fn write_proxy_error(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
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

fn revoke_http_mediator(args: &[OsString]) -> io::Result<()> {
    let lease_id = network_arg_value(args, "--lease")
        .filter(|lease_id| safe_network_token(lease_id))
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing or invalid --lease"))?;
    send_supervisor_request(
        args,
        &NetworkSupervisorRequest::RevokeHttpMediator {
            lease_id: lease_id.to_string(),
        },
    )
}

fn begin_http_transaction(args: &[OsString]) -> io::Result<()> {
    let transaction_id = required_safe_network_arg(args, "--transaction")?;
    let operation_id = required_safe_network_arg(args, "--operation")?;
    let effect = required_safe_network_arg(args, "--effect")?;
    let ttl_seconds = network_arg_value(args, "--ttl-seconds")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "missing or invalid --ttl-seconds")
        })?;
    send_supervisor_request(
        args,
        &NetworkSupervisorRequest::BeginHttpTransaction {
            transaction_id,
            operation_id,
            effect,
            ttl_seconds,
        },
    )
}

fn activate_http_transaction(args: &[OsString]) -> io::Result<()> {
    send_http_transaction_terminal_request(args, "activate")
}

fn revoke_http_transaction(args: &[OsString]) -> io::Result<()> {
    send_http_transaction_terminal_request(args, "revoke")
}

fn end_http_transaction(args: &[OsString]) -> io::Result<()> {
    send_http_transaction_terminal_request(args, "end")
}

fn send_http_transaction_terminal_request(args: &[OsString], action: &str) -> io::Result<()> {
    let transaction_id = required_safe_network_arg(args, "--transaction")?;
    let operation_id = required_safe_network_arg(args, "--operation")?;
    let request = match action {
        "activate" => NetworkSupervisorRequest::ActivateHttpTransaction {
            transaction_id,
            operation_id,
        },
        "revoke" => NetworkSupervisorRequest::RevokeHttpTransaction {
            transaction_id,
            operation_id,
        },
        "end" => NetworkSupervisorRequest::EndHttpTransaction {
            transaction_id,
            operation_id,
        },
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid transaction action",
            ))
        }
    };
    send_supervisor_request(args, &request)
}

fn required_safe_network_arg(args: &[OsString], name: &str) -> io::Result<String> {
    network_arg_value(args, name)
        .filter(|value| safe_network_token(value))
        .map(ToString::to_string)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("missing or invalid {name}"),
            )
        })
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

#[cfg(unix)]
fn prepare_privileged_boundary_environment(
    args: &[OsString],
    config_path: &Path,
) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the boundary daemon must run as root",
        ));
    }
    let state_root = network_arg_value(args, "--state-root")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "privileged boundary daemon requires --state-root",
            )
        })?;
    validate_root_owned_path(config_path, false, true)?;
    validate_root_owned_path(&state_root, true, true)?;
    // Downstream operation supervision and the capability broker share this
    // already-validated authority root. Do not inherit GENSEE_HOME from the
    // launching shell for a privileged boundary process.
    env::set_var("GENSEE_HOME", &state_root);
    Ok(())
}

#[cfg(not(unix))]
fn prepare_privileged_boundary_environment(
    _args: &[OsString],
    _config_path: &Path,
) -> io::Result<()> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "privileged boundary daemon requires Unix",
    ))
}

#[cfg(unix)]
fn validate_root_owned_path(path: &Path, directory: bool, owner_only: bool) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "privileged boundary paths must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.uid() != 0
        || metadata.mode() & if owner_only { 0o077 } else { 0o022 } != 0
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "privileged boundary paths must be root-owned, non-symlink, and non-writable by other principals",
        ));
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "privileged boundary path ancestry is not root-controlled",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn peer_effective_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error());
    }
    Ok(credential.uid)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_effective_uid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "privileged boundary peer authentication requires Linux SO_PEERCRED",
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

#[cfg(any(unix, test))]
fn network_operation_identity_lock_path(
    state_root: &Path,
    operation_id: &str,
) -> io::Result<PathBuf> {
    if !safe_network_token(operation_id) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid network operation id",
        ));
    }
    let lock_root = state_root.join("network-operation-locks");
    create_restrictive_dir_all(&lock_root)?;
    if !fs::symlink_metadata(&lock_root)?.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "network operation identity lock root is not a directory",
        ));
    }
    Ok(lock_root.join(format!("{operation_id}.lock")))
}

fn validate_stored_network_record(record: &NetworkOperationRecord) -> io::Result<()> {
    let subject_count =
        usize::from(record.root_pid.is_some()) + usize::from(record.source_address.is_some());
    if record.schema_version != NETWORK_SUPERVISOR_SCHEMA_VERSION
        || record.policy.schema_version != NETWORK_BOUNDARY_SCHEMA_VERSION
        || !safe_network_token(&record.operation_id)
        || !safe_network_token(&record.source_run_id)
        || subject_count != 1
        || record.root_pid == Some(0)
        || record
            .source_address
            .as_deref()
            .is_some_and(|address| address.parse::<IpAddr>().is_err())
        || record
            .active_table_name
            .as_deref()
            .is_some_and(|name| !safe_nft_table_name(name))
        || record
            .revoked_http_mediator_leases
            .iter()
            .any(|lease_id| !safe_network_token(lease_id))
        || record
            .evidence_rotation_count
            .keys()
            .any(|kind| !safe_network_token(kind))
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "stored network operation record is not safe to reconcile",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn terminal_boundary_table_names(record: &NetworkOperationRecord) -> io::Result<BTreeSet<String>> {
    validate_stored_network_record(record)?;
    let terminal_table = terminal_deny_plan_for_record(record)?.nftables.table_name;
    let mut tables = record
        .active_table_name
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    tables.insert(terminal_table);
    Ok(tables)
}

#[cfg(any(target_os = "linux", test))]
fn mark_terminal_network_boundary_reaped(
    record_path: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<()> {
    let mut record: NetworkOperationRecord =
        serde_json::from_str(&read_nofollow_to_string(record_path)?).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("cannot finalize terminal network operation record: {error}"),
            )
        })?;
    validate_stored_network_record(&record)?;
    if record.operation_id != operation_id || record.source_run_id != expected_source_run_id {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "terminal network boundary identity changed during cleanup",
        ));
    }
    let now = unix_millis()?;
    record.active_table_name = None;
    record.terminal_boundary_reaped_at_ms = Some(now);
    record.updated_at_ms = now;
    write_atomic_nofollow(record_path, &serde_json::to_vec_pretty(&record)?, 0o600)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct NetworkBoundaryRecoveryReport {
    recovered: usize,
    archived: usize,
    skipped_entries: usize,
}

#[cfg(any(target_os = "linux", test))]
fn record_network_boundary_recovery_report(
    operation: &mut OperationSupervisor,
    report: NetworkBoundaryRecoveryReport,
) -> io::Result<()> {
    if report.skipped_entries > 0 {
        operation.record_network_recovery_skipped_entries(report.skipped_entries)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn visit_pending_network_boundary_recovery_with(
    state_root: &Path,
    mut recover: impl FnMut(&NetworkOperationRecord, &Path) -> io::Result<bool>,
    mut archive: impl FnMut(&NetworkOperationRecord, &Path) -> io::Result<bool>,
) -> io::Result<NetworkBoundaryRecoveryReport> {
    let root = state_root.join("network-operations");
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(NetworkBoundaryRecoveryReport::default());
        }
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "network operation recovery root is not a directory",
        ));
    }

    let mut report = NetworkBoundaryRecoveryReport::default();
    for entry in fs::read_dir(&root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        let is_directory = match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        if !is_directory {
            continue;
        }
        let operation_id = match entry.file_name().into_string() {
            Ok(operation_id) => operation_id,
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        if !safe_network_token(&operation_id) {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let record_path = entry.path().join("record.json");
        let record_metadata = match fs::symlink_metadata(&record_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        if !record_metadata.file_type().is_file() {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }
        let contents = match read_nofollow_to_string(&record_path) {
            Ok(contents) => contents,
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        let record: NetworkOperationRecord = match serde_json::from_str(&contents) {
            Ok(record) => record,
            Err(_) => {
                report.skipped_entries = report.skipped_entries.saturating_add(1);
                continue;
            }
        };
        if validate_stored_network_record(&record).is_err() || record.operation_id != operation_id {
            report.skipped_entries = report.skipped_entries.saturating_add(1);
            continue;
        }

        let ready_to_archive = if record.terminal_boundary_reaped_at_ms.is_some() {
            true
        } else {
            match recover(&record, &record_path) {
                Ok(true) => {
                    report.recovered = report.recovered.saturating_add(1);
                    true
                }
                Ok(false) => false,
                Err(_) => {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                    false
                }
            }
        };
        if ready_to_archive {
            match archive(&record, &record_path) {
                Ok(true) => report.archived = report.archived.saturating_add(1),
                Ok(false) => {}
                Err(_) => {
                    report.skipped_entries = report.skipped_entries.saturating_add(1);
                }
            }
        }
    }
    Ok(report)
}

#[cfg(target_os = "linux")]
fn recover_pending_terminal_network_boundaries(
    state_root: &Path,
) -> io::Result<NetworkBoundaryRecoveryReport> {
    visit_pending_network_boundary_recovery_with(
        state_root,
        |record, _| {
            retry_and_reap_terminal_network_boundary_for_operation(
                state_root,
                &record.operation_id,
                &record.source_run_id,
            )
        },
        |record, _| {
            archive_reaped_network_operation(
                state_root,
                &record.operation_id,
                &record.source_run_id,
            )
        },
    )
}

#[cfg(any(target_os = "linux", test))]
fn archive_reaped_network_operation(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    let active_root = state_root.join("network-operations");
    let operation_root = active_root.join(operation_id);
    match fs::symlink_metadata(&operation_root) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "reaped network operation is not a directory",
            ));
        }
        Err(error) => return Err(error),
    }
    let _operation_locks =
        match NetworkOperationLocks::acquire(state_root, &operation_root, operation_id) {
            Ok(locks) => locks,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
    let record_path = operation_root.join("record.json");
    let record: NetworkOperationRecord =
        serde_json::from_str(&read_nofollow_to_string(&record_path)?).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("cannot archive reaped network operation record: {error}"),
            )
        })?;
    validate_stored_network_record(&record)?;
    if record.operation_id != operation_id
        || record.source_run_id != expected_source_run_id
        || record.terminal_boundary_reaped_at_ms.is_none()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "network operation is not safe to archive",
        ));
    }

    // Preserve the complete operation directory for forensics, but move it
    // outside the hot recovery scan once its subject and policy are reaped.
    let archive_root = state_root.join("network-operations-archive");
    create_restrictive_dir_all(&archive_root)?;
    if !fs::symlink_metadata(&archive_root)?.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "network operation archive root is not a directory",
        ));
    }
    let archived_operation_root = archive_root.join(operation_id);
    match fs::symlink_metadata(&archived_operation_root) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Ok(_) => {
            // Preserve both records without leaving a terminal operation in
            // the hot recovery set forever. A collision should be exceptional
            // for single-use operation ids, so make it explicit in the
            // forensic name rather than overwriting either side.
            for attempt in 0..1_024_u16 {
                let collision_root = archive_root.join(format!(
                    "{operation_id}.collision.{}.{}.{attempt}",
                    record.source_run_id, record.updated_at_ms
                ));
                match fs::symlink_metadata(&collision_root) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        fs::rename(&operation_root, collision_root)?;
                        return Ok(true);
                    }
                    Ok(_) => continue,
                    Err(error) => return Err(error),
                }
            }
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "network operation archive collision namespace is exhausted",
            ));
        }
        Err(error) => return Err(error),
    }
    fs::rename(&operation_root, &archived_operation_root)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn retry_and_reap_terminal_network_boundary_for_operation(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    let root = state_root.join("network-operations").join(operation_id);
    let _operation_locks = match NetworkOperationLocks::acquire(state_root, &root, operation_id) {
        Ok(locks) => locks,
        Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !crate::operation_supervisor::retry_terminal_operation_subject_release_at(
        state_root,
        operation_id,
        expected_source_run_id,
    )? {
        return Ok(false);
    }
    reap_terminal_network_boundary_while_locked(state_root, operation_id, expected_source_run_id)
}

/// Reaps policy for one exact operation only after its durable lifecycle
/// record says the operation is terminal and its subject has been released.
/// A live supervisor lock or incomplete subject teardown leaves the terminal
/// deny generation intact.
#[cfg(target_os = "linux")]
pub(crate) fn reap_terminal_network_boundary_for_operation(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    let root = state_root.join("network-operations").join(operation_id);
    let record_path = root.join("record.json");
    if !record_path.exists() {
        return Ok(true);
    }
    let _operation_locks = match NetworkOperationLocks::acquire(state_root, &root, operation_id) {
        Ok(locks) => locks,
        Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    reap_terminal_network_boundary_while_locked(state_root, operation_id, expected_source_run_id)
}

/// Reaps one exact terminal boundary while its network-supervisor lock is
/// already held by the caller. This supports startup recovery without dropping
/// the lock between validating the stale record and deleting its tables.
#[cfg(target_os = "linux")]
fn reap_terminal_network_boundary_while_locked(
    state_root: &Path,
    operation_id: &str,
    expected_source_run_id: &str,
) -> io::Result<bool> {
    let root = state_root.join("network-operations").join(operation_id);
    let record_path = root.join("record.json");
    if !record_path.exists() {
        return Ok(true);
    }
    let record: NetworkOperationRecord =
        serde_json::from_str(&read_nofollow_to_string(&record_path)?).map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("cannot inspect terminal network operation record: {error}"),
            )
        })?;
    validate_stored_network_record(&record)?;
    if record.operation_id != operation_id || record.source_run_id != expected_source_run_id {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "terminal network boundary identity does not match the operation",
        ));
    }
    if record.terminal_boundary_reaped_at_ms.is_some() {
        return Ok(true);
    }
    if !crate::operation_supervisor::terminal_operation_subject_is_released_at(
        state_root,
        operation_id,
        expected_source_run_id,
    )? {
        return Ok(false);
    }
    for table in terminal_boundary_table_names(&record)? {
        gensee_crate_linux::delete_nftables_table_if_exists(&table)?;
    }
    mark_terminal_network_boundary_reaped(&record_path, operation_id, expected_source_run_id)?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn reap_terminal_network_boundary_for_operation(
    _state_root: &Path,
    _operation_id: &str,
    _expected_source_run_id: &str,
) -> io::Result<bool> {
    Ok(true)
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

fn append_bounded_json_line<T: Serialize>(path: &Path, value: &T, sync: bool) -> io::Result<bool> {
    append_bounded_json_line_with_limit(path, value, sync, MAX_NETWORK_EVIDENCE_LOG_BYTES)
}

fn append_bounded_json_line_with_limit<T: Serialize>(
    path: &Path,
    value: &T,
    sync: bool,
    max_bytes: u64,
) -> io::Result<bool> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    if max_bytes == 0 || line.len() as u64 > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "network evidence record exceeds its bounded log size",
        ));
    }
    let mut rotated = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "network evidence log is not a regular non-symlink file",
                ));
            }
            if metadata.len().saturating_add(line.len() as u64) > max_bytes {
                let file_name = path.file_name().ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidInput, "network evidence path has no name")
                })?;
                let mut rotated_name = file_name.to_os_string();
                rotated_name.push(".1");
                fs::rename(path, path.with_file_name(rotated_name))?;
                rotated = true;
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = open_owner_append_nofollow(path)?;
    file.write_all(&line)?;
    if sync {
        file.sync_data()?;
    }
    Ok(rotated)
}

fn network_plan_for_record(
    record: &NetworkOperationRecord,
) -> io::Result<gensee_crate_linux::LinuxNetworkEnforcementPlan> {
    let session = format!("{}_{}", record.operation_id, record.generation);
    network_plan_for_record_with_session(record, session)
}

fn terminal_deny_plan_for_record(
    record: &NetworkOperationRecord,
) -> io::Result<gensee_crate_linux::LinuxNetworkEnforcementPlan> {
    let mut terminal = record.clone();
    terminal.envelope.grants.clear();
    network_plan_for_record_with_session(&terminal, format!("{}_terminal", record.operation_id))
}

fn network_plan_for_record_with_session(
    record: &NetworkOperationRecord,
    session: String,
) -> io::Result<gensee_crate_linux::LinuxNetworkEnforcementPlan> {
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

    fn transaction_policy(authority: String, path_prefix: &str) -> HttpTransactionPolicy {
        HttpTransactionPolicy {
            effect: "external_http_read".to_string(),
            scopes: vec![HttpTransactionScope {
                scheme: "http".to_string(),
                authority,
                path_prefix: path_prefix.to_string(),
            }],
            max_ttl_seconds: 60,
            max_requests: 8,
            max_request_bytes: 1024,
            max_response_bytes: 4096,
        }
    }

    fn transactional_proxy(policy: HttpTransactionPolicy) -> HttpGatewayConfig {
        HttpGatewayConfig {
            listen: "127.0.0.1:0".to_string(),
            client_address: "127.0.0.1".to_string(),
            max_request_bytes: 1024,
            max_response_bytes: 4096,
            max_redirects: 2,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 2,
            lease_id: None,
            expires_at_ms: None,
            credential: None,
            gateway_id: None,
            commit_token_id: None,
            transaction: Some(policy),
        }
    }

    fn install_transaction_policy(
        supervisor: &Arc<Mutex<NetworkSupervisor>>,
        policy: &HttpTransactionPolicy,
    ) {
        let mut state = supervisor.lock().unwrap();
        state.http_transaction_policy = Some(policy.clone());
        state.record.http_transaction_policy = Some(policy.clone());
    }

    fn begin_and_activate(supervisor: &Arc<Mutex<NetworkSupervisor>>, transaction_id: &str) {
        let mut state = supervisor.lock().unwrap();
        state
            .begin_http_transaction(transaction_id, "op_1", "external_http_read", 30)
            .unwrap();
        state
            .activate_http_transaction(transaction_id, "op_1")
            .unwrap();
    }

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
                suppressed_fault_count: 0,
                evidence_rotation_count: BTreeMap::new(),
                terminal_boundary_reaped_at_ms: None,
                counter_snapshot: BTreeMap::new(),
                revoked_http_mediator_leases: BTreeSet::new(),
                http_mediator_lease_id: None,
                http_mediator_expires_at_ms: None,
                http_transaction_policy: None,
                http_transaction: None,
                used_http_transaction_ids: BTreeSet::new(),
                started_at_ms: 1,
                updated_at_ms: 1,
            },
            record_path: root.join("record.json"),
            event_log_path: root.join("effects.jsonl"),
            counter_log_path: root.join("counters.jsonl"),
            fault_log_path: root.join("faults.jsonl"),
            mediator_log_path: root.join("http-mediator.jsonl"),
            transaction_log_path: root.join("http-transactions.jsonl"),
            dry_run: true,
            operation: None,
            active_plan: None,
            counter_snapshot: BTreeMap::new(),
            next_usage_sample_at_ms: u64::MAX,
            last_counter_error: None,
            http_mediator_lease_id: None,
            http_transaction_policy: None,
            active_http_transports: BTreeMap::new(),
            next_http_transport_id: 0,
            #[cfg(target_os = "linux")]
            attempt_monitor: None,
            #[cfg(any(target_os = "linux", test))]
            observed_attempt_traces: BTreeSet::new(),
            #[cfg(any(target_os = "linux", test))]
            observed_attempt_trace_order: VecDeque::new(),
            #[cfg(any(target_os = "linux", test))]
            fault_rate_window_started_at_ms: 1,
            #[cfg(any(target_os = "linux", test))]
            detailed_faults_in_window: 0,
            #[cfg(any(target_os = "linux", test))]
            fault_rate_violation_recorded_in_window: false,
            #[cfg(any(target_os = "linux", test))]
            dedupe_eviction_recorded: false,
        }))
    }

    #[test]
    fn in_flight_connection_limit_releases_capacity_on_drop() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let first = try_acquire_connection(&in_flight, 1).expect("first connection is admitted");
        assert!(try_acquire_connection(&in_flight, 1).is_none());
        drop(first);
        assert!(try_acquire_connection(&in_flight, 1).is_some());
    }

    #[test]
    fn transaction_lifecycle_is_fail_closed_and_ids_cannot_be_replayed() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-lifecycle-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        let url = Url::parse("http://api.example.test/v1/data/a.bin").unwrap();

        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 0).is_err());
        {
            let mut state = supervisor.lock().unwrap();
            assert_eq!(
                state
                    .begin_http_transaction("tx_wrong", "op_wrong", "external_http_read", 10,)
                    .unwrap_err(),
                "http_transaction_request_outside_policy"
            );
            state
                .begin_http_transaction("tx_1", "op_1", "external_http_read", 10)
                .unwrap();
        }
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 0).is_err());
        supervisor
            .lock()
            .unwrap()
            .activate_http_transaction("tx_1", "op_1")
            .unwrap();
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 0)
            .unwrap()
            .is_some());
        {
            let mut state = supervisor.lock().unwrap();
            state
                .terminal_http_transaction("tx_1", "op_1", HttpTransactionStatus::Revoked, "revoke")
                .unwrap();
            assert_eq!(
                state
                    .begin_http_transaction("tx_1", "op_1", "external_http_read", 10,)
                    .unwrap_err(),
                "http_transaction_id_replayed"
            );
        }
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 0).is_err());
    }

    #[test]
    fn activation_persistence_failure_rolls_back_in_memory_authority() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-activation-persist-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        install_transaction_policy(&supervisor, &policy);
        {
            let mut state = supervisor.lock().unwrap();
            state
                .begin_http_transaction("tx_persist_failure", "op_1", "external_http_read", 30)
                .unwrap();
            let failing_record_path = root.join("record-path-is-a-directory");
            fs::create_dir(&failing_record_path).unwrap();
            state.record_path = failing_record_path;
            assert!(state
                .activate_http_transaction("tx_persist_failure", "op_1")
                .is_err());
            let transaction = state.record.http_transaction.as_ref().unwrap();
            assert_eq!(transaction.status, HttpTransactionStatus::Prepared);
            assert_eq!(transaction.generation, 0);
            assert!(transaction.activated_at_ms.is_none());
        }
    }

    #[test]
    fn audit_failure_after_durable_activation_does_not_report_denial() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-activation-audit-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        install_transaction_policy(&supervisor, &policy);
        {
            let mut state = supervisor.lock().unwrap();
            state
                .begin_http_transaction("tx_audit_failure", "op_1", "external_http_read", 30)
                .unwrap();
            fs::remove_file(&state.transaction_log_path).unwrap();
            fs::create_dir(&state.transaction_log_path).unwrap();
            assert!(state
                .activate_http_transaction("tx_audit_failure", "op_1")
                .is_ok());
            assert_eq!(
                state.record.http_transaction.as_ref().unwrap().status,
                HttpTransactionStatus::Active
            );
        }
        let persisted: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(root.join("record.json")).unwrap()).unwrap();
        assert_eq!(
            persisted.http_transaction.unwrap().status,
            HttpTransactionStatus::Active
        );
    }

    #[test]
    fn response_reservation_is_single_in_flight_and_release_is_durable() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-reservation-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        begin_and_activate(&supervisor, "tx_reservation");
        let url = Url::parse("http://api.example.test/v1/data/a").unwrap();

        let first = reserve_http_transaction_hop(&supervisor, &proxy, &url, 0)
            .unwrap()
            .unwrap();
        let persisted_reserved: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(root.join("record.json")).unwrap()).unwrap();
        assert_eq!(
            persisted_reserved
                .http_transaction
                .unwrap()
                .response_reservation
                .unwrap()
                .reservation_id,
            first.reservation_id
        );
        let concurrent = reserve_http_transaction_hop(&supervisor, &proxy, &url, 0).unwrap_err();
        assert_eq!(concurrent.kind(), ErrorKind::WouldBlock);
        release_http_transaction_reservation(&supervisor, &first).unwrap();
        let second = reserve_http_transaction_hop(&supervisor, &proxy, &url, 0)
            .unwrap()
            .unwrap();
        assert_ne!(first.reservation_id, second.reservation_id);
        release_http_transaction_reservation(&supervisor, &second).unwrap();
        let persisted: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(root.join("record.json")).unwrap()).unwrap();
        assert!(persisted
            .http_transaction
            .unwrap()
            .response_reservation
            .is_none());
    }

    #[test]
    fn revoke_invalidates_reserved_get_before_upstream_connect() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-final-check-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        begin_and_activate(&supervisor, "tx_final_check");
        let url = Url::parse("http://api.example.test/v1/data/a").unwrap();
        let reservation = reserve_http_transaction_hop(&supervisor, &proxy, &url, 0)
            .unwrap()
            .unwrap();
        supervisor
            .lock()
            .unwrap()
            .terminal_http_transaction(
                "tx_final_check",
                "op_1",
                HttpTransactionStatus::Revoked,
                "revoke",
            )
            .unwrap();
        let denied = validate_http_transaction_reservation_before_upstream(
            &supervisor,
            &proxy,
            &reservation,
        )
        .unwrap_err();
        assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn prepared_deadline_expires_and_double_encoded_paths_are_denied() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-prepared-expiry-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        {
            let mut state = supervisor.lock().unwrap();
            state
                .begin_http_transaction("tx_prepared_expiry", "op_1", "external_http_read", 30)
                .unwrap();
            state
                .record
                .http_transaction
                .as_mut()
                .unwrap()
                .expires_at_ms = Some(1);
            state
                .expire_http_transaction_if_needed(unix_millis().unwrap())
                .unwrap();
            assert_eq!(
                state.record.http_transaction.as_ref().unwrap().status,
                HttpTransactionStatus::Expired
            );
        }

        begin_and_activate(&supervisor, "tx_encoded_path");
        let double_encoded =
            Url::parse("http://api.example.test/v1/data/%252e%252e/escape").unwrap();
        assert!(check_http_transaction_hop(&supervisor, &proxy, &double_encoded).is_err());
    }

    #[test]
    fn active_http_scope_denies_uci_like_destination_before_dns() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-uci-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/simple");
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        begin_and_activate(&supervisor, "tx_effect");

        let legitimate = Url::parse("http://api.example.test/simple/demo").unwrap();
        assert!(
            reserve_http_transaction_hop(&supervisor, &proxy, &legitimate, 0)
                .unwrap()
                .is_some()
        );
        let uci = Url::parse("http://uci-benchmark.example.test/private/dataset").unwrap();
        let denied = reserve_http_transaction_hop(&supervisor, &proxy, &uci, 0).unwrap_err();
        assert_eq!(denied.kind(), ErrorKind::PermissionDenied);
        assert!(denied.to_string().contains("immutable scope"));
        let audit = fs::read_to_string(root.join("http-transactions.jsonl")).unwrap();
        assert!(audit.contains("http_transaction_url_outside_scope"));
    }

    #[test]
    fn transaction_expiry_and_budget_are_enforced_from_host_state() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-expiry-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        policy.max_requests = 1;
        let proxy = transactional_proxy(policy.clone());
        install_transaction_policy(&supervisor, &policy);
        begin_and_activate(&supervisor, "tx_expiry");
        let url = Url::parse("http://api.example.test/v1/data/a").unwrap();
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 1).is_ok());
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 1).is_err());
        {
            let mut state = supervisor.lock().unwrap();
            let transaction = state.record.http_transaction.as_mut().unwrap();
            transaction.expires_at_ms = Some(1);
            state
                .expire_http_transaction_if_needed(unix_millis().unwrap())
                .unwrap();
            assert_eq!(
                state.record.http_transaction.as_ref().unwrap().status,
                HttpTransactionStatus::Expired
            );
        }
        assert!(reserve_http_transaction_hop(&supervisor, &proxy, &url, 0).is_err());
    }

    #[test]
    fn terminal_cleanup_generation_is_deny_only_and_deterministic() {
        let root = env::temp_dir().join(format!(
            "gensee-network-terminal-cleanup-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut record = lock_supervisor(&supervisor).unwrap().record.clone();
        record
            .envelope
            .grants
            .push(gensee_crate_rules::network_boundary::NetworkEndpointGrant {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
                expires_at_ms: None,
                lease_id: None,
            });
        let normal = network_plan_for_record(&record).unwrap().nftables;
        let terminal = terminal_deny_plan_for_record(&record).unwrap().nftables;
        assert_ne!(terminal.table_name, normal.table_name);
        assert!(terminal.table_name.contains("terminal"));
        assert!(terminal.destinations.is_empty());
        assert!(terminal.endpoint_counters.is_empty());
        assert!(terminal
            .block_counters
            .iter()
            .any(|counter| counter.reason
                == gensee_crate_linux::LinuxNetworkBlockReason::DefaultReject));
        assert_eq!(
            terminal,
            terminal_deny_plan_for_record(&record).unwrap().nftables
        );
        record.active_table_name = Some(normal.table_name.clone());
        assert_eq!(
            terminal_boundary_table_names(&record).unwrap(),
            BTreeSet::from([normal.table_name, terminal.table_name])
        );
    }

    #[test]
    fn standalone_boundary_cleanup_finishes_the_operation_it_owns() {
        let root = env::temp_dir().join(format!(
            "gensee-network-owned-lifecycle-test-{}",
            Uuid::new_v4()
        ));
        let operation_root = root.join("operation-state");
        let mut operation = OperationSupervisor::prepare_external_subject_at(
            &operation_root,
            "op_1",
            "run_1",
            "network_boundary",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();
        operation.activate_external_subject().unwrap();
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        {
            let mut state = lock_supervisor(&supervisor).unwrap();
            state.operation = Some(operation);
        }
        let terminal_deny_plan = {
            let state = lock_supervisor(&supervisor).unwrap();
            terminal_deny_plan_for_record(&state.record)
                .unwrap()
                .nftables
        };
        let cleanup = NetworkRuntimeCleanup {
            supervisor: Arc::clone(&supervisor),
            owns_operation_lifecycle: true,
            table_names: Arc::new(Mutex::new(Vec::new())),
            terminal_deny_plan,
            state_root: operation_root.clone(),
            record_path: root.join("record.json"),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            dry_run: true,
        };

        drop(cleanup);

        let record: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(operation_root.join("operations/op_1/record.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record["state"], "failed");
        assert!(record["exit_code"].is_null());
        assert!(record["finished_at_ms"].is_number());
        assert!(record["cgroup"]["path"].as_str().unwrap().is_empty());
        assert_eq!(record["violations"].as_array().unwrap().len(), 0);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn startup_recovery_skips_invalid_entries_and_archives_every_valid_reaped_operation() {
        let root = env::temp_dir().join(format!(
            "gensee-network-recovery-sweep-test-{}",
            Uuid::new_v4()
        ));
        let network_root = root.join("network-operations");
        fs::create_dir_all(&network_root).unwrap();
        let template_root = root.join("template");
        let template = lock_supervisor(&test_supervisor(
            &template_root,
            NetworkBoundaryPolicy::default(),
        ))
        .unwrap()
        .record
        .clone();

        for (operation_id, reaped_at, schema_version) in [
            ("op_zgood", None, NETWORK_SUPERVISOR_SCHEMA_VERSION),
            ("op_reaped", Some(1), NETWORK_SUPERVISOR_SCHEMA_VERSION),
            ("op_abad", None, NETWORK_SUPERVISOR_SCHEMA_VERSION - 1),
        ] {
            let operation_root = network_root.join(operation_id);
            fs::create_dir_all(&operation_root).unwrap();
            let mut record = template.clone();
            record.schema_version = schema_version;
            record.operation_id = operation_id.to_string();
            record.source_run_id = format!("run_{operation_id}");
            record.active_table_name = Some(format!("gensee_{operation_id}"));
            record.terminal_boundary_reaped_at_ms = reaped_at;
            write_atomic_nofollow(
                &operation_root.join("record.json"),
                &serde_json::to_vec_pretty(&record).unwrap(),
                0o600,
            )
            .unwrap();
        }
        let preexisting_archive = root.join("network-operations-archive/op_reaped");
        fs::create_dir_all(&preexisting_archive).unwrap();
        fs::write(preexisting_archive.join("sentinel"), "preserve me").unwrap();

        let mut visited = Vec::new();
        let report = visit_pending_network_boundary_recovery_with(
            &root,
            |record, record_path| {
                visited.push(record.operation_id.clone());
                mark_terminal_network_boundary_reaped(
                    record_path,
                    &record.operation_id,
                    &record.source_run_id,
                )?;
                Ok(true)
            },
            |record, _| {
                archive_reaped_network_operation(&root, &record.operation_id, &record.source_run_id)
            },
        )
        .unwrap();

        assert_eq!(
            report,
            NetworkBoundaryRecoveryReport {
                recovered: 1,
                archived: 2,
                skipped_entries: 1,
            }
        );
        assert_eq!(visited, vec!["op_zgood"]);
        assert!(network_root.join("op_abad/record.json").is_file());
        assert!(!network_root.join("op_zgood").exists());
        assert!(!network_root.join("op_reaped").exists());
        let archive_root = root.join("network-operations-archive");
        assert!(archive_root.join("op_zgood/record.json").is_file());
        assert_eq!(
            fs::read_to_string(archive_root.join("op_reaped/sentinel")).unwrap(),
            "preserve me"
        );
        let collision = fs::read_dir(&archive_root)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("op_reaped.collision.run_op_reaped.")
            })
            .expect("colliding terminal record should be preserved under a unique forensic name");
        assert!(collision.path().join("record.json").is_file());
        assert!(root
            .join("network-operation-locks/op_reaped.lock")
            .is_file());
        let stale: NetworkOperationRecord = serde_json::from_str(
            &fs::read_to_string(archive_root.join("op_zgood/record.json")).unwrap(),
        )
        .unwrap();
        assert!(stale.terminal_boundary_reaped_at_ms.is_some());
        assert!(stale.active_table_name.is_none());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn stable_identity_lock_excludes_archival_across_directory_rename() {
        let root = env::temp_dir().join(format!(
            "gensee-network-archive-lock-test-{}",
            Uuid::new_v4()
        ));
        let operation_id = "op_locked";
        let source_run_id = "run_locked";
        let operation_root = root.join("network-operations").join(operation_id);
        fs::create_dir_all(&operation_root).unwrap();
        let template_root = root.join("template");
        let mut record = lock_supervisor(&test_supervisor(
            &template_root,
            NetworkBoundaryPolicy::default(),
        ))
        .unwrap()
        .record
        .clone();
        record.operation_id = operation_id.to_string();
        record.source_run_id = source_run_id.to_string();
        record.active_table_name = None;
        record.terminal_boundary_reaped_at_ms = Some(1);
        write_atomic_nofollow(
            &operation_root.join("record.json"),
            &serde_json::to_vec_pretty(&record).unwrap(),
            0o600,
        )
        .unwrap();

        let identity_lock = NetworkOperationLock::acquire(
            &network_operation_identity_lock_path(&root, operation_id).unwrap(),
        )
        .unwrap();
        assert!(!archive_reaped_network_operation(&root, operation_id, source_run_id).unwrap());
        assert!(operation_root.is_dir());
        drop(identity_lock);

        assert!(archive_reaped_network_operation(&root, operation_id, source_run_id).unwrap());
        assert!(!operation_root.exists());
        assert!(root
            .join("network-operations-archive/op_locked/record.json")
            .is_file());
        assert!(!archive_reaped_network_operation(&root, operation_id, source_run_id).unwrap());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn inspect_response_surfaces_informational_recovery_health() {
        let response = NetworkSupervisorResponse {
            ok: true,
            decision: None,
            resolution: None,
            record: None,
            operation_recovery_health: Some(OperationRecoveryHealth {
                network_entries_skipped: 3,
            }),
            error: None,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(
            value["operation_recovery_health"]["network_entries_skipped"],
            3
        );
    }

    #[test]
    fn startup_recovery_skip_count_is_informational_on_the_current_operation() {
        let root = env::temp_dir().join(format!(
            "gensee-network-recovery-report-test-{}",
            Uuid::new_v4()
        ));
        let mut operation = OperationSupervisor::prepare_external_subject_at(
            &root,
            "op_current",
            "run_current",
            "network_boundary",
            OperationCapabilityEnvelope::default(),
        )
        .unwrap();

        record_network_boundary_recovery_report(
            &mut operation,
            NetworkBoundaryRecoveryReport {
                skipped_entries: 2,
                ..NetworkBoundaryRecoveryReport::default()
            },
        )
        .unwrap();
        let attestation = operation.attestation().unwrap();
        assert!(attestation.violations.is_empty());
        assert_eq!(operation.network_recovery_skipped_entry_count().unwrap(), 2);
        let persisted: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("operations/op_current/record.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted["network_recovery_skipped_entry_count"], 2);
        drop(operation);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn proxy_parser_accepts_absolute_https_and_filters_client_credentials() {
        let request = parse_proxy_request_bytes(
            b"GET https://example.test:8443/a?b=1 HTTP/1.1\r\nHost: attacker.test\r\nProxy-Authorization: secret\r\nAuthorization: bearer-secret\r\nCookie: secret=value\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.url.scheme(), "https");
        assert_eq!(request.url.host_str(), Some("example.test"));
        assert_eq!(request.url.port(), Some(8443));
        assert!(client_header_is_forwarded("Accept"));
        for stripped in [
            "Host",
            "Proxy-Authorization",
            "Authorization",
            "Cookie",
            "X-Gensee-Internal",
        ] {
            assert!(!client_header_is_forwarded(stripped));
        }
    }

    #[test]
    fn numeric_loopback_url_forms_normalize_before_boundary_authorization() {
        for authority in ["2130706433", "0x7f000001", "017700000001"] {
            let request =
                format!("GET http://{authority}/artifact HTTP/1.1\r\nHost: ignored.test\r\n\r\n");
            let parsed = parse_proxy_request_bytes(request.as_bytes()).unwrap();
            assert_eq!(
                parsed.url.host_str(),
                Some("127.0.0.1"),
                "numeric host form {authority} was not canonicalized"
            );
        }
    }

    #[test]
    fn credential_audience_is_origin_port_and_path_segment_exact() {
        let credential = HttpCredentialInjection {
            handle_id: "credential_1".to_string(),
            header_name: "Authorization".to_string(),
            value_file: "/not/read/by-this-test".to_string(),
            allowed_url_prefixes: vec!["https://api.example:8443/v1/data".to_string()],
        };
        for allowed in [
            "https://api.example:8443/v1/data",
            "https://api.example:8443/v1/data/item",
        ] {
            assert!(credential_applies_to_url(
                &credential,
                &Url::parse(allowed).unwrap()
            ));
        }
        for outside in [
            "https://api.example/v1/data/item",
            "http://api.example:8443/v1/data/item",
            "https://api.example:8443/v1/data-evil/item",
            "https://api.example.evil:8443/v1/data/item",
        ] {
            assert!(
                !credential_applies_to_url(&credential, &Url::parse(outside).unwrap()),
                "credential escaped to {outside}"
            );
        }
    }

    #[test]
    fn one_restricted_dns_answer_denies_the_entire_brokered_effect() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let supervisor = test_supervisor(
            &root,
            NetworkBoundaryPolicy {
                http_gateway_available: true,
                ..NetworkBoundaryPolicy::default()
            },
        );
        let result = authorize_mediated_http_addresses(
            &supervisor,
            "GET",
            &Url::parse("https://api.example/object").unwrap(),
            "sha256:test-request",
            None,
            vec![
                SocketAddr::from(([8, 8, 8, 8], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ],
        );
        assert!(matches!(
            result,
            Err(error) if error.kind() == ErrorKind::PermissionDenied
        ));
        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert_eq!(effects.lines().count(), 2);
        assert!(effects.contains("http_effect_has_trusted_mediator"));
        assert!(effects.contains("restricted_destination"));
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
    fn privileged_boundary_rejects_state_below_an_untrusted_ancestor() {
        let root = env::temp_dir().join(format!("gensee-boundary-root-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let config = root.join("operation.json");
        fs::write(&config, b"{}").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            validate_root_owned_path(&root, true, true)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            validate_root_owned_path(&config, false, true)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boundary_control_peer_uses_kernel_authenticated_uid() {
        let (left, _right) = UnixStream::pair().unwrap();
        assert_eq!(peer_effective_uid(&left).unwrap(), unsafe {
            libc::geteuid()
        });
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
    fn network_evidence_log_rotates_at_its_hard_size_bound() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("effects.jsonl");
        let first = serde_json::json!({"record": "a".repeat(32)});
        let second = serde_json::json!({"record": "b".repeat(32)});
        assert!(!append_bounded_json_line_with_limit(&path, &first, false, 64).unwrap());
        assert!(append_bounded_json_line_with_limit(&path, &second, false, 64).unwrap());
        assert!(fs::read_to_string(root.join("effects.jsonl.1"))
            .unwrap()
            .contains(&"a".repeat(32)));
        assert!(fs::read_to_string(&path).unwrap().contains(&"b".repeat(32)));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn evidence_rotation_is_explicit_in_network_and_operation_records() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let operation_root = root.join("trusted-operation-state");
        fs::create_dir_all(&operation_root).unwrap();
        let operation = OperationSupervisor::prepare_at(
            &operation_root,
            "op_1",
            "run_1",
            "network_boundary",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut state = supervisor.lock().unwrap();
        state.operation = Some(operation);
        state.record_evidence_rotation("effects").unwrap();
        assert_eq!(
            state.record.evidence_rotation_count.get("effects"),
            Some(&1)
        );
        let attestation = state.operation.as_mut().unwrap().attestation().unwrap();
        assert!(attestation.violations.iter().any(|violation| {
            violation.kind == "network_evidence_log_rotated"
                && violation.detail.contains("effects evidence")
        }));
        drop(state);
        let persisted: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(root.join("record.json")).unwrap()).unwrap();
        assert_eq!(persisted.evidence_rotation_count.get("effects"), Some(&1));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn proxy_parser_rejects_embedded_credentials_and_non_http_protocols() {
        for target in ["http://user:password@example.test/a", "file:///etc/passwd"] {
            let request = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
        for request in [
            "CONNECT example.test:443 HTTP/1.1\r\n\r\n",
            "GET http://example.test/a HTTP/1.evil\r\n\r\n",
            "GET http://example.test/a HTTP/1.1\r\nBad Header: value\r\n\r\n",
            "GET http://example.test/a HTTP/1.1\r\nHost : example.test\r\n\r\n",
        ] {
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn proxy_parser_tracks_content_length_and_rejects_ambiguous_framing() {
        let request = parse_proxy_request_bytes(
            b"POST https://example.test/a HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.declared_body_bytes, 5);
        for request in [
            "POST http://example.test/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://example.test/a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        ] {
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn credential_audience_uses_origin_and_path_segment_boundaries() {
        let credential = HttpCredentialInjection {
            handle_id: "credential_1".to_string(),
            header_name: "X-Test-Token".to_string(),
            value_file: "/unused-in-this-test".to_string(),
            allowed_url_prefixes: vec!["https://api.example/v1/data".to_string()],
        };
        assert!(credential_applies_to_url(
            &credential,
            &Url::parse("https://api.example/v1/data/a.tgz?token=1").unwrap()
        ));
        assert!(!credential_applies_to_url(
            &credential,
            &Url::parse("https://api.example/v1/data-evil/a.tgz").unwrap()
        ));
        assert!(!credential_applies_to_url(
            &credential,
            &Url::parse("https://evil.example/v1/data/a.tgz").unwrap()
        ));
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
                max_request_bytes: 1024,
                max_response_bytes: 1024,
                max_redirects: 0,
                connect_timeout_seconds: 1,
                io_timeout_seconds: 1,
                lease_id: None,
                expires_at_ms: None,
                credential: None,
                gateway_id: None,
                commit_token_id: None,
                transaction: None,
            },
        };
        assert!(validate_network_operation_config(&config).is_err());
        let mut local = config.clone();
        local.root_pid = Some(42);
        assert!(validate_network_operation_config(&local).is_ok());
        local.source_address = Some("10.0.0.2".to_string());
        assert!(validate_network_operation_config(&local).is_err());

        let mut mutation = config;
        mutation.root_pid = Some(42);
        mutation
            .policy
            .http_gateway_methods
            .push("POST".to_string());
        assert!(validate_network_operation_config(&mutation).is_err());
        mutation.proxy.lease_id = Some("lease_http_1".to_string());
        mutation.proxy.expires_at_ms = Some(unix_millis().unwrap().saturating_add(60_000));
        assert!(validate_network_operation_config(&mutation).is_err());
        mutation.proxy.gateway_id = Some("gateway_http_1".to_string());
        mutation.proxy.commit_token_id = Some("commit_http_1".to_string());
        assert!(validate_network_operation_config(&mutation).is_ok());
    }

    #[test]
    fn in_place_lease_is_attached_then_removed_on_expiry() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![gensee_crate_rules::network_boundary::NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
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
            in_place_lease_scopes: vec![gensee_crate_rules::network_boundary::NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
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
    fn fault_outside_the_exact_port_scope_cannot_trigger_authority_growth() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![gensee_crate_rules::network_boundary::NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        let fault = CapabilityFault {
            schema_version: gensee_crate_rules::capability_fault::CAPABILITY_FAULT_SCHEMA_VERSION,
            fault_id: "fault_network_wrong_port".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            subject: CapabilityFaultSubject::NetworkPeer {
                source_address: "10.88.0.12".to_string(),
            },
            effect: BoundaryEffectObservation::NetworkConnect {
                destination: "8.8.8.8".to_string(),
                protocol: "tcp".to_string(),
                port: 8443,
            },
            requested_ttl_seconds: 5,
            observed_at_ms: 1,
        };
        let (resolution, effect) = state
            .resolve_fault(&fault, &Arc::new(Mutex::new(Vec::new())))
            .unwrap();
        assert_eq!(resolution.action, CapabilityFaultAction::Deny);
        assert!(!resolution.retry_allowed);
        assert!(resolution.lease_id.is_none());
        assert!(state.record.envelope.grants.is_empty());
        let effect = effect.expect("denied attempts remain in effect evidence");
        assert_eq!(
            effect.decision.disposition,
            NetworkBoundaryDisposition::Deny
        );
        assert!(effect.decision.lease.is_none());
    }

    #[test]
    fn kernel_observed_unknown_endpoint_becomes_one_typed_fault_and_scoped_lease() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            in_place_lease_scopes: vec![gensee_crate_rules::network_boundary::NetworkLeaseScope {
                destination: "8.8.8.8".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: vec![443],
            }],
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let tables = Arc::new(Mutex::new(Vec::new()));
        let attempt = gensee_crate_linux::LinuxNetworkAttemptEvent {
            trace_id: "trace_1".to_string(),
            table_name: "gensee_op_1_hash_1".to_string(),
            chain_name: "egress".to_string(),
            destination: "8.8.8.8".to_string(),
            protocol: gensee_crate_linux::LinuxNetworkProtocol::Tcp,
            port: 443,
        };
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        state
            .process_kernel_network_attempts(vec![attempt.clone(), attempt], 0, false, &tables)
            .unwrap();
        assert_eq!(state.record.envelope.grants.len(), 1);
        assert_eq!(state.record.envelope.grants[0].destination, "8.8.8.8");
        assert_eq!(state.record.envelope.grants[0].ports, vec![443]);
        drop(state);
        let faults = fs::read_to_string(root.join("faults.jsonl")).unwrap();
        assert_eq!(faults.lines().count(), 1);
        assert!(faults.contains("retry_after_lease"));
        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert_eq!(effects.lines().count(), 1);
        assert!(effects.contains("attach_in_place_lease"));
    }

    #[test]
    fn kernel_observed_private_endpoint_stays_denied_without_authority_growth() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        state
            .process_kernel_network_attempts(
                vec![gensee_crate_linux::LinuxNetworkAttemptEvent {
                    trace_id: "trace_private".to_string(),
                    table_name: "gensee_op_1_hash_1".to_string(),
                    chain_name: "egress".to_string(),
                    destination: "127.0.0.1".to_string(),
                    protocol: gensee_crate_linux::LinuxNetworkProtocol::Tcp,
                    port: 8080,
                }],
                0,
                false,
                &Arc::new(Mutex::new(Vec::new())),
            )
            .unwrap();
        assert!(state.record.envelope.grants.is_empty());
        drop(state);
        let faults = fs::read_to_string(root.join("faults.jsonl")).unwrap();
        assert!(faults.contains("restricted_destination"));
        assert!(faults.contains("\"retry_allowed\":false"));
    }

    #[test]
    fn kernel_attempt_evidence_and_deduplication_are_bounded_under_flood() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut state = supervisor.lock().unwrap();
        state.record.root_pid = None;
        state.record.source_address = Some("10.88.0.12".to_string());
        // A future synthetic boundary makes this test independent of host
        // scheduling and guarantees one deterministic rate window.
        state.fault_rate_window_started_at_ms = u64::MAX;
        let attempts = (0..=MAX_OBSERVED_ATTEMPT_TRACES)
            .map(|index| gensee_crate_linux::LinuxNetworkAttemptEvent {
                trace_id: format!("trace_flood_{index}"),
                table_name: "gensee_op_1_hash_1".to_string(),
                chain_name: "egress".to_string(),
                destination: "127.0.0.1".to_string(),
                protocol: gensee_crate_linux::LinuxNetworkProtocol::Tcp,
                port: 8080,
            })
            .collect();
        state
            .process_kernel_network_attempts(attempts, 0, false, &Arc::new(Mutex::new(Vec::new())))
            .unwrap();
        assert_eq!(
            state.observed_attempt_traces.len(),
            MAX_OBSERVED_ATTEMPT_TRACES
        );
        assert_eq!(
            state.observed_attempt_trace_order.len(),
            MAX_OBSERVED_ATTEMPT_TRACES
        );
        assert!(state.dedupe_eviction_recorded);
        assert_eq!(
            state.record.suppressed_fault_count,
            (MAX_OBSERVED_ATTEMPT_TRACES + 1 - MAX_DETAILED_FAULTS_PER_SECOND as usize) as u64
        );
        let suppressed_fault_count = state.record.suppressed_fault_count;
        drop(state);
        let persisted: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(root.join("record.json")).unwrap()).unwrap();
        assert_eq!(persisted.suppressed_fault_count, suppressed_fault_count);
        assert_eq!(
            fs::read_to_string(root.join("faults.jsonl"))
                .unwrap()
                .lines()
                .count(),
            MAX_DETAILED_FAULTS_PER_SECOND as usize
        );
        assert_eq!(
            fs::read_to_string(root.join("effects.jsonl"))
                .unwrap()
                .lines()
                .count(),
            MAX_DETAILED_FAULTS_PER_SECOND as usize
        );
    }

    #[test]
    fn sensor_loss_records_violations_without_inventing_endpoint_authority() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let operation_root = root.join("trusted-operation-state");
        fs::create_dir_all(&operation_root).unwrap();
        let operation = OperationSupervisor::prepare_at(
            &operation_root,
            "op_1",
            "run_1",
            "hidden_path_test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let mut state = supervisor.lock().unwrap();
        state.operation = Some(operation);
        state
            .process_kernel_network_attempts(Vec::new(), 7, true, &Arc::new(Mutex::new(Vec::new())))
            .unwrap();
        assert!(state.record.envelope.grants.is_empty());
        let attestation = state.operation.as_mut().unwrap().attestation().unwrap();
        let violation_kinds = attestation
            .violations
            .iter()
            .map(|violation| violation.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert!(violation_kinds.contains("network_attempt_event_loss"));
        assert!(violation_kinds.contains("network_attempt_sensor_stopped"));
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
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_redirects: 1,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
            lease_id: None,
            expires_at_ms: None,
            credential: None,
            gateway_id: None,
            commit_token_id: None,
            transaction: None,
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

    #[cfg(unix)]
    #[test]
    fn credential_is_injected_only_for_its_exact_audience_and_never_logged() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let credential_path = root.join("credential");
        fs::write(&credential_path, b"super-secret-value\n").unwrap();
        fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600)).unwrap();

        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_worker = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\nConnection: close\r\n\r\nartifact",
                )
                .unwrap();
            String::from_utf8_lossy(&request[..count]).to_string()
        });

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
        let lease_id = "lease_http_credential".to_string();
        {
            let mut state = supervisor.lock().unwrap();
            state.http_mediator_lease_id = Some(lease_id.clone());
            state.record.http_mediator_lease_id = Some(lease_id.clone());
        }
        let proxy = HttpGatewayConfig {
            listen: "127.0.0.1:0".to_string(),
            client_address: "127.0.0.1".to_string(),
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_redirects: 0,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
            lease_id: Some(lease_id),
            expires_at_ms: Some(unix_millis().unwrap().saturating_add(60_000)),
            credential: Some(HttpCredentialInjection {
                handle_id: "credential_handle_1".to_string(),
                header_name: "Authorization".to_string(),
                value_file: credential_path.display().to_string(),
                allowed_url_prefixes: vec![format!("http://{origin_address}/repo")],
            }),
            gateway_id: None,
            commit_token_id: None,
            transaction: None,
        };
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_address = gateway.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(gateway_address).unwrap();
            write!(
                stream,
                "GET http://{origin_address}/repo/artifact?presigned=do-not-log HTTP/1.1\r\nAuthorization: attacker\r\nCookie: attacker=true\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, peer) = gateway.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            Arc::clone(&supervisor),
            Arc::new(Mutex::new(Vec::new())),
            proxy,
        )
        .unwrap();
        let response = client.join().unwrap();
        let upstream_request = origin_worker.join().unwrap().to_ascii_lowercase();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("artifact"));
        assert!(upstream_request.contains("authorization: super-secret-value"));
        assert!(!upstream_request.contains("authorization: attacker"));
        assert!(!upstream_request.contains("cookie: attacker=true"));

        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert!(effects.contains("credential_handle_1"));
        assert!(!effects.contains("super-secret-value"));
        assert!(!effects.contains("do-not-log"));
    }

    #[test]
    fn client_headers_do_not_cross_redirect_origins() {
        let redirected = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirected_address = redirected.local_addr().unwrap();
        let redirected_worker = thread::spawn(move || {
            let (mut stream, _) = redirected.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            String::from_utf8_lossy(&request[..count]).to_string()
        });
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_worker = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{redirected_address}/artifact\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request[..count]).to_string()
        });

        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        {
            let mut state = supervisor.lock().unwrap();
            for address in [origin_address, redirected_address] {
                state.record.envelope.grants.push(
                    gensee_crate_rules::network_boundary::NetworkEndpointGrant {
                        destination: address.ip().to_string(),
                        protocol: NetworkProtocol::Tcp,
                        ports: vec![address.port()],
                        expires_at_ms: None,
                        lease_id: None,
                    },
                );
            }
        }
        let response = execute_mediated_http(
            ParsedProxyRequest {
                method: "GET".to_string(),
                url: Url::parse(&format!("http://{origin_address}/artifact")).unwrap(),
                headers: vec![("X-Private-Context".to_string(), "secret".to_string())],
                declared_body_bytes: 0,
                body: Vec::new(),
            },
            supervisor,
            &HttpGatewayConfig {
                listen: "127.0.0.1:0".to_string(),
                client_address: "127.0.0.1".to_string(),
                max_request_bytes: 1024,
                max_response_bytes: 1024,
                max_redirects: 1,
                connect_timeout_seconds: 1,
                io_timeout_seconds: 1,
                lease_id: None,
                expires_at_ms: None,
                credential: None,
                gateway_id: None,
                commit_token_id: None,
                transaction: None,
            },
        )
        .unwrap();
        assert_eq!(response.status, 200);
        let first_request = origin_worker.join().unwrap().to_ascii_lowercase();
        let second_request = redirected_worker.join().unwrap().to_ascii_lowercase();
        assert!(first_request.contains("x-private-context: secret"));
        assert!(!second_request.contains("x-private-context"));
    }

    #[test]
    fn revoked_mediator_lease_denies_without_connecting_and_records_redacted_attempt() {
        let root = env::temp_dir().join(format!("gensee-network-test-{}", Uuid::new_v4()));
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        origin.set_nonblocking(true).unwrap();
        let origin_address = origin.local_addr().unwrap();
        let policy = NetworkBoundaryPolicy {
            http_gateway_available: true,
            ..NetworkBoundaryPolicy::default()
        };
        let supervisor = test_supervisor(&root, policy);
        let lease_id = "lease_http_revoked".to_string();
        {
            let mut state = supervisor.lock().unwrap();
            state.http_mediator_lease_id = Some(lease_id.clone());
            state.record.http_mediator_lease_id = Some(lease_id.clone());
            state
                .record
                .revoked_http_mediator_leases
                .insert(lease_id.clone());
        }
        let proxy = HttpGatewayConfig {
            listen: "127.0.0.1:0".to_string(),
            client_address: "127.0.0.1".to_string(),
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            max_redirects: 0,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
            lease_id: Some(lease_id),
            expires_at_ms: Some(unix_millis().unwrap().saturating_add(60_000)),
            credential: None,
            gateway_id: None,
            commit_token_id: None,
            transaction: None,
        };
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_address = gateway.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(gateway_address).unwrap();
            write!(
                stream,
                "GET http://{origin_address}/artifact?token=do-not-log HTTP/1.1\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (stream, peer) = gateway.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            supervisor,
            Arc::new(Mutex::new(Vec::new())),
            proxy,
        )
        .unwrap();
        assert!(client.join().unwrap().starts_with("HTTP/1.1 403"));
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
        let audit = fs::read_to_string(root.join("http-mediator.jsonl")).unwrap();
        assert!(audit.contains("http_mediator_lease_inactive"));
        assert!(!audit.contains("do-not-log"));
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
            max_request_bytes: 64 * 1024,
            max_response_bytes: 64 * 1024,
            max_redirects: 1,
            connect_timeout_seconds: 1,
            io_timeout_seconds: 1,
            lease_id: None,
            expires_at_ms: None,
            credential: None,
            gateway_id: None,
            commit_token_id: None,
            transaction: None,
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
        assert!(first_response.starts_with("HTTP/1.1 403"));
        assert!(matches!(
            challenge.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));

        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert!(effects.contains("\"response_status\":302"));
        assert!(effects.contains("\"reason_code\":\"restricted_destination\""));
        assert!(effects.contains("\"response_status\":403"));
    }

    #[test]
    fn transactional_redirect_cannot_escape_immutable_path_scope() {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        origin.set_nonblocking(false).unwrap();
        let origin_probe = origin.try_clone().unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_worker = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{origin_address}/uci/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-redirect-test-{}",
            Uuid::new_v4()
        ));
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
        let transaction_policy = transaction_policy(origin_address.to_string(), "/v1/data");
        install_transaction_policy(&supervisor, &transaction_policy);
        begin_and_activate(&supervisor, "tx_redirect");
        let proxy = transactional_proxy(transaction_policy);
        let result = execute_mediated_http(
            ParsedProxyRequest {
                method: "GET".to_string(),
                url: Url::parse(&format!("http://{origin_address}/v1/data/demo.bin")).unwrap(),
                headers: Vec::new(),
                declared_body_bytes: 0,
                body: Vec::new(),
            },
            supervisor,
            &proxy,
        );
        origin_worker.join().unwrap();
        assert!(matches!(result, Err(ref error) if error.kind() == ErrorKind::PermissionDenied));
        origin_probe.set_nonblocking(true).unwrap();
        assert!(matches!(
            origin_probe.accept(),
            Err(error) if error.kind() == ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn transaction_proxy_rejects_wrong_client_identity_and_records_it() {
        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-client-test-{}",
            Uuid::new_v4()
        ));
        let supervisor = test_supervisor(&root, NetworkBoundaryPolicy::default());
        let policy = transaction_policy("api.example.test".to_string(), "/v1/data");
        install_transaction_policy(&supervisor, &policy);
        begin_and_activate(&supervisor, "tx_identity");
        let mut proxy = transactional_proxy(policy);
        proxy.client_address = "192.0.2.20".to_string();
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_address = gateway.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(gateway_address).unwrap();
            stream
                .write_all(b"GET http://api.example.test/v1/data/a HTTP/1.1\r\n\r\n")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            response
        });
        let (stream, peer) = gateway.accept().unwrap();
        handle_http_proxy_connection(
            stream,
            peer,
            supervisor,
            Arc::new(Mutex::new(Vec::new())),
            proxy,
        )
        .unwrap();
        let _response = client.join().unwrap();
        let audit = fs::read_to_string(root.join("http-transactions.jsonl")).unwrap();
        assert!(audit.contains("http_transaction_wrong_client_identity"));
    }

    #[test]
    fn revocation_actively_shuts_down_in_flight_client_transport() {
        use std::sync::mpsc;

        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_address = origin.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let origin_worker = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            accepted_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nartifact",
                )
                .unwrap();
        });

        let root = env::temp_dir().join(format!(
            "gensee-network-transaction-revoke-test-{}",
            Uuid::new_v4()
        ));
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
        let transaction_policy = transaction_policy(origin_address.to_string(), "/v1/data");
        install_transaction_policy(&supervisor, &transaction_policy);
        begin_and_activate(&supervisor, "tx_revoke");
        let proxy = transactional_proxy(transaction_policy);
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_address = gateway.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(gateway_address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(750)))
                .unwrap();
            write!(
                stream,
                "GET http://{origin_address}/v1/data/a HTTP/1.1\r\n\r\n"
            )
            .unwrap();
            let mut response = Vec::new();
            let read = stream.read_to_end(&mut response);
            (read, response)
        });
        let (stream, peer) = gateway.accept().unwrap();
        let handler_supervisor = Arc::clone(&supervisor);
        let handler = thread::spawn(move || {
            handle_http_proxy_connection(
                stream,
                peer,
                handler_supervisor,
                Arc::new(Mutex::new(Vec::new())),
                proxy,
            )
        });
        accepted_rx.recv().unwrap();
        supervisor
            .lock()
            .unwrap()
            .terminal_http_transaction(
                "tx_revoke",
                "op_1",
                HttpTransactionStatus::Revoked,
                "revoke",
            )
            .unwrap();
        let (read, response) = client.join().unwrap();
        assert!(read.is_ok(), "revocation should close, not merely time out");
        assert!(response.is_empty());
        release_tx.send(()).unwrap();
        origin_worker.join().unwrap();
        assert!(handler.join().unwrap().is_err());
        let effects = fs::read_to_string(root.join("effects.jsonl")).unwrap();
        assert!(effects.contains("http_transaction_late_response_denied"));
        assert!(effects.contains("\"transaction_id\":\"tx_revoke\""));
        assert!(effects.contains("\"bytes_from_upstream\":8"));
        assert!(effects.contains("\"bytes_to_client\":0"));
    }
}
