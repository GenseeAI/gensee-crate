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
use std::io::{BufReader, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
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
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    #[serde(default)]
    revoked_http_mediator_leases: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_mediator_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_mediator_expires_at_ms: Option<u64>,
    started_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NetworkSupervisorRequest {
    Event { event: NetworkBoundaryEvent },
    Fault { fault: CapabilityFault },
    RevokeHttpMediator { lease_id: String },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_handle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_target: Option<String>,
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
    dry_run: bool,
    operation: Option<OperationSupervisor>,
    active_plan: Option<gensee_crate_linux::LinuxNftablesPlan>,
    counter_snapshot: BTreeMap<String, (u64, u64)>,
    next_usage_sample_at_ms: u64,
    last_counter_error: Option<String>,
    http_mediator_lease_id: Option<String>,
    #[cfg(target_os = "linux")]
    attempt_monitor: Option<gensee_crate_linux::LinuxNetworkAttemptMonitor>,
    #[cfg(any(target_os = "linux", test))]
    observed_attempt_traces: BTreeSet<String>,
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
        Some("revoke-http") => revoke_http_mediator(&args[1..]),
        Some("inspect") => inspect_network_supervisor(&args[1..]),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: gensee run network <serve --state-root ROOT --config FILE [--dry-run]|event --socket PATH --event FILE|fault --socket PATH --fault FILE|revoke-http --socket PATH --lease ID|inspect --socket PATH>",
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

    let root = network_operation_root(&config.operation_id)?;
    create_restrictive_dir_all(&root)?;
    #[cfg(unix)]
    let _operation_lock = NetworkOperationLock::acquire(&root.join("supervisor.lock"))?;
    let socket_path = root.join("supervisor.sock");
    let record_path = root.join("record.json");
    let event_log_path = root.join("effects.jsonl");
    let counter_log_path = root.join("counters.jsonl");
    let fault_log_path = root.join("faults.jsonl");
    let mediator_log_path = root.join("http-mediator.jsonl");
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
            || previous.http_mediator_lease_id != config.proxy.lease_id
            || previous.http_mediator_expires_at_ms != config.proxy.expires_at_ms
            || previous
                .revoked_http_mediator_leases
                .iter()
                .any(|lease_id| !safe_network_token(lease_id))
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
        revoked_http_mediator_leases: previous.as_ref().map_or_else(BTreeSet::new, |record| {
            record.revoked_http_mediator_leases.clone()
        }),
        http_mediator_lease_id: config.proxy.lease_id.clone(),
        http_mediator_expires_at_ms: config.proxy.expires_at_ms,
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
    operation.update_network_envelope(config.envelope.clone())?;
    let supervisor = Arc::new(Mutex::new(NetworkSupervisor {
        record,
        record_path,
        event_log_path,
        counter_log_path,
        fault_log_path,
        mediator_log_path,
        dry_run,
        operation: Some(operation),
        active_plan,
        counter_snapshot,
        next_usage_sample_at_ms: now_ms.saturating_add(NETWORK_USAGE_POLL_INTERVAL_MS),
        last_counter_error: None,
        http_mediator_lease_id: config.proxy.lease_id.clone(),
        #[cfg(target_os = "linux")]
        attempt_monitor,
        #[cfg(any(target_os = "linux", test))]
        observed_attempt_traces: BTreeSet::new(),
    }));
    let _cleanup = NetworkRuntimeCleanup {
        table_names: Arc::clone(&table_names),
        cgroup_path,
    };
    {
        let mut state = lock_supervisor(&supervisor)?;
        state.reconcile_expired_and_apply(&table_names)?;
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

        loop {
            match unix_listener.accept() {
                Ok((stream, _)) => {
                    if !dry_run && peer_effective_uid(&stream)? != 0 {
                        eprintln!(
                            "gensee: rejected non-root boundary control peer for operation={}",
                            config.operation_id
                        );
                        continue;
                    }
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
        || (mutating_http || config.proxy.credential.is_some()) && config.proxy.lease_id.is_none()
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
            request_digest: None,
            response_digest: None,
            credential_handle_id: None,
            redirect_target: None,
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
            if self.observed_attempt_traces.len() > 4096 {
                self.observed_attempt_traces.clear();
                self.observed_attempt_traces.insert(trace_key.clone());
                if let Some(operation) = self.operation.as_mut() {
                    operation.record_boundary_violation(
                        "network_attempt_dedupe_limit_reached",
                        "kernel network attempt deduplication reached its bounded limit",
                    )?;
                }
            }
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
                observed_at_ms: unix_millis()?,
            };
            let (resolution, effect) = self.resolve_fault(&fault, table_names)?;
            self.append_fault_evidence(&fault, &resolution)?;
            if let Some(effect) = effect.as_ref() {
                self.append_effect(effect)?;
            }
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

    fn append_http_mediator_audit(
        &self,
        request: &ParsedProxyRequest,
        disposition: &str,
        reason_code: &str,
    ) -> io::Result<()> {
        let mut file = open_owner_append_nofollow(&self.mediator_log_path)?;
        serde_json::to_writer(
            &mut file,
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
                disposition: disposition.to_string(),
                reason_code: reason_code.to_string(),
                observed_at_ms: unix_millis()?,
            },
        )?;
        file.write_all(b"\n")?;
        file.sync_data()
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
        NetworkSupervisorRequest::RevokeHttpMediator { lease_id } => {
            let mut state = lock_supervisor(&supervisor)?;
            let response = if state.http_mediator_lease_id.as_deref() == Some(&lease_id) {
                state.record.revoked_http_mediator_leases.insert(lease_id);
                state.record.updated_at_ms = unix_millis()?;
                state.persist()?;
                NetworkSupervisorResponse {
                    ok: true,
                    decision: None,
                    resolution: None,
                    record: Some(state.record.clone()),
                    error: None,
                }
            } else {
                NetworkSupervisorResponse {
                    ok: false,
                    decision: None,
                    resolution: None,
                    record: None,
                    error: Some(
                        "HTTP mediator lease does not belong to this operation".to_string(),
                    ),
                }
            };
            response
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
                        request_digest: None,
                        response_digest: None,
                        credential_handle_id: None,
                        redirect_target: None,
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
    _table_names: Arc<Mutex<Vec<String>>>,
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
        let state = lock_supervisor(&supervisor)?;
        if !http_mediator_is_active(&state, &config, now_ms) {
            state.append_http_mediator_audit(&request, "deny", "http_mediator_lease_inactive")?;
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
            let state = lock_supervisor(&supervisor)?;
            if !http_mediator_is_active(&state, config, now_ms) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "HTTP mediator lease expired or was revoked before the effect completed",
                ));
            }
        }
        let request_digest =
            mediated_http_request_digest(&method, &current_url, &request.headers, &request.body);
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
                    response_status: Some(403),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
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
                    response_status: Some(403),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                })?;
                return Err(io::Error::new(ErrorKind::PermissionDenied, error));
            }
        }
        let upstream = perform_pinned_http_request(
            &method,
            &current_url,
            address,
            &request.headers,
            &request.body,
            credential.as_ref(),
            config,
        );
        let response = match upstream {
            Ok(response) => response,
            Err(error) => {
                let effect = NetworkEffectRecord {
                    schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
                    fault_id: None,
                    event,
                    decision,
                    lease_id: config.lease_id.clone(),
                    response_status: Some(502),
                    request_digest: Some(request_digest),
                    response_digest: None,
                    credential_handle_id,
                    redirect_target: None,
                    bytes_from_client: request.body.len() as u64,
                    bytes_to_client: 0,
                    completed_at_ms: unix_millis()?,
                };
                lock_supervisor(&supervisor)?.append_effect(&effect)?;
                return Err(error);
            }
        };
        let redirect = redirect_target(&current_url, &response)?;
        let response_digest = mediated_http_response_digest(&response);
        let effect = NetworkEffectRecord {
            schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
            fault_id: None,
            event,
            decision,
            lease_id: config.lease_id.clone(),
            response_status: Some(response.status),
            request_digest: Some(request_digest),
            response_digest: Some(response_digest),
            credential_handle_id,
            redirect_target: redirect.as_ref().map(redacted_url_for_evidence),
            bytes_from_client: request.body.len() as u64,
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
                response_status: Some(403),
                request_digest: Some(request_digest.to_string()),
                response_digest: None,
                credential_handle_id: None,
                redirect_target: None,
                bytes_from_client: 0,
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
    request.body.resize(body_len, 0);
    stream.read_exact(&mut request.body)?;
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
                revoked_http_mediator_leases: BTreeSet::new(),
                http_mediator_lease_id: None,
                http_mediator_expires_at_ms: None,
                started_at_ms: 1,
                updated_at_ms: 1,
            },
            record_path: root.join("record.json"),
            event_log_path: root.join("effects.jsonl"),
            counter_log_path: root.join("counters.jsonl"),
            fault_log_path: root.join("faults.jsonl"),
            mediator_log_path: root.join("http-mediator.jsonl"),
            dry_run: true,
            operation: None,
            active_plan: None,
            counter_snapshot: BTreeMap::new(),
            next_usage_sample_at_ms: u64::MAX,
            last_counter_error: None,
            http_mediator_lease_id: None,
            #[cfg(target_os = "linux")]
            attempt_monitor: None,
            #[cfg(any(target_os = "linux", test))]
            observed_attempt_traces: BTreeSet::new(),
        }))
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
            allowed_url_prefixes: vec!["https://artifacts.example:8443/repository".to_string()],
        };
        for allowed in [
            "https://artifacts.example:8443/repository",
            "https://artifacts.example:8443/repository/item",
        ] {
            assert!(credential_applies_to_url(
                &credential,
                &Url::parse(allowed).unwrap()
            ));
        }
        for outside in [
            "https://artifacts.example/repository/item",
            "http://artifacts.example:8443/repository/item",
            "https://artifacts.example:8443/repository-evil/item",
            "https://artifacts.example.evil:8443/repository/item",
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
            &Url::parse("https://artifacts.example/object").unwrap(),
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
    fn proxy_parser_rejects_embedded_credentials_and_non_http_protocols() {
        for target in ["http://user:password@example.test/a", "file:///etc/passwd"] {
            let request = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert!(parse_proxy_request_bytes(request.as_bytes()).is_err());
        }
        for request in [
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
            allowed_url_prefixes: vec!["https://repo.example/packages".to_string()],
        };
        assert!(credential_applies_to_url(
            &credential,
            &Url::parse("https://repo.example/packages/a.tgz?token=1").unwrap()
        ));
        assert!(!credential_applies_to_url(
            &credential,
            &Url::parse("https://repo.example/packages-evil/a.tgz").unwrap()
        ));
        assert!(!credential_applies_to_url(
            &credential,
            &Url::parse("https://evil.example/packages/a.tgz").unwrap()
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
}
