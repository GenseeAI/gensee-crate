use crate::*;
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
use std::os::unix::{fs::PermissionsExt, io::AsRawFd};
use std::sync::{Arc, Mutex};
use url::Url;
use uuid::Uuid;

const NETWORK_SUPERVISOR_SCHEMA_VERSION: u32 = 1;
const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const NETWORK_POLL_INTERVAL_MS: u64 = 100;

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
    started_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NetworkSupervisorRequest {
    Event { event: NetworkBoundaryEvent },
    Inspect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkSupervisorResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<NetworkBoundaryDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record: Option<NetworkOperationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkEffectRecord {
    schema_version: u32,
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

struct NetworkSupervisor {
    record: NetworkOperationRecord,
    record_path: PathBuf,
    event_log_path: PathBuf,
    dry_run: bool,
    operation: Option<OperationSupervisor>,
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
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
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
        Some("inspect") => inspect_network_supervisor(&args[1..]),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: gensee run network <serve --config FILE [--dry-run]|event --socket PATH --event FILE|inspect --socket PATH>",
        )),
    }
}

fn serve_network_supervisor(args: &[OsString]) -> io::Result<()> {
    let config_path = network_arg_value(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --config"))?;
    let config: NetworkOperationConfig = serde_json::from_str(&fs::read_to_string(&config_path)?)
        .map_err(|error| {
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
    let stale_table = if record_path.exists() {
        let previous: NetworkOperationRecord =
            serde_json::from_str(&fs::read_to_string(&record_path)?).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("cannot reconcile prior network operation record: {error}"),
                )
            })?;
        if previous.operation_id != config.operation_id
            || previous.source_run_id != config.source_run_id
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
        previous.active_table_name
    } else {
        None
    };
    let started_at_ms = unix_millis()?;
    let record = NetworkOperationRecord {
        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
        operation_id: config.operation_id.clone(),
        source_run_id: config.source_run_id.clone(),
        root_pid: config.root_pid,
        source_address: config.source_address.clone(),
        envelope: config.envelope.clone(),
        policy: config.policy.clone(),
        active_table_name: None,
        generation: 0,
        started_at_ms,
        updated_at_ms: started_at_ms,
    };
    let table_names = Arc::new(Mutex::new(Vec::new()));
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
        dry_run,
        operation: Some(operation),
    }));
    let _cleanup = NetworkRuntimeCleanup {
        table_names: Arc::clone(&table_names),
        cgroup_path,
    };
    {
        let mut state = lock_supervisor(&supervisor)?;
        state.reconcile_expired_and_apply(&table_names)?;
    }
    if let Some(stale_table) = stale_table {
        if !dry_run {
            // The new baseline is active before stale authority is removed.
            gensee_crate_linux::delete_nftables_table_if_exists(&stale_table)?;
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
                if state.has_expired_leases(unix_millis()?) {
                    state.reconcile_expired_and_apply(&table_names)?;
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
        let session = format!("{}_{}", self.record.operation_id, self.record.generation);
        let mut config = gensee_crate_linux::LinuxNetworkEnforcementConfig::new(
            session,
            gensee_crate_linux::LinuxNetworkPolicy {
                mode: gensee_crate_linux::LinuxNetworkMode::AllowListed,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: self
                    .record
                    .envelope
                    .grants
                    .iter()
                    .flat_map(|grant| {
                        grant.ports.iter().map(move |port| {
                            gensee_crate_linux::LinuxNetworkEndpoint {
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
                            }
                        })
                    })
                    .collect(),
            },
        );
        config.root_pid = self.record.root_pid;
        if let Some(pid) = self.record.root_pid {
            config.cgroup_path =
                gensee_crate_linux::default_agent_cgroup_path(&self.record.operation_id)
                    .to_string_lossy()
                    .to_string();
            if !self.dry_run {
                gensee_crate_linux::attach_process_tree_to_cgroup(
                    pid,
                    Path::new(&config.cgroup_path),
                )?;
            }
        }
        let mut plan = gensee_crate_linux::plan_nftables_policy(&config);
        if let Some(address) = self.record.source_address.as_deref() {
            gensee_crate_linux::bind_nftables_plan_to_source_address(
                &mut plan.nftables,
                address.parse().map_err(|_| {
                    io::Error::new(ErrorKind::InvalidData, "invalid stored source address")
                })?,
            );
        }
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
            if let Some(old_table) = self.record.active_table_name.as_deref() {
                gensee_crate_linux::delete_nftables_table_if_exists(old_table)?;
            }
        }
        {
            let mut names = table_names
                .lock()
                .map_err(|_| io::Error::other("network table registry lock poisoned"))?;
            names.push(new_table.clone());
            if let Some(old) = self.record.active_table_name.as_deref() {
                names.retain(|name| name != old);
            }
        }
        self.record.active_table_name = Some(new_table);
        self.record.updated_at_ms = now_ms;
        self.persist()?;
        if let Some(operation) = self.operation.as_mut() {
            operation.update_network_envelope(self.record.envelope.clone())?;
        }
        Ok(())
    }

    fn append_effect(&mut self, effect: &NetworkEffectRecord) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.event_log_path)?;
        #[cfg(unix)]
        fs::set_permissions(
            &self.event_log_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
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
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let request: NetworkSupervisorRequest = serde_json::from_str(&line)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    let response = match request {
        NetworkSupervisorRequest::Inspect => NetworkSupervisorResponse {
            ok: true,
            decision: None,
            record: Some(lock_supervisor(&supervisor)?.record.clone()),
            error: None,
        },
        NetworkSupervisorRequest::Event { mut event } => {
            let mut state = lock_supervisor(&supervisor)?;
            let decision = state.decide(&mut event)?;
            match state.apply_decision(&event, decision, &table_names) {
                Ok(decision) => {
                    let effect = NetworkEffectRecord {
                        schema_version: NETWORK_SUPERVISOR_SCHEMA_VERSION,
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
                        record: None,
                        error: None,
                    }
                }
                Err(error) => NetworkSupervisorResponse {
                    ok: false,
                    decision: None,
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
    let event: NetworkBoundaryEvent = serde_json::from_str(&fs::read_to_string(event_path)?)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    send_supervisor_request(args, &NetworkSupervisorRequest::Event { event })
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
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
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

fn lock_supervisor(
    supervisor: &Arc<Mutex<NetworkSupervisor>>,
) -> io::Result<std::sync::MutexGuard<'_, NetworkSupervisor>> {
    supervisor
        .lock()
        .map_err(|_| io::Error::other("network supervisor lock poisoned"))
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
                started_at_ms: 1,
                updated_at_ms: 1,
            },
            record_path: root.join("record.json"),
            event_log_path: root.join("effects.jsonl"),
            dry_run: true,
            operation: None,
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
