use super::*;
use gensee_crate_rules::capability_broker::{
    BrokerAdapterRequest, BrokerAdapterResponse, BrokerDelivery, BrokerLease, BrokerLeaseRequest,
    BrokerLeaseStatus, BrokerResourceKind, ExternalActionCommitClaims,
    SignedExternalActionCommitToken, BROKER_PROTOCOL_VERSION,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const BROKER_ADAPTER_SCHEMA_VERSION: u32 = 1;
const BROKER_MAX_TTL_SECONDS: u64 = 15 * 60;
const BROKER_ADAPTER_TIMEOUT_SECONDS: u64 = 30;
const BROKER_ADAPTER_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const BUILTIN_EXTERNAL_ACTION_ADAPTER: &str = "gensee.external-action";
const BUILTIN_FILESYSTEM_ADAPTER: &str = "gensee.filesystem";
pub(super) const BUILTIN_NETWORK_ADAPTER: &str = "gensee.network";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerAdapterConfig {
    schema_version: u32,
    adapter_id: String,
    resource_kinds: Vec<BrokerResourceKind>,
    executable: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    environment_allowlist: Vec<String>,
    max_ttl_seconds: u64,
}

pub(crate) fn tclone_capability_broker(args: Vec<OsString>) -> io::Result<()> {
    ensure_broker_host_only()?;
    let command = (
        args.first().and_then(|arg| arg.to_str()),
        args.get(1).and_then(|arg| arg.to_str()),
    );
    let recovery = super::capability_cell::recover_expired_capability_cells(unix_millis()?);
    if matches!(
        command,
        (Some("lease"), Some("issue")) | (Some("commit"), Some("consume"))
    ) {
        recovery?;
    } else if let Err(error) = recovery {
        eprintln!("gensee: warning: capability-cell recovery incomplete: {error}");
    }
    match command {
        (Some("adapter"), Some("register")) => register_broker_adapter(&args[2..]),
        (Some("adapter"), Some("inspect")) => inspect_broker_adapter(&args[2..]),
        (Some("lease"), Some("issue")) => issue_broker_lease(&args[2..]),
        (Some("lease"), Some("inspect")) => inspect_broker_lease(&args[2..]),
        (Some("lease"), Some("revoke")) => revoke_broker_lease(&args[2..]),
        (Some("lease"), Some("revoke-expired")) => revoke_expired_broker_leases(&args[2..]),
        (Some("commit"), Some("consume")) => consume_external_commit_token(&args[2..]),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run broker <adapter register|adapter inspect|lease issue|lease inspect|lease revoke|lease revoke-expired|commit consume> ...",
        )),
    }
}

fn ensure_broker_host_only() -> io::Result<()> {
    if env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some()
        || env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).is_some()
        || env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability broker administration is host-only",
        ));
    }
    Ok(())
}

fn register_broker_adapter(args: &[OsString]) -> io::Result<()> {
    let config_path = arg_value(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --config"))?;
    let config: BrokerAdapterConfig = serde_json::from_str(&read_nofollow_to_string(&config_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_broker_adapter_config(&config)?;
    let path = broker_adapter_path(&config.adapter_id)?;
    if path.exists() && !args.iter().any(|arg| arg == "--replace") {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "broker adapter already exists; use --replace from the trusted host to rotate it",
        ));
    }
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&config)?, 0o600)?;
    println!("registered capability broker adapter {}", config.adapter_id);
    Ok(())
}

fn inspect_broker_adapter(args: &[OsString]) -> io::Result<()> {
    let adapter_id = tclone_target_arg(
        args,
        "usage: gensee run broker adapter inspect <adapter-id> [--json]",
    )?;
    let config = load_broker_adapter(&adapter_id)?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        println!("adapter: {}", config.adapter_id);
        println!("executable: {}", config.executable);
        println!("resource kinds: {:?}", config.resource_kinds);
        println!("maximum TTL: {}s", config.max_ttl_seconds);
    }
    Ok(())
}

fn validate_broker_adapter_config(config: &BrokerAdapterConfig) -> io::Result<()> {
    if config.schema_version != BROKER_ADAPTER_SCHEMA_VERSION
        || !tclone_is_safe_token(&config.adapter_id)
        || config.resource_kinds.is_empty()
        || config.max_ttl_seconds == 0
        || config.max_ttl_seconds > BROKER_MAX_TTL_SECONDS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker adapter id, schema, resource list, or TTL",
        ));
    }
    if [
        BUILTIN_EXTERNAL_ACTION_ADAPTER,
        BUILTIN_FILESYSTEM_ADAPTER,
        BUILTIN_NETWORK_ADAPTER,
    ]
    .contains(&config.adapter_id.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "adapter id is reserved for a built-in mediator",
        ));
    }
    let executable = Path::new(&config.executable);
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker adapter executable must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(executable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter executable must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter executable must not be group- or world-writable",
        ));
    }
    for name in &config.environment_allowlist {
        if !valid_broker_environment_name(name) || dangerous_broker_environment_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsafe broker adapter environment entry: {name}"),
            ));
        }
    }
    Ok(())
}

fn valid_broker_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn dangerous_broker_environment_name(name: &str) -> bool {
    matches!(name, "HOME" | "PATH" | "SHELL" | "PYTHONPATH" | "RUBYLIB")
        || name.starts_with("LD_")
        || name.starts_with("DYLD_")
}

fn issue_broker_lease(args: &[OsString]) -> io::Result<()> {
    let request_path = arg_value(args, "--request")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --request"))?;
    let mut request: BrokerLeaseRequest =
        serde_json::from_str(&read_nofollow_to_string(&request_path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_broker_lease_request(&request)?;
    let source = find_tclone_record(&request.source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker leases require a running source",
        ));
    }

    let issued_at_ms = unix_millis()?;
    if let Some(cell_id) = request.cell_id.as_deref() {
        let cell_expires_at_ms = super::capability_cell::validate_broker_cell_binding(
            cell_id,
            &request.source_run_id,
            &request.operation_id,
            issued_at_ms,
        )?;
        let remaining_seconds = cell_expires_at_ms
            .saturating_sub(issued_at_ms)
            .checked_div(1_000)
            .unwrap_or(0);
        if remaining_seconds == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "capability cell lease expires too soon to attach broker authority",
            ));
        }
        request.ttl_seconds = request.ttl_seconds.min(remaining_seconds);
    }
    let lease_id = format!("broker_lease_{}", Uuid::new_v4().simple());
    let (delivery, public_metadata, gateway_effects, effect_telemetry_complete, adapter_max_ttl) =
        match request.resource_kind {
            BrokerResourceKind::ExternalActionCommitToken => {
                if request.adapter_id != BUILTIN_EXTERNAL_ACTION_ADAPTER {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "external commit tokens must use the built-in signer",
                    ));
                }
                let token_id = issue_external_commit_token(&lease_id, &request, issued_at_ms)?;
                (
                    BrokerDelivery::CommitToken {
                        commit_token_id: token_id,
                    },
                    Value::Null,
                    Vec::new(),
                    true,
                    BROKER_MAX_TTL_SECONDS,
                )
            }
            BrokerResourceKind::FilesystemHandle => {
                if request.adapter_id != BUILTIN_FILESYSTEM_ADAPTER {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "filesystem handles must use the built-in filesystem mediator",
                    ));
                }
                validate_filesystem_constraints(&request.constraints)?;
                (
                    BrokerDelivery::FilesystemHandle {
                        handle_id: format!("fs_handle_{}", Uuid::new_v4().simple()),
                    },
                    Value::Null,
                    Vec::new(),
                    true,
                    BROKER_MAX_TTL_SECONDS,
                )
            }
            BrokerResourceKind::NetworkLease => {
                if request.adapter_id != BUILTIN_NETWORK_ADAPTER {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "network leases must use the built-in network mediator",
                    ));
                }
                validate_network_constraints(&request.constraints)?;
                (
                    BrokerDelivery::NetworkLease {
                        network_lease_id: format!("net_lease_{}", Uuid::new_v4().simple()),
                    },
                    Value::Null,
                    Vec::new(),
                    false,
                    BROKER_MAX_TTL_SECONDS,
                )
            }
            _ => {
                let config = load_broker_adapter(&request.adapter_id)?;
                if !config.resource_kinds.contains(&request.resource_kind) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "broker adapter is not registered for the requested resource kind",
                    ));
                }
                let response = invoke_broker_adapter(&config, "mint", &request, None)?;
                (
                    BrokerDelivery::Gateway {
                        gateway_endpoint: response.gateway_endpoint,
                        provider_handle: response.provider_handle,
                    },
                    response.public_metadata,
                    response.effects,
                    response.effect_telemetry_complete,
                    config.max_ttl_seconds,
                )
            }
        };
    let ttl_seconds = request
        .ttl_seconds
        .min(adapter_max_ttl)
        .min(BROKER_MAX_TTL_SECONDS);
    if request.cell_id.is_some() {
        if let BrokerDelivery::Gateway {
            gateway_endpoint, ..
        } = &delivery
        {
            validate_cell_gateway_socket(gateway_endpoint)?;
        }
    }
    let lease = BrokerLease {
        protocol_version: BROKER_PROTOCOL_VERSION,
        lease_id: lease_id.clone(),
        operation_id: request.operation_id,
        source_run_id: request.source_run_id,
        cell_id: request.cell_id,
        resource_kind: request.resource_kind,
        adapter_id: request.adapter_id,
        audience: request.audience,
        scopes: request.scopes,
        constraints: request.constraints,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        status: BrokerLeaseStatus::Active,
        delivery,
        public_metadata,
        gateway_effects,
        effect_telemetry_complete,
        revoked_at_ms: None,
        consumed_at_ms: None,
    };
    let path = broker_lease_path(&lease_id)?;
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    if let Some(cell_id) = lease.cell_id.as_deref() {
        if let Err(error) = super::capability_cell::attach_broker_lease_to_cell(
            cell_id,
            &lease.source_run_id,
            &lease.operation_id,
            &lease.lease_id,
            lease.resource_kind,
            unix_millis()?,
        ) {
            let mut failed_lease = lease.clone();
            let _ = revoke_broker_lease_record(&mut failed_lease);
            let _ = persist_broker_lease(&failed_lease);
            return Err(error);
        }
    }
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&lease)?);
    } else {
        println!(
            "issued broker lease {} for {:?}; expires at {}",
            lease.lease_id, lease.resource_kind, lease.expires_at_ms
        );
    }
    Ok(())
}

fn validate_broker_lease_request(request: &BrokerLeaseRequest) -> io::Result<()> {
    if request.protocol_version != BROKER_PROTOCOL_VERSION
        || !tclone_is_safe_token(&request.operation_id)
        || !tclone_is_safe_token(&request.source_run_id)
        || request
            .cell_id
            .as_deref()
            .is_some_and(|cell| !tclone_is_safe_token(cell))
        || !tclone_is_safe_token(&request.adapter_id)
        || request.audience.trim().is_empty()
        || request.audience == "*"
        || request.scopes.is_empty()
        || request
            .scopes
            .iter()
            .any(|scope| scope.trim().is_empty() || scope == "*")
        || request.ttl_seconds == 0
        || request.ttl_seconds > BROKER_MAX_TTL_SECONDS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker lease requires a bounded source, adapter, audience, scopes, and TTL",
        ));
    }
    if contains_secret_shaped_json(&request.constraints) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker constraints must contain selectors and handles, never credential material",
        ));
    }
    if request.cell_id.is_some() {
        let expected_gateway_kinds: &[&str] = match request.resource_kind {
            BrokerResourceKind::RepositoryToken => &["repository_api"],
            BrokerResourceKind::ApiToken => {
                &["external_api", "cloud_api", "browser_automation", "secret"]
            }
            BrokerResourceKind::WorkloadIdentity => &["workload_identity"],
            BrokerResourceKind::MtlsCertificate => &["mtls"],
            BrokerResourceKind::DatabaseRole => &["database"],
            BrokerResourceKind::FilesystemHandle
            | BrokerResourceKind::NetworkLease
            | BrokerResourceKind::ExternalActionCommitToken => &[],
        };
        if !expected_gateway_kinds.is_empty() {
            let gateway_kind = required_json_string(&request.constraints, "gateway_kind")?;
            if !expected_gateway_kinds.contains(&gateway_kind) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker gateway kind does not match the requested resource",
                ));
            }
        }
    }
    Ok(())
}

fn validate_filesystem_constraints(value: &Value) -> io::Result<()> {
    let path = required_json_string(value, "path")?;
    let path_value = Path::new(path);
    if path_value.is_absolute()
        || path.starts_with('\\')
        || path.as_bytes().get(1) == Some(&b':')
        || path.split(['/', '\\']).any(|component| component == "..")
        || path_value.components().any(|component| {
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
            "filesystem broker paths must be workspace-relative without traversal",
        ));
    }
    let access = required_json_string(value, "access")?;
    if !matches!(access, "read" | "write" | "read_write") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem handle access must be read, write, or read_write",
        ));
    }
    Ok(())
}

fn validate_network_constraints(value: &Value) -> io::Result<()> {
    let destination = required_json_string(value, "destination")?;
    let protocol = required_json_string(value, "protocol")?;
    let ports = value
        .get("ports")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network ports missing"))?;
    let ip_and_prefix = destination.split_once('/');
    let address = ip_and_prefix
        .map(|(address, _)| address)
        .unwrap_or(destination);
    let parsed_address = address.parse::<std::net::IpAddr>().ok();
    let valid_prefix = match (parsed_address, ip_and_prefix) {
        (Some(std::net::IpAddr::V4(_)), Some((_, prefix))) => prefix
            .parse::<u8>()
            .is_ok_and(|prefix| prefix > 0 && prefix <= 32),
        (Some(std::net::IpAddr::V6(_)), Some((_, prefix))) => prefix
            .parse::<u8>()
            .is_ok_and(|prefix| prefix > 0 && prefix <= 128),
        (Some(_), None) => true,
        _ => false,
    };
    if destination == "*"
        || destination == "0.0.0.0/0"
        || destination == "::/0"
        || !valid_prefix
        || !matches!(protocol, "tcp" | "udp")
        || ports.is_empty()
        || ports.iter().any(|port| {
            port.as_u64()
                .is_none_or(|port| port == 0 || port > u16::MAX as u64)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "network lease requires bounded destinations, protocols, and ports",
        ));
    }
    Ok(())
}

fn inspect_broker_lease(args: &[OsString]) -> io::Result<()> {
    let lease_id = tclone_target_arg(
        args,
        "usage: gensee run broker lease inspect <lease-id> [--json]",
    )?;
    let mut lease = load_broker_lease(&lease_id)?;
    if lease.status == BrokerLeaseStatus::Active && unix_millis()? >= lease.expires_at_ms {
        lease.status = BrokerLeaseStatus::Expired;
    }
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&lease)?);
    } else {
        println!("lease: {}", lease.lease_id);
        println!("resource: {:?}", lease.resource_kind);
        println!("status: {:?}", lease.status);
        println!("expires: {}", lease.expires_at_ms);
        println!("delivery: {:?}", lease.delivery);
    }
    Ok(())
}

fn revoke_broker_lease(args: &[OsString]) -> io::Result<()> {
    let lease_id = tclone_target_arg(
        args,
        "usage: gensee run broker lease revoke <lease-id> [--json]",
    )?;
    let lease_path = broker_lease_path(&lease_id)?;
    let _lock = TcloneStateLock::acquire(&lease_path)?;
    let mut lease = load_broker_lease(&lease_id)?;
    revoke_broker_lease_record(&mut lease)?;
    persist_broker_lease(&lease)?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&lease)?);
    } else {
        println!("broker lease {} is now {:?}", lease.lease_id, lease.status);
    }
    Ok(())
}

fn revoke_broker_lease_record(lease: &mut BrokerLease) -> io::Result<()> {
    if matches!(
        lease.status,
        BrokerLeaseStatus::Revoked | BrokerLeaseStatus::Consumed
    ) {
        return Ok(());
    }
    match &lease.delivery {
        BrokerDelivery::Gateway {
            provider_handle, ..
        } => {
            let config = load_broker_adapter(&lease.adapter_id)?;
            let request = lease_to_request(lease);
            let response =
                invoke_broker_adapter(&config, "revoke", &request, Some(provider_handle.clone()))?;
            lease.gateway_effects.extend(response.effects);
            lease.effect_telemetry_complete = response.effect_telemetry_complete;
            lease.public_metadata = response.public_metadata;
        }
        BrokerDelivery::CommitToken { commit_token_id } => {
            let token_path = external_commit_token_path(commit_token_id)?;
            let _token_lock = TcloneStateLock::acquire(&token_path)?;
            let mut token = load_external_commit_token(commit_token_id)?;
            if let Some(consumed_at_ms) = token.consumed_at_ms {
                lease.status = BrokerLeaseStatus::Consumed;
                lease.consumed_at_ms = Some(consumed_at_ms);
                return Ok(());
            }
            if token.revoked_at_ms.is_none() {
                token.revoked_at_ms = Some(unix_millis()?);
                persist_external_commit_token(&token)?;
            }
        }
        BrokerDelivery::FilesystemHandle { .. } | BrokerDelivery::NetworkLease { .. } => {}
    }
    lease.status = BrokerLeaseStatus::Revoked;
    lease.revoked_at_ms = Some(unix_millis()?);
    Ok(())
}

fn revoke_expired_broker_leases(args: &[OsString]) -> io::Result<()> {
    let now = unix_millis()?;
    let mut revoked = Vec::new();
    let leases_dir = broker_root()?.join("leases");
    if leases_dir.exists() {
        for entry in fs::read_dir(&leases_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let mut lease: BrokerLease =
                serde_json::from_str(&read_nofollow_to_string(&entry.path())?)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if lease.status == BrokerLeaseStatus::Active && now >= lease.expires_at_ms {
                let _lock = TcloneStateLock::acquire(&entry.path())?;
                lease = load_broker_lease(&lease.lease_id)?;
                if lease.status != BrokerLeaseStatus::Active || now < lease.expires_at_ms {
                    continue;
                }
                revoke_broker_lease_record(&mut lease)?;
                if lease.status != BrokerLeaseStatus::Consumed {
                    lease.status = BrokerLeaseStatus::Expired;
                }
                persist_broker_lease(&lease)?;
                revoked.push(lease.lease_id);
            }
        }
    }
    if args.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "revoked_expired": revoked }))?
        );
    } else {
        println!("revoked {} expired broker lease(s)", revoked.len());
    }
    Ok(())
}

fn invoke_broker_adapter(
    config: &BrokerAdapterConfig,
    action: &str,
    lease: &BrokerLeaseRequest,
    provider_handle: Option<String>,
) -> io::Result<BrokerAdapterResponse> {
    validate_broker_adapter_config(config)?;
    let request = BrokerAdapterRequest {
        protocol_version: BROKER_PROTOCOL_VERSION,
        action: action.to_string(),
        lease: lease.clone(),
        provider_handle,
    };
    let invocation_dir = broker_root()?.join("adapter-invocations");
    create_restrictive_dir_all(&invocation_dir)?;
    let invocation_id = Uuid::new_v4().simple().to_string();
    let stdout_path = invocation_dir.join(format!("{invocation_id}.stdout"));
    let stderr_path = invocation_dir.join(format!("{invocation_id}.stderr"));
    let cleanup = BrokerInvocationCleanup {
        stdout: stdout_path.clone(),
        stderr: stderr_path.clone(),
    };
    let stdout_file = restrictive_output_file(&stdout_path)?;
    let stderr_file = restrictive_output_file(&stderr_path)?;
    let mut command = Command::new(&config.executable);
    command
        .args(&config.args)
        .env_clear()
        .env(
            "GENSEE_BROKER_PROTOCOL",
            BROKER_PROTOCOL_VERSION.to_string(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    for name in &config.environment_allowlist {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("broker adapter stdin unavailable"))?
        .write_all(&serde_json::to_vec(&request)?)?;
    let deadline = Instant::now() + Duration::from_secs(BROKER_ADAPTER_TIMEOUT_SECONDS);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker adapter invocation timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let result = (|| {
        let stdout = read_bounded_adapter_output(&stdout_path)?;
        let stderr = read_bounded_adapter_output(&stderr_path)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "broker adapter failed with {status}; stderr_digest=sha256:{:x}",
                Sha256::digest(stderr.as_bytes())
            )));
        }
        let response: BrokerAdapterResponse = serde_json::from_str(&stdout)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        validate_broker_adapter_response(&response)?;
        Ok(response)
    })();
    drop(cleanup);
    result
}

fn restrictive_output_file(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }
}

fn read_bounded_adapter_output(path: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > BROKER_ADAPTER_MAX_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker adapter output exceeded the bounded regular-file protocol",
        ));
    }
    read_nofollow_to_string(path)
}

struct BrokerInvocationCleanup {
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Drop for BrokerInvocationCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stdout);
        let _ = fs::remove_file(&self.stderr);
    }
}

fn validate_broker_adapter_response(response: &BrokerAdapterResponse) -> io::Result<()> {
    if response.protocol_version != BROKER_PROTOCOL_VERSION
        || response.provider_handle.trim().is_empty()
        || response.provider_handle.len() > 512
        || secret_shaped_string(&response.provider_handle)
        || !valid_gateway_endpoint(&response.gateway_endpoint)
        || contains_secret_shaped_json(&response.public_metadata)
        || response.effects.iter().any(|effect| {
            effect.occurred_at_ms == 0
                || effect.target.trim().is_empty()
                || effect.target == "*"
                || effect.action.trim().is_empty()
                || effect.action == "*"
                || !effect.request_digest.starts_with("sha256:")
                || effect.request_digest.len() != "sha256:".len() + 64
                || effect
                    .protocol
                    .as_deref()
                    .is_some_and(|protocol| protocol.trim().is_empty())
                || effect
                    .broker_handle_id
                    .as_deref()
                    .is_some_and(secret_shaped_string)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter response must contain only an opaque handle, mediated endpoint, and non-secret public metadata",
        ));
    }
    Ok(())
}

fn valid_gateway_endpoint(endpoint: &str) -> bool {
    !endpoint.contains('@')
        && (endpoint.starts_with("unix://")
            || endpoint.starts_with("https://")
            || endpoint.starts_with("http://127.0.0.1:")
            || endpoint.starts_with("http://[::1]:"))
}

fn contains_secret_shaped_json(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            [
                "access_token",
                "refresh_token",
                "secret",
                "password",
                "private_key",
                "client_key",
                "certificate_pem",
                "credential",
            ]
            .iter()
            .any(|needle| key.contains(needle))
                || contains_secret_shaped_json(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_shaped_json),
        Value::String(value) => secret_shaped_string(value),
        _ => false,
    }
}

fn secret_shaped_string(value: &str) -> bool {
    value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("github_pat_")
        || value.contains("BEGIN PRIVATE KEY")
        || value.contains("BEGIN CERTIFICATE")
}

fn issue_external_commit_token(
    lease_id: &str,
    request: &BrokerLeaseRequest,
    issued_at_ms: u64,
) -> io::Result<String> {
    let gateway = required_json_string(&request.constraints, "gateway")?;
    let target = required_json_string(&request.constraints, "target")?;
    let action = required_json_string(&request.constraints, "action")?;
    let request_digest = required_json_string(&request.constraints, "request_digest")?;
    if target == "*"
        || action == "*"
        || !request_digest.starts_with("sha256:")
        || request_digest.len() != "sha256:".len() + 64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "external commit token requires an exact gateway, target, action, and sha256 digest",
        ));
    }
    let token_id = format!("commit_{}", Uuid::new_v4().simple());
    let claims = ExternalActionCommitClaims {
        protocol_version: BROKER_PROTOCOL_VERSION,
        token_id: token_id.clone(),
        lease_id: lease_id.to_string(),
        operation_id: request.operation_id.clone(),
        source_run_id: request.source_run_id.clone(),
        gateway: gateway.to_string(),
        target: target.to_string(),
        action: action.to_string(),
        request_digest: request_digest.to_string(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(request.ttl_seconds.saturating_mul(1_000)),
        nonce: Uuid::new_v4().simple().to_string(),
    };
    let signature = sign_external_commit_claims(&claims)?;
    let token = SignedExternalActionCommitToken {
        claims,
        signature,
        consumed_at_ms: None,
        revoked_at_ms: None,
    };
    persist_external_commit_token(&token)?;
    Ok(token_id)
}

fn consume_external_commit_token(args: &[OsString]) -> io::Result<()> {
    let token_id = tclone_target_arg(
        args,
        "usage: gensee run broker commit consume <token-id> --gateway <id> --target <target> --action <action> --request-digest <sha256:...> [--json]",
    )?;
    let gateway = required_arg(args, "--gateway")?;
    let target = required_arg(args, "--target")?;
    let action = required_arg(args, "--action")?;
    let digest = required_arg(args, "--request-digest")?;
    let (lease_id, now) = consume_external_commit_token_for_gateway(
        &token_id, &gateway, &target, &action, &digest, None, None,
    )?;
    if args.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "token_id": token_id,
                "lease_id": lease_id,
                "consumed_at_ms": now,
                "request_digest": digest,
            }))?
        );
    } else {
        println!("consumed one-use external commit token {token_id}");
    }
    Ok(())
}

/// Atomically consume a one-use, signed external-action commit token for an
/// exact trusted gateway request. The caller must invoke this immediately
/// before performing the irreversible effect; a crash after consumption is
/// therefore fail-safe (the effect may be absent, but cannot be duplicated).
pub(crate) fn consume_external_commit_token_for_gateway(
    token_id: &str,
    gateway: &str,
    target: &str,
    action: &str,
    digest: &str,
    expected_operation_id: Option<&str>,
    expected_source_run_id: Option<&str>,
) -> io::Result<(String, u64)> {
    let initial_token = load_external_commit_token(token_id)?;
    let lease_path = broker_lease_path(&initial_token.claims.lease_id)?;
    let _lease_lock = TcloneStateLock::acquire(&lease_path)?;
    let path = external_commit_token_path(token_id)?;
    let _token_lock = TcloneStateLock::acquire(&path)?;
    let mut token = load_external_commit_token(token_id)?;
    let mut lease = load_broker_lease(&token.claims.lease_id)?;
    let now = unix_millis()?;
    if lease.status != BrokerLeaseStatus::Active
        || now >= lease.expires_at_ms
        || expected_operation_id.is_some_and(|id| token.claims.operation_id != id)
        || expected_source_run_id.is_some_and(|id| token.claims.source_run_id != id)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "external commit token lease is not active or belongs to another operation",
        ));
    }
    validate_and_consume_external_commit_token(
        &mut token, token_id, gateway, target, action, digest, now,
    )?;
    persist_external_commit_token(&token)?;
    lease.status = BrokerLeaseStatus::Consumed;
    lease.consumed_at_ms = Some(now);
    persist_broker_lease(&lease)?;
    Ok((lease.lease_id, now))
}

#[allow(clippy::too_many_arguments)]
fn validate_and_consume_external_commit_token(
    token: &mut SignedExternalActionCommitToken,
    token_id: &str,
    gateway: &str,
    target: &str,
    action: &str,
    digest: &str,
    now: u64,
) -> io::Result<()> {
    let expected_signature = sign_external_commit_claims(&token.claims)?;
    if !constant_time_bytes_eq(token.signature.as_bytes(), expected_signature.as_bytes())
        || token.claims.token_id != token_id
        || token.consumed_at_ms.is_some()
        || token.revoked_at_ms.is_some()
        || now < token.claims.issued_at_ms
        || now >= token.claims.expires_at_ms
        || token.claims.gateway != gateway
        || token.claims.target != target
        || token.claims.action != action
        || token.claims.request_digest != digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "external commit token is invalid, expired, consumed, revoked, or does not match the exact request",
        ));
    }
    token.consumed_at_ms = Some(now);
    Ok(())
}

fn sign_external_commit_claims(claims: &ExternalActionCommitClaims) -> io::Result<String> {
    sign_host_evidence("external-action-commit-v1", &serde_json::to_vec(claims)?)
}

pub(super) fn sign_host_evidence(domain: &str, payload: &[u8]) -> io::Result<String> {
    if !tclone_is_safe_token(domain) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid host-evidence signature domain",
        ));
    }
    let key = broker_signing_key()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    mac.update(domain.as_bytes());
    mac.update(&[0]);
    mac.update(payload);
    Ok(format!("hmac-sha256:{:x}", mac.finalize().into_bytes()))
}

pub(super) fn verify_host_evidence(
    domain: &str,
    payload: &[u8],
    signature: &str,
) -> io::Result<()> {
    let expected = sign_host_evidence(domain, payload)?;
    if constant_time_bytes_eq(signature.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host-evidence signature is invalid",
        ))
    }
}

fn broker_signing_key() -> io::Result<Zeroizing<String>> {
    let path = broker_root()?.join("signing.key");
    let _lock = TcloneStateLock::acquire(&path)?;
    if path.exists() {
        let mut key = Zeroizing::new(read_nofollow_to_string(&path)?);
        let trimmed_len = key.trim_end().len();
        key.truncate(trimmed_len);
        return Ok(key);
    }
    let key = Zeroizing::new(format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ));
    let mut persisted = Zeroizing::new(key.as_bytes().to_vec());
    persisted.push(b'\n');
    write_atomic_nofollow(&path, &persisted, 0o600)?;
    Ok(key)
}

fn required_json_string<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("broker constraint missing {field}"),
            )
        })
}

fn required_arg(args: &[OsString], name: &str) -> io::Result<String> {
    arg_value(args, name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))
}

fn lease_to_request(lease: &BrokerLease) -> BrokerLeaseRequest {
    BrokerLeaseRequest {
        protocol_version: lease.protocol_version,
        operation_id: lease.operation_id.clone(),
        source_run_id: lease.source_run_id.clone(),
        cell_id: lease.cell_id.clone(),
        resource_kind: lease.resource_kind,
        adapter_id: lease.adapter_id.clone(),
        audience: lease.audience.clone(),
        scopes: lease.scopes.clone(),
        ttl_seconds: lease
            .expires_at_ms
            .saturating_sub(lease.issued_at_ms)
            .saturating_add(999)
            / 1_000,
        constraints: lease.constraints.clone(),
    }
}

fn broker_root() -> io::Result<PathBuf> {
    let root = default_root()?.join("capability-broker");
    create_restrictive_dir_all(&root)?;
    Ok(root)
}

fn broker_adapter_path(adapter_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(adapter_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker adapter id",
        ));
    }
    let dir = broker_root()?.join("adapters");
    create_restrictive_dir_all(&dir)?;
    Ok(dir.join(format!("{adapter_id}.json")))
}

fn broker_lease_path(lease_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(lease_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker lease id",
        ));
    }
    let dir = broker_root()?.join("leases");
    create_restrictive_dir_all(&dir)?;
    Ok(dir.join(format!("{lease_id}.json")))
}

fn external_commit_token_path(token_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(token_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid external commit token id",
        ));
    }
    let dir = broker_root()?.join("commit-tokens");
    create_restrictive_dir_all(&dir)?;
    Ok(dir.join(format!("{token_id}.json")))
}

fn load_broker_adapter(adapter_id: &str) -> io::Result<BrokerAdapterConfig> {
    let config: BrokerAdapterConfig =
        serde_json::from_str(&read_nofollow_to_string(&broker_adapter_path(adapter_id)?)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_broker_adapter_config(&config)?;
    if config.adapter_id != adapter_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker adapter id does not match its filename",
        ));
    }
    Ok(config)
}

fn load_broker_lease(lease_id: &str) -> io::Result<BrokerLease> {
    let lease: BrokerLease =
        serde_json::from_str(&read_nofollow_to_string(&broker_lease_path(lease_id)?)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lease.protocol_version != BROKER_PROTOCOL_VERSION || lease.lease_id != lease_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker lease identity or protocol does not match",
        ));
    }
    Ok(lease)
}

fn persist_broker_lease(lease: &BrokerLease) -> io::Result<()> {
    write_atomic_nofollow(
        &broker_lease_path(&lease.lease_id)?,
        &serde_json::to_vec_pretty(lease)?,
        0o600,
    )
}

fn load_external_commit_token(token_id: &str) -> io::Result<SignedExternalActionCommitToken> {
    serde_json::from_str(&read_nofollow_to_string(&external_commit_token_path(
        token_id,
    )?)?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn persist_external_commit_token(token: &SignedExternalActionCommitToken) -> io::Result<()> {
    write_atomic_nofollow(
        &external_commit_token_path(&token.claims.token_id)?,
        &serde_json::to_vec_pretty(token)?,
        0o600,
    )
}

pub(super) fn revoke_attached_broker_leases(lease_ids: &[String]) -> io::Result<Vec<BrokerLease>> {
    let mut errors = Vec::new();
    let mut revoked = Vec::new();
    for lease_id in lease_ids {
        let result = (|| {
            let path = broker_lease_path(lease_id)?;
            let _lock = TcloneStateLock::acquire(&path)?;
            let mut lease = load_broker_lease(lease_id)?;
            revoke_broker_lease_record(&mut lease)?;
            persist_broker_lease(&lease)?;
            Ok::<BrokerLease, io::Error>(lease)
        })();
        match result {
            Ok(lease) => revoked.push(lease),
            Err(error) => errors.push(format!("{lease_id}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(revoked)
    } else {
        Err(io::Error::other(format!(
            "failed to revoke attached broker leases: {}",
            errors.join("; ")
        )))
    }
}

pub(super) fn active_attached_broker_leases(
    lease_ids: &[String],
    source_run_id: &str,
    operation_id: &str,
    cell_id: &str,
    now_ms: u64,
) -> io::Result<Vec<BrokerLease>> {
    let mut leases = Vec::new();
    let mut unique = BTreeSet::new();
    for lease_id in lease_ids {
        if !unique.insert(lease_id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate broker lease attachment",
            ));
        }
        let path = broker_lease_path(lease_id)?;
        let _lock = TcloneStateLock::acquire(&path)?;
        let lease = load_broker_lease(lease_id)?;
        if lease.status != BrokerLeaseStatus::Active
            || lease.source_run_id != source_run_id
            || lease.operation_id != operation_id
            || lease.cell_id.as_deref() != Some(cell_id)
            || now_ms < lease.issued_at_ms
            || now_ms >= lease.expires_at_ms
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("broker lease is inactive or bound to another operation: {lease_id}"),
            ));
        }
        if let BrokerDelivery::Gateway {
            gateway_endpoint, ..
        } = &lease.delivery
        {
            validate_cell_gateway_socket(gateway_endpoint)?;
        }
        leases.push(lease);
    }
    Ok(leases)
}

fn validate_cell_gateway_socket(endpoint: &str) -> io::Result<PathBuf> {
    let path = endpoint.strip_prefix("unix://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "cell-bound gateways must use a Unix socket so the cell can keep IP networking disabled",
        )
    })?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker gateway Unix socket must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(&path)?;
    #[cfg(unix)]
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker gateway endpoint is not a Unix socket",
        ));
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker gateway endpoint is not a supported local endpoint",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "gateway has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker gateway parent must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    if parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker gateway parent must not be group- or world-writable",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_rejects_secret_shaped_public_data() {
        assert!(contains_secret_shaped_json(&json!({
            "access_token": "not-public"
        })));
        assert!(contains_secret_shaped_json(&json!({
            "nested": { "value": "sk-not-public" }
        })));
        assert!(!contains_secret_shaped_json(&json!({
            "repository": "one",
            "expires_in": 60
        })));
    }

    #[test]
    fn broker_request_requires_bounded_scopes() {
        let request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: None,
            resource_kind: BrokerResourceKind::NetworkLease,
            adapter_id: BUILTIN_NETWORK_ADAPTER.to_string(),
            audience: "*".to_string(),
            scopes: vec!["*".to_string()],
            ttl_seconds: 60,
            constraints: json!({
                "destination": "0.0.0.0/0",
                "protocol": "tcp",
                "ports": [443]
            }),
        };

        assert_eq!(
            validate_broker_lease_request(&request).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn direct_network_lease_requires_a_pinned_ip_protocol_and_ports() {
        assert!(validate_network_constraints(&json!({
            "destination": "repo.example.test",
            "protocol": "tcp",
            "ports": [443]
        }))
        .is_err());
        assert!(validate_network_constraints(&json!({
            "destination": "10.20.30.40/32",
            "protocol": "https",
            "ports": [443]
        }))
        .is_err());
        validate_network_constraints(&json!({
            "destination": "10.20.30.40/32",
            "protocol": "tcp",
            "ports": [443, 8443]
        }))
        .unwrap();
    }

    #[test]
    fn signed_commit_token_is_exact_expiring_and_one_use() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-test-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: Some("cell_1".to_string()),
            resource_kind: BrokerResourceKind::ExternalActionCommitToken,
            adapter_id: BUILTIN_EXTERNAL_ACTION_ADAPTER.to_string(),
            audience: "deploy.example.test".to_string(),
            scopes: vec!["deployment:one:commit".to_string()],
            ttl_seconds: 60,
            constraints: json!({
                "gateway": "deploy-gateway",
                "target": "deployment/one",
                "action": "promote",
                "request_digest": format!("sha256:{}", "a".repeat(64)),
            }),
        };
        let token_id = issue_external_commit_token("broker_lease_1", &request, 100).unwrap();
        let mut token = load_external_commit_token(&token_id).unwrap();
        assert_eq!(token.claims.target, "deployment/one");
        assert_eq!(
            token.signature,
            sign_external_commit_claims(&token.claims).unwrap()
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            validate_and_consume_external_commit_token(
                &mut token,
                &token_id,
                "deploy-gateway",
                "wrong-target",
                "promote",
                &digest,
                150,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        validate_and_consume_external_commit_token(
            &mut token,
            &token_id,
            "deploy-gateway",
            "deployment/one",
            "promote",
            &digest,
            150,
        )
        .unwrap();
        assert_eq!(token.consumed_at_ms, Some(150));
        assert_eq!(
            validate_and_consume_external_commit_token(
                &mut token,
                &token_id,
                "deploy-gateway",
                "deployment/one",
                "promote",
                &digest,
                151,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn gateway_endpoints_must_be_mediated() {
        assert!(valid_gateway_endpoint("unix:///run/gensee/repo.sock"));
        assert!(valid_gateway_endpoint("https://gateway.example.test"));
        assert!(valid_gateway_endpoint("http://127.0.0.1:8080"));
        assert!(!valid_gateway_endpoint("http://gateway.example.test"));
        assert!(!valid_gateway_endpoint("file:///tmp/token"));
    }

    #[cfg(unix)]
    #[test]
    fn cell_gateway_requires_a_socket_in_a_private_directory() {
        let suffix = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from("/tmp").join(format!("gs-{}", &suffix[..8]));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("gateway.sock");
        let _listener = UnixListener::bind(&socket).unwrap();

        assert_eq!(
            validate_cell_gateway_socket(&format!("unix://{}", socket.display())).unwrap(),
            socket
        );
        let regular = root.join("not-a-socket");
        fs::write(&regular, "no").unwrap();
        assert_eq!(
            validate_cell_gateway_socket(&format!("unix://{}", regular.display()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn external_adapter_returns_only_gateway_and_opaque_handle() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-adapter-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        env::set_var("GENSEE_HOME", &root);
        let executable = root.join("adapter.sh");
        fs::write(
            &executable,
            "#!/bin/sh\nwhile IFS= read -r line; do :; done\nprintf '%s\\n' '{\"protocol_version\":1,\"provider_handle\":\"opaque_1\",\"gateway_endpoint\":\"unix:///run/gensee/repo.sock\",\"public_metadata\":{\"repository\":\"one\"},\"effects\":[],\"effect_telemetry_complete\":false}'\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = BrokerAdapterConfig {
            schema_version: BROKER_ADAPTER_SCHEMA_VERSION,
            adapter_id: "repo_adapter".to_string(),
            resource_kinds: vec![BrokerResourceKind::RepositoryToken],
            executable: executable.to_string_lossy().to_string(),
            args: Vec::new(),
            environment_allowlist: Vec::new(),
            max_ttl_seconds: 60,
        };
        let request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: Some("cell_1".to_string()),
            resource_kind: BrokerResourceKind::RepositoryToken,
            adapter_id: "repo_adapter".to_string(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["repository:one:read".to_string()],
            ttl_seconds: 60,
            constraints: json!({ "repository": "one" }),
        };

        let response = invoke_broker_adapter(&config, "mint", &request, None).unwrap();

        assert_eq!(response.provider_handle, "opaque_1");
        assert_eq!(response.gateway_endpoint, "unix:///run/gensee/repo.sock");
        assert_eq!(response.public_metadata["repository"], "one");
        let invocation_dir = root.join("capability-broker/adapter-invocations");
        assert_eq!(fs::read_dir(invocation_dir).unwrap().count(), 0);

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }
}
