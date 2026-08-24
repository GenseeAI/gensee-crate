use super::*;
use gensee_crate_rules::capability_broker::{
    BrokerAdapterRequest, BrokerAdapterResponse, BrokerDelivery, BrokerLease, BrokerLeaseRequest,
    BrokerLeaseStatus, BrokerProviderStatus, BrokerResourceKind, ExternalActionCommitClaims,
    SignedExternalActionCommitToken, BROKER_PROTOCOL_VERSION,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const BROKER_ADAPTER_SCHEMA_VERSION: u32 = 1;
const BROKER_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
const BROKER_MAX_TTL_SECONDS: u64 = 15 * 60;
const BROKER_ADAPTER_TIMEOUT_SECONDS: u64 = 30;
const BROKER_ADAPTER_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const BROKER_ADAPTER_SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024;
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
    /// Explicit protocol negotiation for durable idempotent mint/status/revoke.
    #[serde(default)]
    lifecycle_v2: bool,
    max_ttl_seconds: u64,
    #[serde(default)]
    legacy_revoke_acknowledgement: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerAdapterSnapshot {
    config: BrokerAdapterConfig,
    original_executable: String,
    executable_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerIssueIndexRecord {
    schema_version: u32,
    request_digest: String,
    lease_id: String,
    signature: String,
}

/// Durable, deny-only provider state. This record is created before an
/// adapter can mint authority. The public lease is only materialized after an
/// authenticated `Active` transition has reached disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerLeaseLifecycle {
    schema_version: u32,
    lease_id: String,
    idempotency_key: String,
    adapter_snapshot: BrokerAdapterSnapshot,
    request: BrokerLeaseRequest,
    issued_at_ms: u64,
    expires_at_ms: u64,
    boot_marker: String,
    monotonic_issued_at_ms: u64,
    monotonic_deadline_ms: u64,
    #[serde(default)]
    public_lease_published: bool,
    #[serde(default)]
    cell_attachment_confirmed: bool,
    status: BrokerLeaseStatus,
    pending_action: BrokerProviderOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_endpoint: Option<String>,
    #[serde(default)]
    public_metadata: Value,
    #[serde(default)]
    effects: Vec<gensee_crate_rules::capability_broker::BrokerGatewayEffect>,
    #[serde(default)]
    effect_telemetry_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    transitions: Vec<BrokerLifecycleTransition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrokerProviderOperation {
    Mint,
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerAdapterWireMode {
    Legacy,
    LifecycleV2,
}

#[derive(Debug, Clone, Copy)]
struct BrokerAdapterInvocation<'a> {
    lease_id: Option<&'a str>,
    idempotency_key: Option<&'a str>,
    provider_handle: Option<&'a str>,
    wire_mode: BrokerAdapterWireMode,
    expected_executable_sha256: Option<&'a str>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerLifecycleTransition {
    sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<BrokerLeaseStatus>,
    to: BrokerLeaseStatus,
    occurred_at_ms: u64,
    provider_operation: BrokerProviderOperation,
    expires_at_ms: u64,
    boot_marker: String,
    monotonic_deadline_ms: u64,
    adapter_snapshot_digest: String,
    provider_state_digest: String,
    reason: String,
    previous_signature: String,
    signature: String,
}

#[derive(serde::Serialize)]
struct BrokerLifecycleTransitionClaims<'a> {
    lease_id: &'a str,
    idempotency_key: &'a str,
    sequence: u64,
    from: Option<BrokerLeaseStatus>,
    to: BrokerLeaseStatus,
    occurred_at_ms: u64,
    provider_operation: BrokerProviderOperation,
    expires_at_ms: u64,
    boot_marker: &'a str,
    monotonic_deadline_ms: u64,
    adapter_snapshot_digest: &'a str,
    provider_state_digest: &'a str,
    reason: &'a str,
    previous_signature: &'a str,
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
    if config.lifecycle_v2 {
        for arg in &config.args {
            let token = arg.strip_prefix("--").unwrap_or(arg);
            if token.is_empty()
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("lifecycle-v2 broker adapter argument is not a static token: {arg}"),
                ));
            }
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

fn pin_broker_adapter(
    config: &BrokerAdapterConfig,
    lease_id: &str,
) -> io::Result<BrokerAdapterSnapshot> {
    validate_broker_adapter_config(config)?;
    if !config.lifecycle_v2 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter did not negotiate lifecycle-v2",
        ));
    }
    if !config.environment_allowlist.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lifecycle-v2 adapters cannot inherit host environment values",
        ));
    }
    let mut source = open_nofollow_read(Path::new(&config.executable))?;
    let metadata = source.metadata()?;
    if metadata.len() > BROKER_ADAPTER_SNAPSHOT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker adapter executable exceeds snapshot size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut source)
        .take(BROKER_ADAPTER_SNAPSHOT_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > BROKER_ADAPTER_SNAPSHOT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "broker adapter executable exceeds snapshot size limit",
        ));
    }
    let dir = broker_root()?.join("adapter-snapshots");
    create_durable_broker_dir(&dir)?;
    let snapshot_path = dir.join(format!("{lease_id}.adapter"));
    write_atomic_nofollow(&snapshot_path, &bytes, 0o500)?;
    sync_broker_directory(&dir)?;
    let mut pinned_config = config.clone();
    pinned_config.executable = snapshot_path.to_string_lossy().to_string();
    let snapshot = BrokerAdapterSnapshot {
        config: pinned_config,
        original_executable: config.executable.clone(),
        executable_sha256: format!("sha256:{:x}", Sha256::digest(&bytes)),
    };
    validate_broker_adapter_snapshot(&snapshot, lease_id)?;
    Ok(snapshot)
}

fn validate_broker_adapter_snapshot(
    snapshot: &BrokerAdapterSnapshot,
    lease_id: &str,
) -> io::Result<()> {
    validate_broker_adapter_config(&snapshot.config)?;
    let expected_path = broker_root()?
        .join("adapter-snapshots")
        .join(format!("{lease_id}.adapter"));
    if !snapshot.config.lifecycle_v2
        || !snapshot.config.environment_allowlist.is_empty()
        || Path::new(&snapshot.config.executable) != expected_path
        || !Path::new(&snapshot.original_executable).is_absolute()
        || !snapshot.executable_sha256.starts_with("sha256:")
        || snapshot.executable_sha256.len() != "sha256:".len() + 64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker lifecycle adapter snapshot identity is invalid",
        ));
    }
    let mut file = open_nofollow_read(&expected_path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(BROKER_ADAPTER_SNAPSHOT_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > BROKER_ADAPTER_SNAPSHOT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter snapshot exceeds its size limit",
        ));
    }
    let actual = format!("sha256:{:x}", Sha256::digest(&bytes));
    if !constant_time_bytes_eq(actual.as_bytes(), snapshot.executable_sha256.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter snapshot digest changed",
        ));
    }
    Ok(())
}

fn broker_adapter_snapshot_digest(snapshot: &BrokerAdapterSnapshot) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(snapshot)?)
    ))
}

fn broker_issue_request_digest(request: &BrokerLeaseRequest) -> io::Result<String> {
    let mut canonical = request.clone();
    canonical.scopes.sort();
    canonical.scopes.dedup();
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

fn broker_issue_identity_digest(request: &BrokerLeaseRequest) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&json!({
            "request_id": request.request_id,
            "operation_id": request.operation_id,
            "source_run_id": request.source_run_id,
            "cell_id": request.cell_id,
        }))?)
    ))
}

fn broker_issue_index_path(request_digest: &str) -> io::Result<PathBuf> {
    let digest = request_digest.strip_prefix("sha256:").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid broker request digest")
    })?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker request digest",
        ));
    }
    let dir = broker_root()?.join("issue-index");
    create_durable_broker_dir(&dir)?;
    Ok(dir.join(format!("{digest}.json")))
}

fn sign_broker_issue_index(record: &BrokerIssueIndexRecord) -> io::Result<String> {
    sign_host_evidence(
        "broker-issue-index-v1",
        &serde_json::to_vec(&json!({
            "schema_version": record.schema_version,
            "request_digest": record.request_digest,
            "lease_id": record.lease_id,
        }))?,
    )
}

fn load_or_create_broker_issue_index(
    path: &Path,
    request_digest: &str,
) -> io::Result<(BrokerIssueIndexRecord, bool)> {
    if path.exists() {
        let record: BrokerIssueIndexRecord = serde_json::from_str(&read_nofollow_to_string(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if record.schema_version != 1
            || record.request_digest != request_digest
            || !tclone_is_safe_token(&record.lease_id)
            || !constant_time_bytes_eq(
                record.signature.as_bytes(),
                sign_broker_issue_index(&record)?.as_bytes(),
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker issue index authentication failed",
            ));
        }
        maybe_inject_broker_fault("after_existing_issue_index_load_before_dirsync")?;
        sync_broker_directory(
            path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "index has no parent")
            })?,
        )?;
        return Ok((record, false));
    }
    let mut record = BrokerIssueIndexRecord {
        schema_version: 1,
        request_digest: request_digest.to_string(),
        lease_id: format!("broker_lease_{}", Uuid::new_v4().simple()),
        signature: String::new(),
    };
    record.signature = sign_broker_issue_index(&record)?;
    write_atomic_nofollow(path, &serde_json::to_vec_pretty(&record)?, 0o600)?;
    sync_broker_directory(
        path.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "index has no parent"))?,
    )?;
    maybe_inject_broker_fault("after_request_index_persisted")?;
    Ok((record, true))
}

fn sync_broker_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn create_durable_broker_dir(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("broker state directory is unsafe: {}", cursor.display()),
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "broker directory has no parent",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        #[cfg(unix)]
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        sync_broker_directory(directory)?;
        maybe_inject_broker_fault("after_broker_directory_create_before_parent_dirsync")?;
        sync_broker_directory(directory.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "broker directory has no parent",
            )
        })?)?;
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    // If a previous process stopped after mkdir but before the parent fsync,
    // retrying this helper repairs that exact durability boundary.
    sync_broker_directory(path)?;
    if let Some(parent) = path.parent() {
        sync_broker_directory(parent)?;
    }
    Ok(())
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

    let request_digest = broker_issue_request_digest(&request)?;
    let issue_identity_digest = broker_issue_identity_digest(&request)?;
    let issue_index_path = broker_issue_index_path(&issue_identity_digest)?;
    let _issue_lock = TcloneStateLock::acquire(&issue_index_path)?;
    let (issue_index, _) = load_or_create_broker_issue_index(&issue_index_path, &request_digest)?;

    // Reconcile every unfinished provider operation before accepting another
    // grant. A provider whose authority cannot be determined blocks issuance;
    // otherwise a crash could turn a retry into a second live credential.
    reconcile_broker_lifecycles()?;
    deny_if_provider_authority_indeterminate()?;
    if broker_lease_path(&issue_index.lease_id)?.exists() {
        let lease = load_broker_lease(&issue_index.lease_id)?;
        if lease.status == BrokerLeaseStatus::Active {
            return print_issued_broker_lease(&lease, args);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the indexed broker issuance is not active ({:?}); refusing replacement authority: {}",
                lease.status, lease.lease_id
            ),
        ));
    }
    let existing_lifecycle_path = broker_lifecycle_path(&issue_index.lease_id)?;
    if existing_lifecycle_path.exists() {
        let lifecycle = load_broker_lifecycle(&issue_index.lease_id)?;
        if matches!(
            lifecycle.status,
            BrokerLeaseStatus::Revoked | BrokerLeaseStatus::Expired | BrokerLeaseStatus::Failed
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the indexed broker issuance is terminal ({:?}); refusing replacement authority: {}",
                    lifecycle.status, lifecycle.lease_id
                ),
            ));
        }
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
    let lease_id = issue_index.lease_id;
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
                request.ttl_seconds = request
                    .ttl_seconds
                    .min(config.max_ttl_seconds)
                    .min(BROKER_MAX_TTL_SECONDS);
                let response =
                    mint_external_provider_lease(&config, &lease_id, &request, issued_at_ms)?;
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
        status: if broker_lifecycle_path(&lease_id)?.exists() {
            BrokerLeaseStatus::Publishing
        } else {
            BrokerLeaseStatus::Active
        },
        delivery,
        public_metadata,
        gateway_effects,
        effect_telemetry_complete,
        revoked_at_ms: None,
        consumed_at_ms: None,
    };
    let path = broker_lease_path(&lease_id)?;
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    maybe_inject_broker_fault("after_active_lease_persisted")?;
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
        maybe_inject_broker_fault("after_cell_attachment_persisted")?;
    }
    let lease = if broker_lifecycle_path(&lease_id)?.exists() {
        activate_published_broker_lease(&lease_id)?
    } else {
        lease
    };
    print_issued_broker_lease(&lease, args)
}

fn print_issued_broker_lease(lease: &BrokerLease, args: &[OsString]) -> io::Result<()> {
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(lease)?);
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
        || !tclone_is_safe_token(&request.request_id)
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
    let lifecycle_path = broker_lifecycle_path(&lease_id)?;
    if lifecycle_path.exists() {
        let _lock = TcloneStateLock::acquire(&lifecycle_path)?;
        let mut lifecycle = load_broker_lifecycle(&lease_id)?;
        let _ = reconcile_broker_lifecycle(&mut lifecycle);
        lifecycle = load_broker_lifecycle(&lease_id)?;
        if !broker_lease_path(&lease_id)?.exists() {
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&lifecycle)?);
            } else {
                println!("lease: {}", lifecycle.lease_id);
                println!("resource: {:?}", lifecycle.request.resource_kind);
                println!("status: {:?}", lifecycle.status);
                println!("expires: {}", lifecycle.expires_at_ms);
                println!("provider authority is deny-only until activation is confirmed");
            }
            return Ok(());
        }
    }
    let mut lease = load_broker_lease(&lease_id)?;
    if lifecycle_path.exists() {
        lease.status = load_broker_lifecycle(&lease_id)?.status;
    }
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
    let lifecycle_path = broker_lifecycle_path(&lease_id)?;
    let _lifecycle_lock = if lifecycle_path.exists() {
        Some(TcloneStateLock::acquire(&lifecycle_path)?)
    } else {
        None
    };
    if lifecycle_path.exists() && !lease_path.exists() {
        let mut lifecycle = load_broker_lifecycle(&lease_id)?;
        if !matches!(
            lifecycle.status,
            BrokerLeaseStatus::Revoked | BrokerLeaseStatus::Expired | BrokerLeaseStatus::Failed
        ) {
            lifecycle.pending_action = BrokerProviderOperation::Revoke;
            if lifecycle.status != BrokerLeaseStatus::Revoking {
                append_lifecycle_transition(
                    &mut lifecycle,
                    BrokerLeaseStatus::Revoking,
                    unix_millis()?,
                    "provider_revoke_requested_before_publication",
                )?;
                persist_broker_lifecycle(&lifecycle)?;
            }
            maybe_inject_broker_fault("after_revoking_persisted")?;
            invoke_revoke_for_lifecycle(&mut lifecycle)?;
        }
        if args.iter().any(|arg| arg == "--json") {
            println!("{}", serde_json::to_string_pretty(&lifecycle)?);
        } else {
            println!(
                "broker lease {} is now {:?}",
                lifecycle.lease_id, lifecycle.status
            );
        }
        return Ok(());
    }
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
    let lifecycle_path = broker_lifecycle_path(&lease.lease_id)?;
    if lifecycle_path.exists() {
        let mut lifecycle = load_broker_lifecycle(&lease.lease_id)?;
        if matches!(
            lifecycle.status,
            BrokerLeaseStatus::Revoked | BrokerLeaseStatus::Expired | BrokerLeaseStatus::Failed
        ) {
            repair_terminal_public_lease(&lifecycle)?;
            *lease = load_broker_lease(&lease.lease_id)?;
            return Ok(());
        }
        if lifecycle.status != BrokerLeaseStatus::Revoking {
            lifecycle.pending_action = BrokerProviderOperation::Revoke;
            append_lifecycle_transition(
                &mut lifecycle,
                BrokerLeaseStatus::Revoking,
                unix_millis()?,
                "provider_revoke_requested",
            )?;
            persist_broker_lifecycle(&lifecycle)?;
        }
        lease.status = BrokerLeaseStatus::Revoking;
        persist_broker_lease(lease)?;
        maybe_inject_broker_fault("after_revoking_persisted")?;
        invoke_revoke_for_lifecycle(&mut lifecycle)?;
        *lease = load_broker_lease(&lease.lease_id)?;
        return Ok(());
    }
    match &lease.delivery {
        BrokerDelivery::Gateway {
            provider_handle, ..
        } => {
            let config = load_broker_adapter(&lease.adapter_id)?;
            let request = lease_to_request(lease);
            let response = invoke_broker_adapter(
                &config,
                "revoke",
                &request,
                BrokerAdapterInvocation {
                    lease_id: None,
                    idempotency_key: None,
                    provider_handle: Some(provider_handle),
                    wire_mode: BrokerAdapterWireMode::Legacy,
                    expected_executable_sha256: None,
                },
            )?;
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
    reconcile_broker_lifecycles()?;
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
                let lifecycle_path = broker_lifecycle_path(&lease.lease_id)?;
                let _lifecycle_lock = if lifecycle_path.exists() {
                    Some(TcloneStateLock::acquire(&lifecycle_path)?)
                } else {
                    None
                };
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

fn mint_external_provider_lease(
    config: &BrokerAdapterConfig,
    lease_id: &str,
    request: &BrokerLeaseRequest,
    issued_at_ms: u64,
) -> io::Result<BrokerAdapterResponse> {
    let ttl_seconds = request
        .ttl_seconds
        .min(config.max_ttl_seconds)
        .min(BROKER_MAX_TTL_SECONDS);
    let idempotency_key = broker_idempotency_key(lease_id, request)?;
    let adapter_snapshot = pin_broker_adapter(config, lease_id)?;
    let (boot_marker, monotonic_issued_at_ms) = current_broker_boot_clock()?;
    let mut lifecycle = BrokerLeaseLifecycle {
        schema_version: BROKER_LIFECYCLE_SCHEMA_VERSION,
        lease_id: lease_id.to_string(),
        idempotency_key,
        adapter_snapshot,
        request: request.clone(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        boot_marker,
        monotonic_issued_at_ms,
        monotonic_deadline_ms: monotonic_issued_at_ms
            .saturating_add(ttl_seconds.saturating_mul(1_000)),
        public_lease_published: false,
        cell_attachment_confirmed: false,
        status: BrokerLeaseStatus::Preparing,
        pending_action: BrokerProviderOperation::Mint,
        provider_handle: None,
        gateway_endpoint: None,
        public_metadata: Value::Null,
        effects: Vec::new(),
        effect_telemetry_complete: false,
        last_error: None,
        transitions: Vec::new(),
    };
    append_lifecycle_transition(
        &mut lifecycle,
        BrokerLeaseStatus::Preparing,
        issued_at_ms,
        "provider_mint_intent_persisted",
    )?;
    persist_broker_lifecycle(&lifecycle)?;
    maybe_inject_broker_fault("after_intent_persisted")?;

    append_lifecycle_transition(
        &mut lifecycle,
        BrokerLeaseStatus::Activating,
        unix_millis()?,
        "provider_mint_started",
    )?;
    persist_broker_lifecycle(&lifecycle)?;
    maybe_inject_broker_fault("after_activating_persisted")?;

    let response = match invoke_broker_adapter(
        &lifecycle.adapter_snapshot.config,
        "mint",
        request,
        BrokerAdapterInvocation {
            lease_id: Some(lease_id),
            idempotency_key: Some(&lifecycle.idempotency_key),
            provider_handle: None,
            wire_mode: BrokerAdapterWireMode::LifecycleV2,
            expected_executable_sha256: Some(&lifecycle.adapter_snapshot.executable_sha256),
        },
    ) {
        Ok(response) => response,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
        Err(error) => {
            lifecycle.last_error = Some(adapter_error_digest(&error));
            append_lifecycle_transition(
                &mut lifecycle,
                BrokerLeaseStatus::Indeterminate,
                unix_millis()?,
                "provider_mint_outcome_unknown",
            )?;
            persist_broker_lifecycle(&lifecycle)?;
            return Err(io::Error::other(format!(
                "provider mint outcome is indeterminate; lease {} must be reconciled: {}",
                lifecycle.lease_id,
                lifecycle.last_error.as_deref().unwrap_or("unknown")
            )));
        }
    };
    maybe_inject_broker_fault("after_provider_mint")?;
    apply_active_adapter_response(&mut lifecycle, &response)?;
    append_lifecycle_transition(
        &mut lifecycle,
        BrokerLeaseStatus::Publishing,
        unix_millis()?,
        "provider_mint_confirmed_publication_pending",
    )?;
    persist_broker_lifecycle(&lifecycle)?;
    maybe_inject_broker_fault("after_active_lifecycle_persisted")?;
    Ok(response)
}

fn broker_idempotency_key(lease_id: &str, request: &BrokerLeaseRequest) -> io::Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"gensee-broker-provider-v1\0");
    digest.update(lease_id.as_bytes());
    digest.update([0]);
    digest.update(serde_json::to_vec(request)?);
    Ok(format!("idem_{:x}", digest.finalize()))
}

/// Return a reboot-distinguishing marker and a monotonic timestamp. Rounding
/// the derived boot epoch tolerates ordinary clock slewing; a larger wall-clock
/// correction conservatively looks like a reboot and forces provider teardown.
#[cfg(unix)]
fn current_broker_boot_clock() -> io::Result<(String, u64)> {
    #[cfg(test)]
    if let (Some(marker), Some(monotonic_ms)) = (
        env::var_os("GENSEE_TEST_BROKER_BOOT_MARKER"),
        env::var("GENSEE_TEST_BROKER_MONOTONIC_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok()),
    ) {
        return Ok((marker.to_string_lossy().to_string(), monotonic_ms));
    }
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid writable timespec and CLOCK_MONOTONIC has no
    // pointer lifetime requirements.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let monotonic_ms = u64::try_from(value.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(value.tv_nsec).unwrap_or(0) / 1_000_000);
    let boot_epoch_minute = unix_millis()?.saturating_sub(monotonic_ms) / 60_000;
    Ok((
        format!("boot_epoch_minute_{boot_epoch_minute}"),
        monotonic_ms,
    ))
}

fn broker_lifecycle_now_ms() -> io::Result<u64> {
    #[cfg(test)]
    if let Some(value) = env::var("GENSEE_TEST_BROKER_WALL_NOW_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Ok(value);
    }
    unix_millis()
}

#[cfg(not(unix))]
fn current_broker_boot_clock() -> io::Result<(String, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "crash-safe provider deadlines require a host monotonic clock",
    ))
}

fn adapter_error_digest(error: &io::Error) -> String {
    format!("sha256:{:x}", Sha256::digest(error.to_string().as_bytes()))
}

fn apply_active_adapter_response(
    lifecycle: &mut BrokerLeaseLifecycle,
    response: &BrokerAdapterResponse,
) -> io::Result<()> {
    if response
        .provider_status
        .is_some_and(|status| status != BrokerProviderStatus::Active)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "adapter mint did not report active provider authority",
        ));
    }
    if lifecycle.request.cell_id.is_some() {
        validate_cell_gateway_socket(&response.gateway_endpoint)?;
    }
    lifecycle.provider_handle = Some(response.provider_handle.clone());
    lifecycle.gateway_endpoint = Some(response.gateway_endpoint.clone());
    lifecycle.public_metadata = response.public_metadata.clone();
    lifecycle.effects.extend(response.effects.clone());
    lifecycle.effect_telemetry_complete = response.effect_telemetry_complete;
    lifecycle.last_error = None;
    Ok(())
}

fn broker_provider_state_digest(lifecycle: &BrokerLeaseLifecycle) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&json!({
            "provider_handle": lifecycle.provider_handle,
            "gateway_endpoint": lifecycle.gateway_endpoint,
            "public_metadata": lifecycle.public_metadata,
            "effects": lifecycle.effects,
            "effect_telemetry_complete": lifecycle.effect_telemetry_complete,
            "last_error": lifecycle.last_error,
            "public_lease_published": lifecycle.public_lease_published,
            "cell_attachment_confirmed": lifecycle.cell_attachment_confirmed,
        }))?)
    ))
}

fn append_lifecycle_transition(
    lifecycle: &mut BrokerLeaseLifecycle,
    to: BrokerLeaseStatus,
    occurred_at_ms: u64,
    reason: &str,
) -> io::Result<()> {
    let from = lifecycle.transitions.last().map(|transition| transition.to);
    if !valid_lifecycle_transition(from, to) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid broker lifecycle transition: {from:?} -> {to:?}"),
        ));
    }
    let previous_signature = lifecycle
        .transitions
        .last()
        .map(|transition| transition.signature.clone())
        .unwrap_or_default();
    // The transition chain is a logical clock. Wall-clock regression cannot
    // reorder evidence or extend authority because expiry uses the separately
    // persisted monotonic deadline.
    let occurred_at_ms = lifecycle
        .transitions
        .last()
        .map(|transition| occurred_at_ms.max(transition.occurred_at_ms))
        .unwrap_or(occurred_at_ms);
    let sequence = lifecycle.transitions.len() as u64 + 1;
    let adapter_snapshot_digest = broker_adapter_snapshot_digest(&lifecycle.adapter_snapshot)?;
    let provider_state_digest = broker_provider_state_digest(lifecycle)?;
    let claims = BrokerLifecycleTransitionClaims {
        lease_id: &lifecycle.lease_id,
        idempotency_key: &lifecycle.idempotency_key,
        sequence,
        from,
        to,
        occurred_at_ms,
        provider_operation: lifecycle.pending_action,
        expires_at_ms: lifecycle.expires_at_ms,
        boot_marker: &lifecycle.boot_marker,
        monotonic_deadline_ms: lifecycle.monotonic_deadline_ms,
        adapter_snapshot_digest: &adapter_snapshot_digest,
        provider_state_digest: &provider_state_digest,
        reason,
        previous_signature: &previous_signature,
    };
    let signature = sign_host_evidence(
        "broker-lifecycle-transition-v1",
        &serde_json::to_vec(&claims)?,
    )?;
    lifecycle.transitions.push(BrokerLifecycleTransition {
        sequence,
        from,
        to,
        occurred_at_ms,
        provider_operation: lifecycle.pending_action,
        expires_at_ms: lifecycle.expires_at_ms,
        boot_marker: lifecycle.boot_marker.clone(),
        monotonic_deadline_ms: lifecycle.monotonic_deadline_ms,
        adapter_snapshot_digest,
        provider_state_digest,
        reason: reason.to_string(),
        previous_signature,
        signature,
    });
    lifecycle.status = to;
    Ok(())
}

fn valid_lifecycle_transition(from: Option<BrokerLeaseStatus>, to: BrokerLeaseStatus) -> bool {
    matches!(
        (from, to),
        (None, BrokerLeaseStatus::Preparing)
            | (
                Some(BrokerLeaseStatus::Preparing),
                BrokerLeaseStatus::Activating
            )
            | (
                Some(BrokerLeaseStatus::Preparing),
                BrokerLeaseStatus::Revoking
            )
            | (
                Some(BrokerLeaseStatus::Preparing),
                BrokerLeaseStatus::Failed
            )
            | (
                Some(BrokerLeaseStatus::Preparing),
                BrokerLeaseStatus::Indeterminate
            )
            | (
                Some(BrokerLeaseStatus::Activating),
                BrokerLeaseStatus::Publishing
            )
            | (
                Some(BrokerLeaseStatus::Activating),
                BrokerLeaseStatus::Indeterminate
            )
            | (
                Some(BrokerLeaseStatus::Activating),
                BrokerLeaseStatus::Revoking
            )
            | (
                Some(BrokerLeaseStatus::Activating),
                BrokerLeaseStatus::Failed
            )
            | (Some(BrokerLeaseStatus::Active), BrokerLeaseStatus::Revoking)
            | (
                Some(BrokerLeaseStatus::Publishing),
                BrokerLeaseStatus::Active
            )
            | (
                Some(BrokerLeaseStatus::Publishing),
                BrokerLeaseStatus::Revoking
            )
            | (
                Some(BrokerLeaseStatus::Publishing),
                BrokerLeaseStatus::Indeterminate
            )
            | (
                Some(BrokerLeaseStatus::Active),
                BrokerLeaseStatus::Indeterminate
            )
            | (
                Some(BrokerLeaseStatus::Indeterminate),
                BrokerLeaseStatus::Publishing
            )
            | (
                Some(BrokerLeaseStatus::Indeterminate),
                BrokerLeaseStatus::Revoking
            )
            | (
                Some(BrokerLeaseStatus::Indeterminate),
                BrokerLeaseStatus::Failed
            )
            | (
                Some(BrokerLeaseStatus::Indeterminate),
                BrokerLeaseStatus::Revoked
            )
            | (
                Some(BrokerLeaseStatus::Indeterminate),
                BrokerLeaseStatus::Expired
            )
            | (
                Some(BrokerLeaseStatus::Revoking),
                BrokerLeaseStatus::Revoked
            )
            | (
                Some(BrokerLeaseStatus::Revoking),
                BrokerLeaseStatus::Expired
            )
            | (
                Some(BrokerLeaseStatus::Revoking),
                BrokerLeaseStatus::Indeterminate
            )
    )
}

fn validate_broker_lifecycle(lifecycle: &BrokerLeaseLifecycle) -> io::Result<()> {
    if lifecycle.schema_version != BROKER_LIFECYCLE_SCHEMA_VERSION
        || !tclone_is_safe_token(&lifecycle.lease_id)
        || !lifecycle.idempotency_key.starts_with("idem_")
        || !lifecycle.boot_marker.starts_with("boot_epoch_minute_")
        || lifecycle.expires_at_ms <= lifecycle.issued_at_ms
        || lifecycle
            .expires_at_ms
            .saturating_sub(lifecycle.issued_at_ms)
            > BROKER_MAX_TTL_SECONDS.saturating_mul(1_000)
        || lifecycle.monotonic_deadline_ms <= lifecycle.monotonic_issued_at_ms
        || lifecycle
            .monotonic_deadline_ms
            .saturating_sub(lifecycle.monotonic_issued_at_ms)
            > BROKER_MAX_TTL_SECONDS.saturating_mul(1_000)
        || lifecycle.transitions.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid broker lifecycle identity, deadline, or transition history",
        ));
    }
    let expected_key = broker_idempotency_key(&lifecycle.lease_id, &lifecycle.request)?;
    if !constant_time_bytes_eq(
        lifecycle.idempotency_key.as_bytes(),
        expected_key.as_bytes(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker lifecycle idempotency evidence is invalid",
        ));
    }
    validate_broker_adapter_snapshot(&lifecycle.adapter_snapshot, &lifecycle.lease_id)?;
    if lifecycle.adapter_snapshot.config.adapter_id != lifecycle.request.adapter_id
        || !lifecycle
            .adapter_snapshot
            .config
            .resource_kinds
            .contains(&lifecycle.request.resource_kind)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker lifecycle request does not match its pinned adapter",
        ));
    }
    let mut previous_status = None;
    let mut previous_signature = String::new();
    let mut previous_time = 0;
    for (index, transition) in lifecycle.transitions.iter().enumerate() {
        if transition.sequence != index as u64 + 1
            || transition.from != previous_status
            || !valid_lifecycle_transition(previous_status, transition.to)
            || transition.previous_signature != previous_signature
            || transition.occurred_at_ms < previous_time
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker lifecycle transition chain is invalid",
            ));
        }
        let claims = BrokerLifecycleTransitionClaims {
            lease_id: &lifecycle.lease_id,
            idempotency_key: &lifecycle.idempotency_key,
            sequence: transition.sequence,
            from: transition.from,
            to: transition.to,
            occurred_at_ms: transition.occurred_at_ms,
            provider_operation: transition.provider_operation,
            expires_at_ms: transition.expires_at_ms,
            boot_marker: &transition.boot_marker,
            monotonic_deadline_ms: transition.monotonic_deadline_ms,
            adapter_snapshot_digest: &transition.adapter_snapshot_digest,
            provider_state_digest: &transition.provider_state_digest,
            reason: &transition.reason,
            previous_signature: &transition.previous_signature,
        };
        verify_host_evidence(
            "broker-lifecycle-transition-v1",
            &serde_json::to_vec(&claims)?,
            &transition.signature,
        )?;
        previous_status = Some(transition.to);
        previous_signature = transition.signature.clone();
        previous_time = transition.occurred_at_ms;
    }
    let expected_adapter_snapshot_digest =
        broker_adapter_snapshot_digest(&lifecycle.adapter_snapshot)?;
    let expected_provider_state_digest = broker_provider_state_digest(lifecycle)?;
    if previous_status != Some(lifecycle.status)
        || lifecycle.transitions.last().is_none_or(|transition| {
            transition.provider_operation != lifecycle.pending_action
                || transition.expires_at_ms != lifecycle.expires_at_ms
                || transition.boot_marker != lifecycle.boot_marker
                || transition.monotonic_deadline_ms != lifecycle.monotonic_deadline_ms
                || transition.adapter_snapshot_digest != expected_adapter_snapshot_digest
                || transition.provider_state_digest != expected_provider_state_digest
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker lifecycle status is not authenticated by its final transition",
        ));
    }
    if matches!(
        lifecycle.status,
        BrokerLeaseStatus::Publishing
            | BrokerLeaseStatus::Active
            | BrokerLeaseStatus::Revoking
            | BrokerLeaseStatus::Revoked
            | BrokerLeaseStatus::Expired
            | BrokerLeaseStatus::Indeterminate
    ) && lifecycle.provider_handle.is_some()
    {
        let response = BrokerAdapterResponse {
            protocol_version: BROKER_PROTOCOL_VERSION,
            provider_status: Some(BrokerProviderStatus::Active),
            provider_handle: lifecycle.provider_handle.clone().unwrap_or_default(),
            gateway_endpoint: lifecycle.gateway_endpoint.clone().unwrap_or_default(),
            public_metadata: lifecycle.public_metadata.clone(),
            effects: lifecycle.effects.clone(),
            effect_telemetry_complete: lifecycle.effect_telemetry_complete,
        };
        validate_broker_adapter_response(&lifecycle.adapter_snapshot.config, "mint", &response)?;
    }
    Ok(())
}

fn broker_lifecycle_path(lease_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(lease_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid broker lease id",
        ));
    }
    let dir = broker_root()?.join("lifecycles");
    create_durable_broker_dir(&dir)?;
    Ok(dir.join(format!("{lease_id}.json")))
}

fn persist_broker_lifecycle(lifecycle: &BrokerLeaseLifecycle) -> io::Result<()> {
    validate_broker_lifecycle(lifecycle)?;
    let path = broker_lifecycle_path(&lifecycle.lease_id)?;
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(lifecycle)?, 0o600)?;
    maybe_inject_broker_fault("after_lifecycle_rename_before_dirsync")?;
    sync_broker_directory(
        path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "lifecycle has no parent")
        })?,
    )
}

fn load_broker_lifecycle(lease_id: &str) -> io::Result<BrokerLeaseLifecycle> {
    let lifecycle: BrokerLeaseLifecycle =
        serde_json::from_str(&read_nofollow_to_string(&broker_lifecycle_path(lease_id)?)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lifecycle.lease_id != lease_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker lifecycle id does not match its filename",
        ));
    }
    validate_broker_lifecycle(&lifecycle)?;
    Ok(lifecycle)
}

#[cfg(test)]
pub(super) fn maybe_inject_broker_fault(point: &str) -> io::Result<()> {
    if env::var("GENSEE_TEST_BROKER_FAULT").ok().as_deref() == Some(point) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("injected broker crash after {point}"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
pub(super) fn maybe_inject_broker_fault(_point: &str) -> io::Result<()> {
    Ok(())
}

fn reconcile_broker_lifecycles() -> io::Result<()> {
    let dir = broker_root()?.join("lifecycles");
    if !dir.exists() {
        return Ok(());
    }
    let mut errors = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Some(lease_id) = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .map(str::to_string)
        else {
            errors.push("invalid lifecycle filename".to_string());
            continue;
        };
        let result = (|| {
            let _lock = TcloneStateLock::acquire(&entry.path())?;
            let mut lifecycle = load_broker_lifecycle(&lease_id)?;
            reconcile_broker_lifecycle(&mut lifecycle)
        })();
        if let Err(error) = result {
            errors.push(format!("{lease_id}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "broker provider reconciliation incomplete: {}",
            errors.join("; ")
        )))
    }
}

fn reconcile_broker_lifecycle(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    if matches!(
        lifecycle.status,
        BrokerLeaseStatus::Consumed
            | BrokerLeaseStatus::Revoked
            | BrokerLeaseStatus::Expired
            | BrokerLeaseStatus::Failed
    ) {
        return repair_terminal_public_lease(lifecycle);
    }
    let now = broker_lifecycle_now_ms()?;
    let (boot_marker, monotonic_now_ms) = current_broker_boot_clock()?;
    if boot_marker != lifecycle.boot_marker || monotonic_now_ms < lifecycle.monotonic_issued_at_ms {
        lifecycle.last_error = Some("host_reboot_or_monotonic_clock_reset".to_string());
        lifecycle.pending_action = BrokerProviderOperation::Revoke;
        if lifecycle.status != BrokerLeaseStatus::Revoking {
            append_lifecycle_transition(
                lifecycle,
                BrokerLeaseStatus::Revoking,
                now,
                "boot_changed_provider_teardown_required",
            )?;
            persist_broker_lifecycle(lifecycle)?;
        }
    }

    if (now >= lifecycle.expires_at_ms || monotonic_now_ms >= lifecycle.monotonic_deadline_ms)
        && matches!(
            lifecycle.status,
            BrokerLeaseStatus::Preparing
                | BrokerLeaseStatus::Activating
                | BrokerLeaseStatus::Publishing
                | BrokerLeaseStatus::Active
                | BrokerLeaseStatus::Indeterminate
        )
    {
        lifecycle.pending_action = BrokerProviderOperation::Revoke;
        append_lifecycle_transition(
            lifecycle,
            BrokerLeaseStatus::Revoking,
            now,
            "provider_deadline_elapsed",
        )?;
        persist_broker_lifecycle(lifecycle)?;
    }

    match lifecycle.status {
        BrokerLeaseStatus::Preparing => continue_provider_mint(lifecycle),
        BrokerLeaseStatus::Activating => reconcile_provider_mint(lifecycle),
        BrokerLeaseStatus::Revoking => reconcile_provider_revoke(lifecycle, false),
        BrokerLeaseStatus::Indeterminate => match lifecycle.pending_action {
            BrokerProviderOperation::Mint => reconcile_provider_mint(lifecycle),
            BrokerProviderOperation::Revoke => reconcile_provider_revoke(lifecycle, true),
        },
        BrokerLeaseStatus::Publishing => recover_provider_publication(lifecycle),
        BrokerLeaseStatus::Active => materialize_public_lease(lifecycle, BrokerLeaseStatus::Active),
        BrokerLeaseStatus::Consumed
        | BrokerLeaseStatus::Revoked
        | BrokerLeaseStatus::Expired
        | BrokerLeaseStatus::Failed => unreachable!("terminal lifecycles return above"),
    }
}

fn continue_provider_mint(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    append_lifecycle_transition(
        lifecycle,
        BrokerLeaseStatus::Activating,
        unix_millis()?,
        "provider_mint_recovered",
    )?;
    persist_broker_lifecycle(lifecycle)?;
    invoke_mint_for_lifecycle(lifecycle)
}

fn reconcile_provider_mint(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    validate_broker_adapter_snapshot(&lifecycle.adapter_snapshot, &lifecycle.lease_id)?;
    let config = &lifecycle.adapter_snapshot.config;
    let status = invoke_broker_adapter(
        config,
        "status",
        &lifecycle.request,
        BrokerAdapterInvocation {
            lease_id: Some(&lifecycle.lease_id),
            idempotency_key: Some(&lifecycle.idempotency_key),
            provider_handle: lifecycle.provider_handle.as_deref(),
            wire_mode: BrokerAdapterWireMode::LifecycleV2,
            expected_executable_sha256: Some(&lifecycle.adapter_snapshot.executable_sha256),
        },
    );
    match status {
        Ok(response) => match response.provider_status {
            Some(BrokerProviderStatus::Active) => {
                apply_active_adapter_response(lifecycle, &response)?;
                append_lifecycle_transition(
                    lifecycle,
                    BrokerLeaseStatus::Publishing,
                    unix_millis()?,
                    "provider_status_active_publication_pending",
                )?;
                persist_broker_lifecycle(lifecycle)?;
                recover_provider_publication(lifecycle)
            }
            Some(BrokerProviderStatus::Absent) => invoke_mint_for_lifecycle(lifecycle),
            Some(BrokerProviderStatus::Revoked) => {
                append_lifecycle_transition(
                    lifecycle,
                    BrokerLeaseStatus::Failed,
                    unix_millis()?,
                    "provider_revoked_before_activation",
                )?;
                persist_broker_lifecycle(lifecycle)
            }
            Some(BrokerProviderStatus::Indeterminate) | None => {
                mark_lifecycle_indeterminate(lifecycle, "provider_status_indeterminate")
            }
        },
        Err(error) => {
            lifecycle.last_error = Some(adapter_error_digest(&error));
            mark_lifecycle_indeterminate(lifecycle, "provider_status_failed")?;
            Err(error)
        }
    }
}

fn invoke_mint_for_lifecycle(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    validate_broker_adapter_snapshot(&lifecycle.adapter_snapshot, &lifecycle.lease_id)?;
    let config = &lifecycle.adapter_snapshot.config;
    let response = invoke_broker_adapter(
        config,
        "mint",
        &lifecycle.request,
        BrokerAdapterInvocation {
            lease_id: Some(&lifecycle.lease_id),
            idempotency_key: Some(&lifecycle.idempotency_key),
            provider_handle: lifecycle.provider_handle.as_deref(),
            wire_mode: BrokerAdapterWireMode::LifecycleV2,
            expected_executable_sha256: Some(&lifecycle.adapter_snapshot.executable_sha256),
        },
    );
    match response {
        Ok(response) => {
            apply_active_adapter_response(lifecycle, &response)?;
            append_lifecycle_transition(
                lifecycle,
                BrokerLeaseStatus::Publishing,
                unix_millis()?,
                "provider_mint_reconciled_publication_pending",
            )?;
            persist_broker_lifecycle(lifecycle)?;
            recover_provider_publication(lifecycle)
        }
        Err(error) => {
            lifecycle.last_error = Some(adapter_error_digest(&error));
            mark_lifecycle_indeterminate(lifecycle, "provider_mint_reconcile_failed")?;
            Err(error)
        }
    }
}

fn mark_lifecycle_indeterminate(
    lifecycle: &mut BrokerLeaseLifecycle,
    reason: &str,
) -> io::Result<()> {
    if lifecycle.status != BrokerLeaseStatus::Indeterminate {
        append_lifecycle_transition(
            lifecycle,
            BrokerLeaseStatus::Indeterminate,
            unix_millis()?,
            reason,
        )?;
    }
    persist_broker_lifecycle(lifecycle)
}

fn reconcile_provider_revoke(
    lifecycle: &mut BrokerLeaseLifecycle,
    already_indeterminate: bool,
) -> io::Result<()> {
    validate_broker_adapter_snapshot(&lifecycle.adapter_snapshot, &lifecycle.lease_id)?;
    let config = &lifecycle.adapter_snapshot.config;
    let status = invoke_broker_adapter(
        config,
        "status",
        &lifecycle.request,
        BrokerAdapterInvocation {
            lease_id: Some(&lifecycle.lease_id),
            idempotency_key: Some(&lifecycle.idempotency_key),
            provider_handle: lifecycle.provider_handle.as_deref(),
            wire_mode: BrokerAdapterWireMode::LifecycleV2,
            expected_executable_sha256: Some(&lifecycle.adapter_snapshot.executable_sha256),
        },
    );
    match status {
        Ok(response)
            if matches!(
                response.provider_status,
                Some(BrokerProviderStatus::Absent | BrokerProviderStatus::Revoked)
            ) =>
        {
            finish_provider_revoke(lifecycle)
        }
        Ok(response) if response.provider_status == Some(BrokerProviderStatus::Active) => {
            invoke_revoke_for_lifecycle(lifecycle)
        }
        Ok(_) => {
            if !already_indeterminate {
                mark_lifecycle_indeterminate(lifecycle, "provider_revoke_status_indeterminate")?;
            }
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider revoke status is indeterminate",
            ))
        }
        Err(error) => {
            lifecycle.last_error = Some(adapter_error_digest(&error));
            mark_lifecycle_indeterminate(lifecycle, "provider_revoke_status_failed")?;
            Err(error)
        }
    }
}

fn invoke_revoke_for_lifecycle(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    validate_broker_adapter_snapshot(&lifecycle.adapter_snapshot, &lifecycle.lease_id)?;
    let config = &lifecycle.adapter_snapshot.config;
    let response = invoke_broker_adapter(
        config,
        "revoke",
        &lifecycle.request,
        BrokerAdapterInvocation {
            lease_id: Some(&lifecycle.lease_id),
            idempotency_key: Some(&lifecycle.idempotency_key),
            provider_handle: lifecycle.provider_handle.as_deref(),
            wire_mode: BrokerAdapterWireMode::LifecycleV2,
            expected_executable_sha256: Some(&lifecycle.adapter_snapshot.executable_sha256),
        },
    );
    match response {
        Ok(response) => {
            maybe_inject_broker_fault("after_provider_revoke")?;
            lifecycle.effects.extend(response.effects);
            lifecycle.effect_telemetry_complete = response.effect_telemetry_complete;
            lifecycle.public_metadata = response.public_metadata;
            finish_provider_revoke(lifecycle)
        }
        Err(error) => {
            lifecycle.last_error = Some(adapter_error_digest(&error));
            mark_lifecycle_indeterminate(lifecycle, "provider_revoke_outcome_unknown")?;
            Err(error)
        }
    }
}

fn finish_provider_revoke(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    let terminal = if broker_lifecycle_now_ms()? >= lifecycle.expires_at_ms {
        BrokerLeaseStatus::Expired
    } else {
        BrokerLeaseStatus::Revoked
    };
    lifecycle.last_error = None;
    append_lifecycle_transition(
        lifecycle,
        terminal,
        unix_millis()?,
        "provider_revoke_confirmed",
    )?;
    persist_broker_lifecycle(lifecycle)?;
    maybe_inject_broker_fault("after_revoked_lifecycle_persisted")?;
    repair_terminal_public_lease(lifecycle)
}

fn recover_provider_publication(lifecycle: &mut BrokerLeaseLifecycle) -> io::Result<()> {
    if lifecycle.request.cell_id.is_some() {
        lifecycle.pending_action = BrokerProviderOperation::Revoke;
        append_lifecycle_transition(
            lifecycle,
            BrokerLeaseStatus::Revoking,
            unix_millis()?,
            "recovered_cell_grant_was_not_attachment_confirmed",
        )?;
        persist_broker_lifecycle(lifecycle)?;
        return invoke_revoke_for_lifecycle(lifecycle);
    }
    materialize_public_lease(lifecycle, BrokerLeaseStatus::Publishing)?;
    lifecycle.public_lease_published = true;
    lifecycle.cell_attachment_confirmed = true;
    append_lifecycle_transition(
        lifecycle,
        BrokerLeaseStatus::Active,
        unix_millis()?,
        "recovered_host_lease_publication_confirmed",
    )?;
    persist_broker_lifecycle(lifecycle)?;
    maybe_inject_broker_fault("after_active_lifecycle_persisted")?;
    materialize_public_lease(lifecycle, BrokerLeaseStatus::Active)
}

fn activate_published_broker_lease(lease_id: &str) -> io::Result<BrokerLease> {
    let lifecycle_path = broker_lifecycle_path(lease_id)?;
    let _lock = TcloneStateLock::acquire(&lifecycle_path)?;
    let mut lifecycle = load_broker_lifecycle(lease_id)?;
    if lifecycle.status != BrokerLeaseStatus::Publishing {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker provider grant is not awaiting publication",
        ));
    }
    lifecycle.public_lease_published = true;
    lifecycle.cell_attachment_confirmed = true;
    append_lifecycle_transition(
        &mut lifecycle,
        BrokerLeaseStatus::Active,
        unix_millis()?,
        "public_lease_and_cell_attachment_confirmed",
    )?;
    persist_broker_lifecycle(&lifecycle)?;
    maybe_inject_broker_fault("after_active_lifecycle_persisted")?;
    materialize_public_lease(&lifecycle, BrokerLeaseStatus::Active)?;
    load_broker_lease(lease_id)
}

fn materialize_public_lease(
    lifecycle: &BrokerLeaseLifecycle,
    status: BrokerLeaseStatus,
) -> io::Result<()> {
    if status == BrokerLeaseStatus::Active
        && lifecycle.request.cell_id.is_some()
        && !lifecycle.cell_attachment_confirmed
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell-bound provider authority cannot publish before cleanup attachment",
        ));
    }
    let provider_handle = lifecycle.provider_handle.clone().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "active provider handle missing")
    })?;
    let gateway_endpoint = lifecycle.gateway_endpoint.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "active provider gateway missing",
        )
    })?;
    let mut lease = BrokerLease {
        protocol_version: BROKER_PROTOCOL_VERSION,
        lease_id: lifecycle.lease_id.clone(),
        operation_id: lifecycle.request.operation_id.clone(),
        source_run_id: lifecycle.request.source_run_id.clone(),
        cell_id: lifecycle.request.cell_id.clone(),
        resource_kind: lifecycle.request.resource_kind,
        adapter_id: lifecycle.request.adapter_id.clone(),
        audience: lifecycle.request.audience.clone(),
        scopes: lifecycle.request.scopes.clone(),
        constraints: lifecycle.request.constraints.clone(),
        issued_at_ms: lifecycle.issued_at_ms,
        expires_at_ms: lifecycle.expires_at_ms,
        status,
        delivery: BrokerDelivery::Gateway {
            gateway_endpoint,
            provider_handle,
        },
        public_metadata: lifecycle.public_metadata.clone(),
        gateway_effects: lifecycle.effects.clone(),
        effect_telemetry_complete: lifecycle.effect_telemetry_complete,
        revoked_at_ms: None,
        consumed_at_ms: None,
    };
    if let Ok(existing) = load_broker_lease(&lifecycle.lease_id) {
        lease.consumed_at_ms = existing.consumed_at_ms;
        if status == BrokerLeaseStatus::Active && existing.status == BrokerLeaseStatus::Consumed {
            lease.status = BrokerLeaseStatus::Consumed;
        }
    }
    persist_broker_lease(&lease)?;
    if status == BrokerLeaseStatus::Active {
        maybe_inject_broker_fault("after_active_lease_persisted")?;
    }
    Ok(())
}

fn repair_terminal_public_lease(lifecycle: &BrokerLeaseLifecycle) -> io::Result<()> {
    let Ok(mut lease) = load_broker_lease(&lifecycle.lease_id) else {
        return Ok(());
    };
    lease.status = lifecycle.status;
    if matches!(
        lifecycle.status,
        BrokerLeaseStatus::Revoked | BrokerLeaseStatus::Expired
    ) {
        lease.revoked_at_ms = Some(
            lifecycle
                .transitions
                .last()
                .map(|transition| transition.occurred_at_ms)
                .unwrap_or(lifecycle.expires_at_ms),
        );
    }
    lease.gateway_effects = lifecycle.effects.clone();
    lease.effect_telemetry_complete = lifecycle.effect_telemetry_complete;
    lease.public_metadata = lifecycle.public_metadata.clone();
    persist_broker_lease(&lease)?;
    maybe_inject_broker_fault("after_revoked_lease_persisted")
}

fn deny_if_provider_authority_indeterminate() -> io::Result<()> {
    let dir = broker_root()?.join("lifecycles");
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let lease_id = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid lifecycle filename")
            })?
            .to_string();
        let lifecycle = load_broker_lifecycle(&lease_id)?;
        if matches!(
            lifecycle.status,
            BrokerLeaseStatus::Preparing
                | BrokerLeaseStatus::Activating
                | BrokerLeaseStatus::Publishing
                | BrokerLeaseStatus::Revoking
                | BrokerLeaseStatus::Indeterminate
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "new broker grants denied while provider authority is {:?}: {}",
                    lifecycle.status, lifecycle.lease_id
                ),
            ));
        }
    }
    Ok(())
}

fn invoke_broker_adapter(
    config: &BrokerAdapterConfig,
    action: &str,
    lease: &BrokerLeaseRequest,
    invocation: BrokerAdapterInvocation<'_>,
) -> io::Result<BrokerAdapterResponse> {
    validate_broker_adapter_config(config)?;
    let BrokerAdapterInvocation {
        lease_id,
        idempotency_key,
        provider_handle,
        wire_mode,
        expected_executable_sha256,
    } = invocation;
    let lifecycle_v2_request = wire_mode == BrokerAdapterWireMode::LifecycleV2;
    if lifecycle_v2_request
        && (!config.lifecycle_v2 || lease_id.is_none() || idempotency_key.is_none())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker adapter lifecycle protocol was not explicitly negotiated",
        ));
    }
    if !lifecycle_v2_request
        && (lease_id.is_some() || idempotency_key.is_some() || action == "status")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "legacy broker adapter request contains lifecycle-v2 fields",
        ));
    }
    if lifecycle_v2_request && !config.environment_allowlist.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lifecycle-v2 adapters cannot inherit host environment values",
        ));
    }
    let request = BrokerAdapterRequest {
        protocol_version: BROKER_PROTOCOL_VERSION,
        action: action.to_string(),
        lease: lease.clone(),
        idempotency_key: idempotency_key.map(str::to_string),
        lease_id: lease_id.map(str::to_string),
        provider_handle: provider_handle.map(str::to_string),
    };
    let invocation_dir = broker_root()?.join("adapter-invocations");
    create_durable_broker_dir(&invocation_dir)?;
    let invocation_id = Uuid::new_v4().simple().to_string();
    let stdout_path = invocation_dir.join(format!("{invocation_id}.stdout"));
    let stderr_path = invocation_dir.join(format!("{invocation_id}.stderr"));
    let executable_path = invocation_dir.join(format!("{invocation_id}.exec"));
    let cleanup = BrokerInvocationCleanup {
        stdout: stdout_path.clone(),
        stderr: stderr_path.clone(),
        executable: None,
    };
    let stdout_file = restrictive_output_file(&stdout_path)?;
    let stderr_file = restrictive_output_file(&stderr_path)?;
    #[cfg(unix)]
    let mut cleanup = cleanup;
    #[cfg(unix)]
    let mut command = if let Some(expected_digest) = expected_executable_sha256 {
        use std::os::unix::fs::MetadataExt;
        let mut executable = open_nofollow_read(Path::new(&config.executable))?;
        let metadata = executable.metadata()?;
        if !metadata.is_file() || metadata.len() > BROKER_ADAPTER_SNAPSHOT_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker adapter snapshot is not a bounded regular file",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::by_ref(&mut executable)
            .take(BROKER_ADAPTER_SNAPSHOT_MAX_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        let actual_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if bytes.len() as u64 > BROKER_ADAPTER_SNAPSHOT_MAX_BYTES
            || !constant_time_bytes_eq(actual_digest.as_bytes(), expected_digest.as_bytes())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker adapter snapshot digest changed before execution",
            ));
        }
        // Create a private, unpredictable hard link, then verify it names the
        // exact open inode that was hashed. Rotation can replace the canonical
        // snapshot path afterward without redirecting this invocation.
        fs::hard_link(&config.executable, &executable_path)?;
        let linked = open_nofollow_read(&executable_path)?;
        let linked_metadata = linked.metadata()?;
        if metadata.dev() != linked_metadata.dev() || metadata.ino() != linked_metadata.ino() {
            let _ = fs::remove_file(&executable_path);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker adapter snapshot changed while binding its execution inode",
            ));
        }
        cleanup.executable = Some(executable_path.clone());
        maybe_replace_broker_snapshot_after_open(Path::new(&config.executable))?;
        let mut command = Command::new(&executable_path);
        command.args(&config.args);
        command
    } else {
        let mut command = Command::new(&config.executable);
        command.args(&config.args);
        command
    };
    #[cfg(not(unix))]
    let mut command = {
        if expected_executable_sha256.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "inode-bound lifecycle-v2 adapter execution is unsupported on this platform",
            ));
        }
        let mut command = Command::new(&config.executable);
        command.args(&config.args);
        command
    };
    command
        .env_clear()
        .current_dir("/")
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
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("broker adapter stdin unavailable"))?;
    stdin.write_all(&serde_json::to_vec(&request)?)?;
    stdin.write_all(b"\n")?;
    drop(stdin);
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
        validate_broker_adapter_response(config, action, &response)?;
        Ok(response)
    })();
    drop(cleanup);
    result
}

#[cfg(test)]
fn maybe_replace_broker_snapshot_after_open(snapshot: &Path) -> io::Result<()> {
    let Some(replacement) = env::var_os("GENSEE_TEST_BROKER_ADAPTER_REPLACEMENT") else {
        return Ok(());
    };
    fs::rename(PathBuf::from(replacement), snapshot)
}

#[cfg(not(test))]
fn maybe_replace_broker_snapshot_after_open(_snapshot: &Path) -> io::Result<()> {
    Ok(())
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
    executable: Option<PathBuf>,
}

impl Drop for BrokerInvocationCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stdout);
        let _ = fs::remove_file(&self.stderr);
        if let Some(path) = &self.executable {
            let _ = fs::remove_file(path);
        }
    }
}

fn validate_broker_adapter_response(
    config: &BrokerAdapterConfig,
    action: &str,
    response: &BrokerAdapterResponse,
) -> io::Result<()> {
    let authority_active = match (action, response.provider_status) {
        ("mint", None) | (_, Some(BrokerProviderStatus::Active)) => true,
        ("revoke", None)
        | (_, Some(BrokerProviderStatus::Absent | BrokerProviderStatus::Revoked)) => false,
        ("status", None) | (_, Some(BrokerProviderStatus::Indeterminate)) => false,
        _ => false,
    };
    if response.protocol_version != BROKER_PROTOCOL_VERSION
        || (action == "status" && response.provider_status.is_none())
        || (action == "revoke"
            && match response.provider_status {
                Some(BrokerProviderStatus::Absent | BrokerProviderStatus::Revoked) => false,
                None => !config.legacy_revoke_acknowledgement,
                Some(BrokerProviderStatus::Active | BrokerProviderStatus::Indeterminate) => true,
            })
        || (authority_active && response.provider_handle.trim().is_empty())
        || response.provider_handle.len() > 512
        || secret_shaped_string(&response.provider_handle)
        || (authority_active && !valid_gateway_endpoint(&response.gateway_endpoint))
        || (!response.gateway_endpoint.is_empty()
            && !valid_gateway_endpoint(&response.gateway_endpoint))
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
    let root = broker_root()?;
    let path = root.join("signing.key");
    let _lock = TcloneStateLock::acquire(&path)?;
    match fs::symlink_metadata(&path) {
        Ok(path_metadata) => {
            if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker signing key must be a regular non-symlink file",
                ));
            }
            let mut file = open_nofollow_read(&path)?;
            let metadata = file.metadata()?;
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker signing key must have mode 0600",
                ));
            }
            if !metadata.is_file() || metadata.len() != 65 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker signing key has invalid type or length",
                ));
            }
            let mut bytes = Zeroizing::new(Vec::with_capacity(65));
            file.read_to_end(&mut bytes)?;
            if bytes.len() != 65
                || bytes[64] != b'\n'
                || !bytes[..64]
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker signing key must be exactly 64 lowercase hexadecimal bytes",
                ));
            }
            bytes.truncate(64);
            let key = String::from_utf8(bytes.to_vec())
                .map(Zeroizing::new)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            maybe_inject_broker_fault("after_existing_signing_key_load_before_dirsync")?;
            sync_broker_directory(&root)?;
            return Ok(key);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if retained_host_signed_state_exists(&root)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker signing key is missing while signed state is retained; refusing replacement",
        ));
    }
    let key = Zeroizing::new(format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ));
    let mut persisted = Zeroizing::new(key.as_bytes().to_vec());
    persisted.push(b'\n');
    write_atomic_nofollow(&path, &persisted, 0o600)?;
    maybe_inject_broker_fault("after_signing_key_rename_before_dirsync")?;
    sync_broker_directory(&root)?;
    Ok(key)
}

fn retained_host_signed_state_exists(broker_root: &Path) -> io::Result<bool> {
    for name in ["issue-index", "lifecycles", "commit-tokens"] {
        let dir = broker_root.join(name);
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                {
                    return Ok(true);
                }
            }
        }
    }
    let cells = default_root()?.join("tclone-capability-cells");
    if !cells.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(cells)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        if ["forensics-evidence.json", "promotion-ledger.json"]
            .iter()
            .any(|name| entry.path().join(name).exists())
        {
            return Ok(true);
        }
    }
    Ok(false)
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
        // Lifecycle-less leases predate caller request ids. Omitting this
        // empty field preserves their exact adapter request shape.
        request_id: String::new(),
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
    create_durable_broker_dir(&root)?;
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
    create_durable_broker_dir(&dir)?;
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
    create_durable_broker_dir(&dir)?;
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
    create_durable_broker_dir(&dir)?;
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
            let lifecycle_path = broker_lifecycle_path(lease_id)?;
            let _lifecycle_lock = if lifecycle_path.exists() {
                Some(TcloneStateLock::acquire(&lifecycle_path)?)
            } else {
                None
            };
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
        let lifecycle_path = broker_lifecycle_path(lease_id)?;
        if lifecycle_path.exists() {
            let lifecycle = load_broker_lifecycle(lease_id)?;
            if lifecycle.status != BrokerLeaseStatus::Active
                || (lifecycle.request.cell_id.is_some() && !lifecycle.cell_attachment_confirmed)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "broker provider authority is not confirmed active: {lease_id} ({:?})",
                        lifecycle.status
                    ),
                ));
            }
        }
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

    #[cfg(unix)]
    fn lifecycle_test_fixture(root: &Path) -> (BrokerAdapterConfig, BrokerLeaseRequest, PathBuf) {
        fs::create_dir_all(root).unwrap();
        let state = root.join("provider-state");
        let executable = root.join("idempotent-adapter.sh");
        let script_prefix = format!(
            "#!/bin/sh\nstate='{}'\ngateway_file='{}'\nrevoke_active_file='{}'\n",
            state.display(),
            state.with_extension("gateway").display(),
            state.with_extension("revoke-active").display(),
        );
        let script = script_prefix
            + r#"input=""
while IFS= read -r line; do input="$input$line"; done
pwd > "$state.cwd"
gateway=unix:///run/gensee/repo.sock
if [ -f "$gateway_file" ]; then IFS= read -r gateway < "$gateway_file"; fi
case "$input" in
  *status*)
    if [ ! -f "$state" ]; then
      provider_status=absent
    else
      IFS= read -r provider_status < "$state"
    fi
    if [ "$provider_status" = active ]; then
      printf '{"protocol_version":1,"provider_status":"active","provider_handle":"opaque_1","gateway_endpoint":"%s","effect_telemetry_complete":true}\n' "$gateway"
    else
      printf '{"protocol_version":1,"provider_status":"%s","provider_handle":"","gateway_endpoint":"","effect_telemetry_complete":true}\n' "$provider_status"
    fi
    ;;
  *mint*)
    printf '%s\n' "$input" > "$state.request"
    if [ ! -f "$state" ]; then
      printf '%s\n' active > "$state"
      printf '%s\n' mint >> "$state.log"
    fi
    printf '{"protocol_version":1,"provider_status":"active","provider_handle":"opaque_1","gateway_endpoint":"%s","effect_telemetry_complete":true}\n' "$gateway"
    ;;
  *revoke*)
    printf '%s\n' "$input" > "$state.request"
    if [ -f "$revoke_active_file" ]; then
      printf '{"protocol_version":1,"provider_status":"active","provider_handle":"opaque_1","gateway_endpoint":"%s","effect_telemetry_complete":true}\n' "$gateway"
      exit 0
    fi
    printf '%s\n' revoked > "$state"
    printf '%s\n' revoke >> "$state.log"
    printf '%s\n' '{"protocol_version":1,"provider_status":"revoked","provider_handle":"opaque_1","gateway_endpoint":"","effect_telemetry_complete":true}'
    ;;
  *) exit 64 ;;
esac
"#;
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = BrokerAdapterConfig {
            schema_version: BROKER_ADAPTER_SCHEMA_VERSION,
            adapter_id: "idempotent_adapter".to_string(),
            resource_kinds: vec![BrokerResourceKind::RepositoryToken],
            executable: executable.to_string_lossy().to_string(),
            args: vec!["--lifecycle-v2".to_string()],
            environment_allowlist: Vec::new(),
            lifecycle_v2: true,
            max_ttl_seconds: 60,
            legacy_revoke_acknowledgement: false,
        };
        persist_test_adapter(&config);
        let request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            request_id: "request_1".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: None,
            resource_kind: BrokerResourceKind::RepositoryToken,
            adapter_id: config.adapter_id.clone(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["repository:one:read".to_string()],
            ttl_seconds: 60,
            constraints: json!({ "repository": "one" }),
        };
        (config, request, state)
    }

    #[cfg(unix)]
    fn persist_test_adapter(config: &BrokerAdapterConfig) {
        let path = broker_adapter_path(&config.adapter_id).unwrap();
        write_atomic_nofollow(&path, &serde_json::to_vec_pretty(config).unwrap(), 0o600).unwrap();
    }

    #[cfg(unix)]
    fn clear_broker_test_environment(root: &Path) {
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        env::remove_var("GENSEE_TEST_BROKER_BOOT_MARKER");
        env::remove_var("GENSEE_TEST_BROKER_MONOTONIC_MS");
        env::remove_var("GENSEE_TEST_BROKER_WALL_NOW_MS");
        env::remove_var("GENSEE_TEST_BROKER_ADAPTER_REPLACEMENT");
        env::remove_var("BROKER_TEST_STATE");
        env::remove_var("BROKER_TEST_REVOKE_ACTIVE");
        env::remove_var("BROKER_TEST_GATEWAY");
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    fn persist_running_source(run_id: &str) {
        let record = TcloneRunRecord {
            run_id: run_id.to_string(),
            observe_only: false,
            operation_id: None,
            operation_state_root: None,
            capability_lifecycle: None,
            parent_run_id: None,
            role: "source".to_string(),
            status: "running".to_string(),
            container_name: format!("container-{run_id}"),
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
            agent_cmd: vec!["codex".to_string()],
            path_prefixes: Vec::new(),
            fork_base_git_head: None,
            fork_base_overlay_lowerdir: None,
            fork_overlay_upperdir: None,
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        };
        write_tclone_runs_to_path(&tclone_state_path().unwrap(), &[record]).unwrap();
    }

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
            request_id: "request_1".to_string(),
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
            request_id: "request_1".to_string(),
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
    fn legacy_revoke_acknowledgement_requires_explicit_adapter_opt_in() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-legacy-revoke-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (mut config, _, _) = lifecycle_test_fixture(&root);
        let response = BrokerAdapterResponse {
            protocol_version: BROKER_PROTOCOL_VERSION,
            provider_status: None,
            provider_handle: "opaque_1".to_string(),
            gateway_endpoint: "unix:///run/gensee/repo.sock".to_string(),
            public_metadata: Value::Null,
            effects: Vec::new(),
            effect_telemetry_complete: true,
        };
        assert_eq!(
            validate_broker_adapter_response(&config, "revoke", &response)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        config.legacy_revoke_acknowledgement = true;
        validate_broker_adapter_response(&config, "revoke", &response).unwrap();
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_lease_revoke_stays_legacy_after_adapter_registration_upgrade() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-legacy-upgrade-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        assert!(config.lifecycle_v2);
        fs::write(&state, "active\n").unwrap();
        let mut lease = BrokerLease {
            protocol_version: BROKER_PROTOCOL_VERSION,
            lease_id: "broker_lease_legacy".to_string(),
            operation_id: request.operation_id,
            source_run_id: request.source_run_id,
            cell_id: None,
            resource_kind: request.resource_kind,
            adapter_id: config.adapter_id,
            audience: request.audience,
            scopes: request.scopes,
            constraints: request.constraints,
            issued_at_ms: 1,
            expires_at_ms: u64::MAX,
            status: BrokerLeaseStatus::Active,
            delivery: BrokerDelivery::Gateway {
                gateway_endpoint: "unix:///run/gensee/repo.sock".to_string(),
                provider_handle: "opaque_1".to_string(),
            },
            public_metadata: Value::Null,
            gateway_effects: Vec::new(),
            effect_telemetry_complete: true,
            revoked_at_ms: None,
            consumed_at_ms: None,
        };
        revoke_broker_lease_record(&mut lease).unwrap();
        assert_eq!(lease.status, BrokerLeaseStatus::Revoked);
        let wire: Value =
            serde_json::from_str(&fs::read_to_string(state.with_extension("request")).unwrap())
                .unwrap();
        assert_eq!(wire["action"], "revoke");
        assert!(wire.get("lease_id").is_none());
        assert!(wire.get("idempotency_key").is_none());
        assert!(wire["lease"].get("request_id").is_none());
        clear_broker_test_environment(&root);
    }

    #[test]
    fn lifecycle_transition_graph_is_fail_closed() {
        assert!(valid_lifecycle_transition(
            None,
            BrokerLeaseStatus::Preparing
        ));
        assert!(valid_lifecycle_transition(
            Some(BrokerLeaseStatus::Activating),
            BrokerLeaseStatus::Indeterminate
        ));
        assert!(valid_lifecycle_transition(
            Some(BrokerLeaseStatus::Active),
            BrokerLeaseStatus::Revoking
        ));
        assert!(!valid_lifecycle_transition(
            Some(BrokerLeaseStatus::Preparing),
            BrokerLeaseStatus::Active
        ));
        assert!(!valid_lifecycle_transition(
            Some(BrokerLeaseStatus::Revoked),
            BrokerLeaseStatus::Active
        ));
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_is_strict_and_never_regenerated_over_retained_state() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-key-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        sign_host_evidence("test-domain", b"first").unwrap();
        let key_path = root.join("capability-broker/signing.key");

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            sign_host_evidence("test-domain", b"mode")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&key_path, "short\n").unwrap();
        assert_eq!(
            sign_host_evidence("test-domain", b"length")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        // Restore a valid key, retain authenticated state, then prove a lost
        // key cannot silently establish a new trust root.
        fs::write(&key_path, format!("{}\n", "a".repeat(64))).unwrap();
        let lifecycle_path = broker_lifecycle_path("broker_lease_retained").unwrap();
        write_atomic_nofollow(&lifecycle_path, b"retained", 0o600).unwrap();
        fs::remove_file(&key_path).unwrap();
        assert_eq!(
            sign_host_evidence("test-domain", b"replacement")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!key_path.exists());
        std::os::unix::fs::symlink(root.join("missing-key-target"), &key_path).unwrap();
        assert_eq!(
            sign_host_evidence("test-domain", b"dangling-symlink")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_creation_does_not_return_before_parent_dirsync() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-key-sync-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_signing_key_rename_before_dirsync",
        );
        assert_eq!(
            sign_host_evidence("test-domain", b"not-returned")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        sign_host_evidence("test-domain", b"after-sync").unwrap();
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_existing_signing_key_load_before_dirsync",
        );
        assert_eq!(
            sign_host_evidence("test-domain", b"existing-not-returned")
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        sign_host_evidence("test-domain", b"existing-after-sync").unwrap();
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn broker_subdirectory_creation_repairs_parent_dirsync_on_retry() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-dir-sync-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        broker_root().unwrap();
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_broker_directory_create_before_parent_dirsync",
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            broker_issue_index_path(&digest).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(root.join("capability-broker/issue-index").is_dir());
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        assert!(broker_issue_index_path(&digest)
            .unwrap()
            .parent()
            .unwrap()
            .is_dir());
        clear_broker_test_environment(&root);
    }

    #[test]
    fn provider_idempotency_key_is_stable_and_request_bound() {
        let mut request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            request_id: "request_1".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: None,
            resource_kind: BrokerResourceKind::RepositoryToken,
            adapter_id: "repo_adapter".to_string(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["repository:one:read".to_string()],
            ttl_seconds: 60,
            constraints: json!({ "repository": "one" }),
        };
        let first = broker_idempotency_key("broker_lease_1", &request).unwrap();
        assert_eq!(
            first,
            broker_idempotency_key("broker_lease_1", &request).unwrap()
        );
        request.scopes = vec!["repository:two:read".to_string()];
        assert_ne!(
            first,
            broker_idempotency_key("broker_lease_1", &request).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_issue_retry_resumes_indexed_lease_and_sends_clamped_ttl_once() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-issue-retry-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, mut request, state) = lifecycle_test_fixture(&root);
        persist_running_source(&request.source_run_id);
        request.ttl_seconds = 600;
        request.scopes.push("repository:two:read".to_string());
        let request_path = root.join("request.json");
        write_atomic_nofollow(
            &request_path,
            &serde_json::to_vec_pretty(&request).unwrap(),
            0o600,
        )
        .unwrap();
        let args = vec![
            OsString::from("--request"),
            request_path.as_os_str().to_os_string(),
            OsString::from("--json"),
        ];
        env::set_var("GENSEE_TEST_BROKER_FAULT", "after_provider_mint");
        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");

        issue_broker_lease(&args).unwrap();
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_existing_issue_index_load_before_dirsync",
        );
        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        issue_broker_lease(&args).unwrap();

        // The caller id, not pre-policy request bytes, selects the durable
        // issuance. A changed retry which would clamp to the same authority
        // is rejected rather than minting through a second index.
        request.ttl_seconds = 300;
        request.scopes.reverse();
        write_atomic_nofollow(
            &request_path,
            &serde_json::to_vec_pretty(&request).unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        assert_eq!(
            fs::read_to_string(state.with_extension("log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "mint")
                .count(),
            1
        );
        let adapter_request: BrokerAdapterRequest =
            serde_json::from_str(&fs::read_to_string(state.with_extension("request")).unwrap())
                .unwrap();
        assert_eq!(adapter_request.lease.ttl_seconds, config.max_ttl_seconds);
        assert_eq!(
            fs::read_dir(root.join("capability-broker/leases"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            fs::read_dir(root.join("capability-broker/issue-index"))
                .unwrap()
                .count(),
            1
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_invokes_the_authenticated_adapter_snapshot_after_rotation() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-adapter-pin-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        env::set_var("GENSEE_TEST_BROKER_FAULT", "after_provider_mint");
        mint_external_provider_lease(
            &config,
            "broker_lease_pinned",
            &request,
            unix_millis().unwrap(),
        )
        .unwrap_err();
        env::remove_var("GENSEE_TEST_BROKER_FAULT");

        fs::write(&config.executable, "#!/bin/sh\nexit 77\n").unwrap();
        fs::set_permissions(&config.executable, fs::Permissions::from_mode(0o700)).unwrap();
        persist_test_adapter(&config);
        reconcile_broker_lifecycles().unwrap();

        assert_eq!(
            load_broker_lifecycle("broker_lease_pinned").unwrap().status,
            BrokerLeaseStatus::Active
        );
        assert_eq!(
            fs::read_to_string(state.with_extension("log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "mint")
                .count(),
            1
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_recovery_uses_fixed_cwd_and_rejects_file_like_args() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-cwd-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        for unsafe_arg in ["provider.json", "--config=provider.json"] {
            let mut unsafe_config = config.clone();
            unsafe_config.args = vec![unsafe_arg.to_string()];
            assert_eq!(
                validate_broker_adapter_config(&unsafe_config)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied,
                "{unsafe_arg}"
            );
        }
        let mut legacy_config = config.clone();
        legacy_config.lifecycle_v2 = false;
        legacy_config.args = vec!["--config=provider.json".to_string()];
        validate_broker_adapter_config(&legacy_config).unwrap();

        env::set_var("GENSEE_TEST_BROKER_FAULT", "after_provider_mint");
        assert_eq!(
            mint_external_provider_lease(
                &config,
                "broker_lease_cwd",
                &request,
                unix_millis().unwrap(),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        let original_cwd = env::current_dir().unwrap();
        let changed_cwd = root.join("untrusted-cwd");
        fs::create_dir_all(&changed_cwd).unwrap();
        env::set_current_dir(&changed_cwd).unwrap();
        let recovery = reconcile_broker_lifecycles();
        env::set_current_dir(original_cwd).unwrap();
        recovery.unwrap();

        assert_eq!(
            fs::read_to_string(state.with_extension("cwd"))
                .unwrap()
                .trim(),
            "/"
        );
        assert_eq!(
            load_broker_lifecycle("broker_lease_cwd").unwrap().status,
            BrokerLeaseStatus::Active
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_v2_rejects_mutable_environment_identity() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-env-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (mut config, request, _) = lifecycle_test_fixture(&root);
        config.environment_allowlist = vec!["BROKER_TENANT".to_string()];
        assert_eq!(
            mint_external_provider_lease(
                &config,
                "broker_lease_env",
                &request,
                unix_millis().unwrap(),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!broker_lifecycle_path("broker_lease_env").unwrap().exists());
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_executes_the_verified_inode_when_snapshot_path_is_replaced() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-inode-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        let malicious_marker = root.join("malicious-ran");
        let replacement = root.join("replacement.sh");
        fs::write(
            &replacement,
            format!(
                "#!/bin/sh\nprintf ran > '{}'\nexit 77\n",
                malicious_marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
        env::set_var("GENSEE_TEST_BROKER_ADAPTER_REPLACEMENT", &replacement);

        // The later lifecycle persist notices the path digest changed, but
        // the provider invocation itself used the already-verified inode.
        assert!(mint_external_provider_lease(
            &config,
            "broker_lease_inode",
            &request,
            unix_millis().unwrap(),
        )
        .is_err());
        assert!(!malicious_marker.exists());
        assert_eq!(fs::read_to_string(&state).unwrap().trim(), "active");
        assert_eq!(
            fs::read_to_string(state.with_extension("log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "mint")
                .count(),
            1
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn crash_after_cell_attachment_revokes_before_any_active_publication() {
        let _guard = crate::cli_test_env_lock();
        let suffix = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from("/tmp").join(format!("gcp-{}", &suffix[..8]));
        env::set_var("GENSEE_HOME", &root);
        let (_config, mut request, state) = lifecycle_test_fixture(&root);
        persist_running_source(&request.source_run_id);
        let cell_id = "cell_publish";
        request.cell_id = Some(cell_id.to_string());
        request.constraints = json!({
            "gateway_kind": "repository_api",
            "repository": "one"
        });
        let now = unix_millis().unwrap();
        super::super::capability_cell::persist_test_broker_cell_binding(
            cell_id,
            "cell_lease_publish",
            &request.source_run_id,
            &request.operation_id,
            now.saturating_sub(1_000),
            now.saturating_add(60_000),
        )
        .unwrap();
        let socket_dir = root.join("gateway");
        fs::create_dir_all(&socket_dir).unwrap();
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = socket_dir.join("repo.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::write(
            state.with_extension("gateway"),
            format!("unix://{}\n", socket.display()),
        )
        .unwrap();
        let request_path = root.join("cell-request.json");
        write_atomic_nofollow(
            &request_path,
            &serde_json::to_vec_pretty(&request).unwrap(),
            0o600,
        )
        .unwrap();
        let args = vec![
            OsString::from("--request"),
            request_path.as_os_str().to_os_string(),
            OsString::from("--json"),
        ];
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_cell_attachment_persisted",
        );
        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");

        let lifecycle_entry = fs::read_dir(root.join("capability-broker/lifecycles"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let lease_id = lifecycle_entry
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(
            load_broker_lease(&lease_id).unwrap().status,
            BrokerLeaseStatus::Publishing
        );
        assert_eq!(
            load_broker_lifecycle(&lease_id).unwrap().status,
            BrokerLeaseStatus::Publishing
        );

        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            load_broker_lease(&lease_id).unwrap().status,
            BrokerLeaseStatus::Revoked
        );
        assert_eq!(
            load_broker_lifecycle(&lease_id).unwrap().status,
            BrokerLeaseStatus::Revoked
        );
        assert_eq!(fs::read_to_string(state).unwrap().trim(), "revoked");
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn cell_attachment_dirsync_precedes_any_active_lifecycle_transition() {
        let _guard = crate::cli_test_env_lock();
        let suffix = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from("/tmp").join(format!("gcs-{}", &suffix[..8]));
        env::set_var("GENSEE_HOME", &root);
        let (_config, mut request, state) = lifecycle_test_fixture(&root);
        persist_running_source(&request.source_run_id);
        let cell_id = "cell_dirsync";
        request.cell_id = Some(cell_id.to_string());
        request.constraints = json!({
            "gateway_kind": "repository_api",
            "repository": "one"
        });
        let now = unix_millis().unwrap();
        super::super::capability_cell::persist_test_broker_cell_binding(
            cell_id,
            "cell_lease_dirsync",
            &request.source_run_id,
            &request.operation_id,
            now.saturating_sub(1_000),
            now.saturating_add(60_000),
        )
        .unwrap();
        let socket_dir = root.join("gateway");
        fs::create_dir_all(&socket_dir).unwrap();
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = socket_dir.join("repo.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::write(
            state.with_extension("gateway"),
            format!("unix://{}\n", socket.display()),
        )
        .unwrap();
        let request_path = root.join("cell-request.json");
        write_atomic_nofollow(
            &request_path,
            &serde_json::to_vec_pretty(&request).unwrap(),
            0o600,
        )
        .unwrap();
        let args = vec![
            OsString::from("--request"),
            request_path.as_os_str().to_os_string(),
            OsString::from("--json"),
        ];
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_cell_attachment_rename_before_dirsync",
        );
        assert_eq!(
            issue_broker_lease(&args).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");

        let lifecycle_entry = fs::read_dir(root.join("capability-broker/lifecycles"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let lease_id = lifecycle_entry
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(
            load_broker_lifecycle(&lease_id).unwrap().status,
            BrokerLeaseStatus::Revoked
        );
        assert!(load_broker_lifecycle(&lease_id)
            .unwrap()
            .transitions
            .iter()
            .all(|transition| transition.to != BrokerLeaseStatus::Active));

        // The caller never observes successful attachment, so the outer issue
        // flow tears provider authority down without an Active transition.
        assert_eq!(fs::read_to_string(state).unwrap().trim(), "revoked");
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn crash_recovery_reconciles_each_mint_boundary_without_duplicate_authority() {
        let _guard = crate::cli_test_env_lock();
        for fault in [
            "after_intent_persisted",
            "after_activating_persisted",
            "after_provider_mint",
            "after_active_lifecycle_persisted",
        ] {
            let root =
                env::temp_dir().join(format!("gensee-broker-crash-{fault}-{}", Uuid::new_v4()));
            env::set_var("GENSEE_HOME", &root);
            let (config, request, state) = lifecycle_test_fixture(&root);
            env::set_var("GENSEE_TEST_BROKER_FAULT", fault);
            let error = mint_external_provider_lease(
                &config,
                "broker_lease_crash",
                &request,
                unix_millis().unwrap(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{fault}");
            env::remove_var("GENSEE_TEST_BROKER_FAULT");

            reconcile_broker_lifecycles().unwrap();
            let lifecycle = load_broker_lifecycle("broker_lease_crash").unwrap();
            assert_eq!(lifecycle.status, BrokerLeaseStatus::Active, "{fault}");
            assert_eq!(
                load_broker_lease("broker_lease_crash").unwrap().status,
                BrokerLeaseStatus::Active,
                "{fault}"
            );
            let mint_count = fs::read_to_string(state.with_extension("log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "mint")
                .count();
            assert_eq!(mint_count, 1, "{fault}");
            clear_broker_test_environment(&root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn crash_recovery_reconciles_each_revoke_boundary() {
        let _guard = crate::cli_test_env_lock();
        for fault in [
            "after_revoking_persisted",
            "after_provider_revoke",
            "after_revoked_lifecycle_persisted",
            "after_revoked_lease_persisted",
        ] {
            let root =
                env::temp_dir().join(format!("gensee-broker-revoke-{fault}-{}", Uuid::new_v4()));
            env::set_var("GENSEE_HOME", &root);
            let (config, request, state) = lifecycle_test_fixture(&root);
            let lease_id = "broker_lease_revoke";
            mint_external_provider_lease(&config, lease_id, &request, unix_millis().unwrap())
                .unwrap();
            let mut lifecycle = load_broker_lifecycle(lease_id).unwrap();
            recover_provider_publication(&mut lifecycle).unwrap();
            env::set_var("GENSEE_TEST_BROKER_FAULT", fault);
            let mut lease = load_broker_lease(lease_id).unwrap();
            let error = revoke_broker_lease_record(&mut lease).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{fault}");
            env::remove_var("GENSEE_TEST_BROKER_FAULT");

            reconcile_broker_lifecycles().unwrap();
            let lifecycle = load_broker_lifecycle(lease_id).unwrap();
            assert_eq!(lifecycle.status, BrokerLeaseStatus::Revoked, "{fault}");
            assert_eq!(
                load_broker_lease(lease_id).unwrap().status,
                BrokerLeaseStatus::Revoked
            );
            assert_eq!(fs::read_to_string(&state).unwrap().trim(), "revoked");
            clear_broker_test_environment(&root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn revoke_active_acknowledgement_is_indeterminate_and_never_terminal() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-bad-revoke-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        let lease_id = "broker_lease_bad_revoke";
        mint_external_provider_lease(&config, lease_id, &request, unix_millis().unwrap()).unwrap();
        let mut lifecycle = load_broker_lifecycle(lease_id).unwrap();
        recover_provider_publication(&mut lifecycle).unwrap();
        fs::write(state.with_extension("revoke-active"), "1\n").unwrap();
        let mut lease = load_broker_lease(lease_id).unwrap();
        assert!(revoke_broker_lease_record(&mut lease).is_err());

        assert_eq!(
            load_broker_lifecycle(lease_id).unwrap().status,
            BrokerLeaseStatus::Indeterminate
        );
        assert_eq!(
            load_broker_lease(lease_id).unwrap().status,
            BrokerLeaseStatus::Revoking
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn crash_after_public_lease_persist_is_recoverable_without_remint() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-public-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        let lease_id = "broker_lease_public";
        mint_external_provider_lease(&config, lease_id, &request, unix_millis().unwrap()).unwrap();
        let mut lifecycle = load_broker_lifecycle(lease_id).unwrap();
        env::set_var("GENSEE_TEST_BROKER_FAULT", "after_active_lease_persisted");
        assert_eq!(
            recover_provider_publication(&mut lifecycle)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");

        reconcile_broker_lifecycles().unwrap();
        assert_eq!(
            load_broker_lease(lease_id).unwrap().status,
            BrokerLeaseStatus::Active
        );
        assert_eq!(
            fs::read_to_string(state.with_extension("log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "mint")
                .count(),
            1
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn signed_lifecycle_rejects_tampered_transition_or_deadline() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-tamper-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, _) = lifecycle_test_fixture(&root);
        mint_external_provider_lease(
            &config,
            "broker_lease_tamper",
            &request,
            unix_millis().unwrap(),
        )
        .unwrap();
        let mut lifecycle = load_broker_lifecycle("broker_lease_tamper").unwrap();
        lifecycle.transitions.last_mut().unwrap().reason = "forged".to_string();
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut lifecycle = load_broker_lifecycle("broker_lease_tamper").unwrap();
        lifecycle.expires_at_ms = lifecycle.expires_at_ms.saturating_add(1);
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut lifecycle = load_broker_lifecycle("broker_lease_tamper").unwrap();
        lifecycle.provider_handle = Some("opaque_forged".to_string());
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut lifecycle = load_broker_lifecycle("broker_lease_tamper").unwrap();
        lifecycle.public_metadata = json!({ "repository": "forged" });
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut lifecycle = load_broker_lifecycle("broker_lease_tamper").unwrap();
        lifecycle
            .adapter_snapshot
            .config
            .args
            .push("--forged".to_string());
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn signed_lifecycle_rejects_an_impossible_fully_resigned_chain() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-graph-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, _) = lifecycle_test_fixture(&root);
        mint_external_provider_lease(
            &config,
            "broker_lease_graph",
            &request,
            unix_millis().unwrap(),
        )
        .unwrap();
        let mut lifecycle = load_broker_lifecycle("broker_lease_graph").unwrap();
        lifecycle.transitions[0].to = BrokerLeaseStatus::Active;
        lifecycle.transitions[1].from = Some(BrokerLeaseStatus::Active);

        let mut previous_signature = String::new();
        for transition in &mut lifecycle.transitions {
            transition.previous_signature = previous_signature.clone();
            let claims = BrokerLifecycleTransitionClaims {
                lease_id: &lifecycle.lease_id,
                idempotency_key: &lifecycle.idempotency_key,
                sequence: transition.sequence,
                from: transition.from,
                to: transition.to,
                occurred_at_ms: transition.occurred_at_ms,
                provider_operation: transition.provider_operation,
                expires_at_ms: transition.expires_at_ms,
                boot_marker: &transition.boot_marker,
                monotonic_deadline_ms: transition.monotonic_deadline_ms,
                adapter_snapshot_digest: &transition.adapter_snapshot_digest,
                provider_state_digest: &transition.provider_state_digest,
                reason: &transition.reason,
                previous_signature: &transition.previous_signature,
            };
            transition.signature = sign_host_evidence(
                "broker-lifecycle-transition-v1",
                &serde_json::to_vec(&claims).unwrap(),
            )
            .unwrap();
            verify_host_evidence(
                "broker-lifecycle-transition-v1",
                &serde_json::to_vec(&claims).unwrap(),
                &transition.signature,
            )
            .unwrap();
            previous_signature = transition.signature.clone();
        }
        assert_eq!(
            validate_broker_lifecycle(&lifecycle).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_intent_rename_precedes_directory_sync_and_provider_effect() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-dirsync-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        env::set_var(
            "GENSEE_TEST_BROKER_FAULT",
            "after_lifecycle_rename_before_dirsync",
        );
        assert_eq!(
            mint_external_provider_lease(
                &config,
                "broker_lease_dirsync",
                &request,
                unix_millis().unwrap(),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            !state.exists(),
            "adapter must not run before intent dirsync"
        );
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        let lifecycle = load_broker_lifecycle("broker_lease_dirsync").unwrap();
        assert_eq!(lifecycle.status, BrokerLeaseStatus::Preparing);
        sync_broker_directory(
            broker_lifecycle_path("broker_lease_dirsync")
                .unwrap()
                .parent()
                .unwrap(),
        )
        .unwrap();
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn indeterminate_provider_authority_denies_new_grants_until_reconciled() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-deny-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        env::set_var("GENSEE_TEST_BROKER_FAULT", "after_activating_persisted");
        mint_external_provider_lease(
            &config,
            "broker_lease_unknown",
            &request,
            unix_millis().unwrap(),
        )
        .unwrap_err();
        env::remove_var("GENSEE_TEST_BROKER_FAULT");
        fs::write(&state, "indeterminate\n").unwrap();

        reconcile_broker_lifecycles().unwrap();
        assert_eq!(
            load_broker_lifecycle("broker_lease_unknown")
                .unwrap()
                .status,
            BrokerLeaseStatus::Indeterminate
        );
        assert_eq!(
            deny_if_provider_authority_indeterminate()
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        fs::remove_file(&state).unwrap();
        reconcile_broker_lifecycles().unwrap();
        deny_if_provider_authority_indeterminate().unwrap();
        assert_eq!(
            load_broker_lifecycle("broker_lease_unknown")
                .unwrap()
                .status,
            BrokerLeaseStatus::Active
        );
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn reboot_marker_change_forces_provider_teardown_instead_of_extending_ttl() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-reboot-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        let lease_id = "broker_lease_reboot";
        mint_external_provider_lease(&config, lease_id, &request, unix_millis().unwrap()).unwrap();
        let mut lifecycle = load_broker_lifecycle(lease_id).unwrap();
        recover_provider_publication(&mut lifecycle).unwrap();

        env::set_var(
            "GENSEE_TEST_BROKER_BOOT_MARKER",
            "boot_epoch_minute_rebooted",
        );
        env::set_var(
            "GENSEE_TEST_BROKER_MONOTONIC_MS",
            lifecycle.monotonic_issued_at_ms.to_string(),
        );
        reconcile_broker_lifecycles().unwrap();

        assert_eq!(
            load_broker_lifecycle(lease_id).unwrap().status,
            BrokerLeaseStatus::Revoked
        );
        assert_eq!(
            load_broker_lease(lease_id).unwrap().status,
            BrokerLeaseStatus::Revoked
        );
        assert_eq!(fs::read_to_string(state).unwrap().trim(), "revoked");
        clear_broker_test_environment(&root);
    }

    #[cfg(unix)]
    #[test]
    fn wall_deadline_expiry_revokes_even_when_monotonic_deadline_has_not_elapsed() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-broker-wall-expiry-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let (config, request, state) = lifecycle_test_fixture(&root);
        let lease_id = "broker_lease_wall_expiry";
        mint_external_provider_lease(&config, lease_id, &request, unix_millis().unwrap()).unwrap();
        let mut lifecycle = load_broker_lifecycle(lease_id).unwrap();
        recover_provider_publication(&mut lifecycle).unwrap();
        env::set_var("GENSEE_TEST_BROKER_BOOT_MARKER", &lifecycle.boot_marker);
        env::set_var(
            "GENSEE_TEST_BROKER_MONOTONIC_MS",
            lifecycle.monotonic_issued_at_ms.to_string(),
        );
        env::set_var(
            "GENSEE_TEST_BROKER_WALL_NOW_MS",
            lifecycle.expires_at_ms.saturating_add(1).to_string(),
        );

        reconcile_broker_lifecycles().unwrap();
        assert_eq!(
            load_broker_lifecycle(lease_id).unwrap().status,
            BrokerLeaseStatus::Expired
        );
        assert_eq!(fs::read_to_string(state).unwrap().trim(), "revoked");
        clear_broker_test_environment(&root);
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
            lifecycle_v2: false,
            max_ttl_seconds: 60,
            legacy_revoke_acknowledgement: false,
        };
        let request = BrokerLeaseRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
            request_id: "request_1".to_string(),
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

        let response = invoke_broker_adapter(
            &config,
            "mint",
            &request,
            BrokerAdapterInvocation {
                lease_id: None,
                idempotency_key: None,
                provider_handle: None,
                wire_mode: BrokerAdapterWireMode::Legacy,
                expected_executable_sha256: None,
            },
        )
        .unwrap();

        assert_eq!(response.provider_handle, "opaque_1");
        assert_eq!(response.gateway_endpoint, "unix:///run/gensee/repo.sock");
        assert_eq!(response.public_metadata["repository"], "one");
        let invocation_dir = root.join("capability-broker/adapter-invocations");
        assert_eq!(fs::read_dir(invocation_dir).unwrap().count(), 0);

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }
}
