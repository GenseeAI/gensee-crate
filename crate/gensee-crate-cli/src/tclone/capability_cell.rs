use super::*;
use gensee_crate_rules::capability::{
    Capability, CapabilityRequest, EffectManifest, EffectTelemetryCoverage, EffectViolation,
    ExecutionBoundary, FileChangeEffect, FileChangeKind, FileEntryKind, ProcessEffect,
    PromotionOutput, PromotionReceipt, TelemetryCoverage, CAPABILITY_REQUEST_SCHEMA_VERSION,
    EFFECT_MANIFEST_SCHEMA_VERSION,
};
use gensee_crate_rules::capability_broker::BrokerResourceKind;
use gensee_crate_rules::capability_broker::{BrokerDelivery, BrokerGatewayEffectKind, BrokerLease};
use gensee_crate_rules::capability_policy::{
    CapabilityPolicyDecision, CapabilityPolicyEngine, MediationBoundary, PolicyEvaluationContext,
};
use std::collections::{BTreeMap, BTreeSet};

const CELL_LEASE_SCHEMA_VERSION: u32 = 1;
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
    command: Vec<String>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at_ms: Option<u64>,
    #[serde(default)]
    broker_lease_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CapabilityCellRecord {
    schema_version: u32,
    operation_id: String,
    cell_id: String,
    lease_id: String,
    source_run_id: String,
    request: CapabilityRequest,
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

pub(crate) fn tclone_capability_lease(args: Vec<OsString>) -> io::Result<()> {
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
    validate_cell_request_for_issue(&request)?;
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
        command,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        consumed_at_ms: None,
        broker_lease_ids: Vec::new(),
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
                "execution_boundary": lease.request.execution_boundary,
                "authorization_state": "pending_mediation",
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
    if args.first().and_then(|arg| arg.to_str()) == Some("inspect") {
        return inspect_capability_cell(args[1..].to_vec());
    }
    if args.first().and_then(|arg| arg.to_str()) == Some("promote") {
        return promote_capability_cell(args[1..].to_vec());
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

fn validate_cell_request_for_issue(request: &CapabilityRequest) -> io::Result<()> {
    if request.schema_version != CAPABILITY_REQUEST_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported capability request schema version",
        ));
    }
    if request.execution_boundary != ExecutionBoundary::IsolatedCell
        || !request.source_must_not_execute
        || !request.inspect_before_commit
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell requests must require isolated execution and inspect-before-commit",
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
            locally_authorized_capabilities: Vec::new(),
            isolated_cell_available: true,
            approval_staging_available: false,
        },
    );
    let pending_only_on_attachable_mediators = decision.decision == CapabilityPolicyDecision::Deny
        && !decision.reason_codes.is_empty()
        && decision
            .reason_codes
            .iter()
            .all(|reason| reason == "mandatory_mediator_missing");
    if decision.decision != CapabilityPolicyDecision::DelegateToIsolatedCell
        && !pending_only_on_attachable_mediators
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "capability policy denied cell request structure: {}",
                decision.reason_codes.join(", ")
            ),
        ));
    }
    Ok(())
}

fn validate_cell_request_for_execution(
    lease: &CapabilityCellLease,
    now_ms: u64,
) -> io::Result<Vec<BrokerLease>> {
    validate_cell_request_for_issue(&lease.request)?;
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
            BrokerResourceKind::RepositoryToken | BrokerResourceKind::ApiToken => {
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
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "direct network leases require the nftables/eBPF backend; use a Unix-socket gateway until it is active",
                ));
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
            locally_authorized_capabilities: Vec::new(),
            isolated_cell_available: true,
            approval_staging_available: false,
        },
    );
    if decision.decision != CapabilityPolicyDecision::DelegateToIsolatedCell {
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
        BrokerResourceKind::NetworkLease => lease
            .constraints
            .get("destination")
            .and_then(Value::as_str)
            .is_some_and(|destination| allowed_audiences.contains(destination)),
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
        "repository_api" | "external_api" | "secret" => MediationBoundary::ExternalApiGateway,
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
    create_restrictive_dir_all(&input_snapshot)?;
    let seccomp_profile = write_cell_seccomp_profile(&cell_root)?;
    let podman = tclone_podman();
    copy_capability_scope(&podman, source, lease, &input_snapshot)?;
    copy_path_all(&input_snapshot, &snapshot)?;

    let mut run_args = capability_cell_run_args(
        source,
        lease,
        &container_name,
        &input_snapshot,
        &snapshot,
        &broker_leases,
        &seccomp_profile,
        unix_millis()?,
    )?;
    run_args.extend(lease.command.iter().skip(1).map(OsString::from));
    let cleanup = TcloneContainerCleanup::new(&podman, &container_name);
    let started_at_ms = unix_millis()?;
    let mut child = Command::new(&podman).args(&run_args).spawn()?;
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
    drop(cleanup);
    let finished_at_ms = unix_millis()?;
    let (broker_effect_leases, broker_revocation_error) = match broker_cleanup.revoke() {
        Ok(leases) => (leases, None),
        Err(error) => (Vec::new(), Some(error)),
    };
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
    )?;
    if let Some(error) = broker_revocation_error {
        manifest.violations.push(EffectViolation {
            kind: "broker_lease_revocation_failed".to_string(),
            resource: lease.broker_lease_ids.join(","),
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
    let record = CapabilityCellRecord {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        operation_id: lease.operation_id.clone(),
        cell_id,
        lease_id: lease.lease_id.clone(),
        source_run_id: source.run_id.clone(),
        request: lease.request.clone(),
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
        OsString::from("none"),
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
    args.push(OsString::from(&lease.command[0]));
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
    args.push(OsString::from(&source.image));
    Ok(args)
}

fn capability_cell_apparmor_profile() -> io::Result<String> {
    let profile = env::var("GENSEE_TCLONE_CELL_APPARMOR_PROFILE")
        .unwrap_or_else(|_| "container-default".to_string());
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
) -> io::Result<()> {
    let paths = effective_read_paths(&lease.request)
        .into_iter()
        .chain(effective_write_paths(&lease.request))
        .collect::<BTreeSet<_>>();
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
                BrokerGatewayEffectKind::RepositoryRequest
                | BrokerGatewayEffectKind::ApiRequest
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

    Ok(EffectManifest {
        schema_version: EFFECT_MANIFEST_SCHEMA_VERSION,
        operation_id: lease.operation_id.clone(),
        source_run_id: source.run_id.clone(),
        cell_id: cell_id.to_string(),
        requested_capabilities: lease.request.capabilities.clone(),
        capabilities_used,
        files_read: Vec::new(),
        files_changed,
        network_connections,
        external_requests,
        secrets_accessed,
        processes_started: vec![ProcessEffect {
            executable: lease.command[0].clone(),
            argv_digest,
            pid: None,
            started_at_ms,
            finished_at_ms: Some(finished_at_ms),
            exit_code,
        }],
        outputs_proposed_for_promotion: outputs,
        promotions: Vec::new(),
        violations,
        telemetry_coverage: EffectTelemetryCoverage {
            filesystem_reads: TelemetryCoverage::Unavailable,
            filesystem_writes: TelemetryCoverage::Complete,
            network_connections: broker_coverage_for_capabilities(
                &lease.request,
                &[Capability::NetworkEgress, Capability::NetworkListen],
                broker_telemetry_required,
                broker_telemetry_complete,
            ),
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
            process_tree: TelemetryCoverage::Partial,
        },
        started_at_ms,
        finished_at_ms,
        exit_code,
        timed_out,
    })
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

fn path_is_in_scopes(path: &str, scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|scope| scope == "." || path == scope || path.starts_with(&format!("{scope}/")))
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
    if manifest.promotions.iter().any(|receipt| {
        receipt.paths.iter().any(|promoted| {
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
        manifest.promotions.push(PromotionReceipt {
            promotion_id: promotion_id.clone(),
            source_run_id: source.run_id.clone(),
            paths: selected.iter().map(|output| output.path.clone()).collect(),
            promoted_at_ms: unix_millis()?,
            approval_token_id: None,
        });
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
    if !record.request.inspect_before_commit
        || manifest.telemetry_coverage.filesystem_writes != TelemetryCoverage::Complete
        || !manifest.violations.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "promotion requires inspect-before-commit, complete write telemetry, and zero violations",
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
    if args.iter().any(|arg| arg == "--json") {
        let record: serde_json::Value = serde_json::from_str(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let manifest: EffectManifest = serde_json::from_str(&manifest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "record": record,
                "effect_manifest": manifest,
            }))?
        );
    } else {
        let parsed: CapabilityCellRecord = serde_json::from_str(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let manifest: EffectManifest = serde_json::from_str(&manifest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        println!("cell: {}", parsed.cell_id);
        println!("source: {}", parsed.source_run_id);
        println!("lease: {}", parsed.lease_id);
        println!(
            "exit: {:?} timed_out={}",
            parsed.exit_code, parsed.timed_out
        );
        println!("snapshot: {}", parsed.workspace_snapshot);
        println!("manifest: {}", parsed.effect_manifest);
        println!(
            "effects: {} changed path(s), {} promotion proposal(s), {} violation(s)",
            manifest.files_changed.len(),
            manifest.outputs_proposed_for_promotion.len(),
            manifest.violations.len()
        );
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
        BrokerResourceKind::RepositoryToken | BrokerResourceKind::ApiToken => {
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
            execution_boundary: ExecutionBoundary::IsolatedCell,
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
            source_must_not_execute: true,
            inspect_before_commit: true,
        }
    }

    fn source_record() -> TcloneRunRecord {
        TcloneRunRecord {
            run_id: "run_1".to_string(),
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
            request,
            command: vec!["true".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
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
            request: request(),
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 200,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
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
            request: request(),
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 200,
            consumed_at_ms: None,
            broker_lease_ids: Vec::new(),
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
        let mut gateway_request = CapabilityRequest::isolated(
            "read_repository_metadata",
            EffectScope::ReadOnly,
            vec![
                Capability::NetworkEgress,
                Capability::SecretUse,
                Capability::ProcessExecution,
            ],
        );
        gateway_request.scope.network_destinations = vec![NetworkDestinationScope {
            destination: "repo.example.test".to_string(),
            protocol: "https".to_string(),
            ports: vec![443],
        }];
        gateway_request.scope.secret_identities = vec![SecretIdentityScope {
            handle: "repo_reader".to_string(),
            identity: "repository-reader".to_string(),
            purpose: "read package metadata".to_string(),
        }];
        let cell_lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_gateway".to_string(),
            operation_id: "op_gateway".to_string(),
            cell_id: "cell_gateway".to_string(),
            source_run_id: "run_gateway".to_string(),
            request: gateway_request,
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 300,
            consumed_at_ms: None,
            broker_lease_ids: vec!["broker_gateway".to_string()],
        };
        let broker_lease = BrokerLease {
            protocol_version: gensee_crate_rules::capability_broker::BROKER_PROTOCOL_VERSION,
            lease_id: "broker_gateway".to_string(),
            operation_id: "op_gateway".to_string(),
            source_run_id: "run_gateway".to_string(),
            cell_id: Some("cell_gateway".to_string()),
            resource_kind: BrokerResourceKind::ApiToken,
            adapter_id: "repo_adapter".to_string(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["repository:one:read".to_string()],
            constraints: json!({ "gateway_kind": "external_api" }),
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
            target: "repo.example.test".to_string(),
            action: "read_package_metadata".to_string(),
            request_digest: format!("sha256:{}", "b".repeat(64)),
            protocol: None,
            port: None,
            response_status: Some(200),
            broker_handle_id: Some("repo_reader".to_string()),
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
            request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
        };
        let source = source_record();

        let args =
            capability_cell_run_args(&source, &lease, "cell", &root, &root, &[], &root, 1).unwrap();
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
            .any(|arg| arg == "apparmor=container-default"));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--entrypoint", "cargo"]));
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
            request: manifest_request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
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
    fn promotion_evidence_rejects_tampering_and_incomplete_telemetry() {
        let root = env::temp_dir().join(format!("gensee-cell-promotion-{}", Uuid::new_v4()));
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
            request: request(),
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
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
        )
        .unwrap();
        let record = CapabilityCellRecord {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            lease_id: "lease_1".to_string(),
            source_run_id: "run_1".to_string(),
            request: lease.request,
            command: lease.command,
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
        assert_eq!(
            validate_promotion_evidence(&record, &incomplete, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        fs::write(output.join("Cargo.lock"), "tampered").unwrap();
        assert_eq!(
            validate_promotion_evidence(&record, &manifest, "cell_1", "run_1", &root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
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
        cell_request.scope.write_paths = vec![".".to_string()];
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            cell_id: "cell_1".to_string(),
            source_run_id: "run_1".to_string(),
            request: cell_request,
            command: vec!["true".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
            broker_lease_ids: Vec::new(),
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
        )
        .unwrap();

        assert!(manifest
            .violations
            .iter()
            .any(|violation| violation.kind == "unsafe_symlink_output"));
        fs::remove_dir_all(root).ok();
    }
}
