use crate::*;
use gensee_crate_rules::capability::Capability;
use gensee_crate_rules::capability_policy::MediationBoundary;
use gensee_crate_rules::contract_catalog::ContractResolutionSource;
use gensee_crate_rules::network_boundary::{
    NetworkCapabilityEnvelope, NetworkEndpointGrant, NetworkProtocol,
};
#[cfg(target_os = "linux")]
use gensee_crate_rules::operation_contract::OperationNetworkEffect;
use gensee_crate_rules::operation_contract::{
    ContractAudit, ContractNetworkMode, ContractNetworkProtocol, OperationAdmissionEvidence,
    OperationContract, OperationEnforcementEvidence, OperationProcessEvidence,
    OperationPromotionEvidence, OperationRunManifest, ProductContract, StructuralProductEvidence,
    StructuralProductType,
};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_CONTRACT_BYTES: u64 = 1024 * 1024;
const SCAN_CHUNK_BYTES: usize = 64 * 1024;
const SCAN_MAX_DEPTH: usize = 64;
const SCAN_DEADLINE_SECONDS: u64 = 30;
const START_GATE_TIMEOUT_SECONDS: u64 = 15;
const BOUNDARY_CATALOG_TRUST_ANCHOR: &str = "/etc/gensee/catalog-root-public-key.hex";
const MAX_ADMITTED_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
struct BoundaryRunConfig {
    catalog_path: PathBuf,
    observation_path: PathBuf,
    inference_path: PathBuf,
    workspace: PathBuf,
    manifest_path: Option<PathBuf>,
    command: Vec<OsString>,
}

#[derive(Debug, Clone)]
struct ProductEntry {
    path: String,
    kind: &'static str,
    mode: u32,
    size: u64,
    digest: Option<String>,
}

pub(crate) fn handle_operation_boundary(args: Vec<OsString>) -> io::Result<()> {
    let (subcommand, rest) = args.split_first().ok_or_else(boundary_usage_error)?;
    match subcommand.to_str() {
        Some("catalog") => handle_contract_catalog(rest),
        Some("intent") => handle_intent_resolution(rest),
        Some("validate") => boundary_validate(rest),
        Some("audit") => boundary_audit(rest),
        Some("run") => boundary_run(BoundaryRunConfig::parse(rest)?),
        Some("--help" | "-h") => {
            print_boundary_usage();
            Ok(())
        }
        Some(other) => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("unknown boundary command: {other}"),
        )),
        None => Err(boundary_usage_error()),
    }
}

fn boundary_validate(args: &[OsString]) -> io::Result<()> {
    reject_unknown_options(args, &["--contract"], &["--json"])?;
    let path = required_path_arg(args, "--contract")?;
    let contract = read_contract(&path)?;
    let audit = contract.audit_for_platform(std::env::consts::OS);
    if !audit.valid {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid operation contract: {}", audit.errors.join("; ")),
        ));
    }
    if has_arg_named(args, "--json") {
        print_json(&audit)
    } else {
        println!("valid operation contract: {}", contract.contract_id);
        for warning in audit.warnings {
            eprintln!("gensee boundary: warning: {warning}");
        }
        Ok(())
    }
}

fn boundary_audit(args: &[OsString]) -> io::Result<()> {
    reject_unknown_options(args, &["--contract"], &["--json"])?;
    let path = required_path_arg(args, "--contract")?;
    let contract = read_contract(&path)?;
    let audit = contract.audit_for_platform(std::env::consts::OS);
    if has_arg_named(args, "--json") {
        print_json(&audit)
    } else {
        print_contract_audit(&audit);
        Ok(())
    }
}

fn print_contract_audit(audit: &ContractAudit) {
    println!("contract: {}", audit.contract_id);
    println!("valid: {}", audit.valid);
    println!("enforceable_on_platform: {}", audit.enforceable_on_platform);
    for error in &audit.errors {
        println!("error: {error}");
    }
    for warning in &audit.warnings {
        println!("warning: {warning}");
    }
}

impl BoundaryRunConfig {
    fn parse(args: &[OsString]) -> io::Result<Self> {
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .ok_or_else(boundary_usage_error)?;
        let options = &args[..separator];
        let command = args[separator + 1..].to_vec();
        if command.is_empty() {
            return Err(boundary_usage_error());
        }
        reject_unknown_options(
            options,
            &[
                "--catalog",
                "--observation",
                "--inference",
                "--workspace",
                "--manifest",
            ],
            &[],
        )?;
        Ok(Self {
            catalog_path: required_path_arg(options, "--catalog")?,
            observation_path: required_path_arg(options, "--observation")?,
            inference_path: required_path_arg(options, "--inference")?,
            workspace: optional_path_arg(options, "--workspace")?.unwrap_or(env::current_dir()?),
            manifest_path: optional_path_arg(options, "--manifest")?,
            command,
        })
    }
}

fn boundary_run(mut config: BoundaryRunConfig) -> io::Result<()> {
    validate_boundary_trust_anchor(boundary_catalog_trust_anchor())?;
    let admission = verify_and_resolve(
        &config.catalog_path,
        boundary_catalog_trust_anchor(),
        &config.observation_path,
        &config.inference_path,
        &config.command,
        unix_millis()?,
    )?;
    let contract = admission.contract.clone();
    let contract_bytes = serde_json::to_vec(&contract).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("cannot encode selected contract: {error}"),
        )
    })?;
    let audit = contract.audit_for_platform(std::env::consts::OS);
    if !audit.valid || !audit.enforceable_on_platform {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            format!(
                "contract cannot be enforced on this host: {}",
                audit
                    .errors
                    .iter()
                    .chain(audit.warnings.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ));
    }

    let original = fs::canonicalize(&config.workspace)?;
    if !fs::metadata(&original)?.is_dir() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "boundary workspace must be a directory",
        ));
    }
    let started_at_ms = unix_millis()?;
    let operation_id = format!("op_{}", uuid::Uuid::new_v4().simple());
    let source_run_id = format!("boundary_{}_{}", std::process::id(), started_at_ms);
    let staged = gensee_tmp_root()?.join(&source_run_id).join("workspace");
    copy_workspace(&original, &staged)?;
    let executable_snapshot = snapshot_admitted_executable(
        &admission.canonical_executable,
        &admission.executable_sha256,
        &staged
            .parent()
            .ok_or_else(|| io::Error::other("staged workspace has no operation root"))?
            .join("admitted-executable"),
    )?;
    config.command[0] = executable_snapshot.into_os_string();

    let mut operation = OperationSupervisor::prepare(
        &operation_id,
        &source_run_id,
        &contract.operation_class,
        operation_envelope(&contract),
        None,
    )?;
    if contract.execution.require_os_execution_binding
        && std::env::consts::OS == "linux"
        && operation.cgroup_path().is_none()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "required Linux cgroup identity is unavailable",
        ));
    }
    let mut network = BoundaryNetworkGuard::prepare(&contract, &operation_id)?;
    let start_gate = gensee_tmp_root()?.join(&source_run_id).join("start-gate");
    if let Some(parent) = start_gate.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut command = boundary_command(
        &contract,
        &source_run_id,
        operation.cgroup_path(),
        &original,
        &staged,
        &start_gate,
        &config.command,
    )?;
    command
        .current_dir(&staged)
        .env("GENSEE_OPERATION_ID", &operation_id)
        .env("GENSEE_RUN_ID", &source_run_id)
        .env("GENSEE_WORKSPACE", &staged)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = command.spawn()?;
    let root_pid = child.id();
    if let Err(error) = operation.activate(root_pid) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let root_start_time = local_process_start_time_ticks(root_pid).ok();
    if let Err(error) = write_atomic_nofollow(&start_gate, b"open\n", 0o600) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = operation.finish(None, false);
        return Err(error);
    }
    let execution_cgroup = operation.cgroup_path().map(Path::to_path_buf);
    let (status, timed_out) =
        operation.wait_for_child(&mut child, Some(contract.execution.max_runtime_seconds))?;
    let exit_code = status.code();
    let execution_subject_drained_before_release =
        drain_operation_execution_subject(root_pid, execution_cgroup.as_deref())?;
    let mut network_evidence = network.collect();
    network_evidence.os_execution_binding_established = root_start_time.is_some()
        && (std::env::consts::OS != "linux" || operation.cgroup_path().is_some());
    if contract.execution.require_os_execution_binding
        && !network_evidence.os_execution_binding_established
    {
        let _ = operation.finish(exit_code, timed_out);
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "required stable OS execution-subject binding could not be attested",
        ));
    }
    let allowed_packets = network_evidence
        .allowed_network_effects
        .iter()
        .map(|effect| effect.packets)
        .sum();
    let allowed_bytes = network_evidence
        .allowed_network_effects
        .iter()
        .map(|effect| effect.bytes)
        .sum();
    let denied_packets = network_evidence
        .denied_network_effects
        .iter()
        .map(|effect| effect.packets)
        .sum();
    let denied_bytes = network_evidence
        .denied_network_effects
        .iter()
        .map(|effect| effect.bytes)
        .sum();
    operation.record_network_usage(allowed_packets, allowed_bytes, denied_packets, denied_bytes)?;
    for error in &network_evidence.collection_errors {
        operation.record_boundary_violation("network_effect_collection_failed", error)?;
    }
    operation.finish(exit_code, timed_out)?;
    let release_attestation = operation.attestation()?;
    let process_group_drained = execution_subject_drained_before_release
        && (std::env::consts::OS != "linux"
            || release_attestation.cgroup_state
                == crate::operation_supervisor::OperationCgroupState::Released);
    let product = if process_group_drained {
        contract
            .product
            .as_ref()
            .map(|product| verify_structural_product(&staged, product))
            .transpose()?
    } else {
        None
    };
    let process_succeeded = status.success() && !timed_out;
    let structurally_eligible = process_succeeded
        && process_group_drained
        && product
            .as_ref()
            .is_none_or(|evidence| evidence.structurally_valid);
    // Structural evidence never establishes semantic correctness. A later
    // slice will accept an authenticated verifier receipt bound to this exact
    // product digest; until then this field is deliberately always false.
    let semantically_verified = false;
    let promotion_reason = if !process_succeeded {
        "producer did not complete successfully"
    } else if !process_group_drained {
        "producer process group did not terminate cleanly"
    } else if !structurally_eligible {
        "structural product verification failed"
    } else if contract
        .product
        .as_ref()
        .is_some_and(|product| product.semantic_verifier_profile.is_some())
    {
        "an authenticated semantic verifier receipt is still required"
    } else {
        "structural gate passed without a semantic safety claim; no trusted destination was configured, so nothing was promoted"
    };
    let manifest = OperationRunManifest {
        schema_version: 1,
        operation_id,
        source_run_id,
        contract_id: contract.contract_id,
        contract_digest: sha256_prefixed(&contract_bytes),
        command_digest: digest_command(&config.command),
        admission: OperationAdmissionEvidence {
            catalog_id: admission.resolution.catalog_id,
            catalog_version: admission.resolution.catalog_version,
            catalog_digest: admission.catalog_digest,
            observation_digest: admission.observation_digest,
            inference_digest: admission.inference_digest,
            analyzer_id: admission.resolution.analyzer_id,
            selected_operation_class: admission.resolution.selected_operation_class,
            confidence_bps: admission.resolution.confidence_bps,
            resolution_source: match admission.resolution.source {
                ContractResolutionSource::ProbabilisticInference => {
                    "probabilistic_inference".to_string()
                }
                ContractResolutionSource::ApprovedSafeDefault => {
                    "approved_safe_default".to_string()
                }
            },
            ambiguity_reason: admission.resolution.ambiguity_reason,
        },
        operation_record: operation.record_path().to_string_lossy().to_string(),
        original_workspace: original.to_string_lossy().to_string(),
        staged_workspace: staged.to_string_lossy().to_string(),
        enforcement: network_evidence,
        process: OperationProcessEvidence {
            root_pid,
            root_start_time,
            exit_code,
            timed_out,
            process_group_drained,
        },
        product,
        promotion: OperationPromotionEvidence {
            performed: false,
            structurally_eligible,
            semantically_verified,
            reason: promotion_reason.to_string(),
        },
        started_at_ms,
        finished_at_ms: unix_millis()?,
    };
    if let Some(path) = config.manifest_path {
        write_boundary_manifest(&path, &serde_json::to_vec_pretty(&manifest)?)?;
    }
    print_json(&manifest)?;
    if timed_out {
        Err(io::Error::new(
            ErrorKind::TimedOut,
            "operation exceeded its deadline",
        ))
    } else if !status.success() {
        Err(io::Error::other(format!(
            "operation exited with status {status}"
        )))
    } else if !manifest.promotion.structurally_eligible {
        Err(io::Error::new(
            ErrorKind::InvalidData,
            "operation product failed structural verification",
        ))
    } else {
        Ok(())
    }
}

fn boundary_catalog_trust_anchor() -> &'static Path {
    Path::new(BOUNDARY_CATALOG_TRUST_ANCHOR)
}

fn validate_boundary_trust_anchor(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        validate_root_owned_path(path, false, true)
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "boundary catalog trust anchor must be a regular non-symlink file",
            ));
        }
        Ok(())
    }
}

fn snapshot_admitted_executable(
    source: &Path,
    expected_sha256: &str,
    destination: &Path,
) -> io::Result<PathBuf> {
    let mut input = File::open(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ADMITTED_EXECUTABLE_BYTES {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "admitted executable must be a bounded regular file",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("executable snapshot has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o500);
    let mut output = options.open(destination)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("executable size overflow"))?;
        if total > MAX_ADMITTED_EXECUTABLE_BYTES {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "admitted executable exceeds the snapshot limit",
            ));
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    let observed = format!("sha256:{:x}", hasher.finalize());
    if observed != expected_sha256 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "admitted executable changed before it could be pinned",
        ));
    }
    output.sync_all()?;
    drop(output);
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500))?;
    File::open(parent)?.sync_all()?;
    Ok(destination.to_path_buf())
}

fn operation_envelope(contract: &OperationContract) -> OperationCapabilityEnvelope {
    let mut capabilities = vec![
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::ProcessExecution,
    ];
    if contract.capabilities.network.mode == ContractNetworkMode::AllowExact {
        capabilities.push(Capability::NetworkEgress);
    }
    let grants = contract
        .capabilities
        .network
        .allowed_endpoints
        .iter()
        .map(|endpoint| NetworkEndpointGrant {
            destination: endpoint.destination.clone(),
            protocol: match endpoint.protocol {
                ContractNetworkProtocol::Tcp => NetworkProtocol::Tcp,
                ContractNetworkProtocol::Udp => NetworkProtocol::Udp,
            },
            ports: endpoint.ports.clone(),
            expires_at_ms: None,
            lease_id: None,
        })
        .collect();
    OperationCapabilityEnvelope {
        capabilities,
        active_mediators: vec![
            MediationBoundary::FilesystemBoundary,
            MediationBoundary::NetworkBoundary,
        ],
        network: NetworkCapabilityEnvelope { grants },
        ..OperationCapabilityEnvelope::default()
    }
}

struct BoundaryNetworkGuard {
    #[cfg(target_os = "linux")]
    plan: Option<gensee_crate_linux::LinuxNftablesPlan>,
    #[cfg(target_os = "linux")]
    applied: bool,
    mode: ContractNetworkMode,
    boundary: String,
}

impl BoundaryNetworkGuard {
    fn prepare(contract: &OperationContract, operation_id: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let network = &contract.capabilities.network;
            let policy = gensee_crate_linux::LinuxNetworkPolicy {
                mode: match network.mode {
                    ContractNetworkMode::DenyAll => gensee_crate_linux::LinuxNetworkMode::DenyAll,
                    ContractNetworkMode::AllowExact => {
                        gensee_crate_linux::LinuxNetworkMode::AllowListed
                    }
                },
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: network
                    .allowed_endpoints
                    .iter()
                    .map(|endpoint| gensee_crate_linux::LinuxNetworkEndpoint {
                        destination: endpoint.destination.clone(),
                        protocol: match endpoint.protocol {
                            ContractNetworkProtocol::Tcp => {
                                gensee_crate_linux::LinuxNetworkProtocol::Tcp
                            }
                            ContractNetworkProtocol::Udp => {
                                gensee_crate_linux::LinuxNetworkProtocol::Udp
                            }
                        },
                        ports: endpoint.ports.clone(),
                    })
                    .collect(),
            };
            let config =
                gensee_crate_linux::LinuxNetworkEnforcementConfig::new(operation_id, policy);
            let plan = gensee_crate_linux::plan_nftables_policy(&config).nftables;
            gensee_crate_linux::validate_nftables_plan_for_apply(&plan)?;
            gensee_crate_linux::apply_nftables_script(&plan.script).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot install pre-execution network boundary: {error}"),
                )
            })?;
            return Ok(Self {
                plan: Some(plan),
                applied: true,
                mode: network.mode,
                boundary: "linux-cgroup-v2+nftables-pre-effect".to_string(),
            });
        }
        #[cfg(target_os = "macos")]
        {
            let _ = operation_id;
            return Ok(Self {
                mode: contract.capabilities.network.mode,
                boundary: "macos-seatbelt-deny-network-pre-effect".to_string(),
            });
        }
        #[allow(unreachable_code)]
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "operation network boundary is unavailable on this platform",
        ))
    }

    fn collect(&mut self) -> OperationEnforcementEvidence {
        #[cfg(target_os = "linux")]
        let mut allowed = Vec::new();
        #[cfg(not(target_os = "linux"))]
        let allowed = Vec::new();
        #[cfg(target_os = "linux")]
        let mut denied = Vec::new();
        #[cfg(not(target_os = "linux"))]
        let denied = Vec::new();
        #[cfg(target_os = "linux")]
        let mut errors = Vec::new();
        #[cfg(not(target_os = "linux"))]
        let errors = Vec::new();
        #[cfg(target_os = "linux")]
        if let Some(plan) = self.plan.as_ref() {
            match gensee_crate_linux::read_nftables_endpoint_events(plan) {
                Ok(events) => {
                    allowed.extend(events.into_iter().map(|event| OperationNetworkEffect {
                        destination: event.destination,
                        protocol: format!("{:?}", event.protocol).to_ascii_lowercase(),
                        ports: event.ports,
                        packets: event.packets,
                        bytes: event.bytes,
                        decision: "allow".to_string(),
                    }))
                }
                Err(error) => errors.push(format!("allowed counters: {error}")),
            }
            match gensee_crate_linux::read_nftables_block_events(plan) {
                Ok(events) => {
                    denied.extend(events.into_iter().map(|event| OperationNetworkEffect {
                        destination: event.destination.unwrap_or_else(|| "*".to_string()),
                        protocol: "any".to_string(),
                        ports: Vec::new(),
                        packets: event.packets,
                        bytes: event.bytes,
                        decision: "deny".to_string(),
                    }))
                }
                Err(error) => errors.push(format!("denied counters: {error}")),
            }
        }
        OperationEnforcementEvidence {
            os_execution_binding_established: true,
            execution_subject_kind: if std::env::consts::OS == "linux" {
                "pid_generation+cgroup_v2".to_string()
            } else {
                "pid_generation+seatbelt_process_tree".to_string()
            },
            network_mode: self.mode,
            network_boundary: self.boundary.clone(),
            network_effect_coverage: if std::env::consts::OS == "linux" {
                "aggregate_nftables_counters".to_string()
            } else {
                "enforced_without_attempt_telemetry".to_string()
            },
            allowed_network_effects: allowed,
            denied_network_effects: denied,
            collection_errors: errors,
        }
    }
}

impl Drop for BoundaryNetworkGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.applied {
            if let Some(plan) = self.plan.as_ref() {
                let _ = gensee_crate_linux::delete_nftables_table_if_exists(&plan.table_name);
            }
        }
    }
}

fn boundary_command(
    contract: &OperationContract,
    source_run_id: &str,
    cgroup_path: Option<&Path>,
    original: &Path,
    staged: &Path,
    start_gate: &Path,
    command: &[OsString],
) -> io::Result<Command> {
    let (program, args) = command.split_first().ok_or_else(boundary_usage_error)?;
    let boundary_executable = env::current_exe()?;
    let mut gated_args = vec![
        OsString::from("__boundary-exec"),
        OsString::from("--gate"),
        start_gate.as_os_str().to_os_string(),
        OsString::from("--write-root"),
        staged.as_os_str().to_os_string(),
        OsString::from("--"),
        program.clone(),
    ];
    gated_args.extend_from_slice(args);
    #[cfg(target_os = "linux")]
    {
        let _ = (contract, source_run_id, original, staged);
        let cgroup = cgroup_path.ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "operation cgroup is unavailable",
            )
        })?;
        let mut wrapped = Command::new(env::current_exe()?);
        wrapped
            .arg("__linux-exec")
            .arg("--cgroup-path")
            .arg(cgroup)
            .arg("--")
            .arg(&boundary_executable)
            .args(&gated_args);
        return Ok(wrapped);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = cgroup_path;
        if contract.capabilities.network.mode != ContractNetworkMode::DenyAll {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "macOS v1 supports deny_all network mode only",
            ));
        }
        let dir = gensee_tmp_root()?.join(source_run_id);
        fs::create_dir_all(&dir)?;
        let profile_path = dir.join("operation-boundary.sb");
        let profile = format!(
            "(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath \"{}\"))\n(allow file-write* (subpath \"{}\"))\n",
            sbpl_escape(original),
            sbpl_escape(staged)
        );
        fs::write(&profile_path, profile)?;
        let mut wrapped = Command::new("/usr/bin/sandbox-exec");
        wrapped
            .arg("-f")
            .arg(profile_path)
            .arg(&boundary_executable)
            .args(&gated_args);
        return Ok(wrapped);
    }
    #[allow(unreachable_code)]
    {
        let _ = (contract, source_run_id, cgroup_path, original, staged);
        let mut direct = Command::new(&boundary_executable);
        direct.args(&gated_args);
        Ok(direct)
    }
}

pub(crate) fn boundary_exec_wrapper(args: Vec<OsString>) -> io::Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(boundary_usage_error)?;
    let gate = optional_path_arg(&args[..separator], "--gate")?.ok_or_else(boundary_usage_error)?;
    let write_root =
        optional_path_arg(&args[..separator], "--write-root")?.ok_or_else(boundary_usage_error)?;
    reject_unknown_options(&args[..separator], &["--gate", "--write-root"], &[])?;
    let command = &args[separator + 1..];
    let (program, command_args) = command.split_first().ok_or_else(boundary_usage_error)?;
    #[cfg(unix)]
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(START_GATE_TIMEOUT_SECONDS);
    loop {
        match read_bounded_regular_file(&gate, 16) {
            Ok(contents) if contents == b"open\n" => break,
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "operation start gate contained an invalid acknowledgement",
                ))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "operation start gate was not opened before its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(&gate)?;
    #[cfg(target_os = "linux")]
    gensee_crate_linux::apply_landlock_write_sandbox(&[write_root.to_string_lossy().to_string()])?;
    #[cfg(not(target_os = "linux"))]
    let _ = write_root;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = Command::new(program).args(command_args).exec();
        Err(error)
    }
    #[cfg(not(unix))]
    {
        let status = Command::new(program).args(command_args).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(not(target_os = "linux"))]
fn drain_operation_process_group(root_pid: u32) -> io::Result<bool> {
    #[cfg(unix)]
    {
        let group = -i32::try_from(root_pid)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid operation PID"))?;
        let killed = unsafe { libc::kill(group, libc::SIGKILL) };
        if killed != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(true);
            }
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let result = unsafe { libc::kill(group, 0) };
            if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Ok(true);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(false)
    }
    #[cfg(not(unix))]
    {
        let _ = root_pid;
        Ok(false)
    }
}

fn drain_operation_execution_subject(
    root_pid: u32,
    cgroup_path: Option<&Path>,
) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let _ = root_pid;
        let cgroup_path = cgroup_path.ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "owned operation cgroup disappeared before teardown",
            )
        })?;
        gensee_crate_linux::kill_and_drain_agent_cgroup(cgroup_path, Duration::from_secs(2))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cgroup_path;
        drain_operation_process_group(root_pid)
    }
}

fn verify_structural_product(
    workspace: &Path,
    contract: &ProductContract,
) -> io::Result<StructuralProductEvidence> {
    let root = workspace.join(&contract.path);
    let deadline = Instant::now() + Duration::from_secs(SCAN_DEADLINE_SECONDS);
    let mut entries = Vec::new();
    let mut bytes = 0_u64;
    let mut violations = Vec::new();
    scan_product(
        &root,
        &root,
        contract,
        0,
        deadline,
        &mut entries,
        &mut bytes,
        &mut violations,
    )?;
    match contract.kind {
        StructuralProductType::Blob
        | StructuralProductType::WorkspacePatch
        | StructuralProductType::StructuredResult => {
            if entries.len() != 1 || entries[0].kind != "file" {
                violations.push("product type requires exactly one regular file".to_string());
            }
        }
        _ if entries
            .first()
            .is_none_or(|entry| entry.kind != "directory") =>
        {
            violations.push("product type requires a directory root".to_string());
        }
        _ => {}
    }
    if contract.kind == StructuralProductType::StructuredResult && violations.is_empty() {
        let value = read_bounded_regular_file(&root, contract.max_bytes)?;
        let observed_digest = sha256_prefixed(&value);
        if entries.first().and_then(|entry| entry.digest.as_deref())
            != Some(observed_digest.as_str())
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "structured result changed between hashing and parsing",
            ));
        } else if serde_json::from_slice::<serde_json::Value>(&value).is_err() {
            violations.push("structured_result is not valid JSON".to_string());
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let digest = digest_product_entries(contract.kind, &entries);
    Ok(StructuralProductEvidence {
        kind: contract.kind,
        path: contract.path.clone(),
        digest,
        entries: entries.len() as u64,
        bytes,
        structurally_valid: violations.is_empty(),
        semantic_status: contract
            .semantic_verifier_profile
            .as_ref()
            .map(|profile| format!("receipt_required:{profile}"))
            .unwrap_or_else(|| "not_claimed".to_string()),
        violations,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_product(
    root: &Path,
    path: &Path,
    contract: &ProductContract,
    depth: usize,
    deadline: Instant,
    entries: &mut Vec<ProductEntry>,
    bytes: &mut u64,
    violations: &mut Vec<String>,
) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "product scan timed out",
        ));
    }
    if depth > SCAN_MAX_DEPTH || entries.len() as u64 >= contract.max_entries {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "product exceeds its depth or entry budget",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    let relative = path.strip_prefix(root).unwrap_or(path);
    let relative = if relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        relative.to_string_lossy().to_string()
    };
    #[cfg(unix)]
    let (mode, links) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.mode(), metadata.nlink())
    };
    #[cfg(not(unix))]
    let mode = 0;
    #[cfg(not(unix))]
    let links = 1;
    #[cfg(unix)]
    if mode & 0o6022 != 0 {
        violations.push(format!(
            "unsafe set-id or group/world-writable mode {:o}: {}",
            mode & 0o7777,
            path.display()
        ));
    }
    if metadata.file_type().is_symlink() {
        entries.push(ProductEntry {
            path: relative,
            kind: "symlink",
            mode,
            size: 0,
            digest: None,
        });
        if contract.reject_symlinks {
            violations.push(format!("symlink is forbidden: {}", path.display()));
        }
    } else if metadata.is_file() {
        if links != 1 {
            violations.push(format!(
                "hard-linked regular file is forbidden: {}",
                path.display()
            ));
        }
        *bytes = bytes.saturating_add(metadata.len());
        if *bytes > contract.max_bytes {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "product exceeds its byte budget",
            ));
        }
        entries.push(ProductEntry {
            path: relative,
            kind: "file",
            mode,
            size: metadata.len(),
            digest: Some(hash_regular_file(path, contract.max_bytes, deadline)?),
        });
    } else if metadata.is_dir() {
        entries.push(ProductEntry {
            path: relative,
            kind: "directory",
            mode,
            size: 0,
            digest: None,
        });
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            scan_product(
                root,
                &child.path(),
                contract,
                depth + 1,
                deadline,
                entries,
                bytes,
                violations,
            )?;
        }
    } else {
        entries.push(ProductEntry {
            path: relative,
            kind: "special",
            mode,
            size: 0,
            digest: None,
        });
        if contract.reject_special_files {
            violations.push(format!("special object is forbidden: {}", path.display()));
        }
    }
    Ok(())
}

fn hash_regular_file(path: &Path, max_bytes: u64, deadline: Instant) -> io::Result<String> {
    let before = fs::metadata(path)?;
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; SCAN_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "product hashing timed out",
            ));
        }
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > max_bytes {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "file exceeds byte budget",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    let after = fs::metadata(path)?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "product changed while being verified",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
            || before.nlink() != after.nlink()
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "product file identity changed while being verified",
            ));
        }
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn digest_product_entries(kind: StructuralProductType, entries: &[ProductEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}\n", kind).as_bytes());
    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.kind.as_bytes());
        hasher.update([0]);
        hasher.update(entry.mode.to_be_bytes());
        hasher.update(entry.size.to_be_bytes());
        if let Some(digest) = &entry.digest {
            hasher.update(digest.as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn digest_command(command: &[OsString]) -> String {
    let mut hasher = Sha256::new();
    for arg in command {
        hasher.update(arg.to_string_lossy().as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn read_contract(path: &Path) -> io::Result<OperationContract> {
    serde_json::from_slice(&read_bounded_regular_file(path, MAX_CONTRACT_BYTES)?).map_err(|error| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid contract JSON: {error}"),
        )
    })
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "{} must be a bounded regular non-symlink file",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "file exceeds byte limit",
        ));
    }
    Ok(bytes)
}

fn write_boundary_manifest(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "manifest path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "manifest parent must be an existing non-symlink directory",
        ));
    }
    let temporary = parent.join(format!(
        ".gensee-boundary-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn required_path_arg(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    optional_path_arg(args, name)?
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, format!("missing required {name}")))
}

fn optional_path_arg(args: &[OsString], name: &str) -> io::Result<Option<PathBuf>> {
    let mut found = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == name {
            if found.is_some() || index + 1 >= args.len() {
                return Err(boundary_usage_error());
            }
            found = Some(PathBuf::from(&args[index + 1]));
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(found)
}

fn has_arg_named(args: &[OsString], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn reject_unknown_options(args: &[OsString], valued: &[&str], flags: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(boundary_usage_error)?;
        if valued.contains(&value) {
            if index + 1 >= args.len() {
                return Err(boundary_usage_error());
            }
            index += 2;
        } else if flags.contains(&value) {
            index += 1;
        } else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unknown boundary option: {value}"),
            ));
        }
    }
    Ok(())
}

fn boundary_usage_error() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidInput,
        "usage: gensee boundary <catalog|validate|audit|run> ...",
    )
}

fn print_boundary_usage() {
    println!(
        "gensee boundary\n\nUSAGE:\n  gensee boundary catalog sign --catalog <catalog.json> --key <seed.hex> --key-id <id> --output <signed.json>\n  gensee boundary catalog verify --catalog <signed.json> --trusted-key <public.hex> [--json]\n  gensee boundary intent observe|resolve ...\n  gensee boundary validate --contract <contract.json> [--json]\n  gensee boundary audit --contract <contract.json> [--json]\n  sudo gensee boundary run --catalog <signed.json> --observation <observation.json> --inference <signed-inference.json> [--workspace <dir>] [--manifest <manifest.json>] -- <command> [args...]\n\nThe enforcing runtime pins its catalog trust anchor at /etc/gensee/catalog-root-public-key.hex; callers cannot override it."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use gensee_crate_rules::operation_contract::{
        ContractCapabilities, ContractNetworkCapability, ExecutionContract,
        OPERATION_CONTRACT_SCHEMA_VERSION,
    };

    fn product(kind: StructuralProductType, path: &str) -> ProductContract {
        ProductContract {
            kind,
            path: path.to_string(),
            max_bytes: 1024 * 1024,
            max_entries: 128,
            reject_symlinks: true,
            reject_special_files: true,
            semantic_verifier_profile: None,
        }
    }

    #[test]
    fn structured_product_is_hashed_without_semantic_claim() {
        let root = std::env::temp_dir().join(format!(
            "gensee-boundary-product-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(root.join("out")).unwrap();
        fs::write(root.join("out/result.json"), br#"{"ok":true}"#).unwrap();
        let evidence = verify_structural_product(
            &root,
            &product(StructuralProductType::StructuredResult, "out/result.json"),
        )
        .unwrap();
        assert!(evidence.structurally_valid);
        assert_eq!(evidence.semantic_status, "not_claimed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn product_rejects_symlinks_and_invalid_json() {
        let root = std::env::temp_dir().join(format!(
            "gensee-boundary-product-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(root.join("tree")).unwrap();
        fs::write(root.join("tree/value"), b"not-json").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("value", root.join("tree/link")).unwrap();
        let tree = verify_structural_product(
            &root,
            &product(StructuralProductType::DirectoryTree, "tree"),
        )
        .unwrap();
        #[cfg(unix)]
        assert!(!tree.structurally_valid);
        let structured = verify_structural_product(
            &root,
            &product(StructuralProductType::StructuredResult, "tree/value"),
        )
        .unwrap();
        assert!(!structured.structurally_valid);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn product_rejects_unsafe_modes_and_hardlinks() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "gensee-boundary-product-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(root.join("tree")).unwrap();
        let file = root.join("tree/value");
        fs::write(&file, b"value").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        fs::hard_link(&file, root.join("tree/alias")).unwrap();
        let evidence = verify_structural_product(
            &root,
            &product(StructuralProductType::DirectoryTree, "tree"),
        )
        .unwrap();
        assert!(!evidence.structurally_valid);
        assert!(evidence
            .violations
            .iter()
            .any(|violation| violation.contains("unsafe set-id")));
        assert!(evidence
            .violations
            .iter()
            .any(|violation| violation.contains("hard-linked")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn run_parser_requires_explicit_command_boundary() {
        let args = vec![
            OsString::from("--catalog"),
            OsString::from("catalog.json"),
            OsString::from("--observation"),
            OsString::from("observation.json"),
            OsString::from("--inference"),
            OsString::from("inference.json"),
            OsString::from("--"),
            OsString::from("echo"),
        ];
        assert!(BoundaryRunConfig::parse(&args).is_ok());
        assert!(BoundaryRunConfig::parse(&args[..6]).is_err());
        let mut caller_selected_anchor = args.clone();
        caller_selected_anchor.splice(
            2..2,
            [
                OsString::from("--trusted-key"),
                OsString::from("attacker.hex"),
            ],
        );
        assert!(BoundaryRunConfig::parse(&caller_selected_anchor).is_err());
    }

    #[test]
    fn admitted_executable_snapshot_is_content_bound() {
        let root = std::env::temp_dir().join(format!(
            "gensee-boundary-executable-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let snapshot = root.join("private/snapshot");
        fs::write(&source, b"#!/bin/sh\nprintf original\\n\n").unwrap();
        let expected = sha256_prefixed(&fs::read(&source).unwrap());
        snapshot_admitted_executable(&source, &expected, &snapshot).unwrap();
        fs::write(&source, b"#!/bin/sh\nprintf replaced\\n\n").unwrap();
        assert_eq!(sha256_prefixed(&fs::read(&snapshot).unwrap()), expected);
        assert_ne!(fs::read(&snapshot).unwrap(), fs::read(&source).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contract_fixture_remains_generic() {
        let contract = OperationContract {
            schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
            contract_id: "transform-v1".to_string(),
            operation_class: "data_transform".to_string(),
            execution: ExecutionContract::default(),
            capabilities: ContractCapabilities {
                network: ContractNetworkCapability::default(),
            },
            product: Some(product(
                StructuralProductType::StructuredResult,
                "out/result.json",
            )),
        };
        assert!(contract.audit_for_platform("linux").valid);
        let json = serde_json::to_string(&contract).unwrap();
        assert!(!json.contains("package"));
        assert!(!json.contains("browser"));
    }
}
