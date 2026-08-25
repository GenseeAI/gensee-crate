use crate::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::SignedContractCatalog;
use gensee_crate_rules::operation_contract::{OperationManifestSignature, OperationRunManifest};
use gensee_crate_rules::semantic_verifier::{
    SemanticVerdict, SignedVerifierReceipt, VerifierIsolationClaims, VerifierReceiptClaims,
    VerifierReceiptSignature, VerifierRequest, SEMANTIC_VERIFIER_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Child;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolatedVerifierConfig {
    verifier_id: String,
    policy_version: String,
    executable: String,
    executable_sha256: String,
    #[serde(default)]
    args: Vec<String>,
    working_directory: String,
    max_runtime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierProgramResult {
    verdict: SemanticVerdict,
    reason_codes: Vec<String>,
    validation_effect_manifest_digest: String,
}

const MAX_VERIFIER_TTL_SECONDS: u64 = 300;
const OPERATION_MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"gensee-operation-run-manifest-v1\0";
const OPERATION_MANIFEST_SIGNING_KEY: &str = "/etc/gensee/operation-manifest-signing-key.hex";
const OPERATION_MANIFEST_PUBLIC_KEY: &str = "/etc/gensee/operation-manifest-public-key.hex";
const MAX_VERIFIER_RESULT_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn handle_semantic_verifier(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(verifier_usage_error)?;
    match command.to_str() {
        Some("request") => create_request(rest),
        Some("run") => run_isolated_verifier(rest),
        Some("attest") => attest_receipt(rest),
        Some("sign") => sign_receipt(rest),
        Some("verify") => verify_receipt_command(rest),
        Some("--help" | "-h") => {
            print_verifier_usage();
            Ok(())
        }
        _ => Err(verifier_usage_error()),
    }
}

fn run_isolated_verifier(args: &[OsString]) -> io::Result<()> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "isolated semantic verifiers require Linux Landlock/seccomp or macOS Seatbelt",
        ));
    }
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--request",
            "--config",
            "--verifier-key",
            "--output",
        ],
        &[],
    )?;
    let catalog: SignedContractCatalog = read_catalog_json(
        &required_path(args, "--catalog")?,
        "signed contract catalog",
    )?;
    let now = unix_millis()?;
    verify_signed_catalog(&catalog, &required_path(args, "--trusted-key")?, now)?;
    let request: VerifierRequest =
        read_catalog_json(&required_path(args, "--request")?, "verifier request")?;
    request.validate(now).map_err(invalid_input)?;
    let config: IsolatedVerifierConfig = read_catalog_json(
        &required_path(args, "--config")?,
        "isolated verifier config",
    )?;
    let config_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&config).map_err(json_error)?)
    );
    let approved = approved_verifier(&catalog, &config.verifier_id)?;
    if !approved.require_isolation
        || !approved.profiles.contains(&request.verifier_profile)
        || !approved.policy_versions.contains(&config.policy_version)
        || approved.isolated_runtime_config_digest.as_deref() != Some(&config_digest)
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "isolated verifier is not approved for this request",
        ));
    }
    validate_isolated_verifier_config(&config)?;
    let key = read_signing_key(&required_path(args, "--verifier-key")?)?;
    if hex::encode(key.verifying_key().as_bytes()) != approved.public_key_hex.to_lowercase() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier key is not catalog-approved",
        ));
    }
    let program_result = execute_isolated_verifier(&config, &request)?;
    if program_result.reason_codes.is_empty()
        || program_result.reason_codes.len() > 128
        || !valid_verifier_digest(&program_result.validation_effect_manifest_digest)
    {
        return Err(invalid_data("isolated verifier result is malformed"));
    }
    let request_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&request).map_err(json_error)?)
    );
    let claims = VerifierReceiptClaims {
        schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
        receipt_id: format!("receipt_{}", uuid::Uuid::new_v4().simple()),
        request_digest,
        nonce: request.nonce.clone(),
        operation_id: request.operation_id.clone(),
        contract_id: request.contract_id.clone(),
        contract_digest: request.contract_digest.clone(),
        product_type: request.product_type,
        product_digest: request.product_digest.clone(),
        verifier_profile: request.verifier_profile.clone(),
        verifier_id: config.verifier_id.clone(),
        policy_version: config.policy_version.clone(),
        verdict: program_result.verdict,
        reason_codes: program_result.reason_codes,
        validation_effect_manifest_digest: program_result.validation_effect_manifest_digest,
        isolation: Some(VerifierIsolationClaims {
            profile: isolation_profile().into(),
            executable_digest: config.executable_sha256.clone(),
            runtime_config_digest: config_digest,
            network_denied: true,
            process_creation_denied: true,
            filesystem_mutation_denied: true,
        }),
        issued_at_ms: unix_millis()?,
        expires_at_ms: request.expires_at_ms,
    };
    claims
        .validate_for_request(&request, &claims.request_digest, unix_millis()?)
        .map_err(invalid_input)?;
    let encoded = serde_json::to_vec(&claims).map_err(json_error)?;
    write_json(
        &required_path(args, "--output")?,
        &SignedVerifierReceipt {
            claims,
            signature: VerifierReceiptSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(key.sign(&encoded).to_bytes()),
            },
        },
    )
}

fn validate_isolated_verifier_config(config: &IsolatedVerifierConfig) -> io::Result<()> {
    if !safe_catalog_token(&config.verifier_id)
        || !safe_catalog_token(&config.policy_version)
        || config.max_runtime_seconds == 0
        || config.max_runtime_seconds > 300
        || config.args.len() > 64
    {
        return Err(invalid_input("isolated verifier config is malformed"));
    }
    let executable = Path::new(&config.executable);
    let working = Path::new(&config.working_directory);
    if !executable.is_absolute() || !working.is_absolute() {
        return Err(invalid_input("isolated verifier paths must be absolute"));
    }
    let metadata = fs::symlink_metadata(executable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_input("verifier executable must be a regular file"));
    }
    let digest = hash_verifier_file(executable, 1024 * 1024 * 1024)?;
    if digest != config.executable_sha256 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier executable digest changed",
        ));
    }
    let working_metadata = fs::symlink_metadata(working)?;
    if !working_metadata.is_dir() || working_metadata.file_type().is_symlink() {
        return Err(invalid_input("verifier working directory must be real"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if unsafe { libc::geteuid() } == 0
            && (metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || working_metadata.uid() != 0
                || working_metadata.mode() & 0o022 != 0)
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "verifier executable or working directory is not root-controlled",
            ));
        }
    }
    Ok(())
}

fn execute_isolated_verifier(
    config: &IsolatedVerifierConfig,
    request: &VerifierRequest,
) -> io::Result<VerifierProgramResult> {
    execute_isolated_verifier_at(config, request, &default_root()?)
}

fn execute_isolated_verifier_at(
    config: &IsolatedVerifierConfig,
    request: &VerifierRequest,
    state_root: &Path,
) -> io::Result<VerifierProgramResult> {
    let root = state_root
        .join("isolated-verifiers")
        .join(format!("run_{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let _runtime = VerifierRuntimeGuard(root.clone());
    let snapshot = root.join("verifier-executable");
    fs::copy(&config.executable, &snapshot)?;
    #[cfg(unix)]
    fs::set_permissions(
        &snapshot,
        std::os::unix::fs::PermissionsExt::from_mode(0o500),
    )?;
    if hash_verifier_file(&snapshot, 1024 * 1024 * 1024)? != config.executable_sha256 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier executable changed while creating its private snapshot",
        ));
    }
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("/usr/bin/sandbox-exec");
        c.args([
            "-p",
            "(version 1)(allow default)(deny network*)(deny process-fork)(deny file-write*)",
            "--",
            snapshot
                .to_str()
                .ok_or_else(|| invalid_input("verifier snapshot path is not valid UTF-8"))?,
        ]);
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = Command::new(&snapshot);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut command = Command::new(&snapshot);
    command
        .args(&config.args)
        .current_dir(&config.working_directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            close_inherited_verifier_fds();
            #[cfg(target_os = "linux")]
            {
                gensee_crate_linux::apply_landlock_read_only_sandbox()?;
                gensee_crate_linux::install_seccomp_filter(&verifier_seccomp_profile())?;
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    let mut child = VerifierChildGuard::new(child);
    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| invalid_data("isolated verifier stdout pipe is missing"))?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_VERIFIER_RESULT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    });
    if let Some(mut input) = child.child_mut().stdin.take() {
        serde_json::to_writer(&mut input, request).map_err(json_error)?;
    }
    let deadline = Instant::now() + Duration::from_secs(config.max_runtime_seconds);
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "isolated verifier timed out",
            ));
        }
        if let Some(status) = child.child_mut().try_wait()? {
            child.mark_reaped();
            if !status.success() {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "isolated verifier failed",
                ));
            }
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "isolated verifier completed after its deadline",
        ));
    }
    let bytes = reader
        .join()
        .map_err(|_| invalid_data("isolated verifier output reader panicked"))??;
    if bytes.len() as u64 > MAX_VERIFIER_RESULT_BYTES {
        return Err(invalid_data("isolated verifier result exceeds byte limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid isolated verifier result JSON: {error}")))
}

struct VerifierRuntimeGuard(PathBuf);

impl Drop for VerifierRuntimeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct VerifierChildGuard {
    child: Child,
    reaped: bool,
}

impl VerifierChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for VerifierChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            terminate_verifier_group(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(unix)]
fn close_inherited_verifier_fds() {
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(3, 65536);
    for fd in 3..limit {
        unsafe {
            libc::fcntl(fd as i32, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
}
#[cfg(unix)]
fn terminate_verifier_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}
#[cfg(not(unix))]
fn terminate_verifier_group(_pid: u32) {}
#[cfg(target_os = "linux")]
fn verifier_seccomp_profile() -> gensee_crate_linux::LinuxSeccompProfile {
    use gensee_crate_linux::{
        LinuxSeccompAction, LinuxSeccompDeniedSyscall, LinuxSeccompProfile,
        LinuxSeccompSyscallGroup,
    };
    let mut denied = Vec::new();
    for name in [
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "sendmsg",
        "recvfrom",
        "recvmsg",
        "io_uring_setup",
    ] {
        denied.push(LinuxSeccompDeniedSyscall {
            name: name.into(),
            group: LinuxSeccompSyscallGroup::Network,
            reason: "semantic verifier has no network authority".into(),
        });
    }
    for name in ["clone", "clone3", "fork", "vfork"] {
        denied.push(LinuxSeccompDeniedSyscall {
            name: name.into(),
            group: LinuxSeccompSyscallGroup::ProcessCreation,
            reason: "semantic verifier cannot create descendants".into(),
        });
    }
    LinuxSeccompProfile {
        default_action: LinuxSeccompAction::Allow,
        denied_syscalls: denied,
    }
}
fn isolation_profile() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux_landlock_seccomp_no_write_no_network_no_fork_v1"
    } else if cfg!(target_os = "macos") {
        "macos_seatbelt_no_write_no_network_no_fork_v1"
    } else {
        "unsupported"
    }
}
fn hash_verifier_file(path: &Path, max: u64) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max {
        return Err(invalid_input("verifier executable exceeds limit"));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
fn valid_verifier_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn attest_receipt(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--request",
            "--verifier-id",
            "--policy-version",
            "--verdict",
            "--reason",
            "--effects-digest",
            "--verifier-key",
            "--output",
        ],
        &[],
    )?;
    let request: VerifierRequest =
        read_catalog_json(&required_path(args, "--request")?, "verifier request")?;
    let now_ms = unix_millis()?;
    request.validate(now_ms).map_err(invalid_input)?;
    let verdict = match required_string(args, "--verdict")?.as_str() {
        "accept" => SemanticVerdict::Accept,
        "reject" => SemanticVerdict::Reject,
        "indeterminate" => SemanticVerdict::Indeterminate,
        _ => return Err(invalid_input("invalid semantic verdict")),
    };
    let claims = VerifierReceiptClaims {
        schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
        receipt_id: format!("receipt_{}", uuid::Uuid::new_v4().simple()),
        request_digest: format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&request).map_err(json_error)?)
        ),
        nonce: request.nonce.clone(),
        operation_id: request.operation_id.clone(),
        contract_id: request.contract_id.clone(),
        contract_digest: request.contract_digest.clone(),
        product_type: request.product_type,
        product_digest: request.product_digest.clone(),
        verifier_profile: request.verifier_profile.clone(),
        verifier_id: required_string(args, "--verifier-id")?,
        policy_version: required_string(args, "--policy-version")?,
        verdict,
        reason_codes: vec![required_string(args, "--reason")?],
        validation_effect_manifest_digest: required_string(args, "--effects-digest")?,
        isolation: None,
        issued_at_ms: now_ms,
        expires_at_ms: request.expires_at_ms,
    };
    claims
        .validate_for_request(&request, &claims.request_digest, now_ms)
        .map_err(invalid_input)?;
    let key = read_signing_key(&required_path(args, "--verifier-key")?)?;
    let bytes = serde_json::to_vec(&claims).map_err(json_error)?;
    let receipt = SignedVerifierReceipt {
        claims,
        signature: VerifierReceiptSignature {
            algorithm: "ed25519".into(),
            signature_hex: hex::encode(key.sign(&bytes).to_bytes()),
        },
    };
    write_json(&required_path(args, "--output")?, &receipt)
}

fn create_request(args: &[OsString]) -> io::Result<()> {
    reject_options(args, &["--manifest", "--ttl-seconds", "--output"], &[])?;
    let manifest: OperationRunManifest = read_catalog_json(
        &required_path(args, "--manifest")?,
        "operation run manifest",
    )?;
    verify_operation_manifest(&manifest)?;
    let product = manifest
        .product
        .as_ref()
        .ok_or_else(|| invalid_input("operation manifest contains no staged product"))?;
    if !product.structurally_valid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "semantic verification cannot start for a structurally invalid product",
        ));
    }
    let profile = product
        .semantic_status
        .strip_prefix("receipt_required:")
        .ok_or_else(|| {
            invalid_input("operation contract did not request a semantic verifier profile")
        })?;
    let ttl = required_string(args, "--ttl-seconds")?
        .parse::<u64>()
        .map_err(|_| invalid_input("invalid verifier TTL"))?;
    if !(1..=MAX_VERIFIER_TTL_SECONDS).contains(&ttl) {
        return Err(invalid_input("verifier TTL exceeds the host ceiling"));
    }
    let issued_at_ms = unix_millis()?;
    let request = VerifierRequest {
        schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
        request_id: format!("verify_{}", uuid::Uuid::new_v4().simple()),
        nonce: format!("nonce_{}", uuid::Uuid::new_v4().simple()),
        operation_id: manifest.operation_id,
        contract_id: manifest.contract_id,
        contract_digest: manifest.contract_digest,
        product_type: product.kind,
        product_digest: product.digest.clone(),
        verifier_profile: profile.to_string(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl.saturating_mul(1_000)),
    };
    request.validate(issued_at_ms).map_err(invalid_input)?;
    write_json(&required_path(args, "--output")?, &request)
}

pub(crate) fn sign_operation_manifest(manifest: &mut OperationRunManifest) -> io::Result<()> {
    let path = Path::new(OPERATION_MANIFEST_SIGNING_KEY);
    #[cfg(unix)]
    validate_root_owned_path(path, false, true)?;
    let key = read_signing_key(path)?;
    sign_operation_manifest_with_key(manifest, &key)
}

pub(crate) fn sign_operation_manifest_with_key(
    manifest: &mut OperationRunManifest,
    key: &ed25519_dalek::SigningKey,
) -> io::Result<()> {
    manifest.host_signature = None;
    let bytes = operation_manifest_signing_bytes(manifest)?;
    manifest.host_signature = Some(OperationManifestSignature {
        algorithm: "ed25519".to_string(),
        signature_hex: hex::encode(key.sign(&bytes).to_bytes()),
    });
    Ok(())
}

pub(crate) fn verify_operation_manifest(manifest: &OperationRunManifest) -> io::Result<()> {
    let path = Path::new(OPERATION_MANIFEST_PUBLIC_KEY);
    #[cfg(unix)]
    validate_root_owned_path(path, false, false)?;
    let encoded = read_nofollow_to_string(path)?;
    let public_key = decode_hex_array::<32>(encoded.trim(), "operation manifest public key")?;
    verify_operation_manifest_with_key(manifest, &public_key)
}

pub(crate) fn verify_operation_manifest_with_key(
    manifest: &OperationRunManifest,
    public_key: &[u8; 32],
) -> io::Result<()> {
    let signature = manifest
        .host_signature
        .as_ref()
        .ok_or_else(|| invalid_data("operation manifest is not host-authenticated"))?;
    if signature.algorithm != "ed25519" {
        return Err(invalid_data("unsupported operation manifest signature"));
    }
    let signature_bytes =
        decode_hex_array::<64>(&signature.signature_hex, "operation manifest signature")?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|error| invalid_data(format!("invalid operation manifest public key: {error}")))?
        .verify(
            &operation_manifest_signing_bytes(manifest)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|error| invalid_data(format!("invalid operation manifest signature: {error}")))
}

fn operation_manifest_signing_bytes(manifest: &OperationRunManifest) -> io::Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.host_signature = None;
    let mut bytes = OPERATION_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(&unsigned).map_err(json_error)?);
    Ok(bytes)
}

fn sign_receipt(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--request",
            "--claims",
            "--verifier-key",
            "--output",
        ],
        &[],
    )?;
    let signed_catalog: SignedContractCatalog = read_catalog_json(
        &required_path(args, "--catalog")?,
        "signed contract catalog",
    )?;
    verify_signed_catalog(
        &signed_catalog,
        &required_path(args, "--trusted-key")?,
        unix_millis()?,
    )?;
    let request: VerifierRequest =
        read_catalog_json(&required_path(args, "--request")?, "verifier request")?;
    let claims: VerifierReceiptClaims =
        read_catalog_json(&required_path(args, "--claims")?, "verifier receipt claims")?;
    validate_receipt_claims(&signed_catalog, &request, &claims, unix_millis()?)?;
    let key = read_signing_key(&required_path(args, "--verifier-key")?)?;
    let verifier = approved_verifier(&signed_catalog, &claims.verifier_id)?;
    if verifier.require_isolation {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "isolation-required receipts can only be created by verifier run",
        ));
    }
    if hex::encode(key.verifying_key().as_bytes()) != verifier.public_key_hex.to_lowercase() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier signing key does not match the approved verifier",
        ));
    }
    let claims_bytes = serde_json::to_vec(&claims).map_err(json_error)?;
    let receipt = SignedVerifierReceipt {
        claims,
        signature: VerifierReceiptSignature {
            algorithm: "ed25519".into(),
            signature_hex: hex::encode(key.sign(&claims_bytes).to_bytes()),
        },
    };
    write_json(&required_path(args, "--output")?, &receipt)
}

fn verify_receipt_command(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &["--catalog", "--trusted-key", "--request", "--receipt"],
        &["--json"],
    )?;
    let signed_catalog: SignedContractCatalog = read_catalog_json(
        &required_path(args, "--catalog")?,
        "signed contract catalog",
    )?;
    verify_signed_catalog(
        &signed_catalog,
        &required_path(args, "--trusted-key")?,
        unix_millis()?,
    )?;
    let request: VerifierRequest =
        read_catalog_json(&required_path(args, "--request")?, "verifier request")?;
    let receipt: SignedVerifierReceipt = read_catalog_json(
        &required_path(args, "--receipt")?,
        "signed verifier receipt",
    )?;
    verify_semantic_receipt(&signed_catalog, &request, &receipt, unix_millis()?)?;
    if has_flag(args, "--json") {
        let mut encoded = serde_json::to_vec_pretty(&receipt).map_err(json_error)?;
        encoded.push(b'\n');
        io::stdout().write_all(&encoded)
    } else {
        println!(
            "verified semantic verdict {:?} from {} ({})",
            receipt.claims.verdict, receipt.claims.verifier_id, receipt.claims.policy_version
        );
        Ok(())
    }
}

pub(crate) fn verify_semantic_receipt(
    catalog: &SignedContractCatalog,
    request: &VerifierRequest,
    receipt: &SignedVerifierReceipt,
    now_ms: u64,
) -> io::Result<()> {
    validate_receipt_claims(catalog, request, &receipt.claims, now_ms)?;
    if receipt.signature.algorithm != "ed25519" {
        return Err(invalid_data("unsupported verifier receipt signature"));
    }
    let verifier = approved_verifier(catalog, &receipt.claims.verifier_id)?;
    let public_key = decode_hex_array::<32>(&verifier.public_key_hex, "verifier public key")?;
    let signature = decode_hex_array::<64>(
        &receipt.signature.signature_hex,
        "verifier receipt signature",
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| invalid_data(format!("invalid verifier public key: {error}")))?
        .verify(
            &serde_json::to_vec(&receipt.claims).map_err(json_error)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| invalid_data(format!("invalid verifier receipt signature: {error}")))
}

fn validate_receipt_claims(
    catalog: &SignedContractCatalog,
    request: &VerifierRequest,
    claims: &VerifierReceiptClaims,
    now_ms: u64,
) -> io::Result<()> {
    let request_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(request).map_err(json_error)?)
    );
    claims
        .validate_for_request(request, &request_digest, now_ms)
        .map_err(invalid_data)?;
    let verifier = approved_verifier(catalog, &claims.verifier_id)?;
    if !verifier
        .profiles
        .iter()
        .any(|profile| profile == &claims.verifier_profile)
        || !verifier
            .policy_versions
            .iter()
            .any(|version| version == &claims.policy_version)
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "verifier profile or policy version is not catalog-approved",
        ));
    }
    if verifier.require_isolation {
        let isolation = claims.isolation.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "catalog requires an isolated semantic verifier receipt",
            )
        })?;
        if !matches!(
            isolation.profile.as_str(),
            "linux_landlock_seccomp_no_write_no_network_no_fork_v1"
                | "macos_seatbelt_no_write_no_network_no_fork_v1"
        ) || verifier.isolated_runtime_config_digest.as_deref()
            != Some(isolation.runtime_config_digest.as_str())
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "semantic verifier isolation evidence is not catalog-approved",
            ));
        }
    } else if claims.isolation.is_some() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "catalog does not authorize isolated-runtime claims for this verifier",
        ));
    }
    Ok(())
}

fn approved_verifier<'a>(
    catalog: &'a SignedContractCatalog,
    verifier_id: &str,
) -> io::Result<&'a gensee_crate_rules::contract_catalog::ApprovedSemanticVerifier> {
    catalog
        .catalog
        .semantic_verifiers
        .iter()
        .find(|verifier| verifier.verifier_id == verifier_id)
        .ok_or_else(|| invalid_data("semantic verifier is not catalog-approved"))
}

fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(json_error)?;
    bytes.push(b'\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_atomic_nofollow(path, &bytes, 0o600)
}

fn reject_options(args: &[OsString], valued: &[&str], flags: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(verifier_usage_error)?;
        if valued.contains(&value) {
            if index + 1 >= args.len() {
                return Err(verifier_usage_error());
            }
            index += 2;
        } else if flags.contains(&value) {
            index += 1;
        } else {
            return Err(invalid_input(format!("unknown verifier option: {value}")));
        }
    }
    Ok(())
}

fn required_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(verifier_usage_error)?;
    args.get(index + 1)
        .map(PathBuf::from)
        .ok_or_else(verifier_usage_error)
}

fn required_string(args: &[OsString], name: &str) -> io::Result<String> {
    required_path(args, name).map(|path| path.to_string_lossy().to_string())
}

fn has_flag(args: &[OsString], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn json_error(error: serde_json::Error) -> io::Error {
    invalid_data(format!("cannot encode semantic verifier record: {error}"))
}

fn verifier_usage_error() -> io::Error {
    invalid_input("usage: gensee boundary verifier <request|run|attest|sign|verify> ...")
}

fn print_verifier_usage() {
    println!(
        "gensee boundary verifier\n\nUSAGE:\n  gensee boundary verifier request --manifest <operation.json> --ttl-seconds <n> --output <request.json>\n  gensee boundary verifier run --catalog <signed.json> --trusted-key <org.hex> --request <request.json> --config <verifier.json> --verifier-key <seed.hex> --output <receipt.json>\n  gensee boundary verifier attest --request <request.json> --verifier-id <id> --policy-version <version> --verdict <accept|reject|indeterminate> --reason <code> --effects-digest <sha256> --verifier-key <seed.hex> --output <receipt.json>\n  gensee boundary verifier sign --catalog <signed.json> --trusted-key <org.hex> --request <request.json> --claims <claims.json> --verifier-key <seed.hex> --output <receipt.json>\n  gensee boundary verifier verify --catalog <signed.json> --trusted-key <org.hex> --request <request.json> --receipt <receipt.json> [--json]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use gensee_crate_rules::contract_catalog::{
        AmbiguousIntentAction, ApprovedSemanticVerifier, CatalogSignature, ContractCatalog,
        FallbackPolicy, CONTRACT_CATALOG_SCHEMA_VERSION,
    };
    use gensee_crate_rules::operation_contract::{
        ContractNetworkMode, OperationAdmissionEvidence, OperationEnforcementEvidence,
        OperationProcessEvidence, OperationPromotionEvidence, StructuralProductEvidence,
        StructuralProductType,
    };
    use gensee_crate_rules::semantic_verifier::{
        SemanticVerdict, SEMANTIC_VERIFIER_SCHEMA_VERSION,
    };

    #[test]
    fn receipt_signature_and_request_binding_prevent_substitution() {
        let key = SigningKey::from_bytes(&[44; 32]);
        let catalog = SignedContractCatalog {
            catalog: ContractCatalog {
                schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
                catalog_id: "catalog".into(),
                organization_id: "organization".into(),
                version: 1,
                issued_at_ms: 1,
                expires_at_ms: 10_000,
                contracts: Vec::new(),
                selectors: Vec::new(),
                intent_analyzers: Vec::new(),
                operation_services: Vec::new(),
                semantic_verifiers: vec![ApprovedSemanticVerifier {
                    verifier_id: "verifier_one".into(),
                    public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                    profiles: vec!["content_policy".into()],
                    policy_versions: vec!["policy_v2".into()],
                    require_isolation: false,
                    isolated_runtime_config_digest: None,
                }],
                fallback: FallbackPolicy {
                    on_ambiguous_intent: AmbiguousIntentAction::Deny,
                    safe_default_contract_id: None,
                },
            },
            signature: CatalogSignature {
                algorithm: "ed25519".into(),
                key_id: "unused".into(),
                public_key_hex: String::new(),
                signature_hex: String::new(),
            },
        };
        let request = VerifierRequest {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            request_id: "request_one".into(),
            nonce: "nonce_one".into(),
            operation_id: "operation_one".into(),
            contract_id: "contract_one".into(),
            contract_digest: format!("sha256:{}", "11".repeat(32)),
            product_type: StructuralProductType::StructuredResult,
            product_digest: format!("sha256:{}", "22".repeat(32)),
            verifier_profile: "content_policy".into(),
            issued_at_ms: 100,
            expires_at_ms: 900,
        };
        let request_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&request).unwrap())
        );
        let claims = VerifierReceiptClaims {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            receipt_id: "receipt_one".into(),
            request_digest,
            nonce: request.nonce.clone(),
            operation_id: request.operation_id.clone(),
            contract_id: request.contract_id.clone(),
            contract_digest: request.contract_digest.clone(),
            product_type: request.product_type,
            product_digest: request.product_digest.clone(),
            verifier_profile: request.verifier_profile.clone(),
            verifier_id: "verifier_one".into(),
            policy_version: "policy_v2".into(),
            verdict: SemanticVerdict::Accept,
            reason_codes: vec!["policy_passed".into()],
            validation_effect_manifest_digest: format!("sha256:{}", "33".repeat(32)),
            isolation: None,
            issued_at_ms: 110,
            expires_at_ms: 800,
        };
        let bytes = serde_json::to_vec(&claims).unwrap();
        let receipt = SignedVerifierReceipt {
            claims,
            signature: VerifierReceiptSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(key.sign(&bytes).to_bytes()),
            },
        };
        assert!(verify_semantic_receipt(&catalog, &request, &receipt, 200).is_ok());

        let mut changed = request;
        changed.product_digest = format!("sha256:{}", "44".repeat(32));
        assert!(verify_semantic_receipt(&catalog, &changed, &receipt, 200).is_err());
    }

    #[test]
    fn verifier_request_source_requires_exact_host_signed_manifest() {
        let key = SigningKey::from_bytes(&[45; 32]);
        let mut manifest = OperationRunManifest {
            schema_version: 1,
            operation_id: "operation_one".into(),
            source_run_id: "run_one".into(),
            contract_id: "contract_one".into(),
            contract_digest: format!("sha256:{}", "11".repeat(32)),
            command_digest: format!("sha256:{}", "12".repeat(32)),
            admission: OperationAdmissionEvidence {
                catalog_id: "catalog_one".into(),
                catalog_version: 1,
                catalog_digest: format!("sha256:{}", "13".repeat(32)),
                observation_digest: format!("sha256:{}", "14".repeat(32)),
                inference_digest: format!("sha256:{}", "15".repeat(32)),
                analyzer_id: "analyzer_one".into(),
                selected_operation_class: "transform".into(),
                confidence_bps: 9_000,
                resolution_source: "probabilistic_inference".into(),
                ambiguity_reason: None,
            },
            operation_record: "/var/lib/gensee/operation.json".into(),
            original_workspace: "/workspace".into(),
            staged_workspace: "/staged".into(),
            enforcement: OperationEnforcementEvidence {
                os_execution_binding_established: true,
                execution_subject_kind: "process_group".into(),
                network_mode: ContractNetworkMode::DenyAll,
                network_boundary: "deny_all".into(),
                network_effect_coverage: "complete".into(),
                allowed_network_effects: Vec::new(),
                denied_network_effects: Vec::new(),
                collection_errors: Vec::new(),
            },
            process: OperationProcessEvidence {
                root_pid: 123,
                root_start_time: Some(456),
                exit_code: Some(0),
                timed_out: false,
                execution_subject_drained: true,
            },
            product: Some(StructuralProductEvidence {
                kind: StructuralProductType::StructuredResult,
                path: "out/result.json".into(),
                digest: format!("sha256:{}", "22".repeat(32)),
                entries: 1,
                bytes: 2,
                structurally_valid: true,
                semantic_status: "receipt_required:content_policy".into(),
                violations: Vec::new(),
            }),
            promotion: OperationPromotionEvidence {
                performed: false,
                structurally_eligible: true,
                semantically_verified: false,
                reason: "receipt required".into(),
            },
            started_at_ms: 100,
            finished_at_ms: 110,
            host_signature: None,
        };
        sign_operation_manifest_with_key(&mut manifest, &key).unwrap();
        verify_operation_manifest_with_key(&manifest, key.verifying_key().as_bytes()).unwrap();

        manifest.product.as_mut().unwrap().digest = format!("sha256:{}", "99".repeat(32));
        assert!(
            verify_operation_manifest_with_key(&manifest, key.verifying_key().as_bytes()).is_err()
        );
    }

    #[test]
    fn catalog_required_isolation_rejects_manual_receipt() {
        let key = SigningKey::from_bytes(&[45; 32]);
        let (mut catalog, request, receipt) = receipt_fixture(&key);
        catalog.catalog.semantic_verifiers[0].require_isolation = true;
        let error = verify_semantic_receipt(&catalog, &request, &receipt, 200).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("requires an isolated"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn isolated_runner_executes_snapshot_and_denies_filesystem_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "gensee-isolated-verifier-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        let forbidden = root.join("must-not-write");
        let executable = root.join("verifier");
        fs::write(
            &executable,
            format!(
                "#!/usr/bin/ruby --disable-gems\nbegin; File.write('{}', 'forbidden'); exit 23; rescue Errno::EPERM; end\nputs '{{\"verdict\":\"accept\",\"reason_codes\":[\"isolated\"],\"validation_effect_manifest_digest\":\"sha256:{}\"}}'\n",
                forbidden.display(),
                "55".repeat(32)
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        let config = IsolatedVerifierConfig {
            verifier_id: "verifier_one".into(),
            policy_version: "policy_v2".into(),
            executable: executable.to_string_lossy().into_owned(),
            executable_sha256: hash_verifier_file(&executable, 1024 * 1024).unwrap(),
            args: Vec::new(),
            working_directory: root.to_string_lossy().into_owned(),
            max_runtime_seconds: 10,
        };
        let now = unix_millis().unwrap();
        let request = verifier_request(now);
        let result = execute_isolated_verifier_at(&config, &request, &root).unwrap();
        assert_eq!(result.verdict, SemanticVerdict::Accept);
        assert!(!forbidden.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn verifier_request(now: u64) -> VerifierRequest {
        VerifierRequest {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            request_id: "request_one".into(),
            nonce: "nonce_one".into(),
            operation_id: "operation_one".into(),
            contract_id: "contract_one".into(),
            contract_digest: format!("sha256:{}", "11".repeat(32)),
            product_type: StructuralProductType::StructuredResult,
            product_digest: format!("sha256:{}", "22".repeat(32)),
            verifier_profile: "content_policy".into(),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        }
    }

    fn receipt_fixture(
        key: &SigningKey,
    ) -> (
        SignedContractCatalog,
        VerifierRequest,
        SignedVerifierReceipt,
    ) {
        let catalog = SignedContractCatalog {
            catalog: ContractCatalog {
                schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
                catalog_id: "catalog".into(),
                organization_id: "organization".into(),
                version: 1,
                issued_at_ms: 1,
                expires_at_ms: 10_000,
                contracts: Vec::new(),
                selectors: Vec::new(),
                intent_analyzers: Vec::new(),
                operation_services: Vec::new(),
                semantic_verifiers: vec![ApprovedSemanticVerifier {
                    verifier_id: "verifier_one".into(),
                    public_key_hex: hex::encode(key.verifying_key().as_bytes()),
                    profiles: vec!["content_policy".into()],
                    policy_versions: vec!["policy_v2".into()],
                    require_isolation: false,
                    isolated_runtime_config_digest: None,
                }],
                fallback: FallbackPolicy {
                    on_ambiguous_intent: AmbiguousIntentAction::Deny,
                    safe_default_contract_id: None,
                },
            },
            signature: CatalogSignature {
                algorithm: "ed25519".into(),
                key_id: "unused".into(),
                public_key_hex: String::new(),
                signature_hex: String::new(),
            },
        };
        let request = verifier_request(100);
        let request_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&request).unwrap())
        );
        let claims = VerifierReceiptClaims {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            receipt_id: "receipt_one".into(),
            request_digest,
            nonce: request.nonce.clone(),
            operation_id: request.operation_id.clone(),
            contract_id: request.contract_id.clone(),
            contract_digest: request.contract_digest.clone(),
            product_type: request.product_type,
            product_digest: request.product_digest.clone(),
            verifier_profile: request.verifier_profile.clone(),
            verifier_id: "verifier_one".into(),
            policy_version: "policy_v2".into(),
            verdict: SemanticVerdict::Accept,
            reason_codes: vec!["policy_passed".into()],
            validation_effect_manifest_digest: format!("sha256:{}", "33".repeat(32)),
            isolation: None,
            issued_at_ms: 110,
            expires_at_ms: 800,
        };
        let receipt = SignedVerifierReceipt {
            signature: VerifierReceiptSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(
                    key.sign(&serde_json::to_vec(&claims).unwrap()).to_bytes(),
                ),
            },
            claims,
        };
        (catalog, request, receipt)
    }
}
