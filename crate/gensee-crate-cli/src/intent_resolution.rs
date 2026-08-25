use crate::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::{
    ContractResolution, IntentObservation, ObservedCaller, SignedContractCatalog,
    SignedIntentInference, TrajectoryEvidence, INTENT_OBSERVATION_SCHEMA_VERSION,
};
use gensee_crate_rules::operation_contract::OperationContract;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_TRAJECTORY_REFERENCES: usize = 1024;
const MAX_HASHED_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrajectoryInput {
    history_complete: bool,
    #[serde(default)]
    trajectory: Vec<TrajectoryEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedAdmission {
    pub resolution: ContractResolution,
    pub catalog_digest: String,
    pub observation_digest: String,
    pub inference_digest: String,
    pub contract: OperationContract,
    pub canonical_executable: PathBuf,
    pub executable_sha256: String,
}

pub(crate) fn handle_intent_resolution(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(intent_usage_error)?;
    match command.to_str() {
        Some("observe") => observe_command(rest),
        Some("resolve") => resolve_command(rest),
        Some("--help" | "-h") => {
            print_intent_usage();
            Ok(())
        }
        _ => Err(intent_usage_error()),
    }
}

fn observe_command(args: &[OsString]) -> io::Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(intent_usage_error)?;
    let options = &args[..separator];
    let command = &args[separator + 1..];
    if command.is_empty() {
        return Err(intent_usage_error());
    }
    reject_options(options, &["--output", "--trajectory"], &[])?;
    let output = required_path(options, "--output")?;
    let trajectory = optional_path(options, "--trajectory")?
        .map(|path| read_catalog_json::<TrajectoryInput>(&path, "trajectory evidence"))
        .transpose()?
        .unwrap_or(TrajectoryInput {
            history_complete: false,
            trajectory: Vec::new(),
        });
    if trajectory.trajectory.len() > MAX_TRAJECTORY_REFERENCES {
        return Err(invalid_input("trajectory reference limit exceeded"));
    }
    let normalized = normalize_command(command)?;
    let observation = IntentObservation {
        schema_version: INTENT_OBSERVATION_SCHEMA_VERSION,
        observation_id: format!("obs_{}", uuid::Uuid::new_v4().simple()),
        observed_at_ms: unix_millis()?,
        caller: ObservedCaller {
            uid: effective_uid(),
            executable_sha256: hash_regular_file(&normalized.canonical_executable)?,
            service_identity: None,
        },
        command_digest: digest_command(&normalized.command),
        command_features: structural_command_features(&normalized.command),
        trajectory: trajectory.trajectory,
        history_complete: trajectory.history_complete,
    };
    observation
        .validate()
        .map_err(|error| invalid_input(format!("invalid observation: {error}")))?;
    write_json(&output, &observation)?;
    println!(
        "recorded preflight observation: {}",
        observation.observation_id
    );
    Ok(())
}

fn resolve_command(args: &[OsString]) -> io::Result<()> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(intent_usage_error)?;
    let options = &args[..separator];
    let command = &args[separator + 1..];
    if command.is_empty() {
        return Err(intent_usage_error());
    }
    reject_options(
        options,
        &[
            "--catalog",
            "--trusted-key",
            "--observation",
            "--inference",
            "--output",
        ],
        &[],
    )?;
    let resolved = verify_and_resolve(
        &required_path(options, "--catalog")?,
        &required_path(options, "--trusted-key")?,
        &required_path(options, "--observation")?,
        &required_path(options, "--inference")?,
        command,
        unix_millis()?,
    )?;
    write_json(&required_path(options, "--output")?, &resolved)?;
    println!(
        "resolved operation class {} to approved contract {}",
        resolved.resolution.selected_operation_class, resolved.resolution.selected_contract_id
    );
    Ok(())
}

pub(crate) fn verify_and_resolve(
    catalog_path: &Path,
    trusted_key_path: &Path,
    observation_path: &Path,
    inference_path: &Path,
    command: &[OsString],
    now_ms: u64,
) -> io::Result<ResolvedAdmission> {
    let signed_catalog: SignedContractCatalog =
        read_catalog_json(catalog_path, "signed contract catalog")?;
    verify_signed_catalog(&signed_catalog, trusted_key_path, now_ms)?;
    let observation: IntentObservation = read_catalog_json(observation_path, "intent observation")?;
    let signed_inference: SignedIntentInference =
        read_catalog_json(inference_path, "signed intent inference")?;
    observation
        .validate()
        .map_err(|error| invalid_data(format!("invalid intent observation: {error}")))?;

    let normalized = normalize_command(command)?;
    verify_runtime_binding(&observation, &normalized)?;
    let observation_bytes = serde_json::to_vec(&observation).map_err(json_error)?;
    let observation_digest = digest_bytes(&observation_bytes);
    if signed_inference.inference.observation_digest != observation_digest {
        return Err(invalid_data(
            "intent inference is not bound to the current observation",
        ));
    }
    let analyzer = signed_catalog
        .catalog
        .intent_analyzers
        .iter()
        .find(|item| item.analyzer_id == signed_inference.inference.analyzer_id)
        .ok_or_else(|| invalid_data("intent analyzer is not approved by the catalog"))?;
    let analyzer_key = decode_hex_array::<32>(&analyzer.public_key_hex, "analyzer public key")?;
    let signature = decode_hex_array::<64>(
        &signed_inference.signature.signature_hex,
        "intent inference signature",
    )?;
    if signed_inference.signature.algorithm != "ed25519" {
        return Err(invalid_data("unsupported intent inference signature"));
    }
    let inference_bytes = serde_json::to_vec(&signed_inference.inference).map_err(json_error)?;
    VerifyingKey::from_bytes(&analyzer_key)
        .map_err(|error| invalid_data(format!("invalid analyzer key: {error}")))?
        .verify(&inference_bytes, &Signature::from_bytes(&signature))
        .map_err(|error| invalid_data(format!("invalid intent inference signature: {error}")))?;
    let resolution = signed_catalog
        .catalog
        .resolve_intent(&observation, &signed_inference.inference, now_ms)
        .map_err(|error| io::Error::new(ErrorKind::PermissionDenied, error))?;
    let contract = signed_catalog
        .catalog
        .contract(&resolution.selected_contract_id)
        .ok_or_else(|| invalid_data("resolved contract disappeared from catalog"))?
        .contract
        .clone();
    Ok(ResolvedAdmission {
        resolution,
        catalog_digest: digest_bytes(
            &serde_json::to_vec(&signed_catalog.catalog).map_err(json_error)?,
        ),
        observation_digest,
        inference_digest: digest_bytes(&inference_bytes),
        contract,
        executable_sha256: observation.caller.executable_sha256.clone(),
        canonical_executable: normalized.canonical_executable,
    })
}

struct NormalizedCommand {
    command: Vec<OsString>,
    canonical_executable: PathBuf,
}

fn normalize_command(command: &[OsString]) -> io::Result<NormalizedCommand> {
    let first = command.first().ok_or_else(intent_usage_error)?;
    let canonical = resolve_executable(first)?;
    let mut normalized = command.to_vec();
    normalized[0] = canonical.as_os_str().to_owned();
    Ok(NormalizedCommand {
        command: normalized,
        canonical_executable: canonical,
    })
}

fn resolve_executable(value: &OsStr) -> io::Result<PathBuf> {
    let path = Path::new(value);
    if path.components().count() > 1 || path.is_absolute() {
        return fs::canonicalize(path);
    }
    let search = env::var_os("PATH").ok_or_else(|| invalid_input("PATH is unavailable"))?;
    for directory in env::split_paths(&search) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return fs::canonicalize(candidate);
        }
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        format!("cannot resolve executable {}", path.display()),
    ))
}

fn verify_runtime_binding(
    observation: &IntentObservation,
    normalized: &NormalizedCommand,
) -> io::Result<()> {
    if observation.caller.uid != effective_uid()
        || observation.caller.service_identity.is_some()
        || observation.caller.executable_sha256
            != hash_regular_file(&normalized.canonical_executable)?
        || observation.command_digest != digest_command(&normalized.command)
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "intent observation does not match the current OS caller and command",
        ));
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_HASHED_EXECUTABLE_BYTES
    {
        return Err(invalid_input("executable must be a bounded regular file"));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn digest_command(command: &[OsString]) -> String {
    let mut hasher = Sha256::new();
    for argument in command {
        hasher.update(argument.to_string_lossy().as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn structural_command_features(command: &[OsString]) -> Vec<String> {
    let count = command.len().saturating_sub(1);
    let bucket = match count {
        0 => "args_0",
        1..=4 => "args_1_4",
        5..=16 => "args_5_16",
        _ => "args_17_plus",
    };
    vec![bucket.to_string()]
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(json_error)?;
    encoded.push(b'\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_atomic_nofollow(path, &encoded, 0o600)
}

fn reject_options(args: &[OsString], valued: &[&str], flags: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(intent_usage_error)?;
        if valued.contains(&value) {
            if index + 1 >= args.len() {
                return Err(intent_usage_error());
            }
            index += 2;
        } else if flags.contains(&value) {
            index += 1;
        } else {
            return Err(invalid_input(format!("unknown intent option: {value}")));
        }
    }
    Ok(())
}

fn required_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    optional_path(args, name)?.ok_or_else(intent_usage_error)
}

fn optional_path(args: &[OsString], name: &str) -> io::Result<Option<PathBuf>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    args.get(index + 1)
        .map(PathBuf::from)
        .map(Some)
        .ok_or_else(intent_usage_error)
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not modify memory.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    0
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    catalog_invalid_data(message)
}

fn json_error(error: serde_json::Error) -> io::Error {
    invalid_data(format!("cannot encode intent data: {error}"))
}

fn intent_usage_error() -> io::Error {
    invalid_input("usage: gensee boundary intent <observe|resolve> ...")
}

fn print_intent_usage() {
    println!(
        "gensee boundary intent\n\nUSAGE:\n  gensee boundary intent observe --output <observation.json> [--trajectory <history.json>] -- <command> [args...]\n  gensee boundary intent resolve --catalog <signed.json> --trusted-key <public.hex> --observation <observation.json> --inference <signed-inference.json> --output <resolution.json> -- <command> [args...]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use gensee_crate_rules::contract_catalog::{
        AmbiguousIntentAction, ApprovedContract, ApprovedIntentAnalyzer, CallerSelector,
        CatalogSignature, ContractApproval, ContractCatalog, ContractOwner, ContractSelector,
        FallbackPolicy, InferenceSignature, IntentCandidate, IntentInference,
        SignedIntentInference, CONTRACT_CATALOG_SCHEMA_VERSION, INTENT_INFERENCE_SCHEMA_VERSION,
    };
    use gensee_crate_rules::operation_contract::{
        ContractCapabilities, ExecutionContract, OPERATION_CONTRACT_SCHEMA_VERSION,
    };

    #[test]
    fn signed_inference_can_only_select_catalog_contract() {
        let temp = temp_dir("intent-resolve");
        let organization_key = SigningKey::from_bytes(&[8; 32]);
        let analyzer_key = SigningKey::from_bytes(&[9; 32]);
        let command = vec![env::current_exe().unwrap().into_os_string()];
        let normalized = normalize_command(&command).unwrap();
        let observation = IntentObservation {
            schema_version: INTENT_OBSERVATION_SCHEMA_VERSION,
            observation_id: "obs_test".into(),
            observed_at_ms: 100,
            caller: ObservedCaller {
                uid: effective_uid(),
                executable_sha256: hash_regular_file(&normalized.canonical_executable).unwrap(),
                service_identity: None,
            },
            command_digest: digest_command(&normalized.command),
            command_features: structural_command_features(&normalized.command),
            trajectory: Vec::new(),
            history_complete: false,
        };
        let catalog = ContractCatalog {
            schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
            catalog_id: "catalog_test".into(),
            organization_id: "organization_test".into(),
            version: 1,
            issued_at_ms: 10,
            expires_at_ms: u64::MAX,
            contracts: vec![ApprovedContract {
                contract: OperationContract {
                    schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
                    contract_id: "least_authority_transform".into(),
                    operation_class: "transform".into(),
                    execution: ExecutionContract::default(),
                    capabilities: ContractCapabilities::default(),
                    product: None,
                },
                owner: ContractOwner {
                    application_id: "test_runner".into(),
                    owning_team: "security".into(),
                },
                approval: ContractApproval {
                    approval_id: "approval_test".into(),
                    approved_by: "reviewer".into(),
                    approved_at_ms: 10,
                    expires_at_ms: u64::MAX - 1,
                },
            }],
            selectors: vec![ContractSelector {
                selector_id: "selector_test".into(),
                caller: CallerSelector {
                    uid: Some(effective_uid()),
                    executable_sha256: Some(observation.caller.executable_sha256.clone()),
                    service_identity: None,
                },
                operation_class: "transform".into(),
                contract_id: "least_authority_transform".into(),
            }],
            intent_analyzers: vec![ApprovedIntentAnalyzer {
                analyzer_id: "analyzer_test".into(),
                public_key_hex: hex::encode(analyzer_key.verifying_key().as_bytes()),
                model_identity: "model_test".into(),
                minimum_confidence_bps: 8_000,
                allowed_operation_classes: vec!["transform".into()],
            }],
            operation_services: Vec::new(),
            semantic_verifiers: Vec::new(),
            fallback: FallbackPolicy {
                on_ambiguous_intent: AmbiguousIntentAction::Deny,
                safe_default_contract_id: None,
            },
        };
        let catalog_bytes = serde_json::to_vec(&catalog).unwrap();
        let signed_catalog = SignedContractCatalog {
            catalog,
            signature: CatalogSignature {
                algorithm: "ed25519".into(),
                key_id: "organization_root".into(),
                public_key_hex: hex::encode(organization_key.verifying_key().as_bytes()),
                signature_hex: hex::encode(organization_key.sign(&catalog_bytes).to_bytes()),
            },
        };
        let observation_digest = digest_bytes(&serde_json::to_vec(&observation).unwrap());
        let inference = IntentInference {
            schema_version: INTENT_INFERENCE_SCHEMA_VERSION,
            inference_id: "inference_test".into(),
            analyzer_id: "analyzer_test".into(),
            model_identity: "model_test".into(),
            observation_digest,
            issued_at_ms: 100,
            expires_at_ms: u64::MAX,
            candidates: vec![IntentCandidate {
                operation_class: "transform".into(),
                confidence_bps: 9_000,
                rationale_code: "trajectory_match".into(),
                evidence_ids: Vec::new(),
            }],
        };
        let inference_bytes = serde_json::to_vec(&inference).unwrap();
        let signed_inference = SignedIntentInference {
            inference,
            signature: InferenceSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(analyzer_key.sign(&inference_bytes).to_bytes()),
            },
        };
        let catalog_path = temp.join("catalog.json");
        let key_path = temp.join("organization.hex");
        let observation_path = temp.join("observation.json");
        let inference_path = temp.join("inference.json");
        fs::write(&catalog_path, serde_json::to_vec(&signed_catalog).unwrap()).unwrap();
        fs::write(
            &key_path,
            hex::encode(organization_key.verifying_key().as_bytes()),
        )
        .unwrap();
        fs::write(&observation_path, serde_json::to_vec(&observation).unwrap()).unwrap();
        fs::write(
            &inference_path,
            serde_json::to_vec(&signed_inference).unwrap(),
        )
        .unwrap();

        let resolved = verify_and_resolve(
            &catalog_path,
            &key_path,
            &observation_path,
            &inference_path,
            &command,
            200,
        )
        .unwrap();
        assert_eq!(
            resolved.resolution.selected_contract_id,
            "least_authority_transform"
        );

        let mut changed = command.clone();
        changed.push(OsString::from("different"));
        assert!(verify_and_resolve(
            &catalog_path,
            &key_path,
            &observation_path,
            &inference_path,
            &changed,
            200,
        )
        .is_err());
        fs::remove_dir_all(temp).unwrap();
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("gensee-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
