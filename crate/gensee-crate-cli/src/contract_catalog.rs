use crate::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::{
    CatalogAudit, CatalogSignature, ContractCatalog, SignedContractCatalog,
};
use gensee_crate_rules::operation_contract::{
    ContractCapabilities, ExecutionContract, OperationContract, ProductContract,
    StructuralProductType, TransactionalPromotionContract, OPERATION_CONTRACT_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_CATALOG_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn handle_contract_catalog(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(catalog_usage_error)?;
    match command.to_str() {
        Some("sign") => sign_catalog(rest),
        Some("verify") => verify_catalog_command(rest),
        Some("public-key") => public_key_command(rest),
        Some("template") => template_command(rest),
        Some("install") => install_catalog(rest),
        Some("status") => installed_catalog_status(rest),
        Some("--help" | "-h") => {
            print_catalog_usage();
            Ok(())
        }
        _ => Err(catalog_usage_error()),
    }
}

fn template_command(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(
        args,
        &[
            "--profile",
            "--contract-id",
            "--operation-class",
            "--product-path",
            "--verifier-profile",
            "--destination-root",
            "--active-pointer",
            "--output",
        ],
        &[],
    )?;
    let profile = required_catalog_string(args, "--profile")?;
    let contract_id = required_catalog_string(args, "--contract-id")?;
    let operation_class = required_catalog_string(args, "--operation-class")?;
    if !safe_catalog_token(&contract_id) || !safe_catalog_token(&operation_class) {
        return Err(invalid_input(
            "contract and operation class must be bounded tokens",
        ));
    }
    let product =
        match profile.as_str() {
            "deny-all" => None,
            "structured-result" => {
                let path = required_catalog_string(args, "--product-path")?;
                let verifier = required_catalog_string(args, "--verifier-profile")?;
                if !safe_catalog_token(&verifier) {
                    return Err(invalid_input("verifier profile must be a bounded token"));
                }
                let destination = optional_catalog_string(args, "--destination-root")?;
                let pointer = optional_catalog_string(args, "--active-pointer")?;
                if destination.is_some() != pointer.is_some() {
                    return Err(invalid_input(
                        "destination-root and active-pointer must be supplied together",
                    ));
                }
                Some(ProductContract {
                    kind: StructuralProductType::StructuredResult,
                    path,
                    max_bytes: 1024 * 1024,
                    max_entries: 1,
                    reject_symlinks: true,
                    reject_special_files: true,
                    semantic_verifier_profile: Some(verifier),
                    promotion: destination.zip(pointer).map(
                        |(destination_root, active_pointer)| TransactionalPromotionContract {
                            destination_root,
                            active_pointer,
                        },
                    ),
                })
            }
            _ => return Err(invalid_input("unknown safe template profile")),
        };
    let contract = OperationContract {
        schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
        contract_id,
        operation_class,
        execution: ExecutionContract::default(),
        capabilities: ContractCapabilities::default(),
        product,
    };
    let audit = contract.audit_for_platform(std::env::consts::OS);
    if !audit.valid {
        return Err(invalid_input(format!(
            "generated template is invalid: {}",
            audit.errors.join("; ")
        )));
    }
    write_json_catalog(&required_catalog_path(args, "--output")?, &contract)
}

fn install_catalog(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(args, &["--catalog", "--trusted-key", "--root"], &[])?;
    let input = required_catalog_path(args, "--catalog")?;
    let trusted = required_catalog_path(args, "--trusted-key")?;
    let root = required_catalog_path(args, "--root")?;
    ensure_catalog_root(&root)?;
    let signed: SignedContractCatalog = read_catalog_json(&input, "signed contract catalog")?;
    verify_signed_catalog(&signed, &trusted, unix_millis()?)?;
    let current_path = root.join("current.json");
    if current_path.exists() {
        let current: SignedContractCatalog =
            read_catalog_json(&current_path, "installed contract catalog")?;
        verify_signed_catalog(&current, &trusted, unix_millis()?)?;
        if current.catalog.organization_id != signed.catalog.organization_id
            || current.catalog.catalog_id != signed.catalog.catalog_id
            || signed.catalog.version < current.catalog.version
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "catalog installation would change ownership or roll back a version",
            ));
        }
        if signed.catalog.version == current.catalog.version && signed != current {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "catalog version is already installed with different content",
            ));
        }
    }
    let encoded = serde_json::to_vec_pretty(&signed).map_err(invalid_json)?;
    let digest = format!("{:x}", Sha256::digest(&encoded));
    let archive = root.join("catalogs");
    ensure_catalog_root(&archive)?;
    let archive_path = archive.join(format!(
        "{}-v{}-{}.json",
        signed.catalog.catalog_id,
        signed.catalog.version,
        &digest[..16]
    ));
    if !archive_path.exists() {
        write_atomic_nofollow(&archive_path, &encoded, 0o400)?;
        sync_catalog_dir(&archive)?;
    }
    write_atomic_nofollow(&current_path, &encoded, 0o400)?;
    sync_catalog_dir(&root)?;
    println!(
        "installed contract catalog: {} v{}",
        signed.catalog.catalog_id, signed.catalog.version
    );
    Ok(())
}

fn installed_catalog_status(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(args, &["--root", "--trusted-key"], &["--json"])?;
    let root = required_catalog_path(args, "--root")?;
    let signed: SignedContractCatalog =
        read_catalog_json(&root.join("current.json"), "installed contract catalog")?;
    let audit = verify_signed_catalog(
        &signed,
        &required_catalog_path(args, "--trusted-key")?,
        unix_millis()?,
    )?;
    if has_catalog_flag(args, "--json") {
        write_stdout_json(&signed)
    } else {
        println!("{} v{} valid", audit.catalog_id, audit.version);
        Ok(())
    }
}

fn ensure_catalog_root(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_input("catalog root must be a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 || (unsafe { libc::geteuid() } == 0 && metadata.uid() != 0)
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "catalog root must be owner-controlled and non-group/world-writable",
            ));
        }
    }
    Ok(())
}

fn sync_catalog_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn write_json_catalog(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(invalid_json)?;
    encoded.push(b'\n');
    write_catalog_output(path, &encoded)
}

fn write_stdout_json(value: &impl serde::Serialize) -> io::Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value).map_err(invalid_json)?;
    encoded.push(b'\n');
    io::stdout().write_all(&encoded)
}

fn public_key_command(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(args, &["--key", "--output"], &[])?;
    let key = read_signing_key(&required_catalog_path(args, "--key")?)?;
    let mut encoded = hex::encode(key.verifying_key().as_bytes()).into_bytes();
    encoded.push(b'\n');
    write_catalog_output(&required_catalog_path(args, "--output")?, &encoded)
}

fn sign_catalog(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(args, &["--catalog", "--key", "--key-id", "--output"], &[])?;
    let input = required_catalog_path(args, "--catalog")?;
    let key_path = required_catalog_path(args, "--key")?;
    let key_id = required_catalog_string(args, "--key-id")?;
    let output = required_catalog_path(args, "--output")?;
    if !safe_catalog_token(&key_id) {
        return Err(invalid_input("key-id must be a bounded ASCII token"));
    }
    let catalog: ContractCatalog = read_catalog_json(&input, "contract catalog")?;
    let audit = catalog.audit(std::env::consts::OS, unix_millis()?);
    require_valid_catalog(&audit)?;
    let signing_key = read_signing_key(&key_path)?;
    let catalog_bytes = serde_json::to_vec(&catalog).map_err(invalid_json)?;
    let signature = signing_key.sign(&catalog_bytes);
    let signed = SignedContractCatalog {
        catalog,
        signature: CatalogSignature {
            algorithm: "ed25519".into(),
            key_id,
            public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        },
    };
    let mut encoded = serde_json::to_vec_pretty(&signed).map_err(invalid_json)?;
    encoded.push(b'\n');
    write_catalog_output(&output, &encoded)?;
    println!(
        "signed contract catalog: {} v{}",
        signed.catalog.catalog_id, signed.catalog.version
    );
    Ok(())
}

fn verify_catalog_command(args: &[OsString]) -> io::Result<()> {
    reject_catalog_options(args, &["--catalog", "--trusted-key"], &["--json"])?;
    let catalog_path = required_catalog_path(args, "--catalog")?;
    let trusted_key_path = required_catalog_path(args, "--trusted-key")?;
    let signed: SignedContractCatalog =
        read_catalog_json(&catalog_path, "signed contract catalog")?;
    let audit = verify_signed_catalog(&signed, &trusted_key_path, unix_millis()?)?;
    if has_catalog_flag(args, "--json") {
        let mut encoded = serde_json::to_vec_pretty(&audit).map_err(invalid_json)?;
        encoded.push(b'\n');
        io::stdout().write_all(&encoded)
    } else {
        println!(
            "verified contract catalog: {} v{} ({})",
            audit.catalog_id, audit.version, signed.signature.key_id
        );
        for warning in audit.warnings {
            eprintln!("gensee boundary: warning: {warning}");
        }
        Ok(())
    }
}

pub(crate) fn verify_signed_catalog(
    signed: &SignedContractCatalog,
    trusted_key_path: &Path,
    now_ms: u64,
) -> io::Result<CatalogAudit> {
    if signed.signature.algorithm != "ed25519" || !safe_catalog_token(&signed.signature.key_id) {
        return Err(invalid_data(
            "unsupported or invalid catalog signature metadata",
        ));
    }
    let trusted = read_hex_array::<32>(trusted_key_path, "trusted Ed25519 public key")?;
    let embedded = decode_hex_array::<32>(&signed.signature.public_key_hex, "catalog public key")?;
    if trusted != embedded {
        return Err(invalid_data(
            "catalog signing key is not the trusted organization key",
        ));
    }
    let signature = decode_hex_array::<64>(&signed.signature.signature_hex, "catalog signature")?;
    let verifying_key = VerifyingKey::from_bytes(&trusted)
        .map_err(|error| invalid_data(format!("invalid Ed25519 public key: {error}")))?;
    let catalog_bytes = serde_json::to_vec(&signed.catalog).map_err(invalid_json)?;
    verifying_key
        .verify(&catalog_bytes, &Signature::from_bytes(&signature))
        .map_err(|error| invalid_data(format!("invalid catalog signature: {error}")))?;
    let audit = signed.catalog.audit(std::env::consts::OS, now_ms);
    require_valid_catalog(&audit)?;
    Ok(audit)
}

fn require_valid_catalog(audit: &CatalogAudit) -> io::Result<()> {
    if audit.valid {
        Ok(())
    } else {
        Err(invalid_input(format!(
            "invalid contract catalog: {}",
            audit.errors.join("; ")
        )))
    }
}

pub(crate) fn read_signing_key(path: &Path) -> io::Result<SigningKey> {
    let text = Zeroizing::new(read_bounded_text(path, 256)?);
    let decoded = Zeroizing::new(
        hex::decode(text.trim())
            .map_err(|error| invalid_data(format!("invalid Ed25519 signing key: {error}")))?,
    );
    let bytes = Zeroizing::new(
        <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| invalid_data("Ed25519 signing key must contain exactly 32 bytes"))?,
    );
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn read_hex_array<const N: usize>(path: &Path, label: &str) -> io::Result<[u8; N]> {
    decode_hex_array(&read_bounded_text(path, 1024)?, label)
}

pub(crate) fn decode_hex_array<const N: usize>(value: &str, label: &str) -> io::Result<[u8; N]> {
    hex::decode(value.trim())
        .map_err(|error| invalid_data(format!("invalid {label}: {error}")))?
        .try_into()
        .map_err(|_| invalid_data(format!("{label} must contain exactly {N} bytes")))
}

pub(crate) fn read_catalog_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> io::Result<T> {
    serde_json::from_slice(&read_bounded(path, MAX_CATALOG_BYTES)?)
        .map_err(|error| invalid_data(format!("invalid {label} JSON: {error}")))
}

fn read_bounded_text(path: &Path, max: u64) -> io::Result<String> {
    String::from_utf8(read_bounded(path, max)?)
        .map_err(|error| invalid_data(format!("file is not UTF-8: {error}")))
}

fn read_bounded(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max {
        return Err(invalid_input(format!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(invalid_data("file exceeds byte limit"));
    }
    Ok(bytes)
}

fn write_catalog_output(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input("catalog output path has no parent"))?;
    fs::create_dir_all(parent)?;
    write_atomic_nofollow(path, bytes, 0o600)
}

fn reject_catalog_options(args: &[OsString], valued: &[&str], flags: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(catalog_usage_error)?;
        if valued.contains(&value) {
            if index + 1 >= args.len() {
                return Err(catalog_usage_error());
            }
            index += 2;
        } else if flags.contains(&value) {
            index += 1;
        } else {
            return Err(invalid_input(format!("unknown catalog option: {value}")));
        }
    }
    Ok(())
}

fn required_catalog_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    required_catalog_string(args, name).map(PathBuf::from)
}

fn required_catalog_string(args: &[OsString], name: &str) -> io::Result<String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(catalog_usage_error)?;
    args.get(index + 1)
        .and_then(|value| value.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(catalog_usage_error)
}

fn optional_catalog_string(args: &[OsString], name: &str) -> io::Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    args.get(index + 1)
        .and_then(|value| value.to_str())
        .map(|value| Some(value.to_owned()))
        .ok_or_else(catalog_usage_error)
}

fn has_catalog_flag(args: &[OsString], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

pub(crate) fn safe_catalog_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value != "."
        && value != ".."
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

pub(crate) fn catalog_invalid_data(message: impl Into<String>) -> io::Error {
    invalid_data(message)
}

fn invalid_json(error: serde_json::Error) -> io::Error {
    invalid_data(format!("cannot encode catalog JSON: {error}"))
}

fn catalog_usage_error() -> io::Error {
    invalid_input(
        "usage: gensee boundary catalog <template|sign|verify|install|status|public-key> ...",
    )
}

fn print_catalog_usage() {
    println!(
        "gensee boundary catalog\n\nUSAGE:\n  gensee boundary catalog template --profile <deny-all|structured-result> --contract-id <id> --operation-class <class> [--product-path <path> --verifier-profile <id> [--destination-root <dir> --active-pointer <name>]] --output <contract.json>\n  gensee boundary catalog public-key --key <seed.hex> --output <public.hex>\n  gensee boundary catalog sign --catalog <catalog.json> --key <seed.hex> --key-id <id> --output <signed.json>\n  gensee boundary catalog verify --catalog <signed.json> --trusted-key <public.hex> [--json]\n  gensee boundary catalog install --catalog <signed.json> --trusted-key <public.hex> --root <trusted-dir>\n  gensee boundary catalog status --root <trusted-dir> --trusted-key <public.hex> [--json]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use gensee_crate_rules::contract_catalog::*;
    use gensee_crate_rules::operation_contract::{
        ContractCapabilities, ExecutionContract, OperationContract,
        OPERATION_CONTRACT_SCHEMA_VERSION,
    };

    fn unsigned_catalog(public_key_hex: String) -> ContractCatalog {
        ContractCatalog {
            schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
            catalog_id: "test_catalog".into(),
            organization_id: "test_org".into(),
            version: 1,
            issued_at_ms: 10,
            expires_at_ms: u64::MAX,
            contracts: vec![ApprovedContract {
                contract: OperationContract {
                    schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
                    contract_id: "safe_transform".into(),
                    operation_class: "transform".into(),
                    execution: ExecutionContract::default(),
                    capabilities: ContractCapabilities::default(),
                    product: None,
                },
                owner: ContractOwner {
                    application_id: "test_app".into(),
                    owning_team: "security".into(),
                },
                approval: ContractApproval {
                    approval_id: "approval_1".into(),
                    approved_by: "reviewer".into(),
                    approved_at_ms: 10,
                    expires_at_ms: u64::MAX - 1,
                },
            }],
            selectors: vec![ContractSelector {
                selector_id: "test_transform".into(),
                caller: CallerSelector {
                    uid: Some(1000),
                    executable_sha256: None,
                    service_identity: None,
                },
                operation_class: "transform".into(),
                contract_id: "safe_transform".into(),
            }],
            intent_analyzers: vec![ApprovedIntentAnalyzer {
                analyzer_id: "analyzer".into(),
                public_key_hex,
                model_identity: "model_v1".into(),
                minimum_confidence_bps: 8000,
                allowed_operation_classes: vec!["transform".into()],
            }],
            operation_services: Vec::new(),
            semantic_verifiers: Vec::new(),
            fallback: FallbackPolicy {
                on_ambiguous_intent: AmbiguousIntentAction::Deny,
                safe_default_contract_id: None,
            },
        }
    }

    #[test]
    fn signature_binds_every_catalog_field() {
        let temp = temp_dir("catalog-signature");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let trusted = temp.join("trusted.hex");
        fs::write(
            &trusted,
            hex::encode(signing_key.verifying_key().as_bytes()),
        )
        .unwrap();
        let catalog = unsigned_catalog(hex::encode(signing_key.verifying_key().as_bytes()));
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let mut signed = SignedContractCatalog {
            catalog,
            signature: CatalogSignature {
                algorithm: "ed25519".into(),
                key_id: "org_root".into(),
                public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
                signature_hex: hex::encode(signing_key.sign(&bytes).to_bytes()),
            },
        };
        assert!(verify_signed_catalog(&signed, &trusted, 100).is_ok());
        signed.catalog.contracts[0]
            .contract
            .execution
            .max_runtime_seconds += 1;
        assert!(verify_signed_catalog(&signed, &trusted, 100).is_err());
    }

    #[test]
    fn safe_template_is_deny_by_default() {
        let temp = temp_dir("catalog-template");
        let output = temp.join("contract.json");
        template_command(&[
            "--profile".into(),
            "deny-all".into(),
            "--contract-id".into(),
            "safe_default".into(),
            "--operation-class".into(),
            "unknown_operation".into(),
            "--output".into(),
            output.as_os_str().to_owned(),
        ])
        .unwrap();
        let contract: OperationContract = read_catalog_json(&output, "template").unwrap();
        assert!(matches!(
            contract.capabilities.network.mode,
            gensee_crate_rules::operation_contract::ContractNetworkMode::DenyAll
        ));
        assert!(contract.product.is_none());
        fs::remove_dir_all(temp).unwrap();
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("gensee-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
