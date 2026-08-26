use crate::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::SignedContractCatalog;
use gensee_crate_rules::operation_contract::{OperationManifestSignature, OperationRunManifest};
use gensee_crate_rules::semantic_verifier::{
    SignedVerifierReceipt, VerifierReceiptClaims, VerifierReceiptSignature, VerifierRequest,
    SEMANTIC_VERIFIER_SCHEMA_VERSION,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

const MAX_VERIFIER_TTL_SECONDS: u64 = 300;
const OPERATION_MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"gensee-operation-run-manifest-v1\0";
const OPERATION_MANIFEST_SIGNING_KEY: &str = "/etc/gensee/operation-manifest-signing-key.hex";
const OPERATION_MANIFEST_PUBLIC_KEY: &str = "/etc/gensee/operation-manifest-public-key.hex";

pub(crate) fn handle_semantic_verifier(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(verifier_usage_error)?;
    match command.to_str() {
        Some("request") => create_request(rest),
        Some("sign") => sign_receipt(rest),
        Some("verify") => verify_receipt_command(rest),
        Some("--help" | "-h") => {
            print_verifier_usage();
            Ok(())
        }
        _ => Err(verifier_usage_error()),
    }
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

fn sign_operation_manifest_with_key(
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

fn verify_operation_manifest_with_key(
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
    invalid_input("usage: gensee boundary verifier <request|sign|verify> ...")
}

fn print_verifier_usage() {
    println!(
        "gensee boundary verifier\n\nUSAGE:\n  gensee boundary verifier request --manifest <operation.json> --ttl-seconds <n> --output <request.json>\n  gensee boundary verifier sign --catalog <signed.json> --trusted-key <org.hex> --request <request.json> --claims <claims.json> --verifier-key <seed.hex> --output <receipt.json>\n  gensee boundary verifier verify --catalog <signed.json> --trusted-key <org.hex> --request <request.json> --receipt <receipt.json> [--json]"
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
                process_group_drained: true,
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
}
