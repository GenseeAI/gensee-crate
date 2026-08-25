use crate::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use gensee_crate_rules::boundary_proof::{
    BoundaryProofArtifact, BoundaryProofClaims, SignedBoundaryProof, BOUNDARY_PROOF_SCHEMA_VERSION,
};
use gensee_crate_rules::contract_catalog::{
    IntentObservation, SignedContractCatalog, SignedIntentInference,
};
use gensee_crate_rules::operation_contract::OperationRunManifest;
use gensee_crate_rules::semantic_verifier::{SignedVerifierReceipt, VerifierRequest};
use gensee_crate_rules::transactional_promotion::TransactionalPromotionReceipt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

const PROOF_FILES: &[&str] = &[
    "catalog.signed.json",
    "organization-public.hex",
    "observation.json",
    "inference.signed.json",
    "operation-manifest.json",
    "verifier-request.json",
    "verifier-receipt.json",
    "promotion-receipt.json",
];

pub(crate) fn handle_boundary_proof(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(proof_usage_error)?;
    match command.to_str() {
        Some("sign") => sign_proof(rest),
        Some("verify") => verify_proof_command(rest),
        Some("--help" | "-h") => {
            print_proof_usage();
            Ok(())
        }
        _ => Err(proof_usage_error()),
    }
}

fn sign_proof(args: &[OsString]) -> io::Result<()> {
    reject_options(args, &["--bundle", "--key"])?;
    let bundle = required_path(args, "--bundle")?;
    let created_at_ms = unix_millis()?;
    let evidence = validate_bundle_evidence(&bundle, created_at_ms, true)?;
    let artifacts = hash_proof_artifacts(&bundle)?;
    let claims = BoundaryProofClaims {
        schema_version: BOUNDARY_PROOF_SCHEMA_VERSION,
        proof_id: format!("proof_{}", uuid::Uuid::new_v4().simple()),
        operation_id: evidence.manifest.operation_id.clone(),
        created_at_ms,
        os_execution_binding_established: evidence
            .manifest
            .enforcement
            .os_execution_binding_established,
        allowed_packets: evidence.allowed_packets,
        denied_packets: evidence.denied_packets,
        execution_subject_drained: evidence.manifest.process.execution_subject_drained,
        product_digest: evidence.product_digest,
        active_target: evidence.promotion.active_target,
        artifacts,
    };
    let key = read_signing_key(&required_path(args, "--key")?)?;
    let bytes = serde_json::to_vec(&claims).map_err(json_error)?;
    let proof = SignedBoundaryProof {
        claims,
        algorithm: "ed25519".into(),
        public_key_hex: hex::encode(key.verifying_key().as_bytes()),
        signature_hex: hex::encode(key.sign(&bytes).to_bytes()),
    };
    write_atomic_nofollow(
        &bundle.join("proof.json"),
        &serde_json::to_vec_pretty(&proof).map_err(json_error)?,
        0o600,
    )?;
    println!("signed generic boundary proof: {}", proof.claims.proof_id);
    Ok(())
}

fn verify_proof_command(args: &[OsString]) -> io::Result<()> {
    reject_options(args, &["--bundle", "--trusted-key"])?;
    let bundle = required_path(args, "--bundle")?;
    let proof: SignedBoundaryProof =
        read_catalog_json(&bundle.join("proof.json"), "signed boundary proof")?;
    if proof.algorithm != "ed25519" || proof.claims.schema_version != BOUNDARY_PROOF_SCHEMA_VERSION
    {
        return Err(invalid_data(
            "unsupported boundary proof signature or schema",
        ));
    }
    let trusted = read_hex_array::<32>(
        &required_path(args, "--trusted-key")?,
        "trusted proof public key",
    )?;
    let embedded = decode_hex_array::<32>(&proof.public_key_hex, "proof public key")?;
    if trusted != embedded {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "boundary proof key does not match the trusted key",
        ));
    }
    let signature = decode_hex_array::<64>(&proof.signature_hex, "proof signature")?;
    VerifyingKey::from_bytes(&trusted)
        .map_err(|error| invalid_data(format!("invalid proof public key: {error}")))?
        .verify(
            &serde_json::to_vec(&proof.claims).map_err(json_error)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| invalid_data(format!("invalid boundary proof signature: {error}")))?;
    verify_artifact_manifest(&bundle, &proof.claims.artifacts)?;
    let evidence = validate_bundle_evidence(&bundle, proof.claims.created_at_ms, false)?;
    if proof.claims.operation_id != evidence.manifest.operation_id
        || !proof.claims.os_execution_binding_established
        || proof.claims.allowed_packets != evidence.allowed_packets
        || proof.claims.denied_packets != evidence.denied_packets
        || proof.claims.allowed_packets == 0
        || proof.claims.denied_packets == 0
        || !proof.claims.execution_subject_drained
        || proof.claims.product_digest != evidence.product_digest
        || proof.claims.active_target != evidence.promotion.active_target
    {
        return Err(invalid_data(
            "boundary proof claims do not match independently verified evidence",
        ));
    }
    println!(
        "verified generic boundary proof {}: allowed={} denied={} product={}",
        proof.claims.proof_id,
        proof.claims.allowed_packets,
        proof.claims.denied_packets,
        proof.claims.product_digest
    );
    Ok(())
}

struct VerifiedBundleEvidence {
    manifest: OperationRunManifest,
    promotion: TransactionalPromotionReceipt,
    allowed_packets: u64,
    denied_packets: u64,
    product_digest: String,
}

fn validate_bundle_evidence(
    bundle: &Path,
    validation_time_ms: u64,
    verify_local_promotion_signature: bool,
) -> io::Result<VerifiedBundleEvidence> {
    let catalog: SignedContractCatalog =
        read_catalog_json(&bundle.join(PROOF_FILES[0]), "signed contract catalog")?;
    verify_signed_catalog(&catalog, &bundle.join(PROOF_FILES[1]), validation_time_ms)?;
    let observation: IntentObservation =
        read_catalog_json(&bundle.join(PROOF_FILES[2]), "intent observation")?;
    let inference: SignedIntentInference =
        read_catalog_json(&bundle.join(PROOF_FILES[3]), "signed intent inference")?;
    let resolution =
        verify_intent_evidence(&catalog, &observation, &inference, validation_time_ms)?;
    let manifest: OperationRunManifest =
        read_catalog_json(&bundle.join(PROOF_FILES[4]), "operation run manifest")?;
    let request: VerifierRequest =
        read_catalog_json(&bundle.join(PROOF_FILES[5]), "semantic verifier request")?;
    let receipt: SignedVerifierReceipt =
        read_catalog_json(&bundle.join(PROOF_FILES[6]), "semantic verifier receipt")?;
    verify_semantic_receipt(&catalog, &request, &receipt, validation_time_ms)?;
    let promotion: TransactionalPromotionReceipt = read_catalog_json(
        &bundle.join(PROOF_FILES[7]),
        "transactional promotion receipt",
    )?;
    if verify_local_promotion_signature {
        verify_promotion_receipt(&promotion)?;
    }
    if manifest.admission.catalog_id != catalog.catalog.catalog_id
        || manifest.admission.catalog_version != catalog.catalog.version
        || manifest.admission.selected_operation_class != resolution.selected_operation_class
        || manifest.contract_id != resolution.selected_contract_id
        || request.operation_id != manifest.operation_id
        || receipt.claims.operation_id != manifest.operation_id
        || promotion.operation_id != manifest.operation_id
    {
        return Err(invalid_data(
            "proof artifacts do not share one resolved operation identity",
        ));
    }
    let product = manifest
        .product
        .as_ref()
        .filter(|product| product.structurally_valid)
        .ok_or_else(|| invalid_data("proof operation has no structurally valid product"))?;
    if receipt.claims.product_digest != product.digest
        || promotion.product_digest != product.digest
        || promotion.verifier_receipt_digest != digest_json(&receipt)?
    {
        return Err(invalid_data(
            "proof verifier/promotion product bindings do not match",
        ));
    }
    let approved = catalog
        .catalog
        .contract(&manifest.contract_id)
        .and_then(|approved| approved.contract.product.as_ref())
        .ok_or_else(|| invalid_data("proof contract product is unavailable"))?;
    let promoted = verify_structural_product(&bundle.join("promoted-workspace"), approved)?;
    if !promoted.structurally_valid || promoted.digest != product.digest {
        return Err(invalid_data(
            "bundled promoted product does not match the operation product",
        ));
    }
    let allowed_packets = manifest
        .enforcement
        .allowed_network_effects
        .iter()
        .map(|effect| effect.packets)
        .sum::<u64>();
    let denied_packets = manifest
        .enforcement
        .denied_network_effects
        .iter()
        .map(|effect| effect.packets)
        .sum::<u64>();
    if !manifest.enforcement.os_execution_binding_established
        || allowed_packets == 0
        || denied_packets == 0
        || !manifest.process.execution_subject_drained
    {
        return Err(invalid_data(
            "proof lacks required execution binding, allowed/denied traffic, or descendant drain",
        ));
    }
    Ok(VerifiedBundleEvidence {
        manifest,
        promotion,
        allowed_packets,
        denied_packets,
        product_digest: promoted.digest,
    })
}

fn hash_proof_artifacts(bundle: &Path) -> io::Result<Vec<BoundaryProofArtifact>> {
    PROOF_FILES
        .iter()
        .map(|relative| {
            let (sha256, bytes) = hash_file(&bundle.join(relative))?;
            Ok(BoundaryProofArtifact {
                path: relative.to_string(),
                sha256,
                bytes,
            })
        })
        .collect()
}

fn verify_artifact_manifest(bundle: &Path, artifacts: &[BoundaryProofArtifact]) -> io::Result<()> {
    if artifacts.len() != PROOF_FILES.len() {
        return Err(invalid_data("boundary proof artifact set is incomplete"));
    }
    for expected in PROOF_FILES {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.path == *expected)
            .ok_or_else(|| invalid_data("boundary proof artifact is missing"))?;
        safe_relative_path(&artifact.path)?;
        let (digest, bytes) = hash_file(&bundle.join(&artifact.path))?;
        if digest != artifact.sha256 || bytes != artifact.bytes {
            return Err(invalid_data("boundary proof artifact hash mismatch"));
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<(String, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_data("proof artifact is not a regular file"));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), bytes))
}

fn digest_json(value: &impl Serialize) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(json_error)?)
    ))
}

fn safe_relative_path(value: &str) -> io::Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || value.contains("//")
        || value.contains('\\')
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid_data("unsafe proof artifact path"));
    }
    Ok(())
}

fn reject_options(args: &[OsString], valued: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(proof_usage_error)?;
        if valued.contains(&value) && index + 1 < args.len() {
            index += 2;
        } else {
            return Err(invalid_input(format!("unknown proof option: {value}")));
        }
    }
    Ok(())
}

fn required_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(proof_usage_error)?;
    args.get(index + 1)
        .map(PathBuf::from)
        .ok_or_else(proof_usage_error)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn json_error(error: serde_json::Error) -> io::Error {
    invalid_data(format!("cannot encode boundary proof: {error}"))
}

fn proof_usage_error() -> io::Error {
    invalid_input("usage: gensee boundary proof <sign|verify> ...")
}

fn print_proof_usage() {
    println!(
        "gensee boundary proof\n\nUSAGE:\n  gensee boundary proof sign --bundle <directory> --key <seed.hex>\n  gensee boundary proof verify --bundle <directory> --trusted-key <public.hex>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_paths_are_single_relative_components_or_normal_subpaths() {
        assert!(safe_relative_path("operation-manifest.json").is_ok());
        assert!(safe_relative_path("evidence/manifest.json").is_ok());
        for value in [
            "",
            ".",
            "..",
            "../proof.json",
            "/proof.json",
            "a//b",
            "a\\b",
        ] {
            assert!(safe_relative_path(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn artifact_manifest_detects_post_signature_mutation() {
        let root = std::env::temp_dir().join(format!(
            "gensee-boundary-proof-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        for path in PROOF_FILES {
            fs::write(root.join(path), format!("fixture:{path}\n")).unwrap();
        }
        let artifacts = hash_proof_artifacts(&root).unwrap();
        verify_artifact_manifest(&root, &artifacts).unwrap();
        fs::write(root.join(PROOF_FILES[0]), b"tampered\n").unwrap();
        assert!(verify_artifact_manifest(&root, &artifacts).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
