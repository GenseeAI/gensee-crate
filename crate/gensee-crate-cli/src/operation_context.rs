use crate::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::SignedContractCatalog;
use gensee_crate_rules::operation_context::{
    DownstreamEffectClaims, OperationContextChain, OperationContextClaims,
    OperationContextSignature, SignedDownstreamEffect, SignedOperationContext,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

pub(crate) fn handle_operation_context(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(context_usage_error)?;
    match command.to_str() {
        Some("issue") => issue_context(rest),
        Some("verify") => verify_context_command(rest),
        Some("effect-sign") => sign_effect(rest),
        Some("effect-verify") => verify_effect_command(rest),
        Some("--help" | "-h") => {
            print_context_usage();
            Ok(())
        }
        _ => Err(context_usage_error()),
    }
}

fn issue_context(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--claims",
            "--service-key",
            "--parent-chain",
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
    let claims: OperationContextClaims = read_catalog_json(
        &required_path(args, "--claims")?,
        "operation context claims",
    )?;
    let mut chain = optional_path(args, "--parent-chain")?
        .map(|path| read_catalog_json::<OperationContextChain>(&path, "operation context chain"))
        .transpose()?
        .unwrap_or(OperationContextChain {
            contexts: Vec::new(),
        });
    if !chain.contexts.is_empty() {
        verify_context_chain(&chain, &signed_catalog, unix_millis()?, None)?;
    }
    validate_next_claims(&claims, &chain, &signed_catalog, unix_millis()?)?;
    let key = read_signing_key(&required_path(args, "--service-key")?)?;
    let service = signed_catalog
        .catalog
        .operation_services
        .iter()
        .find(|service| service.service_id == claims.issuer_service)
        .ok_or_else(|| invalid_data("context issuer is not approved"))?;
    if hex::encode(key.verifying_key().as_bytes()) != service.public_key_hex.to_lowercase() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "service signing key does not match the approved issuer",
        ));
    }
    let claims_bytes = serde_json::to_vec(&claims).map_err(json_error)?;
    chain.contexts.push(SignedOperationContext {
        claims,
        signature: OperationContextSignature {
            algorithm: "ed25519".into(),
            signature_hex: hex::encode(key.sign(&claims_bytes).to_bytes()),
        },
    });
    write_json(&required_path(args, "--output")?, &chain)?;
    println!(
        "issued operation context generation {}",
        chain.contexts.len() - 1
    );
    Ok(())
}

fn verify_context_command(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &["--catalog", "--trusted-key", "--chain", "--audience"],
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
    let chain: OperationContextChain =
        read_catalog_json(&required_path(args, "--chain")?, "operation context chain")?;
    let audience = optional_string(args, "--audience")?;
    let tail = verify_context_chain(&chain, &signed_catalog, unix_millis()?, audience.as_deref())?;
    if has_flag(args, "--json") {
        let mut encoded = serde_json::to_vec_pretty(tail).map_err(json_error)?;
        encoded.push(b'\n');
        io::stdout().write_all(&encoded)
    } else {
        println!(
            "verified operation {} generation {} for {}",
            tail.operation_id, tail.generation, tail.audience_service
        );
        Ok(())
    }
}

fn sign_effect(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--chain",
            "--claims",
            "--service-key",
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
    let chain: OperationContextChain =
        read_catalog_json(&required_path(args, "--chain")?, "operation context chain")?;
    let context = verify_context_chain(&chain, &signed_catalog, unix_millis()?, None)?;
    let claims: DownstreamEffectClaims = read_catalog_json(
        &required_path(args, "--claims")?,
        "downstream effect claims",
    )?;
    let context_digest = digest_signed_context(chain.contexts.last().unwrap())?;
    claims
        .validate_for_context(context, &context_digest)
        .map_err(invalid_data)?;
    let key = read_signing_key(&required_path(args, "--service-key")?)?;
    let service = signed_catalog
        .catalog
        .operation_services
        .iter()
        .find(|service| service.service_id == claims.service_id)
        .ok_or_else(|| invalid_data("effect service is not approved"))?;
    if hex::encode(key.verifying_key().as_bytes()) != service.public_key_hex.to_lowercase() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "effect signing key does not match the approved service",
        ));
    }
    let claims_bytes = serde_json::to_vec(&claims).map_err(json_error)?;
    let effect = SignedDownstreamEffect {
        claims,
        signature: OperationContextSignature {
            algorithm: "ed25519".into(),
            signature_hex: hex::encode(key.sign(&claims_bytes).to_bytes()),
        },
    };
    write_json(&required_path(args, "--output")?, &effect)
}

fn verify_effect_command(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &["--catalog", "--trusted-key", "--chain", "--effect"],
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
    let chain: OperationContextChain =
        read_catalog_json(&required_path(args, "--chain")?, "operation context chain")?;
    let context = verify_context_chain(&chain, &signed_catalog, unix_millis()?, None)?;
    let effect: SignedDownstreamEffect = read_catalog_json(
        &required_path(args, "--effect")?,
        "signed downstream effect",
    )?;
    let context_digest = digest_signed_context(chain.contexts.last().unwrap())?;
    effect
        .claims
        .validate_for_context(context, &context_digest)
        .map_err(invalid_data)?;
    verify_service_signature(
        &signed_catalog,
        &effect.claims.service_id,
        &serde_json::to_vec(&effect.claims).map_err(json_error)?,
        &effect.signature,
    )?;
    println!("verified downstream effect: {}", effect.claims.effect_id);
    Ok(())
}

pub(crate) fn verify_context_chain<'a>(
    chain: &'a OperationContextChain,
    catalog: &SignedContractCatalog,
    now_ms: u64,
    expected_audience: Option<&str>,
) -> io::Result<&'a OperationContextClaims> {
    if chain.contexts.is_empty() || chain.contexts.len() > 32 {
        return Err(invalid_data("operation context chain is empty or too deep"));
    }
    for (index, signed) in chain.contexts.iter().enumerate() {
        let claims_bytes = serde_json::to_vec(&signed.claims).map_err(json_error)?;
        verify_service_signature(
            catalog,
            &signed.claims.issuer_service,
            &claims_bytes,
            &signed.signature,
        )?;
        if index == 0 {
            verify_root_authority_binding(&signed.claims, catalog)?;
            signed
                .claims
                .validate_root(&catalog.catalog, now_ms)
                .map_err(invalid_data)?;
        } else {
            let parent = &chain.contexts[index - 1];
            let digest = digest_signed_context(parent)?;
            signed
                .claims
                .validate_child(&parent.claims, &digest, &catalog.catalog, now_ms)
                .map_err(invalid_data)?;
        }
    }
    let tail = &chain.contexts.last().unwrap().claims;
    if expected_audience.is_some_and(|audience| audience != tail.audience_service) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "operation context audience does not match this service",
        ));
    }
    Ok(tail)
}

fn verify_root_authority_binding(
    claims: &OperationContextClaims,
    catalog: &SignedContractCatalog,
) -> io::Result<()> {
    let catalog_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&catalog.catalog).map_err(json_error)?)
    );
    if claims.catalog_digest != catalog_digest {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "root operation context is not bound to the verified catalog",
        ));
    }
    let contract_is_approved = catalog.catalog.contracts.iter().any(|approved| {
        serde_json::to_vec(&approved.contract)
            .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)) == claims.contract_digest)
            .unwrap_or(false)
    });
    if !contract_is_approved {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "root operation context is not bound to an approved catalog contract",
        ));
    }
    Ok(())
}

fn validate_next_claims(
    claims: &OperationContextClaims,
    chain: &OperationContextChain,
    catalog: &SignedContractCatalog,
    now_ms: u64,
) -> io::Result<()> {
    if let Some(parent) = chain.contexts.last() {
        claims
            .validate_child(
                &parent.claims,
                &digest_signed_context(parent)?,
                &catalog.catalog,
                now_ms,
            )
            .map(|_| ())
            .map_err(invalid_data)
    } else {
        verify_root_authority_binding(claims, catalog)?;
        claims
            .validate_root(&catalog.catalog, now_ms)
            .map(|_| ())
            .map_err(invalid_data)
    }
}

fn verify_service_signature(
    catalog: &SignedContractCatalog,
    service_id: &str,
    bytes: &[u8],
    signature: &OperationContextSignature,
) -> io::Result<()> {
    if signature.algorithm != "ed25519" {
        return Err(invalid_data("unsupported operation-context signature"));
    }
    let service = catalog
        .catalog
        .operation_services
        .iter()
        .find(|service| service.service_id == service_id)
        .ok_or_else(|| invalid_data("operation service is not approved"))?;
    let public_key = decode_hex_array::<32>(&service.public_key_hex, "service public key")?;
    let signature_bytes =
        decode_hex_array::<64>(&signature.signature_hex, "operation-context signature")?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| invalid_data(format!("invalid service key: {error}")))?
        .verify(bytes, &Signature::from_bytes(&signature_bytes))
        .map_err(|error| invalid_data(format!("invalid operation-context signature: {error}")))
}

fn digest_signed_context(context: &SignedOperationContext) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(context).map_err(json_error)?)
    ))
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
        let value = args[index].to_str().ok_or_else(context_usage_error)?;
        if valued.contains(&value) {
            if index + 1 >= args.len() {
                return Err(context_usage_error());
            }
            index += 2;
        } else if flags.contains(&value) {
            index += 1;
        } else {
            return Err(invalid_input(format!("unknown context option: {value}")));
        }
    }
    Ok(())
}

fn required_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    optional_path(args, name)?.ok_or_else(context_usage_error)
}

fn optional_path(args: &[OsString], name: &str) -> io::Result<Option<PathBuf>> {
    Ok(args
        .iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1))
        .map(PathBuf::from))
}

fn optional_string(args: &[OsString], name: &str) -> io::Result<Option<String>> {
    optional_path(args, name).map(|value| value.map(|path| path.to_string_lossy().to_string()))
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
    invalid_data(format!("cannot encode operation context: {error}"))
}

fn context_usage_error() -> io::Error {
    invalid_input("usage: gensee boundary context <issue|verify|effect-sign|effect-verify> ...")
}

fn print_context_usage() {
    println!(
        "gensee boundary context\n\nUSAGE:\n  gensee boundary context issue --catalog <signed.json> --trusted-key <org.hex> --claims <claims.json> --service-key <seed.hex> [--parent-chain <chain.json>] --output <chain.json>\n  gensee boundary context verify --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> [--audience <service>] [--json]\n  gensee boundary context effect-sign --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --claims <effect.json> --service-key <seed.hex> --output <signed-effect.json>\n  gensee boundary context effect-verify --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --effect <signed-effect.json>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use gensee_crate_rules::capability_broker::BrokerResourceKind;
    use gensee_crate_rules::contract_catalog::{
        AmbiguousIntentAction, ApprovedContract, ApprovedOperationService, CatalogSignature,
        ContractApproval, ContractCatalog, ContractOwner, FallbackPolicy,
        CONTRACT_CATALOG_SCHEMA_VERSION,
    };
    use gensee_crate_rules::operation_context::{ContextGrant, OPERATION_CONTEXT_SCHEMA_VERSION};
    use gensee_crate_rules::operation_contract::{
        ContractCapabilities, ExecutionContract, OperationContract,
        OPERATION_CONTRACT_SCHEMA_VERSION,
    };

    #[test]
    fn signed_chain_verifies_attenuation_and_audience() {
        let root_key = SigningKey::from_bytes(&[31; 32]);
        let worker_key = SigningKey::from_bytes(&[32; 32]);
        let catalog = SignedContractCatalog {
            catalog: ContractCatalog {
                schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
                catalog_id: "catalog".into(),
                organization_id: "organization".into(),
                version: 1,
                issued_at_ms: 1,
                expires_at_ms: 10_000,
                contracts: vec![ApprovedContract {
                    contract: OperationContract {
                        schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
                        contract_id: "contract_one".into(),
                        operation_class: "transform".into(),
                        execution: ExecutionContract::default(),
                        capabilities: ContractCapabilities::default(),
                        product: None,
                    },
                    owner: ContractOwner {
                        application_id: "entry_app".into(),
                        owning_team: "security".into(),
                    },
                    approval: ContractApproval {
                        approval_id: "approval_one".into(),
                        approved_by: "reviewer".into(),
                        approved_at_ms: 1,
                        expires_at_ms: 9_000,
                    },
                }],
                selectors: Vec::new(),
                intent_analyzers: Vec::new(),
                operation_services: vec![
                    ApprovedOperationService {
                        service_id: "entry_service".into(),
                        public_key_hex: hex::encode(root_key.verifying_key().as_bytes()),
                        can_initiate: true,
                        allowed_audiences: vec!["worker_service".into()],
                    },
                    ApprovedOperationService {
                        service_id: "worker_service".into(),
                        public_key_hex: hex::encode(worker_key.verifying_key().as_bytes()),
                        can_initiate: false,
                        allowed_audiences: vec!["worker_service".into()],
                    },
                ],
                semantic_verifiers: Vec::new(),
                fallback: FallbackPolicy {
                    on_ambiguous_intent: AmbiguousIntentAction::Deny,
                    safe_default_contract_id: None,
                },
            },
            signature: CatalogSignature {
                algorithm: "ed25519".into(),
                key_id: "unused_in_unit".into(),
                public_key_hex: String::new(),
                signature_hex: String::new(),
            },
        };
        let grant = ContextGrant {
            grant_id: "grant_one".into(),
            resource_kind: BrokerResourceKind::HttpApiCall,
            scope_digest: format!("sha256:{}", "11".repeat(32)),
            lease_generation: 3,
            expires_at_ms: 900,
        };
        let catalog_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&catalog.catalog).unwrap())
        );
        let contract_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&catalog.catalog.contracts[0].contract).unwrap())
        );
        let root_claims = OperationContextClaims {
            schema_version: OPERATION_CONTEXT_SCHEMA_VERSION,
            token_id: "context_root".into(),
            operation_id: "operation_one".into(),
            generation: 0,
            issuer_service: "entry_service".into(),
            audience_service: "worker_service".into(),
            catalog_digest: catalog_digest.clone(),
            contract_digest: contract_digest.clone(),
            issued_at_ms: 100,
            expires_at_ms: 900,
            parent_context_digest: None,
            grants: vec![grant.clone()],
        };
        let root = sign_context(root_claims, &root_key);
        let mut child_grant = grant;
        child_grant.expires_at_ms = 800;
        let child_claims = OperationContextClaims {
            schema_version: OPERATION_CONTEXT_SCHEMA_VERSION,
            token_id: "context_child".into(),
            operation_id: "operation_one".into(),
            generation: 1,
            issuer_service: "worker_service".into(),
            audience_service: "worker_service".into(),
            catalog_digest,
            contract_digest,
            issued_at_ms: 101,
            expires_at_ms: 800,
            parent_context_digest: Some(digest_signed_context(&root).unwrap()),
            grants: vec![child_grant],
        };
        let child = sign_context(child_claims, &worker_key);
        let chain = OperationContextChain {
            contexts: vec![root, child],
        };
        let tail = verify_context_chain(&chain, &catalog, 200, Some("worker_service")).unwrap();
        assert_eq!(tail.generation, 1);

        let mut widened = chain.clone();
        widened.contexts[1].claims.grants[0].scope_digest = format!("sha256:{}", "44".repeat(32));
        widened.contexts[1] = sign_context(widened.contexts[1].claims.clone(), &worker_key);
        assert!(verify_context_chain(&widened, &catalog, 200, None).is_err());

        let mut invented_catalog = chain.clone();
        invented_catalog.contexts[0].claims.catalog_digest = format!("sha256:{}", "22".repeat(32));
        invented_catalog.contexts[0] =
            sign_context(invented_catalog.contexts[0].claims.clone(), &root_key);
        assert!(verify_context_chain(&invented_catalog, &catalog, 200, None).is_err());

        let mut invented_contract = chain.clone();
        invented_contract.contexts[0].claims.contract_digest =
            format!("sha256:{}", "33".repeat(32));
        invented_contract.contexts[0] =
            sign_context(invented_contract.contexts[0].claims.clone(), &root_key);
        assert!(verify_context_chain(&invented_contract, &catalog, 200, None).is_err());
    }

    fn sign_context(claims: OperationContextClaims, key: &SigningKey) -> SignedOperationContext {
        let bytes = serde_json::to_vec(&claims).unwrap();
        SignedOperationContext {
            claims,
            signature: OperationContextSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(key.sign(&bytes).to_bytes()),
            },
        }
    }
}
