use crate::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use gensee_crate_rules::contract_catalog::SignedContractCatalog;
use gensee_crate_rules::operation_context::{
    DownstreamEffectClaims, OperationContextChain, OperationContextClaims,
    OperationContextSignature, OperationTransportClaims, SignedDownstreamEffect,
    SignedOperationContext, SignedOperationTransport, OPERATION_TRANSPORT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const TRANSPORT_NONCE_RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_LIVE_TRANSPORT_NONCES_PER_RECIPIENT: usize = 1_024;
const MAX_LIVE_TRANSPORT_NONCES_TOTAL: usize = 8_192;
const MAX_TRANSPORT_NONCE_RECORD_BYTES: u64 = 4 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedTransportNonceRecord {
    schema_version: u32,
    envelope_id: String,
    context_digest: String,
    recipient_service: String,
    nonce_digest: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[cfg(unix)]
struct TransportNonceStoreLock(File);

#[cfg(unix)]
impl TransportNonceStoreLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

#[cfg(unix)]
impl Drop for TransportNonceStoreLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
struct TransportNonceStoreLock;

#[cfg(not(unix))]
impl TransportNonceStoreLock {
    fn acquire(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "durable operation transport replay protection requires file locking",
        ))
    }
}

pub(crate) fn handle_operation_context(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(context_usage_error)?;
    match command.to_str() {
        Some("issue") => issue_context(rest),
        Some("verify") => verify_context_command(rest),
        Some("effect-sign") => sign_effect(rest),
        Some("effect-verify") => verify_effect_command(rest),
        Some("transport-wrap") => wrap_transport(rest),
        Some("transport-verify") => verify_transport(rest),
        Some("--help" | "-h") => {
            print_context_usage();
            Ok(())
        }
        _ => Err(context_usage_error()),
    }
}

fn wrap_transport(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--chain",
            "--payload",
            "--content-type",
            "--service-key",
            "--ttl-seconds",
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
    let chain: OperationContextChain =
        read_catalog_json(&required_path(args, "--chain")?, "operation context chain")?;
    let tail = verify_context_chain(&chain, &catalog, now, None)?;
    let payload = read_transport_payload(&required_path(args, "--payload")?)?;
    let ttl = required_context_u64(args, "--ttl-seconds")?;
    if ttl == 0 || ttl > 900 {
        return Err(invalid_input("transport TTL must be in 1..=900 seconds"));
    }
    let expires = now
        .saturating_add(ttl.saturating_mul(1000))
        .min(tail.expires_at_ms);
    let context_digest = digest_signed_context(chain.contexts.last().unwrap())?;
    let claims = OperationTransportClaims {
        schema_version: OPERATION_TRANSPORT_SCHEMA_VERSION,
        envelope_id: format!("envelope_{}", uuid::Uuid::new_v4().simple()),
        context_digest,
        sender_service: tail.issuer_service.clone(),
        recipient_service: tail.audience_service.clone(),
        payload_digest: format!("sha256:{:x}", Sha256::digest(&payload)),
        content_type: required_context_string(args, "--content-type")?,
        nonce: format!("nonce_{}", uuid::Uuid::new_v4().simple()),
        issued_at_ms: now,
        expires_at_ms: expires,
    };
    claims
        .validate_for_context(tail, &claims.context_digest, &claims.sender_service, now)
        .map_err(invalid_data)?;
    let key = read_signing_key(&required_path(args, "--service-key")?)?;
    let service = catalog
        .catalog
        .operation_services
        .iter()
        .find(|s| s.service_id == claims.sender_service)
        .ok_or_else(|| invalid_data("transport sender is not approved"))?;
    if hex::encode(key.verifying_key().as_bytes()) != service.public_key_hex.to_lowercase() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "transport signing key does not match sender",
        ));
    }
    let encoded = serde_json::to_vec(&claims).map_err(json_error)?;
    write_json(
        &required_path(args, "--output")?,
        &SignedOperationTransport {
            claims,
            payload_hex: hex::encode(payload),
            signature_hex: hex::encode(key.sign(&encoded).to_bytes()),
        },
    )
}

fn verify_transport(args: &[OsString]) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--chain",
            "--envelope",
            "--peer-service",
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
    let chain: OperationContextChain =
        read_catalog_json(&required_path(args, "--chain")?, "operation context chain")?;
    let tail = verify_context_chain(&chain, &catalog, now, None)?;
    let envelope: SignedOperationTransport = read_catalog_json(
        &required_path(args, "--envelope")?,
        "operation transport envelope",
    )?;
    let context_digest = digest_signed_context(chain.contexts.last().unwrap())?;
    let peer = required_context_string(args, "--peer-service")?;
    envelope
        .claims
        .validate_for_context(tail, &context_digest, &peer, now)
        .map_err(invalid_data)?;
    let payload = hex::decode(&envelope.payload_hex)
        .map_err(|_| invalid_data("transport payload is not valid hex"))?;
    if payload.len() > 4 * 1024 * 1024
        || envelope.claims.payload_digest != format!("sha256:{:x}", Sha256::digest(&payload))
    {
        return Err(invalid_data("transport payload digest is invalid"));
    }
    verify_service_signature(
        &catalog,
        &envelope.claims.sender_service,
        &serde_json::to_vec(&envelope.claims).map_err(json_error)?,
        &OperationContextSignature {
            algorithm: "ed25519".into(),
            signature_hex: envelope.signature_hex,
        },
    )?;
    consume_transport_nonce(&envelope.claims, now)?;
    write_atomic_nofollow(&required_path(args, "--output")?, &payload, 0o600)
}

fn consume_transport_nonce(claims: &OperationTransportClaims, now_ms: u64) -> io::Result<()> {
    consume_transport_nonce_at(
        &default_root()?.join("operation-context/consumed-transport-nonces"),
        claims,
        now_ms,
    )
}

fn consume_transport_nonce_at(
    root: &Path,
    claims: &OperationTransportClaims,
    now_ms: u64,
) -> io::Result<()> {
    consume_transport_nonce_at_with_limits(
        root,
        claims,
        now_ms,
        MAX_LIVE_TRANSPORT_NONCES_PER_RECIPIENT,
        MAX_LIVE_TRANSPORT_NONCES_TOTAL,
    )
}

fn consume_transport_nonce_at_with_limits(
    root: &Path,
    claims: &OperationTransportClaims,
    now_ms: u64,
    max_per_recipient: usize,
    max_total: usize,
) -> io::Result<()> {
    if now_ms >= claims.expires_at_ms {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "operation transport expired before nonce consumption",
        ));
    }
    create_restrictive_dir_all(root)?;
    let _lock = TransportNonceStoreLock::acquire(&root.join(".store.lock"))?;
    let (total, recipient) = prune_and_count_transport_nonces(
        root,
        now_ms,
        claims.recipient_service.as_str(),
        max_per_recipient,
        max_total,
    )?;
    if total >= max_total || recipient >= max_per_recipient {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "operation transport nonce store quota is exhausted",
        ));
    }
    let key = format!(
        "{:x}",
        Sha256::digest(
            [
                claims.context_digest.as_bytes(),
                b"\0",
                claims.recipient_service.as_bytes(),
                b"\0",
                claims.nonce.as_bytes(),
            ]
            .concat()
        )
    );
    let path = root.join(key);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "operation transport nonce was already consumed",
            )
        } else {
            error
        }
    })?;
    let record = ConsumedTransportNonceRecord {
        schema_version: TRANSPORT_NONCE_RECORD_SCHEMA_VERSION,
        envelope_id: claims.envelope_id.clone(),
        context_digest: claims.context_digest.clone(),
        recipient_service: claims.recipient_service.clone(),
        nonce_digest: format!("sha256:{:x}", Sha256::digest(claims.nonce.as_bytes())),
        issued_at_ms: claims.issued_at_ms,
        expires_at_ms: claims.expires_at_ms,
    };
    serde_json::to_writer(&mut file, &record).map_err(json_error)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(root)?.sync_all()
}

fn prune_and_count_transport_nonces(
    root: &Path,
    now_ms: u64,
    current_recipient: &str,
    max_per_recipient: usize,
    max_total: usize,
) -> io::Result<(usize, usize)> {
    let mut total = 0usize;
    let mut recipient = 0usize;
    let mut changed = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == ".store.lock" {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_TRANSPORT_NONCE_RECORD_BYTES
        {
            return Err(invalid_data(
                "operation transport nonce store contains an invalid entry",
            ));
        }
        let record = read_transport_nonce_record(&path)?;
        validate_transport_nonce_record(&record)?;
        if now_ms >= record.expires_at_ms {
            fs::remove_file(&path)?;
            changed = true;
            continue;
        }
        total = total.saturating_add(1);
        if record.recipient_service == current_recipient {
            recipient = recipient.saturating_add(1);
        }
        if total > max_total || recipient > max_per_recipient {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "operation transport nonce store exceeds its durable quota",
            ));
        }
    }
    if changed {
        File::open(root)?.sync_all()?;
    }
    Ok((total, recipient))
}

fn read_transport_nonce_record(path: &Path) -> io::Result<ConsumedTransportNonceRecord> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    serde_json::from_reader(options.open(path)?).map_err(json_error)
}

fn validate_transport_nonce_record(record: &ConsumedTransportNonceRecord) -> io::Result<()> {
    if record.schema_version != TRANSPORT_NONCE_RECORD_SCHEMA_VERSION
        || !safe_catalog_token(&record.envelope_id)
        || !safe_catalog_token(&record.recipient_service)
        || !valid_context_digest(&record.context_digest)
        || !valid_context_digest(&record.nonce_digest)
        || record.issued_at_ms >= record.expires_at_ms
    {
        return Err(invalid_data(
            "operation transport nonce record is malformed",
        ));
    }
    Ok(())
}

fn valid_context_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
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

fn required_context_string(args: &[OsString], name: &str) -> io::Result<String> {
    optional_string(args, name)?.ok_or_else(context_usage_error)
}

fn required_context_u64(args: &[OsString], name: &str) -> io::Result<u64> {
    required_context_string(args, name)?
        .parse()
        .map_err(|_| invalid_input(format!("{name} must be an unsigned integer")))
}

fn read_transport_payload(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4 * 1024 * 1024
    {
        return Err(invalid_input(
            "transport payload must be a bounded regular file",
        ));
    }
    fs::read(path)
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
    invalid_input("usage: gensee boundary context <issue|verify|effect-sign|effect-verify|transport-wrap|transport-verify> ...")
}

fn print_context_usage() {
    println!(
        "gensee boundary context\n\nUSAGE:\n  gensee boundary context issue --catalog <signed.json> --trusted-key <org.hex> --claims <claims.json> --service-key <seed.hex> [--parent-chain <chain.json>] --output <chain.json>\n  gensee boundary context verify --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> [--audience <service>] [--json]\n  gensee boundary context effect-sign --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --claims <effect.json> --service-key <seed.hex> --output <signed-effect.json>\n  gensee boundary context effect-verify --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --effect <signed-effect.json>\n  gensee boundary context transport-wrap --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --payload <file> --content-type <token> --service-key <seed.hex> --ttl-seconds <n> --output <envelope.json>\n  gensee boundary context transport-verify --catalog <signed.json> --trusted-key <org.hex> --chain <chain.json> --envelope <envelope.json> --peer-service <authenticated-id> --output <payload>"
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

    #[test]
    fn transport_nonce_is_consumed_once_for_context_and_recipient() {
        let root = env::temp_dir().join(format!(
            "gensee-context-nonce-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let claims = transport_claims("envelope_one", "worker", "nonce_one", 100, 200);
        consume_transport_nonce_at(&root, &claims, 150).unwrap();
        assert_eq!(
            consume_transport_nonce_at(&root, &claims, 150)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_transport_nonces_are_pruned_before_admission() {
        let root = env::temp_dir().join(format!(
            "gensee-context-nonce-expiry-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let expired = transport_claims("envelope_old", "worker", "nonce_old", 100, 200);
        consume_transport_nonce_at(&root, &expired, 150).unwrap();
        let fresh = transport_claims("envelope_new", "worker", "nonce_new", 250, 400);
        consume_transport_nonce_at(&root, &fresh, 250).unwrap();
        assert_eq!(transport_nonce_record_count(&root), 1);
        assert_eq!(
            consume_transport_nonce_at(&root, &expired, 250)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_transport_nonce_quotas_fail_closed_without_eviction() {
        let root = env::temp_dir().join(format!(
            "gensee-context-nonce-quota-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let first = transport_claims("envelope_one", "worker", "nonce_one", 100, 400);
        let same_recipient = transport_claims("envelope_two", "worker", "nonce_two", 100, 400);
        let other_recipient =
            transport_claims("envelope_three", "worker_two", "nonce_three", 100, 400);
        let over_total = transport_claims("envelope_four", "worker_three", "nonce_four", 100, 400);
        consume_transport_nonce_at_with_limits(&root, &first, 150, 1, 2).unwrap();
        assert_eq!(
            consume_transport_nonce_at_with_limits(&root, &same_recipient, 150, 1, 2)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        consume_transport_nonce_at_with_limits(&root, &other_recipient, 150, 1, 2).unwrap();
        assert_eq!(
            consume_transport_nonce_at_with_limits(&root, &over_total, 150, 1, 2)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(transport_nonce_record_count(&root), 2);
        assert_eq!(
            consume_transport_nonce_at_with_limits(&root, &first, 150, 1, 2)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_nonce_admission_respects_recipient_quota() {
        use std::sync::{Arc, Barrier};

        let root = env::temp_dir().join(format!(
            "gensee-context-nonce-concurrent-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let barrier = Arc::new(Barrier::new(2));
        let workers = ["one", "two"].map(|suffix| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let claims = transport_claims(
                    &format!("envelope_{suffix}"),
                    "worker",
                    &format!("nonce_{suffix}"),
                    100,
                    400,
                );
                barrier.wait();
                consume_transport_nonce_at_with_limits(&root, &claims, 150, 1, 2)
            })
        });
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(transport_nonce_record_count(&root), 1);
        fs::remove_dir_all(root).unwrap();
    }

    fn transport_claims(
        envelope_id: &str,
        recipient: &str,
        nonce: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> OperationTransportClaims {
        OperationTransportClaims {
            schema_version: OPERATION_TRANSPORT_SCHEMA_VERSION,
            envelope_id: envelope_id.into(),
            context_digest: format!("sha256:{}", "11".repeat(32)),
            sender_service: "gateway".into(),
            recipient_service: recipient.into(),
            payload_digest: format!("sha256:{}", "22".repeat(32)),
            content_type: "application_json".into(),
            nonce: nonce.into(),
            issued_at_ms,
            expires_at_ms,
        }
    }

    fn transport_nonce_record_count(root: &Path) -> usize {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != ".store.lock")
            .count()
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
