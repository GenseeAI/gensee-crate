use crate::*;
use gensee_crate_rules::contract_catalog::SignedContractCatalog;
use gensee_crate_rules::operation_contract::{
    OperationRunManifest, TransactionalPromotionContract,
};
use gensee_crate_rules::semantic_verifier::{
    SemanticVerdict, SignedVerifierReceipt, VerifierRequest,
};
use gensee_crate_rules::transactional_promotion::{
    PromotionJournalClaims, PromotionJournalState, SignedAuthorityClosure, SignedPromotionJournal,
    TransactionalPromotionReceipt, TRANSACTIONAL_PROMOTION_SCHEMA_VERSION,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const PROMOTION_DEADLINE_SECONDS: u64 = 60;

pub(crate) fn handle_transactional_promotion(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(promotion_usage_error)?;
    match command.to_str() {
        Some("apply") => apply_promotion(rest),
        Some("--help" | "-h") => {
            print_promotion_usage();
            Ok(())
        }
        _ => Err(promotion_usage_error()),
    }
}

fn apply_promotion(args: &[OsString]) -> io::Result<()> {
    apply_promotion_with_manifest_verifier(args, verify_operation_manifest)
}

fn apply_promotion_with_manifest_verifier(
    args: &[OsString],
    manifest_verifier: impl Fn(&OperationRunManifest) -> io::Result<()>,
) -> io::Result<()> {
    reject_options(
        args,
        &[
            "--catalog",
            "--trusted-key",
            "--manifest",
            "--verifier-request",
            "--verifier-receipt",
            "--expected-current",
            "--output",
        ],
    )?;
    let now_ms = unix_millis()?;
    let signed_catalog: SignedContractCatalog = read_catalog_json(
        &required_path(args, "--catalog")?,
        "signed contract catalog",
    )?;
    verify_signed_catalog(
        &signed_catalog,
        &required_path(args, "--trusted-key")?,
        now_ms,
    )?;
    let manifest: OperationRunManifest = read_catalog_json(
        &required_path(args, "--manifest")?,
        "operation run manifest",
    )?;
    manifest_verifier(&manifest)?;
    verify_promotable_manifest_state(&manifest)?;
    let verifier_request: VerifierRequest = read_catalog_json(
        &required_path(args, "--verifier-request")?,
        "semantic verifier request",
    )?;
    let verifier_receipt: SignedVerifierReceipt = read_catalog_json(
        &required_path(args, "--verifier-receipt")?,
        "semantic verifier receipt",
    )?;
    verify_semantic_receipt(
        &signed_catalog,
        &verifier_request,
        &verifier_receipt,
        now_ms,
    )?;
    if verifier_receipt.claims.verdict != SemanticVerdict::Accept {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "transactional promotion requires an authenticated accept verdict",
        ));
    }
    let catalog_digest = digest_json(&signed_catalog.catalog)?;
    if manifest.admission.catalog_id != signed_catalog.catalog.catalog_id
        || manifest.admission.catalog_version != signed_catalog.catalog.version
        || manifest.admission.catalog_digest != catalog_digest
    {
        return Err(invalid_data(
            "operation manifest is not bound to the current signed catalog",
        ));
    }
    let approved = signed_catalog
        .catalog
        .contract(&manifest.contract_id)
        .ok_or_else(|| invalid_data("operation contract is absent from the signed catalog"))?;
    let contract_digest = digest_json(&approved.contract)?;
    if contract_digest != manifest.contract_digest {
        return Err(invalid_data(
            "operation manifest contract digest does not match the catalog",
        ));
    }
    let product_contract = approved
        .contract
        .product
        .as_ref()
        .ok_or_else(|| invalid_input("selected contract has no product"))?;
    let promotion = product_contract
        .promotion
        .as_ref()
        .ok_or_else(|| invalid_input("selected contract has no promotion destination"))?;
    verify_manifest_receipt_binding(&manifest, &verifier_request, &verifier_receipt)?;

    let destination_root =
        validate_destination_root(promotion).map_err(|error| at_stage("destination", error))?;
    let _lock = PromotionLock::acquire(&destination_root.join(".gensee-promotion.lock"))
        .map_err(|error| at_stage("promotion lock", error))?;
    recover_interrupted_promotion(&destination_root)
        .map_err(|error| at_stage("crash recovery", error))?;
    let expected_current = required_string(args, "--expected-current")?;
    let current = read_active_target(&destination_root, &promotion.active_pointer)?;
    let expected = if expected_current == "none" {
        None
    } else {
        validate_relative_target(&expected_current)?;
        Some(expected_current)
    };
    if current != expected {
        return Err(io::Error::new(
            ErrorKind::WouldBlock,
            "active target changed; compare-and-swap precondition failed",
        ));
    }

    let deadline = Instant::now() + Duration::from_secs(PROMOTION_DEADLINE_SECONDS);
    let staged_workspace = PathBuf::from(&manifest.staged_workspace);
    let staged_evidence = verify_structural_product(&staged_workspace, product_contract)
        .map_err(|error| at_stage("staged verification", error))?;
    let manifest_product = manifest
        .product
        .as_ref()
        .ok_or_else(|| invalid_data("operation manifest product is missing"))?;
    if !staged_evidence.structurally_valid
        || staged_evidence.digest != manifest_product.digest
        || staged_evidence.entries != manifest_product.entries
        || staged_evidence.bytes != manifest_product.bytes
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "staged product changed after structural verification",
        ));
    }

    let closure = close_operation_broker_authority(&manifest.operation_id, &manifest.source_run_id)
        .map_err(|error| at_stage("authority closure", error))?;
    verify_authority_closure(&closure, &manifest)?;
    if !closure.claims.active_lease_ids.is_empty()
        || !closure.claims.unresolved_lease_ids.is_empty()
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "operation authority is active or unresolved after revocation",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "promotion deadline elapsed during authority closure",
        ));
    }
    let final_staged_evidence = verify_structural_product(&staged_workspace, product_contract)?;
    if final_staged_evidence.digest != staged_evidence.digest
        || final_staged_evidence.entries != staged_evidence.entries
        || final_staged_evidence.bytes != staged_evidence.bytes
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "staged product changed while authority was being revoked",
        ));
    }

    let verifier_receipt_digest = digest_json(&verifier_receipt)?;
    let authority_closure_digest = digest_json(&closure)?;
    let promotion_id = deterministic_promotion_id(
        &manifest.operation_id,
        &manifest_product.digest,
        &verifier_receipt_digest,
    );
    let objects = destination_root.join(".gensee-objects");
    ensure_private_dir(&objects)?;
    let object = objects.join(&promotion_id);
    if !object.exists() {
        let temp = objects.join(format!(".tmp-{promotion_id}"));
        if temp.exists() {
            fs::remove_dir_all(&temp)?;
        }
        fs::create_dir(&temp)?;
        set_mode(&temp, 0o700)?;
        let source = staged_workspace.join(&product_contract.path);
        let target = temp.join(&product_contract.path);
        copy_product(&source, &target, deadline).map_err(|error| at_stage("copy", error))?;
        let copied = verify_structural_product(&temp, product_contract)?;
        if copied.digest != manifest_product.digest
            || copied.entries != manifest_product.entries
            || copied.bytes != manifest_product.bytes
        {
            fs::remove_dir_all(&temp)?;
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "copied product does not match staged evidence",
            ));
        }
        fs::rename(&temp, &object).map_err(|error| at_stage("object publish", error))?;
        if let Err(error) = freeze_tree(&object) {
            let _ = fs::remove_dir_all(&object);
            return Err(at_stage("freeze", error));
        }
        sync_tree(&object)?;
        let frozen = verify_structural_product(&object, product_contract)?;
        if frozen.digest != manifest_product.digest
            || frozen.entries != manifest_product.entries
            || frozen.bytes != manifest_product.bytes
        {
            let _ = fs::remove_dir_all(&object);
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "read-only promotion object does not match verified staged evidence",
            ));
        }
        sync_dir(&objects)?;
    } else {
        let copied = verify_structural_product(&object, product_contract)?;
        if copied.digest != manifest_product.digest {
            return Err(invalid_data(
                "existing immutable promotion object has the wrong digest",
            ));
        }
    }
    let new_target = format!(".gensee-objects/{promotion_id}/{}", product_contract.path);
    validate_relative_target(&new_target)?;
    let receipt_path = promotion_receipt_path(&destination_root, &promotion_id)?;
    if current.as_deref() == Some(&new_target) && receipt_path.exists() {
        let receipt: TransactionalPromotionReceipt =
            read_catalog_json(&receipt_path, "transactional promotion receipt")?;
        verify_promotion_receipt(&receipt)?;
        write_json(&required_path(args, "--output")?, &receipt)?;
        return Ok(());
    }

    let mut journal = signed_journal(PromotionJournalClaims {
        schema_version: TRANSACTIONAL_PROMOTION_SCHEMA_VERSION,
        promotion_id: promotion_id.clone(),
        operation_id: manifest.operation_id.clone(),
        contract_digest: manifest.contract_digest.clone(),
        product_digest: manifest_product.digest.clone(),
        verifier_receipt_digest: verifier_receipt_digest.clone(),
        authority_closure_digest: authority_closure_digest.clone(),
        destination_root: destination_root.to_string_lossy().to_string(),
        active_pointer: promotion.active_pointer.clone(),
        new_target: new_target.clone(),
        previous_target: current.clone(),
        state: PromotionJournalState::Prepared,
        updated_at_ms: unix_millis()?,
    })?;
    persist_journal(&destination_root, &journal)
        .map_err(|error| at_stage("prepared journal", error))?;
    journal.claims.state = PromotionJournalState::Switching;
    journal.claims.updated_at_ms = unix_millis()?;
    journal = signed_journal(journal.claims)?;
    persist_journal(&destination_root, &journal)
        .map_err(|error| at_stage("switching journal", error))?;
    switch_active_pointer(
        &destination_root,
        &promotion.active_pointer,
        &new_target,
        &promotion_id,
    )
    .map_err(|error| at_stage("active pointer switch", error))?;
    journal.claims.state = PromotionJournalState::Complete;
    journal.claims.updated_at_ms = unix_millis()?;
    journal = signed_journal(journal.claims)?;
    persist_journal(&destination_root, &journal)
        .map_err(|error| at_stage("complete journal", error))?;

    let mut receipt = TransactionalPromotionReceipt {
        schema_version: TRANSACTIONAL_PROMOTION_SCHEMA_VERSION,
        promotion_id,
        operation_id: manifest.operation_id,
        product_digest: manifest_product.digest.clone(),
        verifier_receipt_digest,
        authority_closure_digest,
        active_target: new_target,
        promoted_at_ms: unix_millis()?,
        host_signature: String::new(),
    };
    receipt.host_signature = sign_promotion_receipt(&receipt)?;
    persist_receipt(&destination_root, &receipt)
        .map_err(|error| at_stage("promotion receipt", error))?;
    write_json(&required_path(args, "--output")?, &receipt)
}

fn verify_promotable_manifest_state(manifest: &OperationRunManifest) -> io::Result<()> {
    if manifest.process.exit_code != Some(0)
        || manifest.process.timed_out
        || !manifest.process.process_group_drained
        || !manifest.enforcement.os_execution_binding_established
        || !manifest.promotion.structurally_eligible
        || manifest
            .product
            .as_ref()
            .is_none_or(|product| !product.structurally_valid)
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "promotion requires an authenticated successful, drained, structurally eligible operation manifest",
        ));
    }
    Ok(())
}

fn verify_manifest_receipt_binding(
    manifest: &OperationRunManifest,
    request: &VerifierRequest,
    receipt: &SignedVerifierReceipt,
) -> io::Result<()> {
    let product = manifest
        .product
        .as_ref()
        .ok_or_else(|| invalid_data("operation manifest product is missing"))?;
    if request.operation_id != manifest.operation_id
        || request.contract_id != manifest.contract_id
        || request.contract_digest != manifest.contract_digest
        || request.product_type != product.kind
        || request.product_digest != product.digest
        || receipt.claims.operation_id != manifest.operation_id
        || receipt.claims.product_digest != product.digest
    {
        return Err(invalid_data(
            "semantic receipt does not match the operation manifest product",
        ));
    }
    Ok(())
}

fn verify_authority_closure(
    closure: &SignedAuthorityClosure,
    manifest: &OperationRunManifest,
) -> io::Result<()> {
    if closure.claims.schema_version != TRANSACTIONAL_PROMOTION_SCHEMA_VERSION
        || closure.claims.operation_id != manifest.operation_id
        || closure.claims.source_run_id != manifest.source_run_id
    {
        return Err(invalid_data("authority closure identity is invalid"));
    }
    verify_host_evidence(
        "transactional-authority-closure-v1",
        &serde_json::to_vec(&closure.claims).map_err(json_error)?,
        &closure.host_signature,
    )
}

fn validate_destination_root(contract: &TransactionalPromotionContract) -> io::Result<PathBuf> {
    let root = fs::canonicalize(&contract.destination_root)?;
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_input(
            "promotion destination must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        if metadata.mode() & 0o022 != 0 || (effective_uid() == 0 && metadata.uid() != 0) {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "promotion destination must be owner-controlled and non-group/world-writable",
            ));
        }
    }
    Ok(root)
}

fn recover_interrupted_promotion(root: &Path) -> io::Result<()> {
    let path = journal_path(root);
    if !path.exists() {
        return Ok(());
    }
    let mut journal: SignedPromotionJournal = read_catalog_json(&path, "promotion crash journal")?;
    verify_journal(&journal)?;
    if !matches!(
        journal.claims.state,
        PromotionJournalState::Prepared | PromotionJournalState::Switching
    ) {
        return Ok(());
    }
    let current = read_active_target(root, &journal.claims.active_pointer)?;
    if current.as_deref() == Some(journal.claims.new_target.as_str()) {
        restore_pointer(
            root,
            &journal.claims.active_pointer,
            journal.claims.previous_target.as_deref(),
            &journal.claims.promotion_id,
        )?;
    }
    journal.claims.state = PromotionJournalState::RolledBack;
    journal.claims.updated_at_ms = unix_millis()?;
    persist_journal(root, &signed_journal(journal.claims)?)
}

fn signed_journal(claims: PromotionJournalClaims) -> io::Result<SignedPromotionJournal> {
    let host_signature = sign_host_evidence(
        "transactional-promotion-journal-v1",
        &serde_json::to_vec(&claims).map_err(json_error)?,
    )?;
    Ok(SignedPromotionJournal {
        claims,
        host_signature,
    })
}

fn verify_journal(journal: &SignedPromotionJournal) -> io::Result<()> {
    verify_host_evidence(
        "transactional-promotion-journal-v1",
        &serde_json::to_vec(&journal.claims).map_err(json_error)?,
        &journal.host_signature,
    )
}

fn persist_journal(root: &Path, journal: &SignedPromotionJournal) -> io::Result<()> {
    write_atomic_nofollow(
        &journal_path(root),
        &serde_json::to_vec_pretty(journal).map_err(json_error)?,
        0o600,
    )?;
    sync_dir(root)
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(".gensee-promotion-journal.json")
}

fn read_active_target(root: &Path, pointer: &str) -> io::Result<Option<String>> {
    let path = root.join(pointer);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(path)?;
            let target = target
                .to_str()
                .ok_or_else(|| invalid_data("active target is not UTF-8"))?
                .to_string();
            validate_relative_target(&target)?;
            Ok(Some(target))
        }
        Ok(_) => Err(invalid_data("active pointer is not a symlink")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn switch_active_pointer(root: &Path, pointer: &str, target: &str, id: &str) -> io::Result<()> {
    restore_pointer(root, pointer, Some(target), id)
}

fn restore_pointer(root: &Path, pointer: &str, target: Option<&str>, id: &str) -> io::Result<()> {
    let active = root.join(pointer);
    if let Some(target) = target {
        validate_relative_target(target)?;
        let temporary = root.join(format!(".{pointer}.{id}.tmp"));
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &temporary)?;
        #[cfg(not(unix))]
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "relative-pointer promotion requires Unix symlinks",
        ));
        fs::rename(temporary, active)?;
    } else if active.exists() || fs::symlink_metadata(&active).is_ok() {
        fs::remove_file(active)?;
    }
    sync_dir(root)
}

fn validate_relative_target(value: &str) -> io::Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || value.contains("//")
        || value.contains('\\')
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid_data("promotion target is not a safe relative path"));
    }
    Ok(())
}

fn copy_product(source: &Path, target: &Path, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            ErrorKind::TimedOut,
            "promotion copy timed out",
        ));
    }
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "promotion copy rejects symlinks",
        ));
    }
    if metadata.is_dir() {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_product(&entry.path(), &target.join(entry.file_name()), deadline)?;
        }
        fs::set_permissions(target, metadata.permissions())?;
        sync_dir(target)?;
    } else if metadata.is_file() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "promotion copy timed out",
                ));
            }
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
        }
        output.sync_all()?;
        fs::set_permissions(target, metadata.permissions())?;
        output.sync_all()?;
    } else {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "promotion copy rejects special filesystem objects",
        ));
    }
    Ok(())
}

fn freeze_tree(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            freeze_tree(&entry?.path())?;
        }
        set_mode(path, 0o555)
    } else {
        set_mode(path, 0o444)
    }
}

fn sync_tree(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            sync_tree(&entry?.path())?;
        }
        sync_dir(path)
    } else if metadata.is_file() {
        File::open(path)?.sync_all()
    } else {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "promotion sync rejects special filesystem objects",
        ))
    }
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
        set_mode(path, 0o700)?;
        if let Some(parent) = path.parent() {
            sync_dir(parent)?;
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            "promotion control path is not a real directory",
        ));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "promotion control directory is not owner-only",
        ));
    }
    Ok(())
}

fn promotion_receipt_path(root: &Path, promotion_id: &str) -> io::Result<PathBuf> {
    let receipts = root.join(".gensee-receipts");
    ensure_private_dir(&receipts)?;
    Ok(receipts.join(format!("{promotion_id}.json")))
}

fn persist_receipt(root: &Path, receipt: &TransactionalPromotionReceipt) -> io::Result<()> {
    let path = promotion_receipt_path(root, &receipt.promotion_id)?;
    write_atomic_nofollow(
        &path,
        &serde_json::to_vec_pretty(receipt).map_err(json_error)?,
        0o600,
    )?;
    sync_dir(path.parent().unwrap())
}

fn sign_promotion_receipt(receipt: &TransactionalPromotionReceipt) -> io::Result<String> {
    let mut unsigned = receipt.clone();
    unsigned.host_signature.clear();
    sign_host_evidence(
        "transactional-promotion-receipt-v1",
        &serde_json::to_vec(&unsigned).map_err(json_error)?,
    )
}

fn verify_promotion_receipt(receipt: &TransactionalPromotionReceipt) -> io::Result<()> {
    let expected = sign_promotion_receipt(receipt)?;
    if expected != receipt.host_signature {
        return Err(invalid_data(
            "transactional promotion receipt signature is invalid",
        ));
    }
    Ok(())
}

fn deterministic_promotion_id(operation: &str, product: &str, receipt: &str) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{operation}\0{product}\0{receipt}"))
    );
    format!("promotion_{}", &digest[..32])
}

fn digest_json(value: &impl Serialize) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(json_error)?)
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

fn reject_options(args: &[OsString], valued: &[&str]) -> io::Result<()> {
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str().ok_or_else(promotion_usage_error)?;
        if valued.contains(&value) && index + 1 < args.len() {
            index += 2;
        } else {
            return Err(invalid_input(format!("unknown promotion option: {value}")));
        }
    }
    Ok(())
}

fn required_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(promotion_usage_error)?;
    args.get(index + 1)
        .map(PathBuf::from)
        .ok_or_else(promotion_usage_error)
}

fn required_string(args: &[OsString], name: &str) -> io::Result<String> {
    required_path(args, name).map(|path| path.to_string_lossy().to_string())
}

#[cfg(unix)]
struct PromotionLock(File);

#[cfg(unix)]
impl PromotionLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        // SAFETY: flock operates on this owned, open file descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(file))
    }
}

#[cfg(unix)]
impl Drop for PromotionLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until after Drop returns.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(not(unix))]
struct PromotionLock;

#[cfg(not(unix))]
impl PromotionLock {
    fn acquire(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "transactional promotion currently requires Unix",
        ))
    }
}

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
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
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn at_stage(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

fn json_error(error: serde_json::Error) -> io::Error {
    invalid_data(format!(
        "cannot encode transactional promotion record: {error}"
    ))
}

fn promotion_usage_error() -> io::Error {
    invalid_input("usage: gensee boundary promotion apply ...")
}

fn print_promotion_usage() {
    println!(
        "gensee boundary promotion\n\nUSAGE:\n  sudo gensee boundary promotion apply --catalog <signed.json> --trusted-key <org.hex> --manifest <operation.json> --verifier-request <request.json> --verifier-receipt <receipt.json> --expected-current <relative-target|none> --output <promotion-receipt.json>"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use gensee_crate_rules::contract_catalog::{
        AmbiguousIntentAction, ApprovedContract, ApprovedSemanticVerifier, CatalogSignature,
        ContractApproval, ContractCatalog, ContractOwner, FallbackPolicy,
        CONTRACT_CATALOG_SCHEMA_VERSION,
    };
    use gensee_crate_rules::operation_contract::{
        ContractCapabilities, ContractNetworkMode, ExecutionContract, OperationAdmissionEvidence,
        OperationEnforcementEvidence, OperationProcessEvidence, OperationPromotionEvidence,
        OperationRunManifest, ProductContract, StructuralProductType,
        TransactionalPromotionContract, OPERATION_CONTRACT_SCHEMA_VERSION,
    };
    use gensee_crate_rules::semantic_verifier::{
        SemanticVerdict, VerifierReceiptClaims, VerifierReceiptSignature,
        SEMANTIC_VERIFIER_SCHEMA_VERSION,
    };

    #[cfg(unix)]
    #[test]
    fn generic_product_is_verified_revoked_and_atomically_promoted() {
        let _guard = crate::cli_test_env_lock();
        let root = temp_dir("generic-promotion");
        let state = root.join("state");
        let staged = root.join("staged");
        let destination = root.join("destination");
        fs::create_dir_all(staged.join("out")).unwrap();
        fs::create_dir_all(&destination).unwrap();
        set_mode(&destination, 0o700).unwrap();
        fs::write(staged.join("out/result.json"), b"{\"ok\":true}\n").unwrap();
        env::set_var("GENSEE_HOME", &state);

        let product_contract = ProductContract {
            kind: StructuralProductType::StructuredResult,
            path: "out/result.json".into(),
            max_bytes: 4096,
            max_entries: 1,
            reject_symlinks: true,
            reject_special_files: true,
            semantic_verifier_profile: Some("content_policy".into()),
            promotion: Some(TransactionalPromotionContract {
                destination_root: destination.to_string_lossy().to_string(),
                active_pointer: "current".into(),
            }),
        };
        let contract = gensee_crate_rules::operation_contract::OperationContract {
            schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
            contract_id: "structured_transform".into(),
            operation_class: "transform".into(),
            execution: ExecutionContract::default(),
            capabilities: ContractCapabilities::default(),
            product: Some(product_contract.clone()),
        };
        let verifier_key = SigningKey::from_bytes(&[51; 32]);
        let organization_key = SigningKey::from_bytes(&[52; 32]);
        let catalog = ContractCatalog {
            schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
            catalog_id: "promotion_catalog".into(),
            organization_id: "test_organization".into(),
            version: 1,
            issued_at_ms: 1,
            expires_at_ms: u64::MAX,
            contracts: vec![ApprovedContract {
                contract: contract.clone(),
                owner: ContractOwner {
                    application_id: "test_application".into(),
                    owning_team: "security".into(),
                },
                approval: ContractApproval {
                    approval_id: "approval_one".into(),
                    approved_by: "reviewer".into(),
                    approved_at_ms: 1,
                    expires_at_ms: u64::MAX - 1,
                },
            }],
            selectors: Vec::new(),
            intent_analyzers: Vec::new(),
            operation_services: Vec::new(),
            semantic_verifiers: vec![ApprovedSemanticVerifier {
                verifier_id: "verifier_one".into(),
                public_key_hex: hex::encode(verifier_key.verifying_key().as_bytes()),
                profiles: vec!["content_policy".into()],
                policy_versions: vec!["policy_v1".into()],
            }],
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
        let catalog_digest = digest_json(&signed_catalog.catalog).unwrap();
        let contract_digest = digest_json(&contract).unwrap();
        seal_structural_product(&staged.join("out/result.json")).unwrap();
        let product_evidence = verify_structural_product(&staged, &product_contract).unwrap();
        let manifest_key = SigningKey::from_bytes(&[53; 32]);
        let mut manifest = OperationRunManifest {
            schema_version: 1,
            operation_id: "operation_promotion".into(),
            source_run_id: "source_promotion".into(),
            contract_id: contract.contract_id.clone(),
            contract_digest: contract_digest.clone(),
            command_digest: format!("sha256:{}", "10".repeat(32)),
            admission: OperationAdmissionEvidence {
                catalog_id: signed_catalog.catalog.catalog_id.clone(),
                catalog_version: 1,
                catalog_digest,
                observation_digest: format!("sha256:{}", "11".repeat(32)),
                inference_digest: format!("sha256:{}", "12".repeat(32)),
                analyzer_id: "analyzer".into(),
                selected_operation_class: "transform".into(),
                confidence_bps: 9000,
                resolution_source: "probabilistic_inference".into(),
                ambiguity_reason: None,
            },
            operation_record: root.join("record.json").to_string_lossy().to_string(),
            original_workspace: root.to_string_lossy().to_string(),
            staged_workspace: staged.to_string_lossy().to_string(),
            enforcement: OperationEnforcementEvidence {
                os_execution_binding_established: true,
                execution_subject_kind: "test".into(),
                network_mode: ContractNetworkMode::DenyAll,
                network_boundary: "deny_all".into(),
                network_effect_coverage: "complete".into(),
                allowed_network_effects: Vec::new(),
                denied_network_effects: Vec::new(),
                collection_errors: Vec::new(),
            },
            process: OperationProcessEvidence {
                root_pid: 1,
                root_start_time: Some(1),
                exit_code: Some(0),
                timed_out: false,
                process_group_drained: true,
            },
            product: Some(product_evidence.clone()),
            promotion: OperationPromotionEvidence {
                performed: false,
                structurally_eligible: true,
                semantically_verified: false,
                reason: "awaiting verifier".into(),
            },
            started_at_ms: 1,
            finished_at_ms: 2,
            host_signature: None,
        };
        crate::semantic_verifier::sign_operation_manifest_with_key(&mut manifest, &manifest_key)
            .unwrap();
        verify_promotable_manifest_state(&manifest).unwrap();
        let mut failed_manifest = manifest.clone();
        failed_manifest.process.exit_code = Some(1);
        assert_eq!(
            verify_promotable_manifest_state(&failed_manifest)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let mut undrained_manifest = manifest.clone();
        undrained_manifest.process.process_group_drained = false;
        assert_eq!(
            verify_promotable_manifest_state(&undrained_manifest)
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        let request = VerifierRequest {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            request_id: "verify_promotion".into(),
            nonce: "nonce_promotion".into(),
            operation_id: manifest.operation_id.clone(),
            contract_id: manifest.contract_id.clone(),
            contract_digest,
            product_type: product_evidence.kind,
            product_digest: product_evidence.digest.clone(),
            verifier_profile: "content_policy".into(),
            issued_at_ms: 100,
            expires_at_ms: u64::MAX,
        };
        let request_digest = digest_json(&request).unwrap();
        let claims = VerifierReceiptClaims {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            receipt_id: "receipt_promotion".into(),
            request_digest,
            nonce: request.nonce.clone(),
            operation_id: request.operation_id.clone(),
            contract_id: request.contract_id.clone(),
            contract_digest: request.contract_digest.clone(),
            product_type: request.product_type,
            product_digest: request.product_digest.clone(),
            verifier_profile: request.verifier_profile.clone(),
            verifier_id: "verifier_one".into(),
            policy_version: "policy_v1".into(),
            verdict: SemanticVerdict::Accept,
            reason_codes: vec!["accepted".into()],
            validation_effect_manifest_digest: format!("sha256:{}", "13".repeat(32)),
            issued_at_ms: 110,
            expires_at_ms: u64::MAX - 1,
        };
        let receipt = SignedVerifierReceipt {
            signature: VerifierReceiptSignature {
                algorithm: "ed25519".into(),
                signature_hex: hex::encode(
                    verifier_key
                        .sign(&serde_json::to_vec(&claims).unwrap())
                        .to_bytes(),
                ),
            },
            claims,
        };
        let catalog_path = root.join("catalog.json");
        let key_path = root.join("org.hex");
        let manifest_path = root.join("manifest.json");
        let request_path = root.join("request.json");
        let receipt_path = root.join("verifier-receipt.json");
        let output_path = root.join("promotion-receipt.json");
        fs::write(&catalog_path, serde_json::to_vec(&signed_catalog).unwrap()).unwrap();
        fs::write(
            &key_path,
            hex::encode(organization_key.verifying_key().as_bytes()),
        )
        .unwrap();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let args = vec![
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--trusted-key",
            key_path.to_str().unwrap(),
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--verifier-request",
            request_path.to_str().unwrap(),
            "--verifier-receipt",
            receipt_path.to_str().unwrap(),
            "--expected-current",
            "none",
            "--output",
            output_path.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        apply_promotion_with_manifest_verifier(&args, |candidate| {
            crate::semantic_verifier::verify_operation_manifest_with_key(
                candidate,
                manifest_key.verifying_key().as_bytes(),
            )
        })
        .unwrap();
        let active = read_active_target(&destination, "current")
            .unwrap()
            .unwrap();
        assert!(active.starts_with(".gensee-objects/promotion_"));
        assert_eq!(
            fs::read(destination.join(active)).unwrap(),
            b"{\"ok\":true}\n"
        );
        let promotion_receipt: TransactionalPromotionReceipt =
            read_catalog_json(&output_path, "promotion receipt").unwrap();
        verify_promotion_receipt(&promotion_receipt).unwrap();

        env::remove_var("GENSEE_HOME");
        thaw_tree_for_test(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stale_crash_journal_does_not_overwrite_newer_pointer() {
        let _guard = crate::cli_test_env_lock();
        let root = temp_dir("promotion-recovery");
        env::set_var("GENSEE_HOME", root.join("state"));
        set_mode(&root, 0o700).unwrap();
        std::os::unix::fs::symlink("objects/newer", root.join("current")).unwrap();
        let journal = signed_journal(PromotionJournalClaims {
            schema_version: TRANSACTIONAL_PROMOTION_SCHEMA_VERSION,
            promotion_id: "promotion_old".into(),
            operation_id: "operation_old".into(),
            contract_digest: format!("sha256:{}", "11".repeat(32)),
            product_digest: format!("sha256:{}", "22".repeat(32)),
            verifier_receipt_digest: format!("sha256:{}", "33".repeat(32)),
            authority_closure_digest: format!("sha256:{}", "44".repeat(32)),
            destination_root: root.to_string_lossy().to_string(),
            active_pointer: "current".into(),
            new_target: "objects/old".into(),
            previous_target: Some("objects/previous".into()),
            state: PromotionJournalState::Switching,
            updated_at_ms: 1,
        })
        .unwrap();
        persist_journal(&root, &journal).unwrap();
        recover_interrupted_promotion(&root).unwrap();
        assert_eq!(
            read_active_target(&root, "current").unwrap().as_deref(),
            Some("objects/newer")
        );
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).unwrap();
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("gensee-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[cfg(unix)]
    fn thaw_tree_for_test(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let _ = set_mode(path, 0o700);
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    thaw_tree_for_test(&entry.path());
                }
            }
        } else if metadata.is_file() {
            let _ = set_mode(path, 0o600);
        }
    }
}
