use super::*;
use serde::{Deserialize, Serialize};

const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_REF_PREFIX: &str = "refs/gensee/checkpoints";
const DEFAULT_CHECKPOINT_PRUNE_HOURS: u64 = 24 * 30;
const PENDING_RECOVERY_MAX_AGE_MS: u64 = 60 * 60 * 1_000;
const RECOVERY_CREATION_LOCK_STALE_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct WorkspaceCheckpoint {
    schema_version: u32,
    id: String,
    created_at_ms: u64,
    workspace: String,
    commit: String,
    base_head: Option<String>,
    label: Option<String>,
    rescue_of: Option<String>,
    #[serde(default)]
    request_id: Option<i64>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    trigger: Option<String>,
}

#[derive(Debug, Serialize)]
struct CheckpointListResponse {
    workspace: String,
    checkpoints: Vec<WorkspaceCheckpoint>,
}

#[derive(Debug, Serialize)]
struct CheckpointRestoreResponse {
    restored: WorkspaceCheckpoint,
    rescue: WorkspaceCheckpoint,
}

#[derive(Debug, Serialize)]
struct CheckpointDeleteResponse {
    deleted: Vec<String>,
    failed: Vec<CheckpointDeleteFailure>,
}

#[derive(Debug, Serialize)]
struct CheckpointDeleteFailure {
    id: String,
    workspace: String,
    error: String,
    orphaned_metadata_removed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PendingRecoveryRequest {
    schema_version: u32,
    pub(crate) id: String,
    pub(crate) request_id: i64,
    pub(crate) session_id: String,
    pub(crate) provider: String,
    pub(crate) workspace: String,
    pub(crate) reason: String,
    pub(crate) created_at_ms: u64,
    pub(crate) status: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RecoveryPointContext<'a> {
    pub(crate) request_id: i64,
    pub(crate) session_id: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) trigger: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryPointMarker {
    checkpoint_id: String,
    session_id: String,
}

pub(crate) fn handle_checkpoint(args: Vec<OsString>) -> io::Result<()> {
    let command = args.first().and_then(|arg| arg.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint requires create, list, restore, delete, prune, pending, or resolve",
        )
    })?;
    let parsed = CheckpointArgs::parse(&args[1..])?;
    let workspace = parsed.workspace.clone().unwrap_or(env::current_dir()?);
    let storage_root = checkpoint_storage_root()?;

    match command {
        "create" => {
            let checkpoint =
                create_checkpoint_at(&workspace, &storage_root, parsed.label.as_deref(), None)?;
            if parsed.json {
                println!("{}", serde_json::to_string_pretty(&checkpoint)?);
            } else {
                println!(
                    "Created checkpoint {} for {}",
                    checkpoint.id, checkpoint.workspace
                );
            }
            Ok(())
        }
        "list" => {
            let (workspace_label, checkpoints) = if let Some(request_id) = parsed.request_id {
                let checkpoints = list_request_recovery_points_at(
                    &storage_root,
                    request_id,
                    parsed.session_id.as_deref(),
                )?;
                let workspace = checkpoints
                    .first()
                    .map(|checkpoint| checkpoint.workspace.clone())
                    .unwrap_or_default();
                (workspace, checkpoints)
            } else {
                let repository = git_repository_root(&workspace)?;
                let checkpoints = list_checkpoints_at(&repository, &storage_root)?;
                (repository.to_string_lossy().into_owned(), checkpoints)
            };
            if parsed.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&CheckpointListResponse {
                        workspace: workspace_label.clone(),
                        checkpoints,
                    })?
                );
            } else if checkpoints.is_empty() {
                if let Some(request_id) = parsed.request_id {
                    println!("No Gensee recovery point for request {request_id}");
                } else {
                    println!("No Gensee checkpoints for {workspace_label}");
                }
            } else {
                for checkpoint in checkpoints {
                    println!(
                        "{}\t{}\t{}",
                        checkpoint.id,
                        checkpoint.created_at_ms,
                        checkpoint.label.as_deref().unwrap_or("Checkpoint")
                    );
                }
            }
            Ok(())
        }
        "restore" => {
            let id = parsed.positionals.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint restore requires an id",
                )
            })?;
            if !parsed.yes {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "restore changes tracked and untracked non-ignored files; pass --yes after reviewing the checkpoint",
                ));
            }
            let result = restore_checkpoint_at(&workspace, &storage_root, id)?;
            if parsed.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Restored {}. Rescue checkpoint: {}",
                    result.restored.id, result.rescue.id
                );
            }
            Ok(())
        }
        "delete" => {
            let id = parsed.positionals.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint delete requires an id",
                )
            })?;
            require_checkpoint_confirmation(&parsed, "delete")?;
            let repository = git_repository_root(&workspace)?;
            delete_checkpoint_at(&repository, &storage_root, id)?;
            if parsed.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&CheckpointDeleteResponse {
                        deleted: vec![id.clone()],
                        failed: Vec::new(),
                    })?
                );
            } else {
                println!("Deleted checkpoint {id}");
            }
            Ok(())
        }
        "prune" => {
            require_checkpoint_confirmation(&parsed, "prune")?;
            let older_than_hours = parsed
                .older_than_hours
                .unwrap_or(DEFAULT_CHECKPOINT_PRUNE_HOURS);
            let cutoff = now_ms()?.saturating_sub(older_than_hours.saturating_mul(3_600_000));
            let response = if parsed.all_workspaces {
                prune_all_checkpoints_at(&storage_root, cutoff, parsed.all_ages)?
            } else {
                let repository = git_repository_root(&workspace)?;
                prune_repository_checkpoints_at(
                    &repository,
                    &storage_root,
                    cutoff,
                    parsed.all_ages,
                )?
            };
            if parsed.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!(
                    "Pruned {} checkpoint(s); {} could not be fully removed",
                    response.deleted.len(),
                    response.failed.len()
                );
            }
            Ok(())
        }
        "pending" => {
            let pending = list_pending_recovery_requests()?;
            if parsed.json {
                println!("{}", serde_json::to_string_pretty(&pending)?);
            } else if pending.is_empty() {
                println!("No pending recovery-point approvals");
            } else {
                for request in pending {
                    println!(
                        "{}\t{}\t{}\t{}",
                        request.id, request.provider, request.workspace, request.reason
                    );
                }
            }
            Ok(())
        }
        "resolve" => {
            let id = parsed.positionals.first().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint resolve requires a pending approval id",
                )
            })?;
            let action = parsed.action.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint resolve requires --action create|continue",
                )
            })?;
            let resolved = resolve_pending_recovery_request(id, action)?;
            if parsed.json {
                println!("{}", serde_json::to_string_pretty(&resolved)?);
            } else {
                println!("Resolved {} with {}", resolved.id, resolved.status);
            }
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown checkpoint command: {other}"),
        )),
    }
}

#[derive(Default)]
struct CheckpointArgs {
    workspace: Option<PathBuf>,
    label: Option<String>,
    request_id: Option<i64>,
    session_id: Option<String>,
    json: bool,
    yes: bool,
    older_than_hours: Option<u64>,
    all_workspaces: bool,
    all_ages: bool,
    action: Option<String>,
    positionals: Vec<String>,
}

impl CheckpointArgs {
    fn parse(args: &[OsString]) -> io::Result<Self> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].to_str() {
                Some("--workspace") => {
                    index += 1;
                    parsed.workspace =
                        Some(PathBuf::from(required_value(args, index, "--workspace")?));
                }
                Some("--label") => {
                    index += 1;
                    parsed.label = Some(required_value(args, index, "--label")?.to_string());
                }
                Some("--request-id") => {
                    index += 1;
                    let request_id = required_value(args, index, "--request-id")?
                        .parse::<i64>()
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "--request-id must be a positive integer",
                            )
                        })?;
                    if request_id <= 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--request-id must be a positive integer",
                        ));
                    }
                    parsed.request_id = Some(request_id);
                }
                Some("--session-id") => {
                    index += 1;
                    parsed.session_id =
                        Some(required_value(args, index, "--session-id")?.to_string());
                }
                Some("--json") => parsed.json = true,
                Some("--yes") => parsed.yes = true,
                Some("--older-than-hours") => {
                    index += 1;
                    parsed.older_than_hours = Some(
                        required_value(args, index, "--older-than-hours")?
                            .parse()
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "--older-than-hours must be a positive integer",
                                )
                            })?,
                    );
                    if parsed.older_than_hours == Some(0) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--older-than-hours must be greater than zero",
                        ));
                    }
                }
                Some("--all-workspaces") => parsed.all_workspaces = true,
                Some("--all-ages") => parsed.all_ages = true,
                Some("--action") => {
                    index += 1;
                    parsed.action = Some(required_value(args, index, "--action")?.to_string());
                }
                Some(value) if value.starts_with('-') => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown checkpoint option: {value}"),
                    ));
                }
                Some(value) => parsed.positionals.push(value.to_string()),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "checkpoint arguments must be valid UTF-8",
                    ));
                }
            }
            index += 1;
        }
        if parsed.all_workspaces && parsed.workspace.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--all-workspaces cannot be combined with --workspace",
            ));
        }
        if parsed.all_ages && parsed.older_than_hours.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--all-ages cannot be combined with --older-than-hours",
            ));
        }
        Ok(parsed)
    }
}

fn require_checkpoint_confirmation(parsed: &CheckpointArgs, operation: &str) -> io::Result<()> {
    if parsed.yes {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("checkpoint {operation} removes recovery data; pass --yes after reviewing it"),
    ))
}

fn required_value<'a>(args: &'a [OsString], index: usize, option: &str) -> io::Result<&'a str> {
    args.get(index)
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{option} requires a value"),
            )
        })
}

fn checkpoint_storage_root() -> io::Result<PathBuf> {
    Ok(default_root()?.join("checkpoints"))
}

fn create_checkpoint_at(
    workspace: &Path,
    storage_root: &Path,
    label: Option<&str>,
    rescue_of: Option<&str>,
) -> io::Result<WorkspaceCheckpoint> {
    create_checkpoint_with_context(workspace, storage_root, label, rescue_of, None)
}

fn create_checkpoint_with_context(
    workspace: &Path,
    storage_root: &Path,
    label: Option<&str>,
    rescue_of: Option<&str>,
    context: Option<&RecoveryPointContext<'_>>,
) -> io::Result<WorkspaceCheckpoint> {
    let repository = git_repository_root(workspace)?;
    let base_head = git_optional(&repository, &["rev-parse", "--verify", "HEAD"])?;
    let temporary_index = TemporaryGitIndex::new()?;

    if let Some(head) = base_head.as_deref() {
        git(
            &repository,
            Some(&temporary_index.path),
            &["read-tree", head],
        )?;
    } else {
        git(
            &repository,
            Some(&temporary_index.path),
            &["read-tree", "--empty"],
        )?;
    }
    git(
        &repository,
        Some(&temporary_index.path),
        &["add", "-A", "--", "."],
    )?;
    let tree = git(&repository, Some(&temporary_index.path), &["write-tree"])?;
    let created_at_ms = now_ms()?;
    let id = format!("cp-{created_at_ms}-{}", &tree[..tree.len().min(8)]);

    let mut commit_args = vec![
        "commit-tree",
        tree.as_str(),
        "-m",
        "Gensee workspace checkpoint",
    ];
    if let Some(head) = base_head.as_deref() {
        commit_args.extend(["-p", head]);
    }
    let commit = git_with_identity(&repository, &commit_args)?;
    let reference = format!("{CHECKPOINT_REF_PREFIX}/{id}");
    git(&repository, None, &["update-ref", &reference, &commit])?;

    let checkpoint = WorkspaceCheckpoint {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        id,
        created_at_ms,
        workspace: repository.to_string_lossy().into_owned(),
        commit,
        base_head,
        label: label.map(str::to_string),
        rescue_of: rescue_of.map(str::to_string),
        request_id: context.map(|context| context.request_id),
        session_id: context.map(|context| context.session_id.to_string()),
        provider: context.map(|context| context.provider.to_string()),
        trigger: context.map(|context| context.trigger.to_string()),
    };
    write_checkpoint_metadata(storage_root, &repository, &checkpoint)?;
    Ok(checkpoint)
}

fn list_checkpoints_at(
    repository: &Path,
    storage_root: &Path,
) -> io::Result<Vec<WorkspaceCheckpoint>> {
    let repository = fs::canonicalize(repository)?;
    let directory = repository_checkpoint_directory(storage_root, &repository);
    let mut checkpoints = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(checkpoints),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(checkpoint) = serde_json::from_slice::<WorkspaceCheckpoint>(&bytes) else {
            continue;
        };
        if checkpoint.workspace == repository.to_string_lossy() {
            checkpoints.push(checkpoint);
        }
    }
    checkpoints.sort_by_key(|checkpoint| std::cmp::Reverse(checkpoint.created_at_ms));
    Ok(checkpoints)
}

fn list_all_checkpoints_at(storage_root: &Path) -> io::Result<Vec<WorkspaceCheckpoint>> {
    let mut checkpoints = Vec::new();
    let repositories = match fs::read_dir(storage_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(checkpoints),
        Err(error) => return Err(error),
    };
    for repository in repositories {
        let repository = repository?;
        if !repository.file_type()?.is_dir() {
            continue;
        }
        let entries = match fs::read_dir(repository.path()) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(path) else { continue };
            let Ok(checkpoint) = serde_json::from_slice::<WorkspaceCheckpoint>(&bytes) else {
                continue;
            };
            checkpoints.push(checkpoint);
        }
    }
    checkpoints.sort_by_key(|checkpoint| std::cmp::Reverse(checkpoint.created_at_ms));
    Ok(checkpoints)
}

fn list_request_recovery_points_at(
    storage_root: &Path,
    request_id: i64,
    session_id: Option<&str>,
) -> io::Result<Vec<WorkspaceCheckpoint>> {
    let mut checkpoints = Vec::new();
    for checkpoint in list_all_checkpoints_at(storage_root)? {
        if checkpoint.request_id != Some(request_id) || checkpoint.rescue_of.is_some() {
            continue;
        }
        if let Some(session_id) = session_id {
            if checkpoint.session_id.as_deref() != Some(session_id) {
                continue;
            }
        }
        checkpoints.push(checkpoint);
    }
    checkpoints.sort_by_key(|checkpoint| std::cmp::Reverse(checkpoint.created_at_ms));
    Ok(checkpoints)
}

fn prune_all_checkpoints_at(
    storage_root: &Path,
    cutoff: u64,
    all_ages: bool,
) -> io::Result<CheckpointDeleteResponse> {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for checkpoint in list_all_checkpoints_at(storage_root)? {
        if !all_ages && checkpoint.created_at_ms >= cutoff {
            continue;
        }
        match checkpoint_repository_for_cleanup(&checkpoint) {
            Ok(repository) => match delete_checkpoint_at(&repository, storage_root, &checkpoint.id)
            {
                Ok(()) => deleted.push(checkpoint.id),
                Err(error) => failed.push(CheckpointDeleteFailure {
                    id: checkpoint.id,
                    workspace: checkpoint.workspace,
                    error: error.to_string(),
                    orphaned_metadata_removed: false,
                }),
            },
            Err(repository_error) => {
                // The path may now be a symlink or nested under a different
                // Git root. Delete only a ref that still resolves to this
                // checkpoint's recorded commit, then discard stale metadata.
                let _ = remove_matching_checkpoint_reference_at(
                    Path::new(&checkpoint.workspace),
                    &checkpoint,
                );
                let cleanup = remove_checkpoint_metadata_at(storage_root, &checkpoint);
                let orphaned_metadata_removed = cleanup.is_ok();
                let error = match cleanup {
                    Ok(()) => repository_error.to_string(),
                    Err(cleanup_error) => format!(
                        "{repository_error}; orphaned metadata cleanup also failed: {cleanup_error}"
                    ),
                };
                failed.push(CheckpointDeleteFailure {
                    id: checkpoint.id,
                    workspace: checkpoint.workspace,
                    error,
                    orphaned_metadata_removed,
                });
            }
        }
    }
    Ok(CheckpointDeleteResponse { deleted, failed })
}

fn prune_repository_checkpoints_at(
    repository: &Path,
    storage_root: &Path,
    cutoff: u64,
    all_ages: bool,
) -> io::Result<CheckpointDeleteResponse> {
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    for checkpoint in list_checkpoints_at(repository, storage_root)? {
        if !all_ages && checkpoint.created_at_ms >= cutoff {
            continue;
        }
        match delete_checkpoint_at(repository, storage_root, &checkpoint.id) {
            Ok(()) => deleted.push(checkpoint.id),
            Err(error) => failed.push(CheckpointDeleteFailure {
                id: checkpoint.id,
                workspace: checkpoint.workspace,
                error: error.to_string(),
                orphaned_metadata_removed: false,
            }),
        }
    }
    Ok(CheckpointDeleteResponse { deleted, failed })
}

fn checkpoint_repository_for_cleanup(checkpoint: &WorkspaceCheckpoint) -> io::Result<PathBuf> {
    let repository = fs::canonicalize(&checkpoint.workspace)?;
    if checkpoint.workspace != repository.to_string_lossy() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint workspace now resolves to a different path",
        ));
    }
    let git_root = git_repository_root(&repository)?;
    if git_root != repository {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint workspace is no longer a Git repository root",
        ));
    }
    Ok(repository)
}

fn remove_matching_checkpoint_reference_at(
    workspace: &Path,
    checkpoint: &WorkspaceCheckpoint,
) -> io::Result<bool> {
    validate_checkpoint_id(&checkpoint.id)?;
    let repository = git_repository_root(workspace)?;
    let reference = format!("{CHECKPOINT_REF_PREFIX}/{}", checkpoint.id);
    let Some(commit) = git_optional(&repository, &["rev-parse", "--verify", &reference])? else {
        return Ok(false);
    };
    if commit != checkpoint.commit {
        return Ok(false);
    }
    git(&repository, None, &["update-ref", "-d", &reference])?;
    Ok(true)
}

pub(crate) fn ensure_request_recovery_point_in_repository(
    repository: &Path,
    context: &RecoveryPointContext<'_>,
    retention_hours: u64,
) -> io::Result<WorkspaceCheckpoint> {
    let storage_root = checkpoint_storage_root()?;
    ensure_request_recovery_point_in_repository_at(
        repository,
        &storage_root,
        context,
        retention_hours,
    )
}

#[cfg(test)]
fn ensure_request_recovery_point_at(
    workspace: &Path,
    storage_root: &Path,
    context: &RecoveryPointContext<'_>,
    retention_hours: u64,
) -> io::Result<WorkspaceCheckpoint> {
    let repository = git_repository_root(workspace)?;
    ensure_request_recovery_point_in_repository_at(
        &repository,
        storage_root,
        context,
        retention_hours,
    )
}

fn ensure_request_recovery_point_in_repository_at(
    repository: &Path,
    storage_root: &Path,
    context: &RecoveryPointContext<'_>,
    retention_hours: u64,
) -> io::Result<WorkspaceCheckpoint> {
    let repository = fs::canonicalize(repository)?;
    if let Some(existing) = recovery_point_for_request(&repository, storage_root, context)? {
        return Ok(existing);
    }

    let directory = repository_checkpoint_directory(storage_root, &repository);
    fs::create_dir_all(&directory)?;
    let lock = directory.join(format!(".request-{}.lock", context.request_id));
    let mut acquired = false;
    for _ in 0..51 {
        match fs::create_dir(&lock) {
            Ok(()) => {
                acquired = true;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                remove_stale_recovery_lock(&lock)?;
                if let Some(existing) =
                    recovery_point_for_request(&repository, storage_root, context)?
                {
                    return Ok(existing);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    if !acquired {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "another hook is creating this request's recovery point",
        ));
    }
    let _guard = RecoveryCreationLock(lock);

    if let Some(existing) = recovery_point_for_request(&repository, storage_root, context)? {
        return Ok(existing);
    }
    let label = format!("Before {} request {}", context.provider, context.request_id);
    let checkpoint = create_checkpoint_with_context(
        &repository,
        storage_root,
        Some(&label),
        None,
        Some(context),
    )?;
    write_recovery_point_marker(&repository, storage_root, context, &checkpoint)?;
    prune_recovery_points(
        &repository,
        storage_root,
        retention_hours,
        checkpoint.created_at_ms,
    )?;
    Ok(checkpoint)
}

fn recovery_point_for_request(
    repository: &Path,
    storage_root: &Path,
    context: &RecoveryPointContext<'_>,
) -> io::Result<Option<WorkspaceCheckpoint>> {
    let marker_path = recovery_point_marker_path(repository, storage_root, context.request_id);
    if let Ok(bytes) = fs::read(&marker_path) {
        if let Ok(marker) = serde_json::from_slice::<RecoveryPointMarker>(&bytes) {
            if marker.session_id == context.session_id {
                let metadata = repository_checkpoint_directory(storage_root, repository)
                    .join(format!("{}.json", marker.checkpoint_id));
                if let Ok(bytes) = fs::read(metadata) {
                    let checkpoint: WorkspaceCheckpoint = serde_json::from_slice(&bytes)?;
                    if checkpoint.request_id == Some(context.request_id)
                        && checkpoint.session_id.as_deref() == Some(context.session_id)
                        && checkpoint.rescue_of.is_none()
                    {
                        return Ok(Some(checkpoint));
                    }
                }
            }
        }
        let _ = fs::remove_file(&marker_path);
    }

    let checkpoint = list_checkpoints_at(repository, storage_root)?
        .into_iter()
        .find(|checkpoint| {
            checkpoint.request_id == Some(context.request_id)
                && checkpoint.session_id.as_deref() == Some(context.session_id)
                && checkpoint.rescue_of.is_none()
        });
    if let Some(checkpoint) = checkpoint.as_ref() {
        write_recovery_point_marker(repository, storage_root, context, checkpoint)?;
    }
    Ok(checkpoint)
}

fn prune_recovery_points(
    repository: &Path,
    storage_root: &Path,
    retention_hours: u64,
    now: u64,
) -> io::Result<()> {
    let cutoff = now.saturating_sub(retention_hours.max(1).saturating_mul(3_600_000));
    for checkpoint in list_checkpoints_at(repository, storage_root)? {
        if checkpoint.created_at_ms < cutoff
            && checkpoint.request_id.is_some()
            && checkpoint.rescue_of.is_none()
        {
            delete_checkpoint_at(repository, storage_root, &checkpoint.id)?;
        }
    }
    Ok(())
}

struct RecoveryCreationLock(PathBuf);

impl Drop for RecoveryCreationLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn remove_stale_recovery_lock(lock: &Path) -> io::Result<()> {
    let Ok(metadata) = fs::metadata(lock) else {
        return Ok(());
    };
    let Ok(modified) = metadata.modified() else {
        return Ok(());
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return Ok(());
    };
    if age.as_millis() as u64 > RECOVERY_CREATION_LOCK_STALE_MS {
        match fs::remove_dir(lock) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn request_recovery_approval(
    workspace: &Path,
    context: &RecoveryPointContext<'_>,
) -> io::Result<PendingRecoveryRequest> {
    let repository = git_repository_root(workspace)?;
    let id = pending_recovery_id(&repository, context);
    let path = pending_recovery_directory()?.join(format!("{id}.json"));
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(existing) = serde_json::from_slice::<PendingRecoveryRequest>(&bytes) {
            if pending_recovery_is_fresh(existing.created_at_ms, now_ms()?) {
                return Ok(existing);
            }
        }
        let _ = fs::remove_file(&path);
    }
    let request = PendingRecoveryRequest {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        id,
        request_id: context.request_id,
        session_id: context.session_id.to_string(),
        provider: context.provider.to_string(),
        workspace: repository.to_string_lossy().into_owned(),
        reason: context.trigger.to_string(),
        created_at_ms: now_ms()?,
        status: "pending".to_string(),
    };
    write_pending_recovery_request(&path, &request)?;
    Ok(request)
}

pub(crate) fn clear_pending_recovery_request(id: &str) {
    if validate_pending_recovery_id(id).is_err() {
        return;
    }
    if let Ok(directory) = pending_recovery_directory() {
        let _ = fs::remove_file(directory.join(format!("{id}.json")));
    }
}

fn resolve_pending_recovery_request(id: &str, action: &str) -> io::Result<PendingRecoveryRequest> {
    validate_pending_recovery_id(id)?;
    if !matches!(action, "create" | "continue") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--action must be create or continue",
        ));
    }
    let path = pending_recovery_directory()?.join(format!("{id}.json"));
    let mut request: PendingRecoveryRequest = serde_json::from_slice(&fs::read(&path)?)?;
    if action == "create" {
        let context = RecoveryPointContext {
            request_id: request.request_id,
            session_id: &request.session_id,
            provider: &request.provider,
            trigger: &request.reason,
        };
        let retention = Policy::load_current().document().recovery.retention_hours;
        ensure_request_recovery_point_in_repository(
            Path::new(&request.workspace),
            &context,
            retention,
        )?;
        request.status = "created".to_string();
    } else {
        request.status = "continue".to_string();
    }
    write_pending_recovery_request(&path, &request)?;
    Ok(request)
}

fn list_pending_recovery_requests() -> io::Result<Vec<PendingRecoveryRequest>> {
    let directory = pending_recovery_directory()?;
    let mut requests = Vec::new();
    let now = now_ms()?;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let request: PendingRecoveryRequest = match serde_json::from_slice(&fs::read(&path)?) {
            Ok(request) => request,
            Err(_) => continue,
        };
        if !pending_recovery_is_fresh(request.created_at_ms, now) {
            let _ = fs::remove_file(path);
        } else if request.status == "pending" {
            requests.push(request);
        }
    }
    requests.sort_by_key(|request| request.created_at_ms);
    Ok(requests)
}

fn pending_recovery_directory() -> io::Result<PathBuf> {
    let directory = default_root()?.join("recovery-approvals");
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

fn pending_recovery_is_fresh(created_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(created_at_ms) <= PENDING_RECOVERY_MAX_AGE_MS
}

fn pending_recovery_id(repository: &Path, context: &RecoveryPointContext<'_>) -> String {
    let mut digest = Sha256::new();
    digest.update(repository.as_os_str().as_encoded_bytes());
    digest.update(context.session_id.as_bytes());
    digest.update(context.request_id.to_le_bytes());
    format!("rp-{}-{:.12x}", context.request_id, digest.finalize())
}

fn validate_pending_recovery_id(id: &str) -> io::Result<()> {
    if id.starts_with("rp-")
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid pending recovery approval id",
        ))
    }
}

fn write_pending_recovery_request(path: &Path, request: &PendingRecoveryRequest) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(request)?)?;
    fs::rename(temporary, path)
}

fn restore_checkpoint_at(
    workspace: &Path,
    storage_root: &Path,
    id: &str,
) -> io::Result<CheckpointRestoreResponse> {
    validate_checkpoint_id(id)?;
    let repository = git_repository_root(workspace)?;
    let metadata_path =
        repository_checkpoint_directory(storage_root, &repository).join(format!("{id}.json"));
    let restored: WorkspaceCheckpoint = match fs::read(&metadata_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "checkpoint {id} does not exist for {}",
                    repository.display()
                ),
            ));
        }
        Err(error) => return Err(error),
    };
    if restored.workspace != repository.to_string_lossy() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint metadata belongs to a different workspace",
        ));
    }
    let reference = format!("{CHECKPOINT_REF_PREFIX}/{id}");
    let referenced_commit = git(&repository, None, &["rev-parse", "--verify", &reference])?;
    if referenced_commit != restored.commit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint reference does not match its metadata",
        ));
    }

    let rescue_label = format!("Before restoring {id}");
    let rescue = create_checkpoint_at(&repository, storage_root, Some(&rescue_label), Some(id))?;

    let temporary_index = TemporaryGitIndex::new()?;
    if let Some(head) = git_optional(&repository, &["rev-parse", "--verify", "HEAD"])? {
        git(
            &repository,
            Some(&temporary_index.path),
            &["read-tree", &head],
        )?;
    } else {
        git(
            &repository,
            Some(&temporary_index.path),
            &["read-tree", "--empty"],
        )?;
    }
    git(
        &repository,
        Some(&temporary_index.path),
        &["add", "-A", "--", "."],
    )?;
    git(
        &repository,
        Some(&temporary_index.path),
        &["read-tree", "--reset", "-u", &restored.commit],
    )?;

    Ok(CheckpointRestoreResponse { restored, rescue })
}

fn delete_checkpoint_at(repository: &Path, storage_root: &Path, id: &str) -> io::Result<()> {
    validate_checkpoint_id(id)?;
    let repository = fs::canonicalize(repository)?;
    let metadata_path =
        repository_checkpoint_directory(storage_root, &repository).join(format!("{id}.json"));
    let checkpoint: WorkspaceCheckpoint =
        serde_json::from_slice(&fs::read(&metadata_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "checkpoint {id} does not exist for {}",
                        repository.display()
                    ),
                )
            } else {
                error
            }
        })?)?;
    if checkpoint.workspace != repository.to_string_lossy() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint metadata belongs to a different workspace",
        ));
    }
    let reference = format!("{CHECKPOINT_REF_PREFIX}/{id}");
    git(&repository, None, &["update-ref", "-d", &reference])?;
    remove_checkpoint_metadata_at(storage_root, &checkpoint)
}

fn remove_checkpoint_metadata_at(
    storage_root: &Path,
    checkpoint: &WorkspaceCheckpoint,
) -> io::Result<()> {
    validate_checkpoint_id(&checkpoint.id)?;
    let repository = Path::new(&checkpoint.workspace);
    let directory = repository_checkpoint_directory(storage_root, repository);
    let metadata_path = directory.join(format!("{}.json", checkpoint.id));
    match fs::remove_file(metadata_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(request_id) = checkpoint.request_id {
        let marker_path = recovery_point_marker_path(repository, storage_root, request_id);
        if let Ok(bytes) = fs::read(&marker_path) {
            if serde_json::from_slice::<RecoveryPointMarker>(&bytes)
                .is_ok_and(|marker| marker.checkpoint_id == checkpoint.id)
            {
                match fs::remove_file(marker_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

fn validate_checkpoint_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint id contains unsupported characters",
        ));
    }
    Ok(())
}

pub(crate) fn git_repository_root(workspace: &Path) -> io::Result<PathBuf> {
    let root = git(workspace, None, &["rev-parse", "--show-toplevel"])?;
    fs::canonicalize(root)
}

fn git(directory: &Path, index: Option<&Path>, args: &[&str]) -> io::Result<String> {
    git_output(directory, index, args, &[]).and_then(require_git_success)
}

fn git_with_identity(directory: &Path, args: &[&str]) -> io::Result<String> {
    git_output(
        directory,
        None,
        args,
        &[
            ("GIT_AUTHOR_NAME", "Gensee Crate"),
            ("GIT_AUTHOR_EMAIL", "checkpoint@gensee.ai"),
            ("GIT_COMMITTER_NAME", "Gensee Crate"),
            ("GIT_COMMITTER_EMAIL", "checkpoint@gensee.ai"),
        ],
    )
    .and_then(require_git_success)
}

fn git_optional(directory: &Path, args: &[&str]) -> io::Result<Option<String>> {
    let output = git_output(directory, None, args, &[])?;
    if output.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    } else {
        Ok(None)
    }
}

fn git_output(
    directory: &Path,
    index: Option<&Path>,
    args: &[&str],
    environment: &[(&str, &str)],
) -> io::Result<std::process::Output> {
    let mut command = Command::new("git");
    command.current_dir(directory).args(args);
    if let Some(index) = index {
        command.env("GIT_INDEX_FILE", index);
    }
    for (key, value) in environment {
        command.env(key, value);
    }
    command.output()
}

fn require_git_success(output: std::process::Output) -> io::Result<String> {
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn repository_checkpoint_directory(storage_root: &Path, repository: &Path) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(repository.as_os_str().as_encoded_bytes());
    storage_root.join(format!("{:x}", digest.finalize()))
}

fn recovery_point_marker_path(repository: &Path, storage_root: &Path, request_id: i64) -> PathBuf {
    repository_checkpoint_directory(storage_root, repository)
        .join(format!(".request-{request_id}.marker"))
}

fn write_recovery_point_marker(
    repository: &Path,
    storage_root: &Path,
    context: &RecoveryPointContext<'_>,
    checkpoint: &WorkspaceCheckpoint,
) -> io::Result<()> {
    let directory = repository_checkpoint_directory(storage_root, repository);
    fs::create_dir_all(&directory)?;
    let destination = recovery_point_marker_path(repository, storage_root, context.request_id);
    let temporary = directory.join(format!(
        ".request-{}-{}.tmp",
        context.request_id,
        std::process::id()
    ));
    let marker = RecoveryPointMarker {
        checkpoint_id: checkpoint.id.clone(),
        session_id: context.session_id.to_string(),
    };
    fs::write(&temporary, serde_json::to_vec(&marker)?)?;
    fs::rename(temporary, destination)
}

fn write_checkpoint_metadata(
    storage_root: &Path,
    repository: &Path,
    checkpoint: &WorkspaceCheckpoint,
) -> io::Result<()> {
    let directory = repository_checkpoint_directory(storage_root, repository);
    fs::create_dir_all(&directory)?;
    let destination = directory.join(format!("{}.json", checkpoint.id));
    let temporary = directory.join(format!(".{}.tmp", checkpoint.id));
    fs::write(&temporary, serde_json::to_vec_pretty(checkpoint)?)?;
    fs::rename(temporary, destination)
}

fn now_ms() -> io::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    Ok(duration.as_millis().try_into().unwrap_or(u64::MAX))
}

struct TemporaryGitIndex {
    path: PathBuf,
    directory: PathBuf,
}

impl TemporaryGitIndex {
    fn new() -> io::Result<Self> {
        let parent = env::temp_dir().join("gensee-checkpoints");
        fs::create_dir_all(&parent)?;
        let mut nonce = now_ms()?;
        for _ in 0..128 {
            let directory = parent.join(format!("{}-{nonce}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => {
                    let path = directory.join("index");
                    return Ok(Self { path, directory });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    nonce = nonce.wrapping_add(1);
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private checkpoint workspace",
        ))
    }
}

impl Drop for TemporaryGitIndex {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("index.lock"));
        let _ = fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "gensee-checkpoint-{name}-{}-{}",
            std::process::id(),
            now_ms().expect("clock")
        ))
    }

    fn run_git(repository: &Path, args: &[&str]) {
        git(repository, None, args).expect("git command");
    }

    #[test]
    fn restore_preserves_index_and_ignored_files_and_creates_rescue() {
        let sandbox = test_directory("restore");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        run_git(&repository, &["config", "user.name", "Test"]);
        run_git(&repository, &["config", "user.email", "test@example.com"]);
        fs::write(repository.join("tracked.txt"), "original\n").expect("write tracked");
        fs::write(repository.join(".gitignore"), "ignored.txt\n").expect("write ignore");
        run_git(&repository, &["add", "."]);
        run_git(&repository, &["commit", "-m", "initial"]);

        fs::write(repository.join("tracked.txt"), "checkpoint\n").expect("edit tracked");
        fs::write(repository.join("untracked.txt"), "captured\n").expect("write untracked");
        let checkpoint = create_checkpoint_at(&repository, &storage, Some("Before agent"), None)
            .expect("create checkpoint");

        fs::write(repository.join("tracked.txt"), "staged later\n").expect("edit staged");
        run_git(&repository, &["add", "tracked.txt"]);
        let index_before = git(&repository, None, &["write-tree"]).expect("index tree");
        fs::write(repository.join("tracked.txt"), "working later\n").expect("edit worktree");
        fs::remove_file(repository.join("untracked.txt")).expect("remove captured file");
        fs::write(repository.join("new.txt"), "remove me\n").expect("write new file");
        fs::write(repository.join("ignored.txt"), "keep me\n").expect("write ignored file");

        let result = restore_checkpoint_at(&repository, &storage, &checkpoint.id)
            .expect("restore checkpoint");

        assert_eq!(
            fs::read_to_string(repository.join("tracked.txt")).expect("read tracked"),
            "checkpoint\n"
        );
        assert_eq!(
            fs::read_to_string(repository.join("untracked.txt")).expect("read untracked"),
            "captured\n"
        );
        assert!(!repository.join("new.txt").exists());
        assert_eq!(
            fs::read_to_string(repository.join("ignored.txt")).expect("read ignored"),
            "keep me\n"
        );
        assert_eq!(
            git(&repository, None, &["write-tree"]).expect("index after"),
            index_before
        );
        assert_eq!(
            result.rescue.rescue_of.as_deref(),
            Some(checkpoint.id.as_str())
        );
        assert_eq!(
            list_checkpoints_at(&repository, &storage)
                .expect("list")
                .len(),
            2
        );
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn checkpoint_cannot_be_restored_in_another_repository() {
        let sandbox = test_directory("scope");
        let first = sandbox.join("first");
        let second = sandbox.join("second");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&first).expect("create first");
        fs::create_dir_all(&second).expect("create second");
        run_git(&first, &["init"]);
        run_git(&second, &["init"]);
        fs::write(first.join("file.txt"), "one").expect("write first");
        let checkpoint = create_checkpoint_at(&first, &storage, None, None).expect("checkpoint");
        let error = restore_checkpoint_at(&second, &storage, &checkpoint.id)
            .expect_err("cross-repository restore must fail");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn deleting_checkpoint_removes_metadata_and_git_reference() {
        let sandbox = test_directory("delete");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        fs::write(repository.join("file.txt"), "captured").expect("write file");
        let checkpoint =
            create_checkpoint_at(&repository, &storage, None, None).expect("create checkpoint");

        delete_checkpoint_at(&repository, &storage, &checkpoint.id).expect("delete checkpoint");

        assert!(list_checkpoints_at(&repository, &storage)
            .expect("list checkpoints")
            .is_empty());
        assert!(git_optional(
            &repository,
            &[
                "rev-parse",
                "--verify",
                &format!("{CHECKPOINT_REF_PREFIX}/{}", checkpoint.id)
            ]
        )
        .expect("check reference")
        .is_none());
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn request_recovery_point_is_created_once_with_request_context() {
        let sandbox = test_directory("request-dedup");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        fs::write(repository.join("file.txt"), "before").expect("write file");
        let context = RecoveryPointContext {
            request_id: 42,
            session_id: "session-1",
            provider: "codex",
            trigger: "File mutation",
        };

        let first = ensure_request_recovery_point_at(&repository, &storage, &context, 168)
            .expect("first recovery point");
        fs::write(repository.join("file.txt"), "after").expect("edit after checkpoint");
        let second = ensure_request_recovery_point_at(&repository, &storage, &context, 168)
            .expect("deduplicated recovery point");

        assert_eq!(first.id, second.id);
        assert_eq!(first.request_id, Some(42));
        assert_eq!(first.session_id.as_deref(), Some("session-1"));
        assert_eq!(first.provider.as_deref(), Some("codex"));
        assert_eq!(first.trigger.as_deref(), Some("File mutation"));
        assert_eq!(
            list_checkpoints_at(&repository, &storage)
                .expect("list checkpoints")
                .len(),
            1
        );
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn request_recovery_point_can_be_found_without_inferring_its_workspace() {
        let sandbox = test_directory("request-lookup");
        let first_repository = sandbox.join("first");
        let second_repository = sandbox.join("second");
        let storage = sandbox.join("storage");
        for repository in [&first_repository, &second_repository] {
            fs::create_dir_all(repository).expect("create repository");
            run_git(repository, &["init"]);
            fs::write(repository.join("file.txt"), "before").expect("write file");
        }

        let first_context = RecoveryPointContext {
            request_id: 42,
            session_id: "old-session",
            provider: "claude-code",
            trigger: "File mutation",
        };
        let second_context = RecoveryPointContext {
            request_id: 42,
            session_id: "current-session",
            provider: "claude-code",
            trigger: "Request indicates a rewrite",
        };
        ensure_request_recovery_point_at(&first_repository, &storage, &first_context, 168)
            .expect("first recovery point");
        let expected =
            ensure_request_recovery_point_at(&second_repository, &storage, &second_context, 168)
                .expect("second recovery point");

        let found = list_request_recovery_points_at(&storage, 42, Some("current-session"))
            .expect("find recovery point by request and session");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, expected.id);
        assert_eq!(
            found[0].workspace,
            fs::canonicalize(&second_repository)
                .unwrap()
                .to_string_lossy()
        );
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn checkpoint_listing_skips_corrupt_metadata_in_any_repository() {
        let sandbox = test_directory("corrupt-metadata");
        let repository = sandbox.join("repo");
        let other_repository = sandbox.join("other");
        let storage = sandbox.join("storage");
        for path in [&repository, &other_repository] {
            fs::create_dir_all(path).expect("create repository");
            run_git(path, &["init"]);
            fs::write(path.join("file.txt"), "before").expect("write file");
        }
        let context = RecoveryPointContext {
            request_id: 42,
            session_id: "session-42",
            provider: "codex",
            trigger: "File mutation",
        };
        let checkpoint = ensure_request_recovery_point_at(&repository, &storage, &context, 168)
            .expect("create recovery point");
        let other_directory = repository_checkpoint_directory(
            &storage,
            &fs::canonicalize(&other_repository).expect("canonical other repository"),
        );
        fs::create_dir_all(&other_directory).expect("create other metadata directory");
        fs::write(other_directory.join("foreign.json"), b"not-json")
            .expect("write corrupt metadata");

        let found = list_request_recovery_points_at(&storage, 42, Some("session-42"))
            .expect("corrupt metadata must not abort lookup");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, checkpoint.id);
        assert_eq!(
            list_checkpoints_at(&other_repository, &storage)
                .expect("repository listing")
                .len(),
            0
        );
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn all_workspace_prune_continues_after_removing_orphaned_metadata() {
        let sandbox = test_directory("all-workspace-prune-orphan");
        let valid_repository = sandbox.join("valid");
        let missing_repository = sandbox.join("missing");
        let storage = sandbox.join("storage");
        for (repository, contents) in [
            (&valid_repository, "valid contents"),
            (&missing_repository, "missing contents"),
        ] {
            fs::create_dir_all(repository).expect("create repository");
            run_git(repository, &["init"]);
            fs::write(repository.join("file.txt"), contents).expect("write file");
        }
        let valid_context = RecoveryPointContext {
            request_id: 81,
            session_id: "session-81",
            provider: "codex",
            trigger: "File mutation",
        };
        let missing_context = RecoveryPointContext {
            request_id: 82,
            session_id: "session-82",
            provider: "claude-code",
            trigger: "File mutation",
        };
        let valid = ensure_request_recovery_point_at(
            &valid_repository,
            &storage,
            &valid_context,
            DEFAULT_CHECKPOINT_PRUNE_HOURS,
        )
        .expect("valid recovery point");
        let missing = ensure_request_recovery_point_at(
            &missing_repository,
            &storage,
            &missing_context,
            DEFAULT_CHECKPOINT_PRUNE_HOURS,
        )
        .expect("orphaned recovery point");
        let missing_canonical = fs::canonicalize(&missing_repository).expect("canonical missing");
        let missing_marker =
            recovery_point_marker_path(&missing_canonical, &storage, missing_context.request_id);
        assert!(missing_marker.exists());
        fs::remove_dir_all(&missing_repository).expect("remove repository");

        let response = prune_all_checkpoints_at(&storage, 0, true).expect("global prune");
        assert_eq!(response.deleted, vec![valid.id.clone()]);
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].id, missing.id);
        assert!(response.failed[0].orphaned_metadata_removed);
        assert!(!missing_marker.exists());
        assert!(list_all_checkpoints_at(&storage)
            .expect("list after prune")
            .is_empty());
        let reference = format!("{CHECKPOINT_REF_PREFIX}/{}", valid.id);
        assert_eq!(
            git_optional(&valid_repository, &["rev-parse", "--verify", &reference])
                .expect("check deleted ref"),
            None
        );
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn orphan_cleanup_removes_a_matching_ref_from_a_relocated_repository() {
        let sandbox = test_directory("relocated-repository-cleanup");
        let original_repository = sandbox.join("original");
        let relocated_repository = sandbox.join("relocated");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&original_repository).expect("create repository");
        run_git(&original_repository, &["init"]);
        fs::write(original_repository.join("file.txt"), "before").expect("write file");
        let context = RecoveryPointContext {
            request_id: 91,
            session_id: "session-91",
            provider: "codex",
            trigger: "File mutation",
        };
        let checkpoint = ensure_request_recovery_point_at(
            &original_repository,
            &storage,
            &context,
            DEFAULT_CHECKPOINT_PRUNE_HOURS,
        )
        .expect("recovery point");
        fs::rename(&original_repository, &relocated_repository).expect("move repository");
        std::os::unix::fs::symlink(&relocated_repository, &original_repository)
            .expect("link old path to relocated repository");

        let response = prune_all_checkpoints_at(&storage, 0, true).expect("global prune");
        assert!(response.deleted.is_empty());
        assert_eq!(response.failed.len(), 1);
        assert!(response.failed[0].orphaned_metadata_removed);
        let reference = format!("{CHECKPOINT_REF_PREFIX}/{}", checkpoint.id);
        assert_eq!(
            git_optional(
                &relocated_repository,
                &["rev-parse", "--verify", &reference]
            )
            .expect("check relocated ref"),
            None
        );
        assert!(list_all_checkpoints_at(&storage)
            .expect("list after cleanup")
            .is_empty());
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn single_workspace_prune_reports_one_failure_and_continues() {
        let sandbox = test_directory("single-workspace-prune-failure");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        fs::write(repository.join("file.txt"), "first").expect("write first file");
        let first = create_checkpoint_at(&repository, &storage, Some("First"), None)
            .expect("first checkpoint");
        fs::write(repository.join("file.txt"), "second").expect("write second file");
        let second = create_checkpoint_at(&repository, &storage, Some("Second"), None)
            .expect("second checkpoint");
        let canonical = fs::canonicalize(&repository).expect("canonical repository");
        let first_metadata = repository_checkpoint_directory(&storage, &canonical)
            .join(format!("{}.json", first.id));
        let mut invalid: WorkspaceCheckpoint =
            serde_json::from_slice(&fs::read(&first_metadata).expect("read metadata"))
                .expect("decode metadata");
        invalid.id = "invalid/id".to_string();
        fs::write(
            first_metadata,
            serde_json::to_vec(&invalid).expect("encode invalid metadata"),
        )
        .expect("write invalid metadata");

        let response =
            prune_repository_checkpoints_at(&canonical, &storage, 0, true).expect("prune");
        assert_eq!(response.deleted, vec![second.id]);
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].id, "invalid/id");
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn automatic_pruning_preserves_manual_and_rescue_checkpoints() {
        let sandbox = test_directory("safe-auto-prune");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        fs::write(repository.join("file.txt"), "before").expect("write file");

        let manual = create_checkpoint_at(&repository, &storage, Some("Manual"), None)
            .expect("manual checkpoint");
        fs::write(repository.join("file.txt"), "rescue").expect("change for rescue");
        let rescue =
            create_checkpoint_at(&repository, &storage, Some("Rescue"), Some("cp-previous"))
                .expect("rescue checkpoint");
        fs::write(repository.join("file.txt"), "automatic").expect("change for automatic");
        let context = RecoveryPointContext {
            request_id: 9,
            session_id: "session-9",
            provider: "codex",
            trigger: "File mutation",
        };
        let automatic = ensure_request_recovery_point_at(
            &repository,
            &storage,
            &context,
            DEFAULT_CHECKPOINT_PRUNE_HOURS,
        )
        .expect("automatic checkpoint");

        for checkpoint in [&manual, &rescue, &automatic] {
            let directory = repository_checkpoint_directory(
                &storage,
                &fs::canonicalize(&repository).expect("canonical repository"),
            );
            let path = directory.join(format!("{}.json", checkpoint.id));
            let mut metadata: WorkspaceCheckpoint =
                serde_json::from_slice(&fs::read(&path).expect("read metadata"))
                    .expect("decode metadata");
            metadata.created_at_ms = 1;
            fs::write(
                path,
                serde_json::to_vec(&metadata).expect("encode metadata"),
            )
            .expect("age metadata");
        }

        prune_recovery_points(&repository, &storage, 1, 3_600_002).expect("automatic prune");
        let remaining = list_checkpoints_at(&repository, &storage).expect("list remaining");
        assert!(remaining
            .iter()
            .any(|checkpoint| checkpoint.id == manual.id));
        assert!(remaining
            .iter()
            .any(|checkpoint| checkpoint.id == rescue.id));
        assert!(!remaining
            .iter()
            .any(|checkpoint| checkpoint.id == automatic.id));
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn request_marker_avoids_duplicate_creation_and_is_removed_with_checkpoint() {
        let sandbox = test_directory("request-marker");
        let repository = sandbox.join("repo");
        let storage = sandbox.join("storage");
        fs::create_dir_all(&repository).expect("create repository");
        run_git(&repository, &["init"]);
        fs::write(repository.join("file.txt"), "before").expect("write file");
        let context = RecoveryPointContext {
            request_id: 71,
            session_id: "session-71",
            provider: "claude-code",
            trigger: "File mutation",
        };
        let checkpoint = ensure_request_recovery_point_at(
            &repository,
            &storage,
            &context,
            DEFAULT_CHECKPOINT_PRUNE_HOURS,
        )
        .expect("create checkpoint");
        let canonical = fs::canonicalize(&repository).expect("canonical repository");
        let marker = recovery_point_marker_path(&canonical, &storage, context.request_id);
        assert!(marker.exists());

        delete_checkpoint_at(&repository, &storage, &checkpoint.id).expect("delete checkpoint");
        assert!(!marker.exists());
        fs::remove_dir_all(sandbox).expect("cleanup");
    }

    #[test]
    fn pending_recovery_freshness_is_bounded() {
        assert!(pending_recovery_is_fresh(1_000, 1_000));
        assert!(pending_recovery_is_fresh(
            1_000,
            1_000 + PENDING_RECOVERY_MAX_AGE_MS
        ));
        assert!(!pending_recovery_is_fresh(
            1_000,
            1_001 + PENDING_RECOVERY_MAX_AGE_MS
        ));
    }
}
