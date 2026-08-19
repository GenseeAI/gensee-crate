use super::*;
use serde::{Deserialize, Serialize};

const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_REF_PREFIX: &str = "refs/gensee/checkpoints";

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

pub(crate) fn handle_checkpoint(args: Vec<OsString>) -> io::Result<()> {
    let command = args.first().and_then(|arg| arg.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint requires create, list, or restore",
        )
    })?;
    let parsed = CheckpointArgs::parse(&args[1..])?;
    let workspace = parsed.workspace.unwrap_or(env::current_dir()?);
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
            let repository = git_repository_root(&workspace)?;
            let checkpoints = list_checkpoints_at(&repository, &storage_root)?;
            if parsed.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&CheckpointListResponse {
                        workspace: repository.to_string_lossy().into_owned(),
                        checkpoints,
                    })?
                );
            } else if checkpoints.is_empty() {
                println!("No Gensee checkpoints for {}", repository.display());
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
    json: bool,
    yes: bool,
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
                Some("--json") => parsed.json = true,
                Some("--yes") => parsed.yes = true,
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
        Ok(parsed)
    }
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
        let checkpoint: WorkspaceCheckpoint = serde_json::from_slice(&fs::read(path)?)?;
        if checkpoint.workspace == repository.to_string_lossy() {
            checkpoints.push(checkpoint);
        }
    }
    checkpoints.sort_by_key(|checkpoint| std::cmp::Reverse(checkpoint.created_at_ms));
    Ok(checkpoints)
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

fn git_repository_root(workspace: &Path) -> io::Result<PathBuf> {
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
}

impl TemporaryGitIndex {
    fn new() -> io::Result<Self> {
        let directory = env::temp_dir().join("gensee-checkpoints");
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("index-{}-{}.index", std::process::id(), now_ms()?));
        Ok(Self { path })
    }
}

impl Drop for TemporaryGitIndex {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("index.lock"));
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
}
