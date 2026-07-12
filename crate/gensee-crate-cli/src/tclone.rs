use crate::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

const DEFAULT_TCLONE_IMAGE: &str = "ghcr.io/wuklab/webtop:ubuntu-kde";
const DEFAULT_CONTAINER_HOME: &str = "/home/gensee";
const DEFAULT_CONTAINER_WORKSPACE: &str = "/workspace";
const TCLONE_STATE_LOCK_STALE_SECS: u64 = 30;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct TcloneRunRecord {
    pub(crate) run_id: String,
    pub(crate) parent_run_id: Option<String>,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) container_name: String,
    pub(crate) container_id: Option<String>,
    pub(crate) source_container: Option<String>,
    pub(crate) fork_prefix: Option<String>,
    pub(crate) image: String,
    pub(crate) workspace: String,
    pub(crate) container_workspace: String,
    pub(crate) container_home: String,
    pub(crate) agent_cmd: Vec<String>,
    #[serde(default)]
    pub(crate) fork_base_git_head: Option<String>,
    #[serde(default)]
    pub(crate) fork_base_overlay_lowerdir: Option<String>,
    #[serde(default)]
    pub(crate) fork_overlay_upperdir: Option<String>,
    pub(crate) started_at_ms: u64,
    pub(crate) updated_at_ms: u64,
    pub(crate) exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcloneMergeScope {
    Git,
    Filesystem,
    Paths(Vec<String>),
}

pub(crate) fn run_tclone_agent(config: RunConfig) -> io::Result<()> {
    if std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "--runtime tclone is supported on Linux tclone hosts, not {}",
                std::env::consts::OS
            ),
        ));
    }

    let started_at_ms = unix_millis()?;
    let run_id = format!("run_{}_{}", std::process::id(), started_at_ms);
    let safe_id = run_id.replace('_', "-");
    let source_container = format!("gensee-tclone-src-{safe_id}");
    let fork_prefix = format!("gensee-tclone-fork-{safe_id}");
    let image = env::var("GENSEE_TCLONE_IMAGE").unwrap_or_else(|_| DEFAULT_TCLONE_IMAGE.into());
    let container_home =
        env::var("GENSEE_TCLONE_HOME").unwrap_or_else(|_| DEFAULT_CONTAINER_HOME.into());
    let container_workspace =
        env::var("GENSEE_TCLONE_WORKSPACE").unwrap_or_else(|_| DEFAULT_CONTAINER_WORKSPACE.into());
    let podman = tclone_podman();
    let original_workspace = canonicalize_or_original(&config.workspace);
    let repo_path = find_repo_root(&original_workspace);
    let seed_root = gensee_tmp_root()?.join(&run_id).join("tclone-seed");
    let staged_workspace = seed_root.join(container_relative_path(&container_workspace)?);

    let agent_binary = config.agent_cmd[0].to_string_lossy().to_string();
    let agent_home = detect_agent_home(&agent_binary);
    let gensee_home = default_root().ok().filter(|path| path.exists());
    prepare_tclone_seed(
        &seed_root,
        &original_workspace,
        agent_home.as_ref(),
        gensee_home.as_ref(),
        &container_workspace,
        &container_home,
    )?;
    if let Ok(current_exe) = env::current_exe() {
        if current_exe.exists() {
            let destination = seed_root.join("usr/local/bin/gensee");
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&current_exe, destination)?;
        }
    }

    let mut create_args = vec![
        OsString::from("create"),
        OsString::from("-i"),
        OsString::from("-t"),
        OsString::from("--name"),
        OsString::from(&source_container),
        OsString::from("--entrypoint"),
        config.agent_cmd[0].clone(),
        OsString::from("--log-driver=k8s-file"),
        OsString::from("--security-opt"),
        OsString::from("seccomp=unconfined"),
        OsString::from("--security-opt"),
        OsString::from("apparmor=unconfined"),
        OsString::from("--tmpfs"),
        OsString::from("/config:size=512m"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp:size=1g"),
        OsString::from("--tmpfs"),
        OsString::from("/run:size=256m"),
        OsString::from("-e"),
        OsString::from(format!("HOME={container_home}")),
        OsString::from("-e"),
        OsString::from(format!("GENSEE_HOME={container_home}/.gensee")),
        OsString::from("-e"),
        OsString::from(format!("GENSEE_RUN_ID={run_id}")),
        OsString::from("-e"),
        OsString::from(format!("AGENT_SHIELD_SESSION_ID={run_id}")),
        OsString::from("-e"),
        OsString::from(format!("GENSEE_WORKSPACE={container_workspace}")),
        OsString::from("-w"),
        OsString::from(&container_workspace),
    ];
    if let Some((name, _host, container_path)) = agent_home.as_ref() {
        create_args.push(OsString::from("-e"));
        create_args.push(OsString::from(format!("{name}={container_path}")));
    }
    if let Some((node_root, node_bin)) = tclone_node_mount() {
        create_args.push(OsString::from("-v"));
        create_args.push(OsString::from(format!(
            "{}:{}:ro",
            node_root.display(),
            node_root.display()
        )));
        create_args.push(OsString::from("-e"));
        create_args.push(OsString::from(format!(
            "PATH={}:{}",
            node_bin.display(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )));
    }
    create_args.push(OsString::from(&image));
    create_args.extend(config.agent_cmd.iter().skip(1).cloned());

    let output = run_command_capture(&podman, &create_args)?;
    let container_id = output.lines().next().map(str::trim).map(str::to_string);
    let cleanup_guard = TcloneContainerCleanup::new(&podman, &source_container);
    append_tclone_record(&TcloneRunRecord {
        run_id: run_id.clone(),
        parent_run_id: None,
        role: "source".to_string(),
        status: "preparing".to_string(),
        container_name: source_container.clone(),
        container_id: container_id.clone(),
        source_container: Some(source_container.clone()),
        fork_prefix: Some(fork_prefix),
        image,
        workspace: original_workspace.to_string_lossy().to_string(),
        container_workspace: container_workspace.clone(),
        container_home: container_home.clone(),
        agent_cmd: config
            .agent_cmd
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect(),
        fork_base_git_head: None,
        fork_base_overlay_lowerdir: None,
        fork_overlay_upperdir: None,
        started_at_ms,
        updated_at_ms: started_at_ms,
        exit_code: None,
    })?;
    eprintln!(
        "gensee: preparing tclone run {run_id} source_container={source_container} workspace={}",
        original_workspace.display()
    );

    podman_cp_contents(&podman, &seed_root, &format!("{source_container}:/"))?;
    run_command_status(
        &podman,
        &[OsString::from("start"), OsString::from(&source_container)],
    )?;
    let root_pid = inspect_container_pid(&podman, &source_container).unwrap_or(0);

    let store = EventStore::default_local()?;
    store.append_session(&AgentSession {
        session_id: run_id.clone(),
        agent_binary: agent_binary.clone(),
        root_pid,
        cwd: container_workspace.clone(),
        repo_path: repo_path
            .clone()
            .map(|path| path.to_string_lossy().to_string()),
        mode: Some("managed-run:tclone:source".to_string()),
        workspace_mode: Some("tclone-rootfs".to_string()),
        original_workspace: Some(original_workspace.to_string_lossy().to_string()),
        staged_workspace: Some(staged_workspace.to_string_lossy().to_string()),
        sandbox_profile: Some("tclone-container".to_string()),
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: None,
        exit_code: None,
    })?;
    append_tclone_status(&run_id, "running", None)?;
    cleanup_guard.disarm();

    eprintln!(
        "gensee: started tclone run {run_id} source_container={source_container} workspace={}",
        original_workspace.display()
    );
    eprintln!("gensee: fork from another terminal with: gensee fork {run_id}");

    let status = Command::new(&podman)
        .arg("attach")
        .arg(&source_container)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    let ended_at_ms = unix_millis()?;
    let exit_code = status.code();
    store.append_session(&AgentSession {
        session_id: run_id.clone(),
        agent_binary,
        root_pid,
        cwd: container_workspace,
        repo_path: repo_path.map(|path| path.to_string_lossy().to_string()),
        mode: Some("managed-run:tclone:source".to_string()),
        workspace_mode: Some("tclone-rootfs".to_string()),
        original_workspace: Some(original_workspace.to_string_lossy().to_string()),
        staged_workspace: Some(staged_workspace.to_string_lossy().to_string()),
        sandbox_profile: Some("tclone-container".to_string()),
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: Some(ended_at_ms),
        exit_code,
    })?;
    append_tclone_status(&run_id, "agent-ended", exit_code)?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone agent exited with status {status}"
        )))
    }
}

pub(crate) fn tclone_fork(args: Vec<OsString>) -> io::Result<()> {
    let parent = tclone_target_arg(
        &args,
        "usage: gensee fork <run_id> [--copies N] [--name <prefix>]",
    )?;
    let copies = arg_value(&args, "--copies")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid --copies: {err}"),
            )
        })?
        .unwrap_or(1);
    if copies == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--copies must be greater than zero",
        ));
    }
    let source = find_tclone_record(&parent)?;
    if source.status == "preparing" {
        return Err(io::Error::other(format!(
            "tclone source {} is still preparing; wait for status=running before forking",
            source.run_id
        )));
    }
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &source)?;
    let forked_at_ms = unix_millis()?;
    let fork_base_git_head = capture_tclone_git_head(&podman, &source).ok();
    let prefix = arg_value(&args, "--name").unwrap_or_else(|| {
        format!(
            "gensee-tclone-fork-{}-{}",
            parent.replace(['_', '/'], "-"),
            forked_at_ms
        )
    });
    let clone_args = vec![
        OsString::from("container"),
        OsString::from("clone"),
        OsString::from("--live"),
        OsString::from(format!("--copies={copies}")),
        OsString::from("--persistent=async"),
        OsString::from("--tfork-overlay-btrfs"),
        OsString::from("--tfork-tcp-close"),
        OsString::from("--tfork-ghost-limit=67108864"),
        OsString::from("--name"),
        OsString::from(&prefix),
        OsString::from(&source.container_name),
    ];
    let output =
        run_command_capture_with_env(&podman, &clone_args, &[("PODMAN_TFORK_NO_REAP", "1")])?;
    let ids = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for index in 0..copies {
        let run_id = format!("{}_fork_{}_{}", source.run_id, forked_at_ms, index);
        let container_name = ids
            .get(index)
            .and_then(|id| inspect_container_name(&podman, id).ok())
            .unwrap_or_else(|| {
                if copies == 1 {
                    prefix.clone()
                } else {
                    format!("{prefix}-{index}")
                }
            });
        let root_pid = inspect_container_pid(&podman, &container_name).unwrap_or(0);
        let overlay_layers = inspect_tclone_overlay_rootfs(&podman, &container_name).ok();
        let observed_at = unix_millis()?;
        EventStore::default_local()?.append_session(&AgentSession {
            session_id: run_id.clone(),
            agent_binary: source.agent_cmd.first().cloned().unwrap_or_default(),
            root_pid,
            cwd: source.container_workspace.clone(),
            repo_path: None,
            mode: Some(format!("managed-run:tclone:fork:{}", source.run_id)),
            workspace_mode: Some("tclone-rootfs".to_string()),
            original_workspace: Some(source.workspace.clone()),
            staged_workspace: None,
            sandbox_profile: Some("tclone-container".to_string()),
            sandbox_profile_path: None,
            started_at_ms: observed_at,
            ended_at_ms: None,
            exit_code: None,
        })?;
        append_tclone_record(&TcloneRunRecord {
            run_id: run_id.clone(),
            parent_run_id: Some(source.run_id.clone()),
            role: "fork".to_string(),
            status: "running".to_string(),
            container_name: container_name.clone(),
            container_id: ids.get(index).cloned(),
            source_container: Some(source.container_name.clone()),
            fork_prefix: Some(prefix.clone()),
            image: source.image.clone(),
            workspace: source.workspace.clone(),
            container_workspace: source.container_workspace.clone(),
            container_home: source.container_home.clone(),
            agent_cmd: source.agent_cmd.clone(),
            fork_base_git_head: fork_base_git_head.clone(),
            fork_base_overlay_lowerdir: overlay_layers
                .as_ref()
                .map(|layers| layers.lowerdir.to_string_lossy().to_string()),
            fork_overlay_upperdir: overlay_layers
                .as_ref()
                .map(|layers| layers.upperdir.to_string_lossy().to_string()),
            started_at_ms: observed_at,
            updated_at_ms: observed_at,
            exit_code: None,
        })?;
        println!("{run_id} | container={container_name}");
    }
    Ok(())
}

pub(crate) fn tclone_shell(args: Vec<OsString>) -> io::Result<()> {
    let target = tclone_target_arg(&args, "usage: gensee run shell <run_id-or-container>")?;
    let record = find_tclone_record(&target)?;
    let podman = tclone_podman();
    let shell = arg_value(&args, "--shell").unwrap_or_else(|| "bash".to_string());
    let status = Command::new(&podman)
        .arg("exec")
        .arg("-it")
        .arg("-w")
        .arg(&record.container_workspace)
        .arg(&record.container_name)
        .arg(shell)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone shell exited with status {status}"
        )))
    }
}

pub(crate) fn tclone_attach(args: Vec<OsString>) -> io::Result<()> {
    let target = tclone_target_arg(&args, "usage: gensee run attach <run_id-or-container>")?;
    let record = find_tclone_record(&target)?;
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &record)?;
    let status = Command::new(&podman)
        .arg("attach")
        .arg(&record.container_name)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone attach exited with status {status}"
        )))
    }
}

pub(crate) fn tclone_diff(args: Vec<OsString>) -> io::Result<()> {
    let target = tclone_target_arg(&args, "usage: gensee run diff <run_id-or-container>")?;
    let record = find_tclone_record(&target)?;
    let script = "cd \"$GENSEE_WORKSPACE\" && if git rev-parse --show-toplevel >/dev/null 2>&1; then git status --short && git diff --stat && git diff; else echo 'non-git tclone workspace; showing files:'; find . -maxdepth 3 -type f | sort | sed -n '1,200p'; fi";
    tclone_exec_env(
        &tclone_podman(),
        &record.container_name,
        &[("GENSEE_WORKSPACE", &record.container_workspace)],
        &["bash", "-lc", script],
    )
}

pub(crate) fn tclone_merge(args: Vec<OsString>) -> io::Result<()> {
    let fork_target = tclone_target_arg(
        &args,
        "usage: gensee run merge <fork-id> --into <source-id> [--git|--filesystem|--paths <path>...] [--dry-run] [--force]",
    )?;
    let source_target = arg_value(&args, "--into").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run merge <fork-id> --into <source-id> [--git|--filesystem|--paths <path>...] [--dry-run] [--force]",
        )
    })?;
    let dry_run = arg_flag(&args, "--dry-run");
    let force = arg_flag(&args, "--force");
    let scope = tclone_merge_scope(&args)?;
    let fork = find_tclone_record(&fork_target)?;
    let source = find_tclone_record(&source_target)?;
    validate_tclone_merge_pair(&fork, &source, force)?;

    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &fork)?;
    ensure_tclone_container_exists(&podman, &source)?;

    match scope {
        TcloneMergeScope::Git => tclone_merge_git(&podman, &fork, &source, dry_run),
        TcloneMergeScope::Filesystem => {
            tclone_merge_filesystem(&podman, &fork, &source, None, dry_run)
        }
        TcloneMergeScope::Paths(paths) => {
            tclone_merge_filesystem(&podman, &fork, &source, Some(paths), dry_run)
        }
    }
}

pub(crate) fn tclone_switch(args: Vec<OsString>) -> io::Result<()> {
    let target = tclone_target_arg(&args, "usage: gensee run switch <fork-id>")?;
    let fork = find_tclone_record(&target)?;
    if fork.role != "fork" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("switch target must be a fork, got role={}", fork.role),
        ));
    }

    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &fork)?;
    let switched_at_ms = unix_millis()?;

    if let Some(parent_run_id) = fork.parent_run_id.as_deref() {
        if let Ok(mut previous_source) = find_tclone_record(parent_run_id) {
            if previous_source.role == "source" {
                previous_source.status = "switched-away".to_string();
                previous_source.updated_at_ms = switched_at_ms;
                append_tclone_record(&previous_source)?;
            }
        }
    }

    let switched = switched_tclone_source_record(fork, switched_at_ms)?;
    append_tclone_record(&switched)?;
    println!(
        "gensee: switched active tclone source to {} ({})",
        switched.run_id, switched.container_name
    );
    Ok(())
}

pub(crate) fn tclone_delete(args: Vec<OsString>) -> io::Result<()> {
    let delete_all = args.iter().any(|arg| arg == "--all");
    if delete_all {
        return tclone_delete_all();
    }

    let target = tclone_target_arg(
        &args,
        "usage: gensee run delete <tclone-run-or-container>|--all",
    )?;
    let record = find_tclone_record(&target)?;
    let removed_container = remove_tclone_container(&record).map_err(|error| {
        io::Error::other(format!(
            "could not remove tclone container {} (record preserved): {error}",
            record.container_name
        ))
    })?;
    let removed_records = delete_tclone_records(|candidate| candidate.run_id == record.run_id)?;

    println!(
        "gensee: deleted tclone run {} ({}) container={} records_removed={removed_records}",
        record.run_id,
        record.container_name,
        removed_container.as_str()
    );
    Ok(())
}

fn tclone_delete_all() -> io::Result<()> {
    let podman = tclone_podman();
    let records = list_tclone_runs()?;
    let tracked_container_names = records
        .iter()
        .map(|record| record.container_name.clone())
        .collect::<HashSet<_>>();
    let orphan_container_names = list_tclone_container_names(&podman)?
        .into_iter()
        .filter(|name| !tracked_container_names.contains(name))
        .collect::<Vec<_>>();
    if records.is_empty() && orphan_container_names.is_empty() {
        println!("gensee: no tclone runs to delete");
        return Ok(());
    }

    let mut removed_containers = 0;
    let mut already_gone = 0;
    let mut failed = 0;
    let mut deleted_run_ids = HashSet::new();
    for record in &records {
        match remove_tclone_container(record) {
            Ok(TcloneContainerRemoval::Removed) => {
                removed_containers += 1;
                deleted_run_ids.insert(record.run_id.clone());
            }
            Ok(TcloneContainerRemoval::AlreadyGone) => {
                already_gone += 1;
                deleted_run_ids.insert(record.run_id.clone());
            }
            Err(error) => {
                failed += 1;
                eprintln!(
                    "gensee: warning: could not remove tclone container {} (record preserved): {error}",
                    record.container_name
                );
            }
        }
    }
    let mut removed_orphans = 0;
    for container_name in orphan_container_names {
        match remove_tclone_container_by_name(&podman, &container_name) {
            Ok(TcloneContainerRemoval::Removed) => {
                removed_orphans += 1;
            }
            Ok(TcloneContainerRemoval::AlreadyGone) => {}
            Err(error) => {
                failed += 1;
                eprintln!(
                    "gensee: warning: could not remove orphaned tclone container {container_name}: {error}"
                );
            }
        }
    }
    let removed_records =
        delete_tclone_records(|record| deleted_run_ids.contains(record.run_id.as_str()))?;
    println!(
        "gensee: deleted {removed_records} tclone run records, removed {removed_containers} tracked containers, removed {removed_orphans} orphaned containers, and pruned {already_gone} stale records"
    );
    if failed > 0 {
        return Err(io::Error::other(format!(
            "{failed} tclone container(s) could not be removed; their records were preserved"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcloneContainerRemoval {
    Removed,
    AlreadyGone,
}

impl TcloneContainerRemoval {
    fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::AlreadyGone => "already-gone",
        }
    }
}

fn remove_tclone_container(record: &TcloneRunRecord) -> io::Result<TcloneContainerRemoval> {
    let podman = tclone_podman();
    remove_tclone_container_by_name(&podman, &record.container_name)
}

fn remove_tclone_container_by_name(
    podman: &OsString,
    container_name: &str,
) -> io::Result<TcloneContainerRemoval> {
    if !tclone_container_exists(podman, container_name)? {
        return Ok(TcloneContainerRemoval::AlreadyGone);
    }

    run_command_status(
        podman,
        &[
            OsString::from("rm"),
            OsString::from("-f"),
            OsString::from(container_name),
        ],
    )?;
    Ok(TcloneContainerRemoval::Removed)
}

fn list_tclone_container_names(podman: &OsString) -> io::Result<Vec<String>> {
    let output = run_command_capture(
        podman,
        &[
            OsString::from("ps"),
            OsString::from("-a"),
            OsString::from("--format"),
            OsString::from("{{.Names}}"),
        ],
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with("gensee-tclone-"))
        .map(ToString::to_string)
        .collect())
}

fn tclone_container_exists(podman: &OsString, container_name: &str) -> io::Result<bool> {
    let output = Command::new(podman)
        .arg("inspect")
        .arg("--type")
        .arg("container")
        .arg(container_name)
        .output()?;
    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("no such")
        || stderr.contains("not found")
        || stderr.contains("does not exist")
        || stderr.contains("no container with name")
    {
        return Ok(false);
    }

    Err(io::Error::other(format!(
        "{} inspect failed for {}: {}",
        podman.to_string_lossy(),
        container_name,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn switched_tclone_source_record(
    mut fork: TcloneRunRecord,
    switched_at_ms: u64,
) -> io::Result<TcloneRunRecord> {
    if fork.role != "fork" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("switch target must be a fork, got role={}", fork.role),
        ));
    }
    fork.parent_run_id = None;
    fork.role = "source".to_string();
    fork.status = "active".to_string();
    fork.source_container = Some(fork.container_name.clone());
    fork.updated_at_ms = switched_at_ms;
    Ok(fork)
}

fn tclone_merge_git(
    podman: &OsString,
    fork: &TcloneRunRecord,
    source: &TcloneRunRecord,
    dry_run: bool,
) -> io::Result<()> {
    let patch = tclone_merge_patch(podman, fork)?;
    if patch.trim().is_empty() {
        println!(
            "gensee: no changes to merge from {} into {}",
            fork.run_id, source.run_id
        );
        return Ok(());
    }

    let patch_id = format!("gensee-merge-{}.patch", unix_millis()?);
    let host_patch = gensee_tmp_root()?.join(&patch_id);
    fs::write(&host_patch, patch)?;
    let container_patch = format!("/tmp/{patch_id}");
    let result = (|| {
        podman_cp(
            podman,
            &host_patch,
            &format!("{}:{container_patch}", source.container_name),
        )?;
        tclone_apply_merge_patch(podman, source, &container_patch, dry_run)
    })();
    let _ = fs::remove_file(&host_patch);
    let _ = tclone_exec(
        podman,
        &source.container_name,
        &["rm", "-f", &container_patch],
    );
    result?;

    if dry_run {
        println!(
            "gensee: git merge dry-run succeeded from {} into {}",
            fork.run_id, source.run_id
        );
    } else {
        append_tclone_status(&fork.run_id, "merged", None)?;
        println!(
            "gensee: merged git changes from {} into {}",
            fork.run_id, source.run_id
        );
    }
    Ok(())
}

fn tclone_merge_filesystem(
    podman: &OsString,
    fork: &TcloneRunRecord,
    source: &TcloneRunRecord,
    paths: Option<Vec<String>>,
    dry_run: bool,
) -> io::Result<()> {
    if paths.as_ref().is_some_and(Vec::is_empty) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gensee run merge --paths requires at least one path",
        ));
    }

    let fork_overlay = inspect_tclone_overlay_rootfs(podman, &fork.container_name)?;
    let source_rootfs = inspect_tclone_rootfs(podman, &source.container_name)?;
    let filter = paths.map(|paths| {
        paths
            .into_iter()
            .map(|path| normalize_tclone_merge_path(&path))
            .collect::<Vec<_>>()
    });
    let plan = build_tclone_overlay_merge_plan(
        &fork_overlay.lowerdir,
        &fork_overlay.upperdir,
        &source_rootfs,
        &filter,
    )?;

    if !plan.conflicts.is_empty() {
        let shown = plan
            .conflicts
            .iter()
            .take(20)
            .map(|path| format!("/{path}"))
            .collect::<Vec<_>>()
            .join("\n  ");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "filesystem merge has {} conflict(s); resolve manually before retrying. First conflicts:\n  {shown}",
                plan.conflicts.len()
            ),
        ));
    }
    if plan.changes.is_empty() {
        println!(
            "gensee: no filesystem changes to merge from {} into {}",
            fork.run_id, source.run_id
        );
        return Ok(());
    }
    if dry_run {
        println!(
            "gensee: overlay filesystem merge dry-run found {} change(s) and no conflicts",
            plan.changes.len()
        );
        return Ok(());
    }

    apply_tclone_overlay_merge(&source_rootfs, &plan)?;
    append_tclone_status(&fork.run_id, "merged", None)?;
    println!(
        "gensee: merged overlay filesystem changes from {} into {}",
        fork.run_id, source.run_id
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcloneOverlayRootfs {
    rootfs: PathBuf,
    lowerdir: PathBuf,
    upperdir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcloneOverlayMergeOp {
    UpsertFile,
    CreateDir,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcloneOverlayMergeChange {
    path: String,
    op: TcloneOverlayMergeOp,
    source: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcloneOverlayMergePlan {
    changes: Vec<TcloneOverlayMergeChange>,
    conflicts: Vec<String>,
}

impl TcloneOverlayMergePlan {
    fn upserts(&self) -> impl Iterator<Item = &TcloneOverlayMergeChange> {
        self.changes
            .iter()
            .filter(|change| change.op != TcloneOverlayMergeOp::Delete)
    }

    fn deletions(&self) -> impl Iterator<Item = &TcloneOverlayMergeChange> {
        self.changes
            .iter()
            .rev()
            .filter(|change| change.op == TcloneOverlayMergeOp::Delete)
    }
}

fn build_tclone_overlay_merge_plan(
    lowerdir: &Path,
    upperdir: &Path,
    source_rootfs: &Path,
    filter: &Option<Vec<String>>,
) -> io::Result<TcloneOverlayMergePlan> {
    let mut upper_changes = enumerate_tclone_overlay_changes(upperdir, filter)?;
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    upper_changes.sort_by(|left, right| left.path.cmp(&right.path));
    upper_changes.dedup_by(|left, right| left.path == right.path && left.op == right.op);

    for change in upper_changes {
        let base_path = lowerdir.join(&change.path);
        if change.op == TcloneOverlayMergeOp::CreateDir && base_path.exists() {
            continue;
        }
        let source_path = source_rootfs.join(&change.path);
        let source_matches_base = path_signatures_equal(&source_path, &base_path)?;
        let source_matches_fork = change
            .source
            .as_ref()
            .map(|fork_path| path_signatures_equal(&source_path, fork_path))
            .transpose()?
            .unwrap_or_else(|| !source_path.exists());
        if !source_matches_base && !source_matches_fork {
            conflicts.push(change.path);
            continue;
        }
        changes.push(change);
    }

    conflicts.sort();
    conflicts.dedup();
    Ok(TcloneOverlayMergePlan { changes, conflicts })
}

fn enumerate_tclone_overlay_changes(
    upperdir: &Path,
    filter: &Option<Vec<String>>,
) -> io::Result<Vec<TcloneOverlayMergeChange>> {
    let mut changes = Vec::new();
    enumerate_tclone_overlay_changes_inner(upperdir, upperdir, filter, &mut changes)?;
    Ok(changes)
}

fn enumerate_tclone_overlay_changes_inner(
    root: &Path,
    current: &Path,
    filter: &Option<Vec<String>>,
    changes: &mut Vec<TcloneOverlayMergeChange>,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name == ".wh..wh..opq" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "overlay opaque directory marker is not supported yet near {}",
                    path.display()
                ),
            ));
        }
        if let Some(deleted) = overlay_whiteout_target(&rel, &entry)? {
            if path_matches_tclone_merge_filter(&deleted, filter) {
                changes.push(TcloneOverlayMergeChange {
                    path: deleted,
                    op: TcloneOverlayMergeOp::Delete,
                    source: None,
                });
            }
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if path_matches_tclone_merge_filter(&rel, filter) {
                changes.push(TcloneOverlayMergeChange {
                    path: rel.clone(),
                    op: TcloneOverlayMergeOp::CreateDir,
                    source: Some(path.clone()),
                });
            }
            enumerate_tclone_overlay_changes_inner(root, &path, filter, changes)?;
        } else if (file_type.is_file() || file_type.is_symlink())
            && path_matches_tclone_merge_filter(&rel, filter)
        {
            changes.push(TcloneOverlayMergeChange {
                path: rel,
                op: TcloneOverlayMergeOp::UpsertFile,
                source: Some(path),
            });
        }
    }
    Ok(())
}

fn overlay_whiteout_target(path: &str, entry: &fs::DirEntry) -> io::Result<Option<String>> {
    let file_name = entry.file_name().to_string_lossy().to_string();
    if let Some(stripped) = file_name.strip_prefix(".wh.") {
        let parent = Path::new(path)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("");
        return Ok(Some(if parent.is_empty() {
            stripped.to_string()
        } else {
            format!("{parent}/{stripped}")
        }));
    }

    #[cfg(unix)]
    {
        if entry.file_type()?.is_char_device() {
            return Ok(Some(path.to_string()));
        }
    }

    Ok(None)
}

fn apply_tclone_overlay_merge(
    source_rootfs: &Path,
    plan: &TcloneOverlayMergePlan,
) -> io::Result<()> {
    for change in plan.deletions() {
        remove_path_if_exists(&source_rootfs.join(&change.path))?;
    }
    for change in plan.upserts() {
        let destination = source_rootfs.join(&change.path);
        match change.op {
            TcloneOverlayMergeOp::CreateDir => fs::create_dir_all(&destination)?,
            TcloneOverlayMergeOp::UpsertFile => {
                let source = change.source.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("missing overlay source for {}", change.path),
                    )
                })?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                remove_path_if_exists(&destination)?;
                copy_path_preserving_metadata(source, &destination)?;
            }
            TcloneOverlayMergeOp::Delete => {}
        }
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn copy_path_preserving_metadata(source: &Path, destination: &Path) -> io::Result<()> {
    let status = Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto")
        .arg(source)
        .arg(destination)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "cp -a --reflink=auto {} {} exited with status {status}",
            source.display(),
            destination.display()
        )))
    }
}

fn normalize_tclone_merge_path(path: &str) -> String {
    path.trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn path_matches_tclone_merge_filter(path: &str, filter: &Option<Vec<String>>) -> bool {
    match filter {
        Some(filters) => filters
            .iter()
            .any(|filter| path == filter || path.starts_with(&format!("{filter}/"))),
        None => true,
    }
}

pub(crate) fn tclone_keep(args: Vec<OsString>) -> io::Result<()> {
    let target = tclone_target_arg(
        &args,
        "usage: gensee run keep <run_id-or-container> --to <path>",
    )?;
    let destination = arg_value(&args, "--to").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run keep <run_id-or-container> --to <path>",
        )
    })?;
    let record = find_tclone_record(&target)?;
    fs::create_dir_all(&destination)?;
    let podman = tclone_podman();
    let target = format!("{}:{}/.", record.container_name, record.container_workspace);
    run_command_status(
        &podman,
        &[
            OsString::from("cp"),
            OsString::from(target),
            OsString::from(&destination),
        ],
    )?;
    println!(
        "gensee: copied tclone workspace {} -> {}",
        record.run_id, destination
    );
    Ok(())
}

fn validate_tclone_merge_pair(
    fork: &TcloneRunRecord,
    source: &TcloneRunRecord,
    force: bool,
) -> io::Result<()> {
    if fork.run_id == source.run_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot merge a tclone container into itself",
        ));
    }
    if fork.role != "fork" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("merge source must be a fork, got role={}", fork.role),
        ));
    }
    if source.role != "source" && !force {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("merge target must be a source, got role={}", source.role),
        ));
    }
    if fork.parent_run_id.as_deref() != Some(source.run_id.as_str()) && !force {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a fork of {}; pass --force to override",
                fork.run_id, source.run_id
            ),
        ));
    }
    Ok(())
}

fn tclone_merge_scope(args: &[OsString]) -> io::Result<TcloneMergeScope> {
    let git = arg_flag(args, "--git");
    let filesystem = arg_flag(args, "--filesystem");
    let paths = arg_values_after(args, "--paths");
    let selected = usize::from(git) + usize::from(filesystem) + usize::from(!paths.is_empty());
    if selected > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "choose only one merge scope: --git, --filesystem, or --paths",
        ));
    }
    if filesystem {
        Ok(TcloneMergeScope::Filesystem)
    } else if !paths.is_empty() {
        Ok(TcloneMergeScope::Paths(paths))
    } else {
        Ok(TcloneMergeScope::Git)
    }
}

fn tclone_merge_patch(podman: &OsString, fork: &TcloneRunRecord) -> io::Result<String> {
    let script = r#"set -euo pipefail
cd "$GENSEE_WORKSPACE"
if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "gensee: merge --git requires a git workspace at $GENSEE_WORKSPACE" >&2
  exit 64
fi
base="${GENSEE_GIT_MERGE_BASE:-HEAD}"
if git rev-parse --verify "$base^{commit}" >/dev/null 2>&1; then
  git diff --binary "$base"
else
  echo "gensee: warning: fork git merge base '$base' is unavailable; falling back to git diff HEAD" >&2
  git diff --binary HEAD
fi
while IFS= read -r -d '' file; do
  git diff --binary --no-index -- /dev/null "$file" || true
done < <(git ls-files --others --exclude-standard -z)
"#;
    let mut envs = vec![("GENSEE_WORKSPACE", fork.container_workspace.as_str())];
    if let Some(base) = fork.fork_base_git_head.as_deref() {
        envs.push(("GENSEE_GIT_MERGE_BASE", base));
    }
    tclone_exec_capture_env(
        podman,
        &fork.container_name,
        &envs,
        &["bash", "-lc", script],
    )
}

fn capture_tclone_git_head(podman: &OsString, source: &TcloneRunRecord) -> io::Result<String> {
    let script = r#"set -euo pipefail
cd "$GENSEE_WORKSPACE"
git rev-parse --verify HEAD
"#;
    let output = tclone_exec_capture_env(
        podman,
        &source.container_name,
        &[("GENSEE_WORKSPACE", &source.container_workspace)],
        &["bash", "-lc", script],
    )?;
    let head = output.trim().to_string();
    if head.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty git HEAD from tclone source container",
        ))
    } else {
        Ok(head)
    }
}

fn ensure_tclone_container_exists(podman: &OsString, record: &TcloneRunRecord) -> io::Result<()> {
    let status = Command::new(podman)
        .arg("inspect")
        .arg("--type")
        .arg("container")
        .arg(&record.container_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "tclone container for {} not found: {}. Checked with podman command `{}`. If the container was created with sudo or GENSEE_TCLONE_PODMAN, run this command through the same wrapper, for example `gensee-tclone fork {}`.",
                record.run_id,
                record.container_name,
                podman.to_string_lossy(),
                record.run_id
            ),
        ))
    }
}

fn inspect_tclone_rootfs(podman: &OsString, container: &str) -> io::Result<PathBuf> {
    let output = run_command_capture(
        podman,
        &[OsString::from("inspect"), OsString::from(container)],
    )?;
    let values = serde_json::from_str::<Vec<serde_json::Value>>(&output)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let Some(value) = values.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("podman inspect returned no container for {container}"),
        ));
    };
    let data = &value["GraphDriver"]["Data"];
    let path = data["Source"]
        .as_str()
        .or_else(|| data["MergedDir"].as_str())
        .or_else(|| value["Rootfs"].as_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("podman inspect for {container} did not include a rootfs path"),
            )
        })?;
    Ok(PathBuf::from(path))
}

fn inspect_tclone_overlay_rootfs(
    podman: &OsString,
    container: &str,
) -> io::Result<TcloneOverlayRootfs> {
    let rootfs = inspect_tclone_rootfs(podman, container)?;
    let Some((lowerdir, upperdir)) = overlay_layers_for_mountpoint(&rootfs)? else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "container {container} is not backed by a visible overlay rootfs; create a new fork with Gensee's tclone overlay mode"
            ),
        ));
    };
    Ok(TcloneOverlayRootfs {
        rootfs,
        lowerdir,
        upperdir,
    })
}

fn overlay_layers_for_mountpoint(rootfs: &Path) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let rootfs = rootfs.to_string_lossy().to_string();
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_whitespace().collect::<Vec<_>>();
        if left_fields.len() < 5 || right_fields.len() < 3 {
            continue;
        }
        let mountpoint = unescape_mountinfo_field(left_fields[4]);
        if mountpoint != rootfs {
            continue;
        }
        if right_fields[0] != "overlay" {
            return Ok(None);
        }
        let opts = right_fields[2];
        let mut lowerdir = None;
        let mut upperdir = None;
        for option in opts.split(',') {
            if let Some(value) = option.strip_prefix("lowerdir=") {
                lowerdir = value.split(':').next().map(unescape_mountinfo_field);
            } else if let Some(value) = option.strip_prefix("upperdir=") {
                upperdir = Some(unescape_mountinfo_field(value));
            }
        }
        return match (lowerdir, upperdir) {
            (Some(lowerdir), Some(upperdir)) => {
                Ok(Some((PathBuf::from(lowerdir), PathBuf::from(upperdir))))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("overlay mount for {rootfs} did not expose lowerdir and upperdir"),
            )),
        };
    }
    Ok(None)
}

fn unescape_mountinfo_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TclonePathSignature {
    Missing,
    File { mode: u32, len: u64, hash: u64 },
    Dir { mode: u32 },
    Symlink(String),
    Other,
}

fn path_signatures_equal(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(path_signature(left)? == path_signature(right)?)
}

fn path_signature(path: &Path) -> io::Result<TclonePathSignature> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(TclonePathSignature::Missing);
        }
        Err(err) => return Err(err),
    };
    let file_type = metadata.file_type();
    #[cfg(unix)]
    let mode = metadata.permissions().mode();
    #[cfg(not(unix))]
    let mode = 0;
    if file_type.is_symlink() {
        return Ok(TclonePathSignature::Symlink(
            fs::read_link(path)?.to_string_lossy().to_string(),
        ));
    }
    if file_type.is_dir() {
        return Ok(TclonePathSignature::Dir { mode });
    }
    if file_type.is_file() {
        return Ok(TclonePathSignature::File {
            mode,
            len: metadata.len(),
            hash: hash_file(path)?,
        });
    }
    Ok(TclonePathSignature::Other)
}

fn hash_file(path: &Path) -> io::Result<u64> {
    let mut file = fs::File::open(path)?;
    let mut hasher = DefaultHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        buffer[..read].hash(&mut hasher);
    }
    Ok(hasher.finish())
}

fn tclone_apply_merge_patch(
    podman: &OsString,
    source: &TcloneRunRecord,
    container_patch: &str,
    dry_run: bool,
) -> io::Result<()> {
    let script = if dry_run {
        format!(
            "set -euo pipefail\ncd \"$GENSEE_WORKSPACE\"\nif ! git rev-parse --show-toplevel >/dev/null 2>&1; then echo \"gensee: merge --git requires a git workspace at $GENSEE_WORKSPACE\" >&2; exit 64; fi\ngit apply --check '{}'\ngit status --short",
            container_patch
        )
    } else {
        format!(
            "set -euo pipefail\ncd \"$GENSEE_WORKSPACE\"\nif ! git rev-parse --show-toplevel >/dev/null 2>&1; then echo \"gensee: merge --git requires a git workspace at $GENSEE_WORKSPACE\" >&2; exit 64; fi\ngit apply '{}'\ngit status --short",
            container_patch
        )
    };
    tclone_exec_env(
        podman,
        &source.container_name,
        &[("GENSEE_WORKSPACE", &source.container_workspace)],
        &["bash", "-lc", &script],
    )
}

pub(crate) fn tclone_discard_if_exists(target: &str) -> io::Result<bool> {
    let Ok(record) = find_tclone_record(target) else {
        return Ok(false);
    };
    run_command_status(
        &tclone_podman(),
        &[
            OsString::from("rm"),
            OsString::from("-f"),
            OsString::from(&record.container_name),
        ],
    )?;
    append_tclone_status(&record.run_id, "discarded", None)?;
    println!(
        "gensee: discarded tclone container {} ({})",
        record.run_id, record.container_name
    );
    Ok(true)
}

pub(crate) fn list_tclone_runs() -> io::Result<Vec<TcloneRunRecord>> {
    let path = tclone_state_path()?;
    read_tclone_runs_from_path(&path)
}

fn delete_tclone_records(
    mut should_delete: impl FnMut(&TcloneRunRecord) -> bool,
) -> io::Result<usize> {
    let path = tclone_state_path()?;
    let records = read_tclone_runs_from_path(&path)?;
    let original_count = records.len();
    let retained = records
        .into_iter()
        .filter(|record| !should_delete(record))
        .collect::<Vec<_>>();
    write_tclone_runs_to_path(&path, &retained)?;
    Ok(original_count.saturating_sub(retained.len()))
}

fn read_tclone_runs_from_path(path: &Path) -> io::Result<Vec<TcloneRunRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut records: Vec<TcloneRunRecord> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<TcloneRunRecord>(&line) else {
            eprintln!(
                "gensee: warning: skipping malformed tclone state line in {}",
                path.display()
            );
            continue;
        };
        if let Some(existing) = records
            .iter_mut()
            .find(|existing| existing.run_id == record.run_id)
        {
            *existing = record;
        } else {
            records.push(record);
        }
    }
    Ok(records)
}

fn write_tclone_runs_to_path(path: &Path, records: &[TcloneRunRecord]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = TcloneStateLock::acquire(path)?;
    let temp_path = path.with_extension("jsonl.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        for record in records {
            let line = serde_json::to_string(record)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
    }
    fs::rename(temp_path, path)?;
    Ok(())
}

fn append_tclone_record(record: &TcloneRunRecord) -> io::Result<()> {
    let path = tclone_state_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = TcloneStateLock::acquire(&path)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = serde_json::to_string(record)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn append_tclone_status(run_id: &str, status: &str, exit_code: Option<i32>) -> io::Result<()> {
    let mut record = find_tclone_record(run_id)?;
    record.status = status.to_string();
    record.updated_at_ms = unix_millis()?;
    record.exit_code = exit_code;
    append_tclone_record(&record)
}

fn find_tclone_record(target: &str) -> io::Result<TcloneRunRecord> {
    list_tclone_runs()?
        .into_iter()
        .rev()
        .find(|record| {
            record.run_id == target
                || record.container_name == target
                || record.container_id.as_deref() == Some(target)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown tclone run or container: {target}"),
            )
        })
}

fn tclone_state_path() -> io::Result<PathBuf> {
    Ok(default_root()?.join("tclone-runs.jsonl"))
}

fn tclone_target_arg(args: &[OsString], usage: &str) -> io::Result<String> {
    let mut index = 0;
    while index < args.len() {
        let Some(value) = args[index].to_str() else {
            index += 1;
            continue;
        };
        if value.starts_with('-') {
            if value.contains('=') {
                index += 1;
                continue;
            }
            index += if tclone_option_takes_value(value) {
                2
            } else {
                1
            };
            continue;
        }
        return Ok(value.to_string());
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, usage))
}

fn tclone_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "--copies" | "--name" | "--shell" | "--to" | "--into" | "--paths"
    )
}

fn detect_agent_home(agent_binary: &str) -> Option<(String, PathBuf, String)> {
    let lower = agent_binary.to_ascii_lowercase();
    let home = env::var_os("HOME").map(PathBuf::from)?;
    if lower.contains("codex") {
        let host = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"));
        Some((
            "CODEX_HOME".to_string(),
            host,
            format!("{DEFAULT_CONTAINER_HOME}/.codex"),
        ))
    } else if lower.contains("claude") {
        let host = env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"));
        Some((
            "CLAUDE_CONFIG_DIR".to_string(),
            host,
            format!("{DEFAULT_CONTAINER_HOME}/.claude"),
        ))
    } else {
        None
    }
}

fn prepare_tclone_seed(
    seed_root: &Path,
    original_workspace: &Path,
    agent_home: Option<&(String, PathBuf, String)>,
    gensee_home: Option<&PathBuf>,
    container_workspace: &str,
    container_home: &str,
) -> io::Result<()> {
    if seed_root.exists() {
        fs::remove_dir_all(seed_root)?;
    }
    fs::create_dir_all(seed_root)?;

    let workspace_seed = seed_root.join(container_relative_path(container_workspace)?);
    copy_tclone_workspace(original_workspace, &workspace_seed)?;

    if let Some((_, host_home, container_path)) = agent_home.filter(|(_, path, _)| path.exists()) {
        copy_path_all(
            host_home,
            &seed_root.join(container_relative_path(container_path)?),
        )?;
    }
    if let Some(gensee_home) = gensee_home.filter(|path| path.exists()) {
        copy_path_all(
            gensee_home,
            &seed_root.join(container_relative_path(&format!(
                "{container_home}/.gensee"
            ))?),
        )?;
    }
    Ok(())
}

fn container_relative_path(path: &str) -> io::Result<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.split('/').any(|part| part == "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid container path for tclone seed: {path}"),
        ));
    }
    Ok(PathBuf::from(trimmed))
}

fn copy_tclone_workspace(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        copy_tclone_path(&entry.path(), &destination.join(entry.file_name()))?;
    }

    Ok(())
}

fn copy_tclone_path(source: &Path, destination: &Path) -> io::Result<()> {
    let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    if should_skip_tclone_workspace_entry(name) {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tclone_path(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(fs::read_link(source)?, destination)?;
        }
        #[cfg(not(unix))]
        {
            fs::copy(source, destination)?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn copy_path_all(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_path_all(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(fs::read_link(source)?, destination)?;
        }
        #[cfg(not(unix))]
        {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, destination)?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn should_skip_tclone_workspace_entry(name: &str) -> bool {
    // Applied at every workspace depth to avoid copying bulky build/dependency trees.
    matches!(name, "target" | "node_modules" | ".gensee" | ".gensee-dev") || name.ends_with(".tmp")
}

fn tclone_node_mount() -> Option<(PathBuf, PathBuf)> {
    let root = env::var_os("GENSEE_TCLONE_NODE_ROOT")
        .or_else(|| env::var_os("NODE_ROOT"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".nvm")))?;
    if !root.exists() {
        return None;
    }
    let node_bin = env::var_os("GENSEE_TCLONE_NODE_BIN")
        .map(PathBuf::from)
        .or_else(|| find_command("node").and_then(|path| path.parent().map(Path::to_path_buf)))?;
    Some((root, node_bin))
}

fn tclone_podman() -> OsString {
    env::var_os("GENSEE_TCLONE_PODMAN")
        .or_else(|| env::var_os("PODMAN_TFORK"))
        .unwrap_or_else(|| OsString::from("podman"))
}

fn podman_cp(podman: &OsString, source: &Path, destination: &str) -> io::Result<()> {
    run_command_status(
        podman,
        &[
            OsString::from("cp"),
            OsString::from(source),
            OsString::from(destination),
        ],
    )
}

fn podman_cp_contents(podman: &OsString, source: &Path, destination: &str) -> io::Result<()> {
    podman_cp(podman, &source.join("."), destination)
}

fn tclone_exec(podman: &OsString, container: &str, command: &[&str]) -> io::Result<()> {
    tclone_exec_env(podman, container, &[], command)
}

fn tclone_exec_env(
    podman: &OsString,
    container: &str,
    envs: &[(&str, &str)],
    command: &[&str],
) -> io::Result<()> {
    let mut args = vec![OsString::from("exec")];
    for (key, value) in envs {
        args.push(OsString::from("-e"));
        args.push(OsString::from(format!("{key}={value}")));
    }
    args.push(OsString::from(container));
    args.extend(command.iter().map(OsString::from));
    run_command_status(podman, &args)
}

fn tclone_exec_capture_env(
    podman: &OsString,
    container: &str,
    envs: &[(&str, &str)],
    command: &[&str],
) -> io::Result<String> {
    let mut args = vec![OsString::from("exec")];
    for (key, value) in envs {
        args.push(OsString::from("-e"));
        args.push(OsString::from(format!("{key}={value}")));
    }
    args.push(OsString::from(container));
    args.extend(command.iter().map(OsString::from));
    run_command_capture(podman, &args)
}

fn inspect_container_pid(podman: &OsString, container: &str) -> io::Result<u32> {
    let output = run_command_capture(
        podman,
        &[
            OsString::from("inspect"),
            OsString::from(container),
            OsString::from("--format"),
            OsString::from("{{.State.Pid}}"),
        ],
    )?;
    output.trim().parse::<u32>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid container pid: {err}"),
        )
    })
}

fn inspect_container_name(podman: &OsString, container: &str) -> io::Result<String> {
    let output = run_command_capture(
        podman,
        &[
            OsString::from("inspect"),
            OsString::from(container),
            OsString::from("--format"),
            OsString::from("{{.Name}}"),
        ],
    )?;
    let name = output.trim().trim_start_matches('/').to_string();
    if name.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty container name from podman inspect",
        ))
    } else {
        Ok(name)
    }
}

struct TcloneStateLock {
    path: PathBuf,
}

impl TcloneStateLock {
    fn acquire(state_path: &Path) -> io::Result<Self> {
        let lock_path = state_path.with_extension("lock");
        for _ in 0..100 {
            match fs::create_dir(&lock_path) {
                Ok(()) => {
                    fs::write(lock_path.join("pid"), std::process::id().to_string())?;
                    return Ok(Self { path: lock_path });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    if tclone_lock_is_stale(&lock_path)? {
                        let _ = fs::remove_dir_all(&lock_path);
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "timed out waiting for tclone state lock {}",
                lock_path.display()
            ),
        ))
    }
}

fn tclone_lock_is_stale(lock_path: &Path) -> io::Result<bool> {
    if let Some(pid) = fs::read_to_string(lock_path.join("pid"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
    {
        if !process_exists(pid) {
            return Ok(true);
        }
    }
    let metadata = fs::metadata(lock_path)?;
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.elapsed().ok());
    Ok(age.is_some_and(|age| age.as_secs() >= TCLONE_STATE_LOCK_STALE_SECS))
}

#[cfg(target_os = "linux")]
fn process_exists(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
fn process_exists(_pid: u32) -> bool {
    true
}

impl Drop for TcloneStateLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TcloneContainerCleanup {
    podman: OsString,
    container_name: String,
    armed: bool,
}

impl TcloneContainerCleanup {
    fn new(podman: &OsString, container_name: &str) -> Self {
        Self {
            podman: podman.clone(),
            container_name: container_name.to_string(),
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TcloneContainerCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = Command::new(&self.podman)
                .arg("rm")
                .arg("-f")
                .arg(&self.container_name)
                .status();
        }
    }
}

fn run_command_status(program: &OsString, args: &[OsString]) -> io::Result<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} exited with status {status}",
            program.to_string_lossy()
        )))
    }
}

fn run_command_capture(program: &OsString, args: &[OsString]) -> io::Result<String> {
    run_command_capture_with_env(program, args, &[])
}

fn run_command_capture_with_env(
    program: &OsString,
    args: &[OsString],
    envs: &[(&str, &str)],
) -> io::Result<String> {
    let output = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(io::Error::other(format!(
            "{} exited with status {}: {}",
            program.to_string_lossy(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn arg_value(args: &[OsString], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| {
            if window[0].to_str() == Some(name) {
                window[1].to_str().map(ToString::to_string)
            } else {
                None
            }
        })
        .or_else(|| {
            let prefix = format!("{name}=");
            args.iter().find_map(|arg| {
                arg.to_str()
                    .and_then(|value| value.strip_prefix(&prefix))
                    .map(ToString::to_string)
            })
        })
}

fn arg_values_after(args: &[OsString], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index].to_str() == Some(name) {
            index += 1;
            while index < args.len() {
                let Some(value) = args[index].to_str() else {
                    index += 1;
                    continue;
                };
                if value.starts_with("--") {
                    break;
                }
                values.push(value.to_string());
                index += 1;
            }
            continue;
        }
        if let Some(value) = args[index]
            .to_str()
            .and_then(|value| value.strip_prefix(&format!("{name}=")))
        {
            values.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
        index += 1;
    }
    values
}

fn arg_flag(args: &[OsString], name: &str) -> bool {
    args.iter().any(|arg| arg.to_str() == Some(name))
}

fn find_command(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record(run_id: &str, status: &str) -> TcloneRunRecord {
        TcloneRunRecord {
            run_id: run_id.to_string(),
            parent_run_id: None,
            role: "source".to_string(),
            status: status.to_string(),
            container_name: format!("container-{run_id}"),
            container_id: None,
            source_container: None,
            fork_prefix: None,
            image: "image".to_string(),
            workspace: "/repo".to_string(),
            container_workspace: "/workspace".to_string(),
            container_home: "/home/gensee".to_string(),
            agent_cmd: vec!["codex".to_string()],
            fork_base_git_head: None,
            fork_base_overlay_lowerdir: None,
            fork_overlay_upperdir: None,
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        }
    }

    fn test_fork_record(run_id: &str, parent_run_id: &str) -> TcloneRunRecord {
        let mut record = test_record(run_id, "running");
        record.role = "fork".to_string();
        record.parent_run_id = Some(parent_run_id.to_string());
        record
    }

    fn temp_state_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "gensee-tclone-state-test-{}-{name}.jsonl",
            std::process::id()
        ))
    }

    fn temp_tree(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "gensee-tclone-tree-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn tclone_state_read_skips_malformed_lines_and_keeps_last_record() {
        let path = temp_state_path("malformed-last-wins");
        let _ = fs::remove_file(&path);
        let first = test_record("run_1", "running");
        let second = test_record("run_1", "discarded");
        fs::write(
            &path,
            format!(
                "{}\nnot-json\n{}\n",
                serde_json::to_string(&first).unwrap(),
                serde_json::to_string(&second).unwrap()
            ),
        )
        .unwrap();

        let records = read_tclone_runs_from_path(&path).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].run_id, "run_1");
        assert_eq!(records[0].status, "discarded");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tclone_state_write_replaces_existing_records() {
        let path = temp_state_path("write-replaces");
        let _ = fs::remove_file(&path);
        let first = test_record("run_1", "running");
        let second = test_record("run_2", "running");
        write_tclone_runs_to_path(&path, &[first.clone(), second.clone()]).unwrap();
        write_tclone_runs_to_path(&path, std::slice::from_ref(&second)).unwrap();

        let records = read_tclone_runs_from_path(&path).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].run_id, "run_2");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tclone_delete_records_filters_matching_runs() {
        let path = temp_state_path("delete-filter");
        let _ = fs::remove_file(&path);
        let first = test_record("run_1", "running");
        let second = test_record("run_2", "running");
        write_tclone_runs_to_path(&path, &[first, second]).unwrap();

        let records = read_tclone_runs_from_path(&path).unwrap();
        let retained = records
            .into_iter()
            .filter(|record| record.run_id != "run_1")
            .collect::<Vec<_>>();
        write_tclone_runs_to_path(&path, &retained).unwrap();

        let records = read_tclone_runs_from_path(&path).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].run_id, "run_2");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tclone_workspace_skip_covers_build_and_temp_entries() {
        assert!(should_skip_tclone_workspace_entry("target"));
        assert!(should_skip_tclone_workspace_entry("node_modules"));
        assert!(should_skip_tclone_workspace_entry(".gensee"));
        assert!(should_skip_tclone_workspace_entry("scratch.tmp"));
        assert!(!should_skip_tclone_workspace_entry(".git"));
        assert!(!should_skip_tclone_workspace_entry("src"));
    }

    #[test]
    fn tclone_target_arg_allows_known_options_before_target() {
        let args = vec![
            OsString::from("--copies"),
            OsString::from("2"),
            OsString::from("--name"),
            OsString::from("fork-prefix"),
            OsString::from("run_1"),
        ];

        assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
    }

    #[test]
    fn tclone_target_arg_and_arg_value_handle_equals_form() {
        let args = vec![
            OsString::from("--copies=2"),
            OsString::from("--name=fork-prefix"),
            OsString::from("--into=source"),
            OsString::from("run_1"),
        ];

        assert_eq!(arg_value(&args, "--copies").unwrap(), "2");
        assert_eq!(arg_value(&args, "--name").unwrap(), "fork-prefix");
        assert_eq!(arg_value(&args, "--into").unwrap(), "source");
        assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
    }

    #[test]
    fn tclone_arg_flag_detects_boolean_options() {
        let args = vec![
            OsString::from("fork_1"),
            OsString::from("--into"),
            OsString::from("source_1"),
            OsString::from("--dry-run"),
        ];

        assert!(arg_flag(&args, "--dry-run"));
        assert!(!arg_flag(&args, "--force"));
    }

    #[test]
    fn tclone_merge_scope_defaults_to_git() {
        let args = vec![
            OsString::from("fork_1"),
            OsString::from("--into"),
            OsString::from("source_1"),
        ];

        assert_eq!(tclone_merge_scope(&args).unwrap(), TcloneMergeScope::Git);
    }

    #[test]
    fn tclone_merge_scope_parses_paths() {
        let args = vec![
            OsString::from("fork_1"),
            OsString::from("--into"),
            OsString::from("source_1"),
            OsString::from("--paths"),
            OsString::from("/workspace"),
            OsString::from("/home/gensee/.codex"),
            OsString::from("--dry-run"),
        ];

        assert_eq!(
            tclone_merge_scope(&args).unwrap(),
            TcloneMergeScope::Paths(vec![
                "/workspace".to_string(),
                "/home/gensee/.codex".to_string()
            ])
        );
    }

    #[test]
    fn tclone_merge_scope_rejects_multiple_scopes() {
        let args = vec![
            OsString::from("fork_1"),
            OsString::from("--into"),
            OsString::from("source_1"),
            OsString::from("--git"),
            OsString::from("--filesystem"),
        ];

        assert!(tclone_merge_scope(&args).is_err());
    }

    #[test]
    fn tclone_switch_promotes_fork_to_source_record() {
        let fork = test_fork_record("fork_1", "source_1");

        let switched = switched_tclone_source_record(fork, 42).unwrap();

        assert_eq!(switched.role, "source");
        assert_eq!(switched.status, "active");
        assert_eq!(switched.parent_run_id, None);
        assert_eq!(
            switched.source_container.as_deref(),
            Some("container-fork_1")
        );
        assert_eq!(switched.updated_at_ms, 42);
    }

    #[test]
    fn tclone_switch_rejects_non_fork_record() {
        let source = test_record("source_1", "running");

        assert!(switched_tclone_source_record(source, 42).is_err());
    }

    #[test]
    fn tclone_overlay_merge_plan_applies_fork_only_change() {
        let root = temp_tree("fork-only");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let source = root.join("source");
        fs::create_dir_all(lower.join("workspace")).unwrap();
        fs::create_dir_all(upper.join("workspace")).unwrap();
        fs::create_dir_all(source.join("workspace")).unwrap();
        fs::write(lower.join("workspace/a.txt"), "old").unwrap();
        fs::write(upper.join("workspace/a.txt"), "new").unwrap();
        fs::write(source.join("workspace/a.txt"), "old").unwrap();

        let plan = build_tclone_overlay_merge_plan(&lower, &upper, &source, &None).unwrap();

        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].path, "workspace/a.txt");
        assert_eq!(plan.changes[0].op, TcloneOverlayMergeOp::UpsertFile);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_overlay_merge_plan_detects_conflict() {
        let root = temp_tree("conflict");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let source = root.join("source");
        fs::create_dir_all(lower.join("workspace")).unwrap();
        fs::create_dir_all(upper.join("workspace")).unwrap();
        fs::create_dir_all(source.join("workspace")).unwrap();
        fs::write(lower.join("workspace/a.txt"), "old").unwrap();
        fs::write(upper.join("workspace/a.txt"), "fork").unwrap();
        fs::write(source.join("workspace/a.txt"), "source").unwrap();

        let plan = build_tclone_overlay_merge_plan(&lower, &upper, &source, &None).unwrap();

        assert_eq!(plan.conflicts, vec!["workspace/a.txt".to_string()]);
        assert!(plan.changes.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_overlay_merge_plan_honors_path_filter() {
        let root = temp_tree("filter");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let source = root.join("source");
        fs::create_dir_all(lower.join("workspace")).unwrap();
        fs::create_dir_all(upper.join("workspace")).unwrap();
        fs::create_dir_all(source.join("workspace")).unwrap();
        fs::create_dir_all(lower.join("home/gensee/.codex")).unwrap();
        fs::create_dir_all(upper.join("home/gensee/.codex")).unwrap();
        fs::create_dir_all(source.join("home/gensee/.codex")).unwrap();
        fs::write(lower.join("workspace/a.txt"), "old").unwrap();
        fs::write(upper.join("workspace/a.txt"), "new").unwrap();
        fs::write(source.join("workspace/a.txt"), "old").unwrap();
        fs::write(lower.join("home/gensee/.codex/config"), "old").unwrap();
        fs::write(upper.join("home/gensee/.codex/config"), "new").unwrap();
        fs::write(source.join("home/gensee/.codex/config"), "old").unwrap();
        let filter = Some(vec!["home/gensee/.codex".to_string()]);

        let plan = build_tclone_overlay_merge_plan(&lower, &upper, &source, &filter).unwrap();

        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].path, "home/gensee/.codex/config");
        assert_eq!(plan.changes[0].op, TcloneOverlayMergeOp::UpsertFile);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_merge_pair_requires_fork_parent_source() {
        let source = test_record("source_1", "running");
        let fork = test_fork_record("fork_1", "source_1");
        let unrelated = test_fork_record("fork_2", "other_source");
        let mut source_as_fork = test_record("not_fork", "running");
        source_as_fork.role = "source".to_string();

        assert!(validate_tclone_merge_pair(&fork, &source, false).is_ok());
        assert!(validate_tclone_merge_pair(&unrelated, &source, false).is_err());
        assert!(validate_tclone_merge_pair(&unrelated, &source, true).is_ok());
        assert!(validate_tclone_merge_pair(&source_as_fork, &source, false).is_err());
    }

    #[test]
    fn tclone_state_lock_breaks_dead_pid_lock() {
        let path = temp_state_path("stale-lock");
        let lock_path = path.with_extension("lock");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&lock_path);
        fs::create_dir_all(&lock_path).unwrap();
        fs::write(lock_path.join("pid"), "999999").unwrap();

        let lock = TcloneStateLock::acquire(&path).unwrap();

        assert!(lock_path.join("pid").exists());
        drop(lock);
        assert!(!lock_path.exists());
        let _ = fs::remove_file(path);
    }
}
