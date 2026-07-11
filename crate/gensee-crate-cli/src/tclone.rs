use crate::*;

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
    pub(crate) started_at_ms: u64,
    pub(crate) updated_at_ms: u64,
    pub(crate) exit_code: Option<i32>,
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
    let staged_workspace = gensee_tmp_root()?.join(&run_id).join("tclone-workspace");
    copy_tclone_workspace(&original_workspace, &staged_workspace)?;

    let agent_binary = config.agent_cmd[0].to_string_lossy().to_string();
    let agent_home = detect_agent_home(&agent_binary);
    let gensee_home = default_root().ok().filter(|path| path.exists());

    let mut run_args = vec![
        OsString::from("run"),
        OsString::from("-d"),
        OsString::from("--name"),
        OsString::from(&source_container),
        OsString::from("--entrypoint"),
        OsString::from("/bin/sleep"),
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
    ];
    if let Some((name, _host, container_path)) = agent_home.as_ref() {
        run_args.push(OsString::from("-e"));
        run_args.push(OsString::from(format!("{name}={container_path}")));
    }
    if let Some((node_root, node_bin)) = tclone_node_mount() {
        run_args.push(OsString::from("-v"));
        run_args.push(OsString::from(format!(
            "{}:{}:ro",
            node_root.display(),
            node_root.display()
        )));
        run_args.push(OsString::from("-e"));
        run_args.push(OsString::from(format!(
            "PATH={}:{}",
            node_bin.display(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )));
    }
    run_args.push(OsString::from(&image));
    run_args.push(OsString::from("infinity"));

    let output = run_command_capture(&podman, &run_args)?;
    let container_id = output.lines().next().map(str::trim).map(str::to_string);
    let cleanup_guard = TcloneContainerCleanup::new(&podman, &source_container);

    tclone_exec(
        &podman,
        &source_container,
        &[
            "bash",
            "-lc",
            &format!("mkdir -p '{}' '{}'", container_home, container_workspace),
        ],
    )?;
    podman_cp_contents(
        &podman,
        &staged_workspace,
        &format!("{source_container}:{container_workspace}/"),
    )?;
    if let Some((_, host_home, container_path)) =
        agent_home.as_ref().filter(|(_, path, _)| path.exists())
    {
        tclone_exec(
            &podman,
            &source_container,
            &["bash", "-lc", &format!("mkdir -p '{}'", container_path)],
        )?;
        podman_cp_contents(
            &podman,
            host_home,
            &format!("{source_container}:{container_path}/"),
        )?;
    }
    if let Some(gensee_home) = gensee_home.as_ref() {
        tclone_exec(
            &podman,
            &source_container,
            &[
                "bash",
                "-lc",
                &format!("mkdir -p '{container_home}/.gensee'"),
            ],
        )?;
        podman_cp_contents(
            &podman,
            gensee_home,
            &format!("{source_container}:{container_home}/.gensee/"),
        )?;
    }
    if let Ok(current_exe) = env::current_exe() {
        if current_exe.exists() {
            podman_cp(
                &podman,
                &current_exe,
                &format!("{source_container}:/usr/local/bin/gensee"),
            )?;
        }
    }

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
    append_tclone_record(&TcloneRunRecord {
        run_id: run_id.clone(),
        parent_run_id: None,
        role: "source".to_string(),
        status: "running".to_string(),
        container_name: source_container.clone(),
        container_id,
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
        started_at_ms,
        updated_at_ms: started_at_ms,
        exit_code: None,
    })?;
    cleanup_guard.disarm();

    eprintln!(
        "gensee: started tclone run {run_id} source_container={source_container} workspace={}",
        original_workspace.display()
    );
    eprintln!("gensee: fork from another terminal with: gensee fork {run_id}");

    let status = Command::new(&podman)
        .arg("exec")
        .arg("-it")
        .arg("-w")
        .arg(&container_workspace)
        .arg("-e")
        .arg(format!("GENSEE_RUN_ID={run_id}"))
        .arg("-e")
        .arg(format!("AGENT_SHIELD_SESSION_ID={run_id}"))
        .arg("-e")
        .arg(format!("GENSEE_HOME={container_home}/.gensee"))
        .arg("-e")
        .arg(format!("GENSEE_WORKSPACE={container_workspace}"))
        .arg(&source_container)
        .arg(&config.agent_cmd[0])
        .args(&config.agent_cmd[1..])
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
    let podman = tclone_podman();
    let forked_at_ms = unix_millis()?;
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
    matches!(option, "--copies" | "--name" | "--shell" | "--to")
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
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        }
    }

    fn temp_state_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "gensee-tclone-state-test-{}-{name}.jsonl",
            std::process::id()
        ))
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
            OsString::from("run_1"),
        ];

        assert_eq!(arg_value(&args, "--copies").unwrap(), "2");
        assert_eq!(arg_value(&args, "--name").unwrap(), "fork-prefix");
        assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
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
