use crate::*;

pub(crate) fn current_dir_string() -> Option<String> {
    env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxMode {
    None,
    Mac,
}

impl SandboxMode {
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "mac" => Ok(Self::Mac),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown sandbox mode: {other}"),
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Mac => "mac",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceMode {
    Direct,
    Staged,
}

impl WorkspaceMode {
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "direct" => Ok(Self::Direct),
            "staged" => Ok(Self::Staged),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown workspace mode: {other}"),
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Staged => "staged",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RunConfig {
    pub(crate) sandbox: SandboxMode,
    pub(crate) profile: String,
    pub(crate) workspace_mode: WorkspaceMode,
    pub(crate) workspace: PathBuf,
    pub(crate) max_runtime_seconds: Option<u64>,
    pub(crate) agent_cmd: Vec<OsString>,
}

impl RunConfig {
    pub(crate) fn parse(args: Vec<OsString>) -> io::Result<Self> {
        let mut sandbox = SandboxMode::None;
        let mut profile = "observe".to_string();
        let mut workspace_mode = WorkspaceMode::Direct;
        let mut workspace: Option<PathBuf> = None;
        // Precedence: --max-runtime-seconds flag (below) > GENSEE_MAX_RUNTIME_SECONDS
        // env > policy doc `runtime.max_runtime_seconds`.
        let mut max_runtime_seconds = env::var("GENSEE_MAX_RUNTIME_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .or(Policy::global().document().runtime.max_runtime_seconds);
        let mut agent_cmd = Vec::new();
        let mut index = 0;

        while index < args.len() {
            match args[index].to_str() {
                Some("--") => {
                    agent_cmd.extend(args[index + 1..].iter().cloned());
                    break;
                }
                Some("--sandbox") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "missing --sandbox value")
                        })?;
                    sandbox = SandboxMode::from_str(value)?;
                }
                Some("--profile") => {
                    index += 1;
                    profile = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "missing --profile value")
                        })?
                        .to_string();
                }
                Some("--workspace-mode") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "missing --workspace-mode value",
                            )
                        })?;
                    workspace_mode = WorkspaceMode::from_str(value)?;
                }
                Some("--workspace") => {
                    index += 1;
                    workspace = Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "missing --workspace value")
                    })?));
                }
                Some("--max-runtime-seconds") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "missing --max-runtime-seconds value",
                            )
                        })?
                        .parse::<u64>()
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "invalid --max-runtime-seconds value",
                            )
                        })?;
                    if value == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--max-runtime-seconds must be greater than zero",
                        ));
                    }
                    max_runtime_seconds = Some(value);
                }
                Some(value) if value.starts_with("--") => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown run option: {value}"),
                    ));
                }
                Some(_) | None => {
                    agent_cmd.extend(args[index..].iter().cloned());
                    break;
                }
            }
            index += 1;
        }

        if agent_cmd.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: gensee run [--sandbox mac] [--profile cautious] [--workspace-mode staged] [--max-runtime-seconds N] -- <agent> [args...]",
            ));
        }

        if sandbox == SandboxMode::Mac && profile == "observe" {
            profile = "cautious".to_string();
        }

        let workspace = workspace.unwrap_or(env::current_dir()?);
        Ok(Self {
            sandbox,
            profile,
            workspace_mode,
            workspace,
            max_runtime_seconds,
            agent_cmd,
        })
    }
}

pub(crate) fn run_agent(config: RunConfig) -> io::Result<()> {
    let started_at_ms = unix_millis()?;
    let run_id = format!("run_{}_{}", std::process::id(), started_at_ms);
    let original_workspace = canonicalize_or_original(&config.workspace);
    let repo_path = find_repo_root(&original_workspace);
    let run_workspace = prepare_run_workspace(&config, &run_id, &original_workspace)?;
    let agent_binary = config.agent_cmd[0].to_string_lossy().to_string();
    let sandbox_profile = if config.sandbox == SandboxMode::Mac {
        Some(write_macos_sandbox_profile(
            &run_id,
            &config.profile,
            &original_workspace,
            &run_workspace,
        )?)
    } else {
        None
    };

    let mut command = if let Some(profile_path) = sandbox_profile.as_ref() {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-f")
            .arg(profile_path)
            .arg(&config.agent_cmd[0]);
        command
    } else {
        Command::new(&config.agent_cmd[0])
    };
    command
        .args(&config.agent_cmd[1..])
        .current_dir(&run_workspace)
        .env("GENSEE_RUN_ID", &run_id)
        .env("AGENT_SHIELD_SESSION_ID", &run_id)
        .env("AGENT_SHIELD_START_TIME_MS", started_at_ms.to_string())
        .env(
            "GENSEE_WORKSPACE",
            run_workspace.to_string_lossy().to_string(),
        )
        .env(
            "GENSEE_ORIGINAL_WORKSPACE",
            original_workspace.to_string_lossy().to_string(),
        );
    if let Some(proxy_url) = env::var("GENSEE_EGRESS_PROXY_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        command
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url);
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = command.spawn()?;
    let root_pid = child.id();

    let store = EventStore::default_local()?;
    store.append_session(&AgentSession {
        session_id: run_id.clone(),
        agent_binary,
        root_pid,
        cwd: run_workspace.to_string_lossy().to_string(),
        repo_path: repo_path
            .clone()
            .map(|path| path.to_string_lossy().to_string()),
        mode: Some(format!("managed-run:{}", config.sandbox.label())),
        workspace_mode: Some(config.workspace_mode.label().to_string()),
        original_workspace: Some(original_workspace.to_string_lossy().to_string()),
        staged_workspace: (config.workspace_mode == WorkspaceMode::Staged)
            .then(|| run_workspace.to_string_lossy().to_string()),
        sandbox_profile: (config.sandbox == SandboxMode::Mac).then(|| config.profile.clone()),
        sandbox_profile_path: sandbox_profile
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        started_at_ms,
        ended_at_ms: None,
        exit_code: None,
    })?;

    eprintln!(
        "gensee: started run {run_id} root_pid={root_pid} workspace={} sandbox={} profile={}",
        run_workspace.display(),
        config.sandbox.label(),
        config.profile,
    );

    let (status, timed_out) = wait_for_child_with_timeout(&mut child, config.max_runtime_seconds)?;
    let ended_at_ms = unix_millis()?;
    let exit_code = status.code();

    store.append_session(&AgentSession {
        session_id: run_id.clone(),
        agent_binary: config.agent_cmd[0].to_string_lossy().to_string(),
        root_pid,
        cwd: run_workspace.to_string_lossy().to_string(),
        repo_path: repo_path.map(|path| path.to_string_lossy().to_string()),
        mode: Some(format!("managed-run:{}", config.sandbox.label())),
        workspace_mode: Some(config.workspace_mode.label().to_string()),
        original_workspace: Some(original_workspace.to_string_lossy().to_string()),
        staged_workspace: (config.workspace_mode == WorkspaceMode::Staged)
            .then(|| run_workspace.to_string_lossy().to_string()),
        sandbox_profile: (config.sandbox == SandboxMode::Mac).then(|| config.profile.clone()),
        sandbox_profile_path: sandbox_profile
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        started_at_ms,
        ended_at_ms: Some(ended_at_ms),
        exit_code,
    })?;

    eprintln!(
        "gensee: ended run {run_id} exit_code={}",
        exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string())
    );
    if timed_out {
        eprintln!(
            "gensee: run {run_id} exceeded max runtime of {}s and was terminated",
            config.max_runtime_seconds.unwrap_or_default()
        );
    }

    if config.workspace_mode == WorkspaceMode::Staged {
        print_staged_workspace_summary(&run_workspace)?;
    }

    if timed_out {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "agent exceeded max runtime",
        ))
    } else if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "agent exited with status {status}"
        )))
    }
}

pub(crate) fn wait_for_child_with_timeout(
    child: &mut std::process::Child,
    max_runtime_seconds: Option<u64>,
) -> io::Result<(std::process::ExitStatus, bool)> {
    let Some(max_runtime_seconds) = max_runtime_seconds else {
        return child.wait().map(|status| (status, false));
    };
    let started = Instant::now();
    let timeout = Duration::from_secs(max_runtime_seconds);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let status = child.wait()?;
            return Ok((status, true));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn prepare_run_workspace(
    config: &RunConfig,
    run_id: &str,
    original_workspace: &Path,
) -> io::Result<PathBuf> {
    match config.workspace_mode {
        WorkspaceMode::Direct => Ok(original_workspace.to_path_buf()),
        WorkspaceMode::Staged => {
            let staged = gensee_tmp_root()?.join(run_id).join("workspace");
            if let Some(parent) = staged.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_workspace(original_workspace, &staged)?;
            Ok(staged)
        }
    }
}

pub(crate) fn copy_workspace(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        copy_path(&entry.path(), &destination.join(entry.file_name()))?;
    }

    Ok(())
}

pub(crate) fn copy_path(source: &Path, destination: &Path) -> io::Result<()> {
    let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    if should_skip_workspace_entry(source, name) {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_path(&entry.path(), &destination.join(entry.file_name()))?;
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

pub(crate) fn should_skip_workspace_entry(path: &Path, name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".gensee" | ".gensee-dev"
    ) || name.ends_with(".tmp")
        || path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .is_some_and(|file_name| file_name.ends_with(".tmp"))
}

pub(crate) fn write_macos_sandbox_profile(
    run_id: &str,
    profile: &str,
    original_workspace: &Path,
    run_workspace: &Path,
) -> io::Result<PathBuf> {
    if profile != "cautious" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only --profile cautious is implemented for --sandbox mac",
        ));
    }

    let profile_dir = gensee_tmp_root()?.join(run_id);
    fs::create_dir_all(&profile_dir)?;
    let profile_path = profile_dir.join("cautious.sb");
    let profile_text = render_cautious_sbpl(original_workspace, run_workspace);
    fs::write(&profile_path, profile_text)?;
    Ok(profile_path)
}

pub(crate) fn render_cautious_sbpl(original_workspace: &Path, run_workspace: &Path) -> String {
    let mut lines = vec![
        "(version 1)".to_string(),
        "(allow default)".to_string(),
        "(deny file-read* file-write*".to_string(),
    ];

    for path in sensitive_paths() {
        lines.push(format!("  (subpath \"{}\")", sbpl_escape(&path)));
    }
    lines.push(")".to_string());

    if canonicalize_or_original(original_workspace) != canonicalize_or_original(run_workspace) {
        lines.push("(deny file-write*".to_string());
        lines.push(format!(
            "  (subpath \"{}\")",
            sbpl_escape(&canonicalize_or_original(original_workspace))
        ));
        lines.push(")".to_string());
    }

    lines.join("\n")
}

pub(crate) fn sensitive_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        for suffix in [
            ".ssh",
            ".aws",
            ".config/gcloud",
            ".gnupg",
            ".kube",
            ".docker",
            ".netrc",
            ".npmrc",
            ".pypirc",
        ] {
            paths.push(home.join(suffix));
        }
    }
    paths
        .into_iter()
        .map(|path| canonicalize_or_original(&path))
        .collect()
}

pub(crate) fn sbpl_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub(crate) fn gensee_tmp_root() -> io::Result<PathBuf> {
    let root = env::temp_dir().join("gensee-agent-guard");
    fs::create_dir_all(&root)?;
    Ok(root)
}

pub(crate) fn print_staged_workspace_summary(workspace: &Path) -> io::Result<()> {
    eprintln!("gensee: staged workspace: {}", workspace.display());

    if workspace.join(".git").exists() {
        let output = Command::new("git")
            .args(["status", "--short"])
            .current_dir(workspace)
            .output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                eprintln!("gensee: staged workspace has no git changes");
            } else {
                eprintln!("gensee: staged workspace changes:\n{stdout}");
            }
        }
    } else {
        eprintln!("gensee: non-git staged workspace; inspect or discard the directory manually");
    }
    if let Some(session_dir) = workspace.parent() {
        if let Some(session_id) = session_dir.file_name().and_then(|name| name.to_str()) {
            eprintln!("gensee: discard staged workspace with: gensee run discard {session_id}");
        }
    }

    Ok(())
}

pub(crate) fn discard_run(args: Vec<OsString>) -> io::Result<()> {
    let Some(session_id) = args.first().and_then(|arg| arg.to_str()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run discard <session_id>",
        ));
    };

    if !is_valid_discard_session_id(session_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid session id for discard",
        ));
    }

    let temp_root = canonicalize_or_original(&gensee_tmp_root()?);
    let run_dir = temp_root.join(session_id);
    let run_dir_canonical = if run_dir.exists() {
        canonicalize_or_original(&run_dir)
    } else {
        run_dir.clone()
    };
    if !run_dir_canonical.starts_with(&temp_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to remove a path outside the Gensee temp root",
        ));
    }

    if run_dir.exists() {
        fs::remove_dir_all(&run_dir)?;
        println!("discarded staged run {session_id}");
    } else {
        println!("no staged directory found for {session_id}");
    }

    Ok(())
}

pub(crate) fn is_valid_discard_session_id(session_id: &str) -> bool {
    session_id.starts_with("run_")
        && session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}
