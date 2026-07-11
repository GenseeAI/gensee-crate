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
    Linux,
}

impl SandboxMode {
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "mac" => Ok(Self::Mac),
            "linux" => Ok(Self::Linux),
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
            Self::Linux => "linux",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeMode {
    Local,
    Tclone,
}

impl RuntimeMode {
    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "local" => Ok(Self::Local),
            "tclone" => Ok(Self::Tclone),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown runtime mode: {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RunConfig {
    pub(crate) runtime: RuntimeMode,
    pub(crate) sandbox: SandboxMode,
    pub(crate) profile: String,
    pub(crate) workspace_mode: WorkspaceMode,
    pub(crate) workspace: PathBuf,
    pub(crate) max_runtime_seconds: Option<u64>,
    pub(crate) linux_seccomp_override: Option<bool>,
    pub(crate) linux_fanotify: bool,
    pub(crate) linux_network_override: Option<gensee_crate_linux::LinuxNetworkMode>,
    pub(crate) linux_allow_net_override: Vec<String>,
    pub(crate) linux_deny_net_override: Vec<String>,
    pub(crate) agent_cmd: Vec<OsString>,
}

impl RunConfig {
    pub(crate) fn parse(args: Vec<OsString>) -> io::Result<Self> {
        let mut runtime = RuntimeMode::Local;
        let mut sandbox = SandboxMode::None;
        let mut profile = "observe".to_string();
        let mut workspace_mode = WorkspaceMode::Direct;
        let mut workspace: Option<PathBuf> = None;
        let mut linux_seccomp_override = None;
        let mut linux_fanotify = false;
        let mut linux_network_override = None;
        let mut linux_allow_net_override = Vec::new();
        let mut linux_deny_net_override = Vec::new();
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
                Some("--runtime") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "missing --runtime value")
                        })?;
                    runtime = RuntimeMode::from_str(value)?;
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
                Some("--linux-seccomp") => {
                    linux_seccomp_override = Some(true);
                }
                Some("--no-linux-seccomp") => {
                    linux_seccomp_override = Some(false);
                }
                Some("--linux-fanotify") => {
                    linux_fanotify = true;
                }
                Some("--linux-network") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "missing --linux-network value",
                            )
                        })?;
                    linux_network_override = Some(match value {
                        "off" => gensee_crate_linux::LinuxNetworkMode::Off,
                        "allowlist" => gensee_crate_linux::LinuxNetworkMode::AllowListed,
                        "deny-all" => gensee_crate_linux::LinuxNetworkMode::DenyAll,
                        "monitor" => gensee_crate_linux::LinuxNetworkMode::Monitor,
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "unknown --linux-network mode: {other} (expected allowlist|deny-all|monitor|off)"
                                ),
                            ));
                        }
                    });
                }
                Some("--allow-net") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "missing --allow-net value")
                        })?;
                    linux_allow_net_override.push(value.to_string());
                    if linux_network_override.is_none() {
                        linux_network_override =
                            Some(gensee_crate_linux::LinuxNetworkMode::AllowListed);
                    }
                }
                Some("--deny-net") => {
                    index += 1;
                    let value = args
                        .get(index)
                        .and_then(|arg| arg.to_str())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "missing --deny-net value")
                        })?;
                    linux_deny_net_override.push(value.to_string());
                    if linux_network_override.is_none() {
                        linux_network_override =
                            Some(gensee_crate_linux::LinuxNetworkMode::Monitor);
                    }
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
                "usage: gensee run [--sandbox none|mac|linux] [--profile cautious] [--workspace-mode direct|staged] [--linux-seccomp|--no-linux-seccomp] [--linux-fanotify] [--linux-network off|allowlist|deny-all|monitor] [--allow-net <ip-or-cidr>]... [--deny-net <ip-or-cidr>]... [--max-runtime-seconds N] -- <agent> [args...]",
            ));
        }

        if runtime == RuntimeMode::Tclone
            && (sandbox != SandboxMode::None
                || linux_seccomp_override.is_some()
                || linux_fanotify
                || linux_network_override.is_some()
                || !linux_allow_net_override.is_empty()
                || !linux_deny_net_override.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--runtime tclone currently owns sandboxing at the container layer; omit --sandbox and Linux host-control flags for this initial integration",
            ));
        }

        if sandbox == SandboxMode::Mac && profile == "observe" {
            profile = "cautious".to_string();
        }
        if (linux_seccomp_override.is_some()
            || linux_fanotify
            || linux_network_override.is_some()
            || !linux_allow_net_override.is_empty()
            || !linux_deny_net_override.is_empty())
            && sandbox != SandboxMode::Linux
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Linux run controls require --sandbox linux",
            ));
        }

        let workspace = workspace.unwrap_or(env::current_dir()?);
        Ok(Self {
            runtime,
            sandbox,
            profile,
            workspace_mode,
            workspace,
            max_runtime_seconds,
            linux_seccomp_override,
            linux_fanotify,
            linux_network_override,
            linux_allow_net_override,
            linux_deny_net_override,
            agent_cmd,
        })
    }
}

pub(crate) fn run_agent(config: RunConfig) -> io::Result<()> {
    if config.runtime == RuntimeMode::Tclone {
        return run_tclone_agent(config);
    }

    if config.sandbox == SandboxMode::Linux && std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "--sandbox linux is supported on Linux, not {}",
                std::env::consts::OS
            ),
        ));
    }

    let started_at_ms = unix_millis()?;
    let run_id = format!("run_{}_{}", std::process::id(), started_at_ms);
    let original_workspace = canonicalize_or_original(&config.workspace);
    let repo_path = find_repo_root(&original_workspace);
    let run_workspace = prepare_run_workspace(&config, &run_id, &original_workspace)?;
    let agent_binary = config.agent_cmd[0].to_string_lossy().to_string();
    let policy_doc = Policy::global().document();
    let linux_seccomp_profile = linux_run_seccomp_profile(&config, policy_doc);
    let linux_network = linux_run_network_config(&config, policy_doc, &run_id)?;
    if config.sandbox == SandboxMode::Linux
        && linux_seccomp_profile.is_none()
        && !config.linux_fanotify
        && linux_network.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--sandbox linux requested, but no Linux controls are enabled; enable linux.seccomp.enabled, configure linux.network, or pass --linux-seccomp/--linux-fanotify/--linux-network/--deny-net",
        ));
    }
    let mut linux_cleanup = None;
    let mut linux_network_plan = None;
    if let Some(network_config) = linux_network.as_ref() {
        gensee_crate_linux::create_agent_cgroup(Path::new(&network_config.cgroup_path))
            .map_err(linux_network_privilege_error("create cgroup"))?;
        let plan = gensee_crate_linux::plan_nftables_policy(network_config);
        for warning in &plan.warnings {
            eprintln!("gensee: linux network warning: {warning}");
        }
        linux_cleanup = Some(LinuxNetworkCleanup::new(
            plan.nftables.table_name.clone(),
            network_config.cgroup_path.clone(),
        ));
        gensee_crate_linux::validate_nftables_plan_for_apply(&plan.nftables)?;
        gensee_crate_linux::apply_nftables_script(&plan.nftables.script)
            .map_err(linux_network_privilege_error("apply nftables policy"))?;
        if let Some(cleanup) = linux_cleanup.as_mut() {
            cleanup.mark_table_applied();
        }
        eprintln!(
            "gensee: applied linux network policy session={} cgroup={} mode={:?}",
            network_config.session_id, network_config.cgroup_path, network_config.network.mode
        );
        linux_network_plan = Some(plan);
    }
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
    } else if config.sandbox == SandboxMode::Linux
        && (linux_seccomp_profile.is_some() || linux_network.is_some())
    {
        let mut command = Command::new(env::current_exe()?);
        command.arg("__linux-exec");
        if let Some(network_config) = linux_network.as_ref() {
            command
                .arg("--cgroup-path")
                .arg(&network_config.cgroup_path);
        }
        if let Some(profile) = linux_seccomp_profile.as_ref() {
            command
                .arg("--seccomp-profile-json")
                .arg(serde_json::to_string(profile)?);
        }
        command.arg("--").arg(&config.agent_cmd[0]);
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

    let store = EventStore::default_local()?;
    let prepared_fanotify_guard = if config.linux_fanotify {
        Some(prepare_linux_fanotify_run_guard(policy_doc)?)
    } else {
        None
    };

    let mut child = command.spawn()?;
    let root_pid = child.id();

    store.append_session(&AgentSession {
        session_id: run_id.clone(),
        agent_binary: agent_binary.clone(),
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

    let fanotify_guard = if let Some(prepared_guard) = prepared_fanotify_guard {
        match prepared_guard.start(&store, &run_id, root_pid, &agent_binary) {
            Ok(guard) => Some(guard),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    } else {
        None
    };

    eprintln!(
        "gensee: started run {run_id} root_pid={root_pid} workspace={} sandbox={} profile={}",
        run_workspace.display(),
        config.sandbox.label(),
        config.profile,
    );

    let (status, timed_out) = wait_for_child_with_timeout(&mut child, config.max_runtime_seconds)?;
    if let Some(plan) = linux_network_plan.as_ref() {
        append_linux_network_block_events(
            &store,
            &plan.nftables,
            &run_id,
            root_pid,
            &agent_binary,
            unix_millis()?,
        )?;
    }
    drop(fanotify_guard);
    drop(linux_cleanup.take());
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

fn linux_network_privilege_error(operation: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                error.kind(),
                format!(
                    "Linux network enforcement could not {operation}: {error}. cgroup/nftables enforcement requires root; retry with sudo and preserve policy with GENSEE_HOME=$HOME/.gensee if policy was configured as your user",
                ),
            )
        } else {
            error
        }
    }
}

fn append_linux_network_block_events(
    store: &EventStore,
    plan: &gensee_crate_linux::LinuxNftablesPlan,
    session_id: &str,
    root_pid: u32,
    process_name: &str,
    observed_at_ms: u64,
) -> io::Result<()> {
    let events = match gensee_crate_linux::read_nftables_block_events(plan) {
        Ok(events) => events,
        Err(error) => {
            eprintln!("gensee: linux network warning: could not read nftables counters: {error}");
            return Ok(());
        }
    };
    for event in events {
        eprintln!(
            "gensee: observed linux network block session={} destination={} packets={} bytes={}",
            session_id,
            event.destination.as_deref().unwrap_or("*"),
            event.packets,
            event.bytes
        );
        store.append_system_event(&linux_network_block_system_event(
            &event,
            session_id,
            root_pid,
            process_name,
            observed_at_ms,
        ))?;
    }
    Ok(())
}

fn linux_network_block_system_event(
    event: &gensee_crate_linux::LinuxNetworkBlockEvent,
    session_id: &str,
    root_pid: u32,
    process_name: &str,
    observed_at_ms: u64,
) -> SystemEvent {
    let raw_json = serde_json::json!({
        "session_id": session_id,
        "action": "block",
        "network_dest": event.destination,
        "reason": event.reason,
        "packets": event.packets,
        "bytes": event.bytes,
        "counter_name": event.counter_name,
        "table_name": event.table_name,
    })
    .to_string();
    SystemEvent {
        source: "linux".to_string(),
        event_type: "network_block".to_string(),
        event_kind: "NetworkBlocked".to_string(),
        observed_at_ms,
        pid: Some(root_pid),
        ppid: None,
        process_name: Some(process_name.to_string()),
        executable_path: None,
        file_path: None,
        command_line: Some(format!(
            "nftables blocked network egress to {} ({} packet(s), {} byte(s))",
            event.destination.as_deref().unwrap_or("default-reject"),
            event.packets,
            event.bytes
        )),
        raw_json,
    }
}

struct LinuxNetworkCleanup {
    table_name: String,
    cgroup_path: String,
    table_applied: bool,
}

impl LinuxNetworkCleanup {
    fn new(table_name: String, cgroup_path: String) -> Self {
        Self {
            table_name,
            cgroup_path,
            table_applied: false,
        }
    }

    fn mark_table_applied(&mut self) {
        self.table_applied = true;
    }
}

impl Drop for LinuxNetworkCleanup {
    fn drop(&mut self) {
        if self.table_applied {
            if let Err(error) = gensee_crate_linux::delete_nftables_table(&self.table_name) {
                eprintln!(
                    "gensee: linux network cleanup warning: could not delete nftables table {}: {error}",
                    self.table_name
                );
            }
        }
        if let Err(error) = gensee_crate_linux::remove_agent_cgroup(Path::new(&self.cgroup_path)) {
            eprintln!(
                "gensee: linux network cleanup warning: could not remove cgroup {}: {error}",
                self.cgroup_path
            );
        }
    }
}

struct LinuxFanotifyRunGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

struct PreparedLinuxFanotifyRunGuard {
    enforcer: gensee_crate_linux::LinuxFanotifyEnforcer,
    status: gensee_crate_linux::LinuxFanotifyStatus,
}

impl Drop for LinuxFanotifyRunGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn prepare_linux_fanotify_run_guard(
    policy_doc: &policy::PolicyDocument,
) -> io::Result<PreparedLinuxFanotifyRunGuard> {
    let policy = linux_fanotify_policy_from_policy_document(policy_doc);
    let enforcer = gensee_crate_linux::LinuxFanotifyEnforcer::new(
        gensee_crate_linux::LinuxFanotifyConfig::new(policy),
    )
    .map_err(linux_fanotify_privilege_error)?;
    let status = enforcer.status();
    Ok(PreparedLinuxFanotifyRunGuard { enforcer, status })
}

impl PreparedLinuxFanotifyRunGuard {
    fn start(
        mut self,
        store: &EventStore,
        session_id: &str,
        root_pid: u32,
        agent_binary: &str,
    ) -> io::Result<LinuxFanotifyRunGuard> {
        let session = gensee_crate_linux::LinuxSessionTarget::from_pid(session_id, root_pid)?;
        self.enforcer.set_session(session);
        eprintln!(
            "gensee: applied linux fanotify policy session={} root_pid={} marked_paths={}",
            session_id,
            root_pid,
            self.status.marked_paths.len()
        );
        for warning in &self.status.warnings {
            eprintln!("gensee: linux fanotify warning: {warning}");
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = stop.clone();
        let store = store.clone();
        let session_id = session_id.to_string();
        let agent_binary = agent_binary.to_string();
        let mut enforcer = self.enforcer;
        let handle = thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                drain_linux_fanotify_events(&store, &mut enforcer, &session_id, &agent_binary);
                thread::sleep(Duration::from_millis(25));
            }
            drain_linux_fanotify_events(&store, &mut enforcer, &session_id, &agent_binary);
        });

        Ok(LinuxFanotifyRunGuard {
            stop,
            handle: Some(handle),
        })
    }
}

pub(crate) fn drain_linux_fanotify_events(
    store: &EventStore,
    enforcer: &mut gensee_crate_linux::LinuxFanotifyEnforcer,
    session_id: &str,
    agent_binary: &str,
) {
    let events = match enforcer.handle_events_once() {
        Ok(events) => events,
        Err(error) => {
            eprintln!("gensee: linux fanotify warning: could not handle events: {error}");
            return;
        }
    };
    for event in events {
        eprintln!(
            "gensee: observed linux fanotify decision session={} verdict={:?} path={}",
            session_id,
            event.decision.verdict,
            event.request.path.as_deref().unwrap_or("-")
        );
        if let Err(error) = store.append_system_event(&linux_fanotify_system_event(
            &event,
            session_id,
            agent_binary,
            unix_millis().unwrap_or(0),
        )) {
            eprintln!("gensee: linux fanotify warning: could not append timeline event: {error}");
        }
    }
}

pub(crate) fn linux_fanotify_system_event(
    event: &gensee_crate_linux::LinuxFanotifyEvent,
    session_id: &str,
    agent_binary: &str,
    observed_at_ms: u64,
) -> SystemEvent {
    let raw_json = serde_json::json!({
        "session_id": session_id,
        "action": format!("{:?}", event.decision.verdict),
        "requested_action": event.decision.requested_action,
        "matched_rule": event.decision.matched_rule,
        "reason": event.decision.reason,
        "pid": event.request.pid,
        "path": event.request.path,
        "operation": event.request.operation,
    })
    .to_string();
    SystemEvent {
        source: "linux".to_string(),
        event_type: "file_access".to_string(),
        event_kind: format!("FileAccess{:?}", event.decision.verdict),
        observed_at_ms,
        pid: event.request.pid,
        ppid: None,
        process_name: event
            .request
            .process_name
            .clone()
            .or_else(|| Some(agent_binary.to_string())),
        executable_path: None,
        file_path: event.request.path.clone(),
        command_line: event.request.command_line.clone(),
        raw_json,
    }
}

pub(crate) fn linux_fanotify_privilege_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(
            error.kind(),
            format!(
                "Linux fanotify enforcement could not start: {error}. fanotify permission enforcement requires root and a kernel with fanotify permission events; retry with sudo and preserve HOME/GENSEE_HOME as needed",
            ),
        )
    } else {
        error
    }
}

fn linux_run_seccomp_profile(
    config: &RunConfig,
    policy_doc: &policy::PolicyDocument,
) -> Option<gensee_crate_linux::LinuxSeccompProfile> {
    let enabled = config
        .linux_seccomp_override
        .unwrap_or(policy_doc.linux.seccomp.enabled);
    enabled.then(|| {
        gensee_crate_linux::LinuxSeccompProfile::from_policy(&linux_dangerous_syscall_policy(
            &policy_doc.linux.seccomp,
        ))
    })
}

fn linux_run_network_config(
    config: &RunConfig,
    policy_doc: &policy::PolicyDocument,
    run_id: &str,
) -> io::Result<Option<gensee_crate_linux::LinuxNetworkEnforcementConfig>> {
    let mode = config
        .linux_network_override
        .unwrap_or_else(|| linux_network_mode_from_policy(policy_doc.linux.network.mode));

    let allowed_hosts = if config.linux_allow_net_override.is_empty() {
        policy_doc.linux.network.allow.clone()
    } else {
        config.linux_allow_net_override.clone()
    };
    if mode == gensee_crate_linux::LinuxNetworkMode::AllowListed && allowed_hosts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux network allowlist mode requires policy linux.network.allow or --allow-net",
        ));
    }
    let denied_hosts = if config.linux_deny_net_override.is_empty() {
        policy_doc.linux.network.deny.clone()
    } else {
        config.linux_deny_net_override.clone()
    };
    let mode = linux_effective_network_mode(mode, !denied_hosts.is_empty());
    if mode == gensee_crate_linux::LinuxNetworkMode::Off {
        return Ok(None);
    }

    Ok(Some(
        gensee_crate_linux::LinuxNetworkEnforcementConfig::new(
            run_id,
            gensee_crate_linux::LinuxNetworkPolicy {
                mode,
                allowed_hosts,
                denied_hosts,
            },
        ),
    ))
}

pub(crate) fn linux_effective_network_mode(
    mode: gensee_crate_linux::LinuxNetworkMode,
    has_denied_hosts: bool,
) -> gensee_crate_linux::LinuxNetworkMode {
    if mode == gensee_crate_linux::LinuxNetworkMode::Off && has_denied_hosts {
        gensee_crate_linux::LinuxNetworkMode::Monitor
    } else {
        mode
    }
}

pub(crate) fn linux_network_mode_from_policy(
    mode: policy::LinuxNetworkMode,
) -> gensee_crate_linux::LinuxNetworkMode {
    match mode {
        policy::LinuxNetworkMode::Off => gensee_crate_linux::LinuxNetworkMode::Off,
        policy::LinuxNetworkMode::Monitor => gensee_crate_linux::LinuxNetworkMode::Monitor,
        policy::LinuxNetworkMode::DenyAll => gensee_crate_linux::LinuxNetworkMode::DenyAll,
        policy::LinuxNetworkMode::Allowlist => gensee_crate_linux::LinuxNetworkMode::AllowListed,
    }
}

pub(crate) fn linux_dangerous_syscall_policy(
    config: &policy::LinuxSeccompConfig,
) -> gensee_crate_linux::DangerousSyscallPolicy {
    gensee_crate_linux::DangerousSyscallPolicy {
        deny_mount_namespace_changes: config.deny_mount_namespace_changes,
        deny_ptrace: config.deny_ptrace,
        deny_bpf: config.deny_bpf,
        deny_kernel_module_loading: config.deny_kernel_modules,
    }
}

pub(crate) fn linux_policy_from_policy_document(
    policy_doc: &policy::PolicyDocument,
) -> gensee_crate_linux::LinuxPolicy {
    let mut policy = gensee_crate_linux::LinuxPolicy {
        network: gensee_crate_linux::LinuxNetworkPolicy {
            mode: linux_network_mode_from_policy(policy_doc.linux.network.mode),
            allowed_hosts: policy_doc.linux.network.allow.clone(),
            denied_hosts: policy_doc.linux.network.deny.clone(),
        },
        seccomp_enabled: policy_doc.linux.seccomp.enabled,
        dangerous_syscalls: linux_dangerous_syscall_policy(&policy_doc.linux.seccomp),
        ..Default::default()
    };
    policy
        .sensitive_paths
        .extend(policy_doc.linux.fanotify.paths.iter().map(|path| {
            gensee_crate_linux::SensitivePathRule {
                pattern: path.clone(),
                access: gensee_crate_linux::SensitivePathAccess::ReadWrite,
                action: gensee_crate_linux::LinuxPolicyAction::Ask,
            }
        }));
    policy
}

pub(crate) fn linux_fanotify_policy_from_policy_document(
    policy_doc: &policy::PolicyDocument,
) -> gensee_crate_linux::LinuxPolicy {
    let mut policy = linux_policy_from_policy_document(policy_doc);
    policy.mode = gensee_crate_linux::LinuxEnforcementMode::Enforce;
    policy
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

    if tclone_discard_if_exists(session_id)? {
        return Ok(());
    }

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
