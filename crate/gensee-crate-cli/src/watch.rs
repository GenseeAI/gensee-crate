use crate::*;

#[cfg(target_os = "macos")]
type CFArrayRef = *const c_void;
#[cfg(target_os = "macos")]
type CFRunLoopRef = *const c_void;
#[cfg(target_os = "macos")]
type CFStringRef = *const c_void;
#[cfg(target_os = "macos")]
type FSEventStreamRef = *mut c_void;
#[cfg(target_os = "macos")]
type ConstFSEventStreamRef = *const c_void;

#[cfg(target_os = "macos")]
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW: u64 = u64::MAX;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x0000_0002;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x0000_0004;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_ITEM_CREATED: u32 = 0x0000_0100;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_ITEM_REMOVED: u32 = 0x0000_0200;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_ITEM_RENAMED: u32 = 0x0000_0800;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_ITEM_MODIFIED: u32 = 0x0000_1000;
#[cfg(target_os = "macos")]
const K_FSEVENT_STREAM_EVENT_FLAG_METADATA_CHANGED: u32 =
    0x0000_0400 | 0x0000_2000 | 0x0000_4000 | 0x0000_8000;

#[cfg(target_os = "macos")]
#[repr(C)]
struct FSEventStreamContext {
    version: isize,
    info: *mut c_void,
    retain: Option<extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<extern "C" fn(*const c_void)>,
    copy_description: Option<extern "C" fn(*const c_void) -> CFStringRef>,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct CFArrayCallBacks {
    version: isize,
    retain: Option<extern "C" fn(*const c_void, *const c_void) -> *const c_void>,
    release: Option<extern "C" fn(*const c_void, *const c_void)>,
    copy_description: Option<extern "C" fn(*const c_void) -> CFStringRef>,
    equal: Option<extern "C" fn(*const c_void, *const c_void) -> u8>,
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFRunLoopDefaultMode: CFStringRef;
    static kCFTypeArrayCallBacks: CFArrayCallBacks;

    fn CFArrayCreate(
        allocator: *const c_void,
        values: *const *const c_void,
        num_values: isize,
        callbacks: *const c_void,
    ) -> CFArrayRef;
    fn CFRelease(cf: *const c_void);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source_handled: u8) -> i32;
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreServices", kind = "framework")]
extern "C" {
    fn FSEventStreamCreate(
        allocator: *const c_void,
        callback: extern "C" fn(
            ConstFSEventStreamRef,
            *mut c_void,
            usize,
            *mut c_void,
            *const u32,
            *const u64,
        ),
        context: *mut FSEventStreamContext,
        paths_to_watch: CFArrayRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamFlushSync(stream_ref: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream_ref: FSEventStreamRef);
    fn FSEventStreamRelease(stream_ref: FSEventStreamRef);
    fn FSEventStreamScheduleWithRunLoop(
        stream_ref: FSEventStreamRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );
    fn FSEventStreamStart(stream_ref: FSEventStreamRef) -> u8;
    fn FSEventStreamStop(stream_ref: FSEventStreamRef);
}

#[derive(Debug, Clone)]
pub(crate) struct WatchConfig {
    pub(crate) workspace: PathBuf,
    pub(crate) watch_roots: Vec<PathBuf>,
    pub(crate) pid: Option<u32>,
    pub(crate) session_id: Option<String>,
    pub(crate) include_sensitive_roots: bool,
    pub(crate) backend: WatchBackend,
    pub(crate) system_events: SystemEventBackend,
    pub(crate) linux_fanotify: bool,
    pub(crate) duration_ms: Option<u64>,
    pub(crate) interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchBackend {
    Auto,
    Snapshot,
    Fsevents,
}

impl WatchBackend {
    pub(crate) fn parse(value: Option<String>) -> io::Result<Self> {
        match value.as_deref().unwrap_or("auto") {
            "auto" => Ok(Self::Auto),
            "snapshot" => Ok(Self::Snapshot),
            "fsevents" => Ok(Self::Fsevents),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown watch backend: {other}"),
            )),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Snapshot => "snapshot",
            Self::Fsevents => "fsevents",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemEventBackend {
    None,
    Eslogger,
}

impl SystemEventBackend {
    pub(crate) fn parse(value: Option<String>, default: Self) -> io::Result<Self> {
        match value.as_deref().unwrap_or(default.label()) {
            "none" => Ok(Self::None),
            "eslogger" => Ok(Self::Eslogger),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown system event backend: {other}"),
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Eslogger => "eslogger",
        }
    }

    fn from_policy(mode: policy::SystemEventMode) -> Self {
        match mode {
            policy::SystemEventMode::None => Self::None,
            policy::SystemEventMode::Eslogger => Self::Eslogger,
        }
    }
}

impl WatchConfig {
    pub(crate) fn parse(args: Vec<OsString>) -> io::Result<Self> {
        let workspace = arg_value(&args, "--workspace")
            .map(PathBuf::from)
            .unwrap_or(env::current_dir()?);
        let watch_roots = arg_values(&args, "--watch-root")
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let pid = arg_value(&args, "--pid")
            .map(|value| {
                value.parse::<u32>().map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid --pid: {err}"))
                })
            })
            .transpose()?;
        let session_id = arg_value(&args, "--session-id");
        let include_sensitive_roots = !has_arg(&args, "--no-sensitive-roots");
        let backend = WatchBackend::parse(arg_value(&args, "--backend"))?;
        let policy_system_events =
            SystemEventBackend::from_policy(Policy::global().document().watch.system_events);
        let system_events = if has_arg(&args, "--eslogger") {
            SystemEventBackend::Eslogger
        } else {
            SystemEventBackend::parse(arg_value(&args, "--system-events"), policy_system_events)?
        };
        let linux_fanotify = has_arg(&args, "--linux-fanotify");
        let duration_ms =
            optional_arg_u64(&args, "--duration-seconds").map(|seconds| seconds * 1000);
        let interval_ms = optional_arg_u64(&args, "--interval-ms").unwrap_or(1000);

        for arg in &args {
            if matches!(arg.to_str(), Some("--help") | Some("-h")) {
                print_usage();
            }
        }

        Ok(Self {
            workspace,
            watch_roots,
            pid,
            session_id,
            include_sensitive_roots,
            backend,
            system_events,
            linux_fanotify,
            duration_ms,
            interval_ms,
        })
    }
}

pub(crate) fn watch_workspace(config: WatchConfig) -> io::Result<()> {
    if config.pid.is_some() {
        return watch_pid(config);
    }
    if config.linux_fanotify {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gensee watch --linux-fanotify currently requires --pid <agent-root-pid>",
        ));
    }

    let workspace = canonicalize_or_original(&config.workspace);
    let watch_roots = resolve_watch_roots(
        &workspace,
        &config.watch_roots,
        config.include_sensitive_roots,
    );
    let store = EventStore::default_local()?;
    let session_id = format!("watch_{}_{}", std::process::id(), unix_millis()?);
    let started_at_ms = unix_millis()?;

    store.append_session(&AgentSession {
        session_id: session_id.clone(),
        agent_binary: "sidecar-watch".to_string(),
        root_pid: std::process::id(),
        cwd: workspace.to_string_lossy().to_string(),
        repo_path: find_repo_root(&workspace).map(|path| path.to_string_lossy().to_string()),
        mode: Some("sidecar-watch".to_string()),
        workspace_mode: Some("direct".to_string()),
        original_workspace: Some(workspace.to_string_lossy().to_string()),
        staged_workspace: None,
        sandbox_profile: None,
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: None,
        exit_code: None,
    })?;

    eprintln!(
        "gensee: watching workspace {} session={session_id}",
        workspace.display()
    );
    eprintln!("gensee: watch backend {}", config.backend.label());
    for root in &watch_roots {
        eprintln!("gensee: watch root {}", root.display());
    }
    eprintln!("gensee: system events {}", config.system_events.label());
    eprintln!("gensee: sidecar watch observes writes/deletes; pure reads need hooks, sandbox denials, or EndpointSecurity");

    let system_event_watcher = start_system_event_watcher(config.system_events, &store)?;
    let watch_result = match config.backend {
        WatchBackend::Snapshot => watch_with_snapshot(
            &store,
            &workspace,
            &watch_roots,
            &session_id,
            config.duration_ms,
            config.interval_ms,
        ),
        WatchBackend::Fsevents => watch_with_fsevents(
            &store,
            &workspace,
            &watch_roots,
            &session_id,
            config.duration_ms,
        ),
        WatchBackend::Auto => {
            let result = watch_with_fsevents(
                &store,
                &workspace,
                &watch_roots,
                &session_id,
                config.duration_ms,
            );
            match result {
                Ok(()) => Ok(()),
                Err(error) => {
                    eprintln!(
                        "gensee: FSEvents unavailable ({error}); falling back to snapshot watch"
                    );
                    watch_with_snapshot(
                        &store,
                        &workspace,
                        &watch_roots,
                        &session_id,
                        config.duration_ms,
                        config.interval_ms,
                    )
                }
            }
        }
    };

    if let Some(watcher) = system_event_watcher {
        watcher.stop();
    }

    let exit_code = if watch_result.is_ok() {
        Some(0)
    } else {
        Some(1)
    };

    store.append_session(&AgentSession {
        session_id,
        agent_binary: "sidecar-watch".to_string(),
        root_pid: std::process::id(),
        cwd: workspace.to_string_lossy().to_string(),
        repo_path: find_repo_root(&workspace).map(|path| path.to_string_lossy().to_string()),
        mode: Some("sidecar-watch".to_string()),
        workspace_mode: Some("direct".to_string()),
        original_workspace: Some(workspace.to_string_lossy().to_string()),
        staged_workspace: None,
        sandbox_profile: None,
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: Some(unix_millis()?),
        exit_code,
    })?;

    watch_result
}

fn watch_pid(config: WatchConfig) -> io::Result<()> {
    if std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "gensee watch --pid is currently supported on Linux, not {}",
                std::env::consts::OS
            ),
        ));
    }

    let pid = config.pid.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee watch --pid <pid> [--session-id <id>]",
        )
    })?;
    let workspace = canonicalize_or_original(&config.workspace);
    let session_id = config
        .session_id
        .unwrap_or_else(|| format!("watch_linux_{pid}_{}", std::process::id()));
    let target = gensee_crate_linux::LinuxSessionTarget::from_pid(session_id.clone(), pid)?;
    let policy_doc = Policy::global().document();
    let store = EventStore::default_local()?;
    let fanotify_guard = if config.linux_fanotify {
        Some(start_watch_linux_fanotify_guard(
            &store,
            &session_id,
            &target,
            policy_doc,
        )?)
    } else {
        None
    };
    let mut monitor = gensee_crate_linux::LinuxAuditMonitor::with_config(
        gensee_crate_linux::LinuxMonitorConfig {
            session: Some(target),
            enable_exec_events: true,
            enable_file_events: false,
            enable_network_events: false,
        },
    );
    monitor.prime_process_snapshot()?;
    let started_at_ms = unix_millis()?;

    store.append_session(&AgentSession {
        session_id: session_id.clone(),
        agent_binary: "sidecar-watch-linux".to_string(),
        root_pid: pid,
        cwd: workspace.to_string_lossy().to_string(),
        repo_path: find_repo_root(&workspace).map(|path| path.to_string_lossy().to_string()),
        mode: Some("sidecar-watch:linux-pid".to_string()),
        workspace_mode: Some("direct".to_string()),
        original_workspace: Some(workspace.to_string_lossy().to_string()),
        staged_workspace: None,
        sandbox_profile: None,
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: None,
        exit_code: None,
    })?;

    eprintln!("gensee: watching linux pid tree root_pid={pid} session={session_id}");
    eprintln!("gensee: poll interval {}ms", config.interval_ms);
    if let Some(duration_ms) = config.duration_ms {
        eprintln!("gensee: duration {}s", duration_ms / 1000);
    }
    if config.linux_fanotify {
        eprintln!("gensee: linux fanotify enabled");
    }

    let started = Instant::now();
    let mut exit_code = Some(0);
    loop {
        match monitor.poll_events() {
            Ok(events) => {
                for event in events {
                    let system_event = event.to_system_event();
                    store.append_system_event(&system_event)?;
                    eprintln!(
                        "gensee: linux event kind={:?} pid={} process={} command={}",
                        event.kind,
                        option_u32_display(event.pid),
                        event.process_name.as_deref().unwrap_or("unknown"),
                        event.command_line.as_deref().unwrap_or("")
                    );
                }
            }
            Err(error) => {
                exit_code = Some(1);
                store.append_session(&AgentSession {
                    session_id,
                    agent_binary: "sidecar-watch-linux".to_string(),
                    root_pid: pid,
                    cwd: workspace.to_string_lossy().to_string(),
                    repo_path: find_repo_root(&workspace)
                        .map(|path| path.to_string_lossy().to_string()),
                    mode: Some("sidecar-watch:linux-pid".to_string()),
                    workspace_mode: Some("direct".to_string()),
                    original_workspace: Some(workspace.to_string_lossy().to_string()),
                    staged_workspace: None,
                    sandbox_profile: None,
                    sandbox_profile_path: None,
                    started_at_ms,
                    ended_at_ms: Some(unix_millis()?),
                    exit_code,
                })?;
                return Err(error);
            }
        }

        if config
            .duration_ms
            .is_some_and(|duration_ms| started.elapsed() >= Duration::from_millis(duration_ms))
        {
            break;
        }
        thread::sleep(Duration::from_millis(config.interval_ms));
    }

    drop(fanotify_guard);
    store.append_session(&AgentSession {
        session_id,
        agent_binary: "sidecar-watch-linux".to_string(),
        root_pid: pid,
        cwd: workspace.to_string_lossy().to_string(),
        repo_path: find_repo_root(&workspace).map(|path| path.to_string_lossy().to_string()),
        mode: Some("sidecar-watch:linux-pid".to_string()),
        workspace_mode: Some("direct".to_string()),
        original_workspace: Some(workspace.to_string_lossy().to_string()),
        staged_workspace: None,
        sandbox_profile: None,
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: Some(unix_millis()?),
        exit_code,
    })?;

    Ok(())
}

struct WatchLinuxFanotifyGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for WatchLinuxFanotifyGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_watch_linux_fanotify_guard(
    store: &EventStore,
    session_id: &str,
    target: &gensee_crate_linux::LinuxSessionTarget,
    policy_doc: &policy::PolicyDocument,
) -> io::Result<WatchLinuxFanotifyGuard> {
    let policy = linux_fanotify_policy_from_policy_document(policy_doc);
    let mut enforcer = gensee_crate_linux::LinuxFanotifyEnforcer::new(
        gensee_crate_linux::LinuxFanotifyConfig::with_session(policy, target.clone()),
    )
    .map_err(linux_fanotify_privilege_error)?;
    let status = enforcer.status();
    eprintln!(
        "gensee: applied linux fanotify policy session={} root_pid={} marked_paths={}",
        session_id,
        target.root_pid,
        status.marked_paths.len()
    );
    for warning in &status.warnings {
        eprintln!("gensee: linux fanotify warning: {warning}");
    }

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = stop.clone();
    let store = store.clone();
    let session_id = session_id.to_string();
    let agent_binary = target
        .executable_path
        .clone()
        .unwrap_or_else(|| "sidecar-watch-linux".to_string());
    let handle = thread::spawn(move || {
        while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
            drain_linux_fanotify_events(&store, &mut enforcer, &session_id, &agent_binary);
            thread::sleep(Duration::from_millis(25));
        }
        drain_linux_fanotify_events(&store, &mut enforcer, &session_id, &agent_binary);
    });

    Ok(WatchLinuxFanotifyGuard {
        stop,
        handle: Some(handle),
    })
}

pub(crate) struct SystemEventWatcher {
    child: std::process::Child,
    reader: thread::JoinHandle<io::Result<u64>>,
}

impl SystemEventWatcher {
    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        match self.reader.join() {
            Ok(Ok(count)) => eprintln!("gensee: ingested {count} eslogger event(s)"),
            Ok(Err(error)) => eprintln!("gensee: eslogger ingest stopped with error: {error}"),
            Err(_) => eprintln!("gensee: eslogger ingest thread panicked"),
        }
    }
}

fn start_system_event_watcher(
    backend: SystemEventBackend,
    store: &EventStore,
) -> io::Result<Option<SystemEventWatcher>> {
    match backend {
        SystemEventBackend::None => Ok(None),
        SystemEventBackend::Eslogger => start_eslogger_watcher(store).map(Some),
    }
}

#[cfg(target_os = "macos")]
const ESLOGGER_WATCH_EVENTS: &[&str] = &["exec", "open", "create", "write", "rename", "unlink"];

#[cfg(target_os = "macos")]
fn start_eslogger_watcher(store: &EventStore) -> io::Result<SystemEventWatcher> {
    let mut child = Command::new("/usr/bin/eslogger")
        .args(ESLOGGER_WATCH_EVENTS)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| io::Error::new(err.kind(), format!("failed to start eslogger: {err}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to capture eslogger stdout"))?;
    let store = store.clone();
    let reader = thread::spawn(move || ingest_eslogger_reader(stdout, store));
    eprintln!(
        "gensee: started eslogger system-event watcher for {}",
        ESLOGGER_WATCH_EVENTS.join(",")
    );
    Ok(SystemEventWatcher { child, reader })
}

#[cfg(not(target_os = "macos"))]
fn start_eslogger_watcher(_store: &EventStore) -> io::Result<SystemEventWatcher> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "eslogger system events are only available on macOS",
    ))
}

#[cfg(target_os = "macos")]
fn ingest_eslogger_reader<R: Read>(reader: R, store: EventStore) -> io::Result<u64> {
    let mut count = 0_u64;
    for line in io::BufReader::new(reader).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let event = system_event_from_eslogger_line(line, unix_millis()?);
        store.append_system_event(&event)?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn watch_with_snapshot(
    store: &EventStore,
    workspace: &Path,
    watch_roots: &[PathBuf],
    session_id: &str,
    duration_ms: Option<u64>,
    interval_ms: u64,
) -> io::Result<()> {
    eprintln!(
        "gensee: snapshot watch mode may coalesce rapid create/modify/delete changes between polls"
    );
    let mut previous = snapshot_watch_roots(watch_roots)?;
    let start = unix_millis()?;

    loop {
        thread::sleep(Duration::from_millis(interval_ms));
        let now = unix_millis()?;
        let current = snapshot_watch_roots(watch_roots)?;
        for effect in
            collect_watch_effects(workspace, watch_roots, &previous, &current, session_id, now)
        {
            print_and_store_workspace_effect(store, &effect)?;
        }
        previous = current;

        if duration_ms.is_some_and(|duration| now.saturating_sub(start) >= duration) {
            break;
        }
    }

    Ok(())
}

pub(crate) fn print_and_store_workspace_effect(
    store: &EventStore,
    effect: &WorkspaceEffect,
) -> io::Result<()> {
    println!(
        "{} {}",
        effect.effect_type,
        path_relative_display(Path::new(&effect.workspace), Path::new(&effect.path))
    );
    store.append_workspace_effect(effect)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn watch_with_fsevents(
    _store: &EventStore,
    _workspace: &Path,
    _watch_roots: &[PathBuf],
    _session_id: &str,
    _duration_ms: Option<u64>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FSEvents watch backend is only available on macOS",
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn watch_with_fsevents(
    store: &EventStore,
    workspace: &Path,
    watch_roots: &[PathBuf],
    session_id: &str,
    duration_ms: Option<u64>,
) -> io::Result<()> {
    if watch_roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FSEvents watch requires at least one root",
        ));
    }

    let mut context = Box::new(FseventsCallbackContext {
        store: store.clone(),
        workspace: workspace.to_path_buf(),
        roots: watch_roots.to_vec(),
        session_id: session_id.to_string(),
    });
    let (cf_paths, paths_array) = create_fsevents_paths_array(watch_roots)?;
    let mut stream_context = FSEventStreamContext {
        version: 0,
        info: context.as_mut() as *mut FseventsCallbackContext as *mut c_void,
        retain: None,
        release: None,
        copy_description: None,
    };

    let stream = unsafe {
        FSEventStreamCreate(
            std::ptr::null(),
            fsevents_callback,
            &mut stream_context,
            paths_array,
            K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW,
            0.2,
            K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS
                | K_FSEVENT_STREAM_CREATE_FLAG_NO_DEFER
                | K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT,
        )
    };

    if stream.is_null() {
        unsafe {
            release_fsevents_paths(paths_array, &cf_paths);
        }
        return Err(io::Error::other("FSEventStreamCreate failed"));
    }

    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if FSEventStreamStart(stream) == 0 {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            release_fsevents_paths(paths_array, &cf_paths);
            return Err(io::Error::other("FSEventStreamStart failed"));
        }
    }

    let run_result = run_fsevents_loop(duration_ms);

    unsafe {
        FSEventStreamFlushSync(stream);
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        release_fsevents_paths(paths_array, &cf_paths);
    }

    run_result
}

#[cfg(target_os = "macos")]
pub(crate) fn run_fsevents_loop(duration_ms: Option<u64>) -> io::Result<()> {
    let start = unix_millis()?;
    loop {
        let wait_seconds = match duration_ms {
            Some(duration) => {
                let elapsed = unix_millis()?.saturating_sub(start);
                if elapsed >= duration {
                    break;
                }
                duration.saturating_sub(elapsed).min(250) as f64 / 1000.0
            }
            None => 0.25,
        };

        unsafe {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, wait_seconds, 1);
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) struct FseventsCallbackContext {
    store: EventStore,
    workspace: PathBuf,
    roots: Vec<PathBuf>,
    session_id: String,
}

#[cfg(target_os = "macos")]
extern "C" fn fsevents_callback(
    _stream_ref: ConstFSEventStreamRef,
    client_call_back_info: *mut c_void,
    num_events: usize,
    event_paths: *mut c_void,
    event_flags: *const u32,
    _event_ids: *const u64,
) {
    if client_call_back_info.is_null() || event_paths.is_null() || event_flags.is_null() {
        return;
    }

    let context = unsafe { &mut *(client_call_back_info as *mut FseventsCallbackContext) };
    let paths = event_paths as *const *const c_char;
    let mut seen_paths = HashSet::new();

    for index in 0..num_events {
        let path_ptr = unsafe { *paths.add(index) };
        if path_ptr.is_null() {
            continue;
        }

        let path = unsafe { CStr::from_ptr(path_ptr) }
            .to_string_lossy()
            .to_string();
        if !seen_paths.insert(path.clone()) {
            continue;
        }

        let flags = unsafe { *event_flags.add(index) };
        let Some(effect_type) = fsevents_effect_type(flags) else {
            continue;
        };
        let Some(root) = best_watch_root_for_path(Path::new(&path), &context.roots) else {
            continue;
        };
        if should_skip_watched_path(root, Path::new(&path)) {
            continue;
        }

        let effect = fsevents_workspace_effect(
            &context.workspace,
            root,
            Path::new(&path),
            effect_type,
            &context.session_id,
            unix_millis().unwrap_or(0),
        );
        if let Err(error) = print_and_store_workspace_effect(&context.store, &effect) {
            eprintln!("gensee: failed to persist FSEvents effect: {error}");
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn fsevents_workspace_effect(
    workspace: &Path,
    root: &Path,
    path: &Path,
    effect_type: &str,
    session_id: &str,
    observed_at_ms: u64,
) -> WorkspaceEffect {
    let in_workspace = path.starts_with(workspace);
    WorkspaceEffect {
        source: "gensee-watch-fsevents".to_string(),
        session_id: Some(session_id.to_string()),
        workspace: root.to_string_lossy().to_string(),
        path: path.to_string_lossy().to_string(),
        effect_type: effect_type.to_string(),
        observed_at_ms,
        attribution: if in_workspace {
            "workspace/fsevents time inference".to_string()
        } else {
            "watch-root/fsevents time inference".to_string()
        },
        confidence: if in_workspace {
            "medium".to_string()
        } else {
            "low".to_string()
        },
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn best_watch_root_for_path<'a>(path: &Path, roots: &'a [PathBuf]) -> Option<&'a Path> {
    roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count())
        .map(PathBuf::as_path)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn should_skip_watched_path(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut current = PathBuf::new();

    for component in relative.components() {
        let std::path::Component::Normal(name_os) = component else {
            continue;
        };
        let Some(name) = name_os.to_str() else {
            continue;
        };
        current.push(name);
        if should_skip_workspace_entry(&current, name) {
            return true;
        }
    }

    false
}

#[cfg(target_os = "macos")]
pub(crate) fn fsevents_effect_type(flags: u32) -> Option<&'static str> {
    if flags & K_FSEVENT_STREAM_EVENT_FLAG_ITEM_REMOVED != 0 {
        Some("delete")
    } else if flags & K_FSEVENT_STREAM_EVENT_FLAG_ITEM_RENAMED != 0 {
        Some("rename")
    } else if flags & K_FSEVENT_STREAM_EVENT_FLAG_ITEM_CREATED != 0 {
        Some("create")
    } else if flags & K_FSEVENT_STREAM_EVENT_FLAG_ITEM_MODIFIED != 0 {
        Some("modify")
    } else if flags & K_FSEVENT_STREAM_EVENT_FLAG_METADATA_CHANGED != 0 {
        Some("metadata")
    } else if flags & K_FSEVENT_STREAM_EVENT_FLAG_MUST_SCAN_SUBDIRS != 0 {
        Some("rescan")
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn create_fsevents_paths_array(
    roots: &[PathBuf],
) -> io::Result<(Vec<CFStringRef>, CFArrayRef)> {
    let mut cf_paths = Vec::new();
    for root in roots {
        let root = CString::new(root.to_string_lossy().as_bytes()).map_err(io::Error::other)?;
        let cf_path = unsafe {
            CFStringCreateWithCString(std::ptr::null(), root.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };
        if cf_path.is_null() {
            unsafe {
                for path in &cf_paths {
                    CFRelease(*path);
                }
            }
            return Err(io::Error::other("CFStringCreateWithCString failed"));
        }
        cf_paths.push(cf_path);
    }

    let values = cf_paths.to_vec();
    let paths_array = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            values.as_ptr(),
            values.len() as isize,
            &kCFTypeArrayCallBacks as *const CFArrayCallBacks as *const c_void,
        )
    };
    if paths_array.is_null() {
        unsafe {
            for path in &cf_paths {
                CFRelease(*path);
            }
        }
        return Err(io::Error::other("CFArrayCreate failed"));
    }

    Ok((cf_paths, paths_array))
}

#[cfg(target_os = "macos")]
unsafe fn release_fsevents_paths(paths_array: CFArrayRef, cf_paths: &[CFStringRef]) {
    if !paths_array.is_null() {
        CFRelease(paths_array);
    }
    for path in cf_paths {
        if !path.is_null() {
            CFRelease(*path);
        }
    }
}

pub(crate) fn resolve_watch_roots(
    workspace: &Path,
    configured_roots: &[PathBuf],
    include_sensitive_roots: bool,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    push_unique_path(&mut roots, workspace.to_path_buf());
    if include_sensitive_roots {
        for root in default_sensitive_watch_roots() {
            push_unique_path(&mut roots, root);
        }
    }
    for root in configured_roots {
        push_unique_path(&mut roots, canonicalize_or_original(root));
    }
    roots
}

pub(crate) fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

pub(crate) fn default_sensitive_watch_roots() -> Vec<PathBuf> {
    let Some(home) = env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };

    [".ssh", ".aws", ".config/gcloud"]
        .into_iter()
        .map(|path| home.join(path))
        .filter(|path| path.is_dir())
        .map(|path| canonicalize_or_original(&path))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileSnapshot {
    pub(crate) modified_ms: u64,
    pub(crate) len: u64,
}

pub(crate) fn snapshot_workspace(workspace: &Path) -> io::Result<HashMap<PathBuf, FileSnapshot>> {
    let mut files = HashMap::new();
    snapshot_workspace_inner(workspace, workspace, &mut files)?;
    Ok(files)
}

pub(crate) fn snapshot_watch_roots(
    roots: &[PathBuf],
) -> io::Result<HashMap<PathBuf, HashMap<PathBuf, FileSnapshot>>> {
    let mut snapshots = HashMap::new();
    for root in roots {
        snapshots.insert(root.clone(), snapshot_workspace(root)?);
    }
    Ok(snapshots)
}

pub(crate) fn collect_watch_effects(
    workspace: &Path,
    roots: &[PathBuf],
    previous: &HashMap<PathBuf, HashMap<PathBuf, FileSnapshot>>,
    current: &HashMap<PathBuf, HashMap<PathBuf, FileSnapshot>>,
    session_id: &str,
    observed_at_ms: u64,
) -> Vec<WorkspaceEffect> {
    let mut effects = Vec::new();
    let mut seen_paths = HashSet::new();

    for root in roots {
        let previous_root = previous.get(root).cloned().unwrap_or_default();
        let current_root = current.get(root).cloned().unwrap_or_default();
        for mut effect in diff_workspace_snapshots(
            root,
            &previous_root,
            &current_root,
            session_id,
            observed_at_ms,
        ) {
            if !seen_paths.insert(effect.path.clone()) {
                continue;
            }
            if !Path::new(&effect.path).starts_with(workspace) {
                effect.confidence = "low".to_string();
                effect.attribution = "watch-root/time inference".to_string();
            }
            effects.push(effect);
        }
    }

    effects
}

pub(crate) fn snapshot_workspace_inner(
    root: &Path,
    current: &Path,
    files: &mut HashMap<PathBuf, FileSnapshot>,
) -> io::Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if should_skip_workspace_entry(&path, &name) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if metadata.is_dir() {
            snapshot_workspace_inner(root, &path, files)?;
        } else if metadata.is_file() {
            let modified_ms = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            files.insert(
                relative,
                FileSnapshot {
                    modified_ms,
                    len: metadata.len(),
                },
            );
        }
    }
    Ok(())
}

pub(crate) fn diff_workspace_snapshots(
    workspace: &Path,
    previous: &HashMap<PathBuf, FileSnapshot>,
    current: &HashMap<PathBuf, FileSnapshot>,
    session_id: &str,
    observed_at_ms: u64,
) -> Vec<WorkspaceEffect> {
    let mut effects = Vec::new();

    for (path, snapshot) in current {
        let effect_type = match previous.get(path) {
            None => Some("create"),
            Some(previous_snapshot) if previous_snapshot != snapshot => Some("modify"),
            _ => None,
        };

        if let Some(effect_type) = effect_type {
            effects.push(workspace_effect(
                workspace,
                path,
                effect_type,
                session_id,
                observed_at_ms,
            ));
        }
    }

    for path in previous.keys() {
        if !current.contains_key(path) {
            effects.push(workspace_effect(
                workspace,
                path,
                "delete",
                session_id,
                observed_at_ms,
            ));
        }
    }

    effects.sort_by(|left, right| left.path.cmp(&right.path));
    effects
}

pub(crate) fn workspace_effect(
    workspace: &Path,
    relative_path: &Path,
    effect_type: &str,
    session_id: &str,
    observed_at_ms: u64,
) -> WorkspaceEffect {
    WorkspaceEffect {
        source: "gensee-watch-snapshot".to_string(),
        session_id: Some(session_id.to_string()),
        workspace: workspace.to_string_lossy().to_string(),
        path: workspace.join(relative_path).to_string_lossy().to_string(),
        effect_type: effect_type.to_string(),
        observed_at_ms,
        attribution: "workspace/time inference".to_string(),
        confidence: "medium".to_string(),
    }
}

pub(crate) fn path_relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

pub(crate) fn canonicalize_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
