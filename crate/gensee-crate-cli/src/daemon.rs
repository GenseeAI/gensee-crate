//! Warm daemon + thin-client fast path for agent hooks.
//!
//! The default hook path spawns the full binary and opens the store on EVERY
//! hook (~8ms spawn + per-call store open + eval). Most of that is fixed
//! overhead paid even for observational events that never block the agent.
//!
//! `gensee daemon` keeps the store and policy warm and listens on a unix
//! socket under `$GENSEE_HOME`. The hook client ([`dispatch_via_daemon`]) hands
//! the raw event over the socket:
//!   * **PreToolUse / PermissionRequest** (synchronous, gates the tool or
//!     native agent approval): the client waits for the decision; the daemon
//!     evaluates against the already-open store/policy.
//!   * **UserPromptSubmit / Antigravity PreInvocation** (synchronous, advisory):
//!     the client waits for optional counter-instructions.
//!   * **PostToolUse / Stop** for providers with no blocking response
//!     (observational, never block): the client writes and returns immediately —
//!     the store write happens on the daemon, off the agent's critical path.
//!     Full lineage is still recorded; it just no longer costs the agent
//!     latency.
//!
//! Managed `gensee run` clients may include a run hint, but the daemon accepts
//! it only when kernel peer credentials place the hook process beneath the
//! operation record's active root PID generation. The hint selects an identity
//! to verify; it does not establish one.
//!
//! If the daemon is not running the client returns `false` and the caller falls
//! back to the in-process path, so enforcement is never silently skipped.

use crate::*;
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const NO_HOOK_OUTPUT: &str = "__gensee_no_hook_output__";
const DAEMON_MANAGED_RUN_AUTH_FAILED: &str = "__gensee_managed_run_auth_failed__";
const DAEMON_MANAGED_RUN_FIRE_AND_FORGET_ACK: u8 = b'1';
const DAEMON_MANAGED_RUN_FIRE_AND_FORGET_NACK: u8 = b'0';
pub(crate) const EVENT_STORE_APPEND_SESSION: &str = "event_store_append_session";
pub(crate) const EVENT_STORE_APPEND_TRANSACTION: &str = "event_store_append_transaction";
const EVENT_STORE_APPEND_TCLONE_HOOK: &str = "event_store_append_tclone_hook";
pub(crate) const AUTHENTICATE_TCLONE_CONTEXT: &str = "authenticate_tclone_context";
const TCLONE_OBSERVER_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const TCLONE_OBSERVER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const TCLONE_OBSERVER_MAX_CONNECTIONS: usize = 32;
const TCLONE_CONTEXT_AUTH_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CACHED_MANAGED_RUN_SUBJECTS: usize = 1_024;

struct TcloneObserverConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl TcloneObserverConnectionPermit {
    fn try_acquire(active: Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current + 1)
            })
            .ok()
            .map(|_| Self { active })
    }
}

impl Drop for TcloneObserverConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaemonResponseMode {
    Required,
    Optional,
    FireAndForget,
}

impl DaemonResponseMode {
    fn protocol_name(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::FireAndForget => "fire_and_forget",
        }
    }

    fn from_protocol_name(value: &str) -> Option<Self> {
        match value {
            "required" => Some(Self::Required),
            "optional" => Some(Self::Optional),
            "fire_and_forget" => Some(Self::FireAndForget),
            _ => None,
        }
    }
}

pub(crate) struct DaemonHookRequest {
    pub(crate) payload: String,
    pub(crate) provider: String,
    pub(crate) tclone_context_run_id: Option<String>,
    pub(crate) tclone_context_capability: Option<String>,
    pub(crate) managed_run_id: Option<String>,
    pub(crate) managed_operation_id: Option<String>,
    pub(crate) response_mode: DaemonResponseMode,
}

#[derive(Clone)]
struct ManagedRunSubjectIdentity {
    run_id: String,
    operation_id: String,
    root_pid: u32,
    root_start_time_ticks: u64,
    record_path: PathBuf,
    record_modified_at: SystemTime,
}

#[derive(Default)]
struct ManagedRunPeerCache {
    by_operation_id: HashMap<String, ManagedRunSubjectIdentity>,
}

/// Run the warm daemon: bind the socket, hold the store open, and service hook
/// connections (one thread per connection; the store's internal mutex
/// serializes SQLite access).
pub(crate) fn run_daemon() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = default_root()?;
    fs::create_dir_all(&root)?;
    // The socket is a local control channel — anyone who can connect could
    // inject hook events/alerts or ask the daemon for decisions. GENSEE_HOME may
    // be user-configured and create_dir_all honors the umask, so harden both:
    // owner-only data root (0700) and owner-only socket (0600).
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let socket = daemon_socket_path(&root);
    let listener = bind_owner_only_listener(&socket)?;
    let observer_socket = tclone_observer_socket_path(&root);
    let observer_listener = bind_owner_only_listener(&observer_socket)?;
    let store = Arc::new(EventStore::default_local()?);
    let managed_runs = Arc::new(Mutex::new(ManagedRunPeerCache::default()));
    eprintln!("gensee daemon: listening on {}", socket.display());
    eprintln!(
        "gensee daemon: tclone observer listening on {}",
        observer_socket.display()
    );

    let observer_store = Arc::clone(&store);
    let observer_connections = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for conn in observer_listener.incoming() {
            match conn {
                Ok(stream) => {
                    let Some(permit) = TcloneObserverConnectionPermit::try_acquire(
                        Arc::clone(&observer_connections),
                        TCLONE_OBSERVER_MAX_CONNECTIONS,
                    ) else {
                        // Refuse excess untrusted clients before allocating a
                        // thread. The hook can use the signed host-control
                        // fallback; if neither boundary authenticates it, the
                        // event remains unattributed rather than claiming the
                        // CRIU-inherited source identity.
                        continue;
                    };
                    let store = Arc::clone(&observer_store);
                    if let Err(error) = thread::Builder::new()
                        .name("gensee-tclone-observer".to_string())
                        .spawn(move || {
                            let _permit = permit;
                            if let Err(error) = serve_tclone_observer_connection(stream, &store) {
                                eprintln!(
                                    "gensee daemon: tclone observer connection error: {error}"
                                );
                            }
                        })
                    {
                        eprintln!("gensee daemon: cannot start tclone observer worker: {error}");
                    }
                }
                Err(error) => eprintln!("gensee daemon: tclone observer accept error: {error}"),
            }
        }
    });

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let store = Arc::clone(&store);
                let managed_runs = Arc::clone(&managed_runs);
                thread::spawn(move || {
                    if let Err(err) =
                        serve_connection_with_managed_cache(stream, &store, &managed_runs)
                    {
                        eprintln!("gensee daemon: connection error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("gensee daemon: accept error: {err}"),
        }
    }
    Ok(())
}

fn bind_owner_only_listener(socket: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    // Clear a stale socket from a previous (crashed) daemon so bind() succeeds.
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn daemon_peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let mut credential = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credential as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(credential.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| io::Error::other("daemon peer did not provide a valid process id"))
}

#[cfg(target_vendor = "apple")]
fn daemon_peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::pid_t>() {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| io::Error::other("daemon peer did not provide a valid process id"))
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn daemon_peer_pid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "daemon peer process authentication is unsupported on this platform",
    ))
}

fn managed_run_subject_identity(
    state_root: &Path,
    run_id: &str,
    operation_id: &str,
    cache: &Mutex<ManagedRunPeerCache>,
) -> io::Result<ManagedRunSubjectIdentity> {
    let cached = cache
        .lock()
        .map_err(|_| io::Error::other("managed-run peer cache is poisoned"))?
        .by_operation_id
        .get(operation_id)
        .filter(|cached| cached.run_id == run_id)
        .cloned();
    if let Some(cached) = cached {
        if managed_run_record_modified_at(&cached.record_path)? == cached.record_modified_at {
            return Ok(cached);
        }
        invalidate_managed_run_subject(cache, operation_id)?;
    }

    let record_path = operation_record_path_at(state_root, operation_id)?;
    let before_open = managed_run_record_modified_at(&record_path)?;
    let supervisor = OperationSupervisor::open_at(state_root, operation_id, run_id)?;
    let (root_pid, root_start_time_ticks) = supervisor.recorded_running_root_identity()?;
    let record_modified_at = managed_run_record_modified_at(supervisor.record_path())?;
    if record_modified_at != before_open {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "managed operation record changed during authentication",
        ));
    }
    let identity = ManagedRunSubjectIdentity {
        run_id: run_id.to_string(),
        operation_id: operation_id.to_string(),
        root_pid,
        root_start_time_ticks,
        record_path,
        record_modified_at,
    };
    let mut cache = cache
        .lock()
        .map_err(|_| io::Error::other("managed-run peer cache is poisoned"))?;
    if cache.by_operation_id.len() >= MAX_CACHED_MANAGED_RUN_SUBJECTS {
        cache.by_operation_id.clear();
    }
    cache
        .by_operation_id
        .insert(operation_id.to_string(), identity.clone());
    Ok(identity)
}

fn managed_run_record_modified_at(path: &Path) -> io::Result<SystemTime> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed operation record is not a regular file",
        ));
    }
    metadata.modified()
}

fn invalidate_managed_run_subject(
    cache: &Mutex<ManagedRunPeerCache>,
    operation_id: &str,
) -> io::Result<()> {
    cache
        .lock()
        .map_err(|_| io::Error::other("managed-run peer cache is poisoned"))?
        .by_operation_id
        .remove(operation_id);
    Ok(())
}

fn invalidate_managed_run_subjects_for_session(
    cache: &Mutex<ManagedRunPeerCache>,
    session_id: &str,
) -> io::Result<()> {
    cache
        .lock()
        .map_err(|_| io::Error::other("managed-run peer cache is poisoned"))?
        .by_operation_id
        .retain(|_, identity| identity.run_id != session_id);
    Ok(())
}

fn authenticate_managed_run_process_at(
    state_root: &Path,
    run_id: &str,
    operation_id: &str,
    peer_pid: u32,
    cache: &Mutex<ManagedRunPeerCache>,
) -> io::Result<()> {
    let subject = managed_run_subject_identity(state_root, run_id, operation_id, cache)?;
    if subject.operation_id != operation_id
        || local_process_start_time_ticks(subject.root_pid).ok()
            != Some(subject.root_start_time_ticks)
    {
        invalidate_managed_run_subject(cache, operation_id)?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed-run root process generation is no longer active",
        ));
    }

    let mut pid = peer_pid;
    for _ in 0..128 {
        if pid == subject.root_pid {
            if local_process_start_time_ticks(subject.root_pid).ok()
                == Some(subject.root_start_time_ticks)
                && managed_run_record_modified_at(&subject.record_path).ok()
                    == Some(subject.record_modified_at)
            {
                return Ok(());
            }
            invalidate_managed_run_subject(cache, operation_id)?;
            break;
        }
        if pid <= 1 {
            break;
        }
        let parent = daemon_parent_pid(pid)?;
        if parent == 0 || parent == pid {
            break;
        }
        pid = parent;
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "hook process is outside the managed operation process tree",
    ))
}

pub(crate) fn authenticate_current_managed_run(run_id: &str, operation_id: &str) -> io::Result<()> {
    let state_root = default_root()?;
    authenticate_managed_run_process_at(
        &state_root,
        run_id,
        operation_id,
        std::process::id(),
        &Mutex::new(ManagedRunPeerCache::default()),
    )
}

#[cfg(target_os = "linux")]
fn daemon_parent_pid(pid: u32) -> io::Result<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let command_end = stat
        .rfind(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process stat"))?;
    stat[command_end + 2..]
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process stat missing ppid"))?
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

#[cfg(target_vendor = "apple")]
fn daemon_parent_pid(pid: u32) -> io::Result<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid process id"))?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).expect("proc_bsdinfo size fits in i32"),
        )
    };
    if result != i32::try_from(expected).expect("proc_bsdinfo size fits in i32") {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() }.pbi_ppid)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn daemon_parent_pid(_pid: u32) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "daemon process-lineage authentication is unsupported on this platform",
    ))
}

pub(crate) fn tclone_observer_socket_path(root: &Path) -> PathBuf {
    root.join("tclone-observer.sock")
}

/// Read one hook event from `stream`, process it against the warm store, and
/// write back any hook output `process_hook_event` produces (a PreToolUse
/// decision or an advisory counter-instruction). The client half-closes
/// its write side after sending, so `read_to_string` returns at end of request.
#[cfg(test)]
pub(crate) fn serve_connection(stream: UnixStream, store: &EventStore) -> io::Result<()> {
    serve_connection_with_managed_cache(stream, store, &Mutex::new(ManagedRunPeerCache::default()))
}

fn serve_connection_with_managed_cache(
    mut stream: UnixStream,
    store: &EventStore,
    managed_runs: &Mutex<ManagedRunPeerCache>,
) -> io::Result<()> {
    crate::tclone::clear_cached_authenticated_tclone_context();
    crate::tclone::clear_cached_authenticated_managed_run();
    let mut request = String::new();
    stream.read_to_string(&mut request)?;
    let value = serde_json::from_str::<Value>(&request).ok();
    if let Some(value) =
        value.filter(|value| value.get("operation").and_then(Value::as_str).is_some())
    {
        return serve_event_store_request(&mut stream, store, managed_runs, value);
    }
    let DaemonHookRequest {
        payload,
        provider,
        tclone_context_run_id,
        tclone_context_capability,
        managed_run_id,
        managed_operation_id,
        response_mode,
    } = match daemon_request_parts(&request) {
        Ok(parts) => parts,
        Err(error) => {
            log_tclone_hook_auth_debug(format_args!("rejected malformed hook envelope: {error}"));
            return Ok(()); // malformed request: nothing to do, nothing to answer
        }
    };
    if let Some(run_id) = tclone_context_run_id.as_deref() {
        let Some(capability) = tclone_context_capability.as_deref() else {
            log_tclone_hook_auth_debug(format_args!(
                "rejected hook for run {run_id}: missing context capability"
            ));
            return Ok(());
        };
        if let Err(error) = authenticate_tclone_observation(run_id, capability) {
            log_tclone_hook_auth_debug(format_args!("rejected hook for run {run_id}: {error}"));
            return Ok(());
        }
    }
    if let Some(managed_run_id) = managed_run_id.as_deref() {
        let managed_operation_id = managed_operation_id
            .as_deref()
            .expect("managed run and operation IDs are parsed as a pair");
        if let Err(error) = daemon_peer_pid(&stream).and_then(|peer_pid| {
            authenticate_managed_run_process_at(
                store.root_path(),
                managed_run_id,
                managed_operation_id,
                peer_pid,
                managed_runs,
            )
        }) {
            log_tclone_hook_auth_debug(format_args!(
                "rejected managed run attribution for {managed_run_id}: {error}"
            ));
            let rejection = if response_mode == DaemonResponseMode::FireAndForget {
                &[DAEMON_MANAGED_RUN_FIRE_AND_FORGET_NACK][..]
            } else {
                DAEMON_MANAGED_RUN_AUTH_FAILED.as_bytes()
            };
            let _ = stream.write_all(rejection);
            return Ok(());
        }
        crate::tclone::cache_authenticated_managed_run(managed_run_id);
        if response_mode == DaemonResponseMode::FireAndForget {
            stream.write_all(&[DAEMON_MANAGED_RUN_FIRE_AND_FORGET_ACK])?;
        }
    }
    let mut event = match build_hook_event_with_tclone_context(
        &payload,
        &provider,
        tclone_context_run_id.as_deref(),
    ) {
        Ok(event) => event,
        Err(_) => return Ok(()), // malformed payload: nothing to do, nothing to answer
    };
    if let Some(managed_run_id) = managed_run_id.as_deref() {
        scope_managed_run_event(&mut event, managed_run_id)?;
    }
    if let Ok(value) = serde_json::from_str::<Value>(&request) {
        if let Some(registration) = value
            .get("session_registration")
            .cloned()
            .and_then(|value| serde_json::from_value::<AgentSession>(value).ok())
        {
            if registration.root_pid != 0
                && event.session_id.as_deref() == Some(registration.session_id.as_str())
            {
                store.append_session(&registration)?;
                invalidate_managed_run_subjects_for_session(
                    managed_runs,
                    &registration.session_id,
                )?;
            }
        }
    }
    if let Some(decision_json) = process_hook_event(&payload, &event, store)? {
        // Best-effort: the client may have already gone away on a non-blocking
        // event; that is not an error worth failing the connection over.
        let _ = stream.write_all(decision_json.as_bytes());
    } else if response_mode == DaemonResponseMode::Required {
        let _ = stream.write_all(NO_HOOK_OUTPUT.as_bytes());
    }
    Ok(())
}

fn serve_event_store_request(
    stream: &mut impl Write,
    store: &EventStore,
    managed_runs: &Mutex<ManagedRunPeerCache>,
    request: Value,
) -> io::Result<()> {
    let result = (|| {
        if request
            .get("gensee_daemon_protocol")
            .and_then(Value::as_u64)
            != Some(1)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event-store request missing gensee_daemon_protocol=1",
            ));
        }
        let input = request.get("input").cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "event-store request missing input",
            )
        })?;
        match request.get("operation").and_then(Value::as_str) {
            Some(EVENT_STORE_APPEND_SESSION) => {
                let session = serde_json::from_value::<AgentSession>(input).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                store.append_session(&session)?;
                invalidate_managed_run_subjects_for_session(managed_runs, &session.session_id)
            }
            Some(EVENT_STORE_APPEND_TRANSACTION) => {
                let event =
                    serde_json::from_value::<TransactionEventInput>(input).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                store.append_transaction_event(&event).map(|_| ())
            }
            Some(operation) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported daemon event-store operation `{operation}`"),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event-store request missing operation",
            )),
        }
    })();
    let response = match result {
        Ok(()) => json!({"gensee_daemon_protocol": 1, "ok": true}),
        Err(error) => json!({
            "gensee_daemon_protocol": 1,
            "ok": false,
            "error": error.to_string(),
        }),
    };
    stream.write_all(response.to_string().as_bytes())
}

fn serve_tclone_observer_connection(mut stream: UnixStream, store: &EventStore) -> io::Result<()> {
    let request = read_tclone_observer_request(
        &mut stream,
        TCLONE_OBSERVER_MAX_REQUEST_BYTES,
        TCLONE_OBSERVER_READ_TIMEOUT,
    )?;
    let result = serde_json::from_str::<Value>(&request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        .and_then(|request| process_tclone_observer_request(store, request));
    // Observation mirrors deliberately do not wait for this response. Context
    // authentication does wait because the host result determines whether the
    // hook may claim fork identity on its decision-critical path.
    let response = match result {
        Ok(()) => json!({"gensee_daemon_protocol": 1, "ok": true}),
        Err(error) => json!({
            "gensee_daemon_protocol": 1,
            "ok": false,
            "error": error.to_string(),
        }),
    };
    let _ = stream.write_all(response.to_string().as_bytes());
    Ok(())
}

fn read_tclone_observer_request(
    stream: &mut UnixStream,
    max_bytes: usize,
    timeout: Duration,
) -> io::Result<String> {
    let deadline = Instant::now() + timeout;
    let mut request = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tclone observer request read timed out",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let count = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tclone observer request read timed out",
                ));
            }
            Err(error) => return Err(error),
        };
        if request.len().saturating_add(count) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tclone observer request exceeds {max_bytes} bytes"),
            ));
        }
        request.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(request).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tclone observer request is not UTF-8: {error}"),
        )
    })
}

fn process_tclone_observer_request(store: &EventStore, request: Value) -> io::Result<()> {
    if request
        .get("gensee_daemon_protocol")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tclone observer request missing gensee_daemon_protocol=1",
        ));
    }
    let operation = request.get("operation").and_then(Value::as_str);
    if !matches!(
        operation,
        Some(AUTHENTICATE_TCLONE_CONTEXT | EVENT_STORE_APPEND_TCLONE_HOOK)
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tclone observer only accepts authenticated context checks and hook observations",
        ));
    }
    let input = request.get("input").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "tclone observation is missing its input",
        )
    })?;
    let run_id = input.get("run_id").and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "tclone observation is missing its run id",
        )
    })?;
    let capability = input
        .get("capability")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tclone observation is missing its capability",
            )
        })?;
    authenticate_tclone_observation(run_id, capability)?;
    match operation {
        Some(AUTHENTICATE_TCLONE_CONTEXT) => Ok(()),
        Some(EVENT_STORE_APPEND_TCLONE_HOOK) => {
            let mut event = serde_json::from_value::<AgentHookEvent>(
                input.get("event").cloned().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tclone observation is missing its event",
                    )
                })?,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            scope_tclone_observation_event(&mut event, run_id)?;
            store.append_hook_event(&event)?;
            if !matches!(
                event.hook_event_name.as_deref(),
                Some("PreToolUse" | "PermissionRequest" | "PreInvocation")
            ) {
                match unix_millis() {
                    Ok(now_ms) => run_tclone_observer_retention_backstop(store, now_ms),
                    Err(error) => {
                        eprintln!("gensee daemon: Falco retention clock failed: {error}")
                    }
                }
            }
            Ok(())
        }
        Some(_) | None => unreachable!("observer operation validated above"),
    }
}

fn dispatch_event_store_request(operation: &str, input: &impl serde::Serialize) -> io::Result<()> {
    let root = default_root()?;
    let socket = daemon_socket_path(&root);
    dispatch_event_store_request_to_socket(&socket, operation, input)
}

fn dispatch_event_store_request_to_socket(
    socket: &Path,
    operation: &str,
    input: &impl serde::Serialize,
) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    let request = json!({
        "gensee_daemon_protocol": 1,
        "operation": operation,
        "input": input,
    });
    stream.write_all(request.to_string().as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response = serde_json::from_str::<Value>(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon event-store response: {error}"),
        )
    })?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    Err(io::Error::other(
        response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("daemon event-store request failed"),
    ))
}

fn dispatch_tclone_hook_observation(event: &AgentHookEvent) -> io::Result<()> {
    let Some(socket) = env::var_os(TCLONE_HOST_OBSERVER_SOCKET_ENV).map(PathBuf::from) else {
        return Ok(());
    };
    let Some((run_id, capability)) = current_tclone_observation_credentials()? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host observation socket is configured without a tclone run context",
        ));
    };
    let mut stream = UnixStream::connect(socket)?;
    let request = json!({
        "gensee_daemon_protocol": 1,
        "operation": EVENT_STORE_APPEND_TCLONE_HOOK,
        "input": {
            "event": event,
            "run_id": run_id,
            "capability": capability,
        },
    });
    stream.write_all(request.to_string().as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)
}

/// Authenticate and append a Tclone hook in one host-observer round trip. The
/// host scopes the event only after checking the host-only capability registry,
/// so a successful response is also the caller's identity proof for this hook.
pub(crate) fn authenticate_and_mirror_tclone_hook_observation(
    event: &AgentHookEvent,
    run_id: &str,
    capability: &str,
) -> io::Result<()> {
    let socket = env::var_os(TCLONE_HOST_OBSERVER_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "host observer is not configured")
        })?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TCLONE_CONTEXT_AUTH_TIMEOUT))?;
    stream.set_write_timeout(Some(TCLONE_CONTEXT_AUTH_TIMEOUT))?;
    let request = json!({
        "gensee_daemon_protocol": 1,
        "operation": EVENT_STORE_APPEND_TCLONE_HOOK,
        "input": {
            "event": event,
            "run_id": run_id,
            "capability": capability,
        },
    });
    stream.write_all(request.to_string().as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response = serde_json::from_str::<Value>(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid host observation response: {error}"),
        )
    })?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("host rejected tclone hook observation"),
        ))
    }
}

/// Verify an agent-writable run context against the host-only capability
/// registry through the observer socket bind-mounted into Tclone containers.
pub(crate) fn authenticate_tclone_context_via_host(
    run_id: &str,
    capability: &str,
) -> io::Result<()> {
    let socket = env::var_os(TCLONE_HOST_OBSERVER_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "host observer is not configured")
        })?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TCLONE_CONTEXT_AUTH_TIMEOUT))?;
    stream.set_write_timeout(Some(TCLONE_CONTEXT_AUTH_TIMEOUT))?;
    let request = json!({
        "gensee_daemon_protocol": 1,
        "operation": AUTHENTICATE_TCLONE_CONTEXT,
        "input": {"run_id": run_id, "capability": capability},
    });
    stream.write_all(request.to_string().as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response = serde_json::from_str::<Value>(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid host context-authentication response: {error}"),
        )
    })?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("host rejected tclone context identity"),
        ))
    }
}

fn log_tclone_hook_auth_debug(message: fmt::Arguments<'_>) {
    if env::var("GENSEE_TCLONE_HOST_OBSERVER_DEBUG")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
    {
        eprintln!("gensee hook: {message}");
    }
}

fn run_tclone_observer_retention_backstop(store: &EventStore, now_ms: u64) {
    let recording = Policy::load_current().document().endpoint_security.clone();
    if let Err(error) = prune_tclone_observer_falco_retention(
        store,
        now_ms,
        recording.raw_event_retention_hours,
        recording.max_raw_events,
    ) {
        eprintln!("gensee daemon: Falco retention backstop failed: {error}");
    }
}

fn prune_tclone_observer_falco_retention(
    store: &EventStore,
    now_ms: u64,
    raw_event_retention_hours: u64,
    max_raw_events: u64,
) -> io::Result<Option<u64>> {
    store.prune_falco_retention_if_due(now_ms, 60_000, raw_event_retention_hours, max_raw_events)
}

/// Best-effort fallback host attribution after the normal hook decision path.
/// The primary Tclone path uses `authenticate_and_mirror_tclone_hook_observation`
/// before local evaluation because that authenticated append is also the run
/// identity proof. Neither path prints per-event failures unless observer
/// diagnostics are enabled.
pub(crate) fn mirror_tclone_hook_observation(event: &AgentHookEvent) {
    if let Err(error) = dispatch_tclone_hook_observation(event) {
        log_tclone_hook_auth_debug(format_args!(
            "could not mirror tclone event to the host observer: {error}"
        ));
    }
}

fn scope_tclone_observation_event(event: &mut AgentHookEvent, run_id: &str) -> io::Result<()> {
    let agent_session_id = event.session_id.replace(run_id.to_string());
    let mut raw = serde_json::from_str::<Value>(&event.raw_json).unwrap_or_else(|_| json!({}));
    let object = raw.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "tclone hook event payload must be a JSON object",
        )
    })?;
    let gensee = object
        .entry("gensee")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "tclone hook event gensee metadata must be an object",
            )
        })?;
    gensee.insert("run_id".to_string(), Value::String(run_id.to_string()));
    if let Some(agent_session_id) = agent_session_id.filter(|value| value != run_id) {
        gensee.insert(
            "agent_session_id".to_string(),
            Value::String(agent_session_id),
        );
    }
    event.raw_json = serde_json::to_string(&raw).map_err(io::Error::other)?;
    Ok(())
}

/// Attribute an ordinary managed-run hook after the daemon has authenticated
/// the socket peer's process lineage. Unlike a Tclone observation, this keeps
/// the provider's own session identity intact and adds Gensee's run identity
/// only as correlation metadata.
fn scope_managed_run_event(event: &mut AgentHookEvent, run_id: &str) -> io::Result<()> {
    let mut raw = serde_json::from_str::<Value>(&event.raw_json).unwrap_or_else(|_| json!({}));
    let object = raw.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "managed-run hook event payload must be a JSON object",
        )
    })?;
    let gensee = object.entry("gensee").or_insert_with(|| json!({}));
    if let Some(gensee) = gensee.as_object_mut() {
        gensee.insert("run_id".to_string(), Value::String(run_id.to_string()));
    } else {
        object.insert(
            "gensee_run_id".to_string(),
            Value::String(run_id.to_string()),
        );
    }
    event.raw_json = serde_json::to_string(&raw).map_err(io::Error::other)?;
    Ok(())
}

pub(crate) fn daemon_append_session(session: &AgentSession) -> io::Result<()> {
    dispatch_event_store_request(EVENT_STORE_APPEND_SESSION, session)
}

pub(crate) fn daemon_append_transaction_event(event: &TransactionEventInput) -> io::Result<()> {
    dispatch_event_store_request(EVENT_STORE_APPEND_TRANSACTION, event)
}

pub(crate) fn daemon_request_parts(request: &str) -> io::Result<DaemonHookRequest> {
    let value = serde_json::from_str::<Value>(request).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("daemon request must be a JSON envelope: {err}"),
        )
    })?;
    if value.get("gensee_daemon_protocol").and_then(Value::as_u64) != Some(1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon request missing gensee_daemon_protocol=1",
        ));
    }
    let payload = value
        .get("payload")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "daemon request missing payload")
        })?
        .to_string();
    let provider = value
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon request missing provider",
            )
        })?
        .to_string();
    if !is_supported_provider(&provider) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported daemon request provider `{provider}`"),
        ));
    }
    let response_mode = value
        .get("response_mode")
        .and_then(Value::as_str)
        .and_then(DaemonResponseMode::from_protocol_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon request has invalid or missing response_mode",
            )
        })?;
    let tclone_context_run_id = value
        .get("tclone_context_run_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    if tclone_context_run_id
        .as_deref()
        .is_some_and(|run_id| !tclone_is_safe_token(run_id))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon request has invalid tclone_context_run_id",
        ));
    }
    let tclone_context_capability = value
        .get("tclone_context_capability")
        .and_then(Value::as_str)
        .map(str::to_string);
    if tclone_context_capability
        .as_deref()
        .is_some_and(|capability| !tclone_is_safe_token(capability))
        || tclone_context_run_id.is_some() != tclone_context_capability.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon request requires matching tclone context credentials",
        ));
    }
    let managed_run_id = value
        .get("managed_run_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let managed_operation_id = value
        .get("managed_operation_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    if managed_run_id
        .as_deref()
        .is_some_and(|run_id| !tclone_is_safe_token(run_id))
        || managed_operation_id
            .as_deref()
            .is_some_and(|operation_id| !tclone_is_safe_token(operation_id))
        || managed_run_id.is_some() != managed_operation_id.is_some()
        || managed_run_id.is_some() && tclone_context_run_id.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon request has invalid, incomplete, or conflicting managed identity",
        ));
    }
    Ok(DaemonHookRequest {
        payload,
        provider,
        tclone_context_run_id,
        tclone_context_capability,
        managed_run_id,
        managed_operation_id,
        response_mode,
    })
}

/// Client fast path. Returns `true` if the event was fully handled via the
/// daemon (and, for PreToolUse, the decision was written to stdout). Returns
/// `false` if the daemon is unreachable or the round trip failed, so the caller
/// falls back to in-process evaluation (never skipping enforcement).
pub(crate) fn dispatch_via_daemon(
    payload: &str,
    event: &AgentHookEvent,
    session_registration: Option<&AgentSession>,
    tclone_context_run_id: Option<&str>,
    tclone_context_capability: Option<&str>,
    managed_run_id: Option<&str>,
    managed_operation_id: Option<&str>,
) -> bool {
    let Ok(root) = default_root() else {
        return false;
    };
    let socket = daemon_socket_path(&root);
    let Ok(mut stream) = UnixStream::connect(&socket) else {
        return false; // no daemon -> in-process fallback
    };
    let request = json!({
        "gensee_daemon_protocol": 1,
        "provider": event.provider,
        "payload": payload,
        "session_registration": session_registration,
        "tclone_context_run_id": tclone_context_run_id,
        "tclone_context_capability": tclone_context_capability,
        "managed_run_id": managed_run_id,
        "managed_operation_id": managed_operation_id,
        "response_mode": daemon_response_mode(event).protocol_name(),
    })
    .to_string();
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    // Signal end-of-request so the daemon's read_to_string returns.
    if stream.shutdown(std::net::Shutdown::Write).is_err() {
        return false;
    }

    match daemon_response_mode(event) {
        DaemonResponseMode::Required => {
            // Synchronous: the decision gates the tool. Any failure or empty
            // response means the daemon could not decide — fall back to
            // in-process rather than fail open.
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_err() || response.trim().is_empty() {
                return false;
            }
            if response.trim() == DAEMON_MANAGED_RUN_AUTH_FAILED {
                return false;
            }
            if response.trim() == NO_HOOK_OUTPUT {
                return true;
            }
            print!("{response}");
            true
        }
        DaemonResponseMode::Optional => {
            // Synchronous but advisory: some hook contracts return optional
            // stdout (`UserPromptSubmit` additionalContext, Antigravity
            // PreInvocation injectSteps, Antigravity PostToolUse/Stop bodies).
            // Empty output is a valid clean result, so print only when present
            // and fall back only on read errors.
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_err() {
                return false;
            }
            if response.trim() == DAEMON_MANAGED_RUN_AUTH_FAILED {
                return false;
            }
            if !response.trim().is_empty() {
                print!("{response}");
            }
            true
        }
        DaemonResponseMode::FireAndForget => {
            if managed_run_id.is_some() {
                let _ = stream.set_read_timeout(Some(TCLONE_CONTEXT_AUTH_TIMEOUT));
                let mut acknowledgement = [0_u8; 1];
                return stream.read_exact(&mut acknowledgement).is_ok()
                    && acknowledgement[0] == DAEMON_MANAGED_RUN_FIRE_AND_FORGET_ACK;
            }
            // Observational (PostToolUse/Stop): fire-and-forget off the critical
            // path — the daemon records it; we don't wait for the store write.
            true
        }
    }
}

pub(crate) fn daemon_response_mode(event: &AgentHookEvent) -> DaemonResponseMode {
    daemon_response_mode_for_name(&event.provider, event.hook_event_name.as_deref())
}

fn daemon_response_mode_for_name(
    provider: &str,
    hook_event_name: Option<&str>,
) -> DaemonResponseMode {
    match hook_event_name {
        Some("PreToolUse" | "PermissionRequest") => DaemonResponseMode::Required,
        Some("UserPromptSubmit") => DaemonResponseMode::Optional,
        // A newly live-cloned fork can use Stop to force one continuation when
        // the inherited orchestration turn ends before task work begins.
        Some("Stop") if provider == PROVIDER_CODEX => DaemonResponseMode::Optional,
        Some("PreInvocation" | "PostToolUse" | "Stop") if provider == PROVIDER_ANTIGRAVITY => {
            DaemonResponseMode::Optional
        }
        _ => DaemonResponseMode::FireAndForget,
    }
}

#[cfg(test)]
mod tclone_observation_tests {
    use super::*;

    fn test_store(label: &str) -> (EventStore, PathBuf) {
        let root = env::temp_dir().join(format!(
            "gensee-tclone-observer-{label}-{}-{}",
            std::process::id(),
            unix_millis().unwrap()
        ));
        (EventStore::new(&root).unwrap(), root)
    }

    fn managed_operation(root: &Path, run_id: &str, operation_id: &str) -> OperationSupervisor {
        let mut supervisor = OperationSupervisor::prepare_at(
            root,
            operation_id,
            run_id,
            "managed-test",
            OperationCapabilityEnvelope::default(),
            None,
        )
        .unwrap();
        supervisor.activate(std::process::id()).unwrap();
        supervisor
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn daemon_reads_unix_peer_pid_from_kernel() {
        let (client, _server) = UnixStream::pair().unwrap();

        assert_eq!(daemon_peer_pid(&client).unwrap(), std::process::id());
    }

    #[test]
    fn managed_run_peer_resolution_requires_stable_operation_identity() {
        let (_store, root) = test_store("managed-peer-lineage");
        let _supervisor = managed_operation(&root, "managed-run-1", "managed-op-1");
        let cache = Mutex::new(ManagedRunPeerCache::default());

        authenticate_managed_run_process_at(
            &root,
            "managed-run-1",
            "managed-op-1",
            std::process::id(),
            &cache,
        )
        .unwrap();
        assert_eq!(cache.lock().unwrap().by_operation_id.len(), 1);

        cache
            .lock()
            .unwrap()
            .by_operation_id
            .get_mut("managed-op-1")
            .unwrap()
            .root_start_time_ticks += 1;
        assert_eq!(
            authenticate_managed_run_process_at(
                &root,
                "managed-run-1",
                "managed-op-1",
                std::process::id(),
                &cache,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(cache.lock().unwrap().by_operation_id.is_empty());

        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn cached_managed_identity_reloads_when_operation_becomes_terminal() {
        let (_store, root) = test_store("managed-peer-terminal");
        let mut supervisor = managed_operation(&root, "managed-run-1", "managed-op-1");
        let cache = Mutex::new(ManagedRunPeerCache::default());
        authenticate_managed_run_process_at(
            &root,
            "managed-run-1",
            "managed-op-1",
            std::process::id(),
            &cache,
        )
        .unwrap();

        thread::sleep(Duration::from_millis(2));
        supervisor.finish(Some(0), false).unwrap();

        assert_eq!(
            authenticate_managed_run_process_at(
                &root,
                "managed-run-1",
                "managed-op-1",
                std::process::id(),
                &cache,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(cache.lock().unwrap().by_operation_id.is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn daemon_authenticates_managed_run_hint_and_preserves_provider_session() {
        let (store, root) = test_store("managed-peer-envelope");
        let _supervisor = managed_operation(&root, "managed-run-1", "managed-op-1");
        let payload = json!({
            "session_id": "provider-session-1",
            "hook_event_name": "PostToolUse",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "true"},
            "tool_response": {"stdout": "", "stderr": ""},
        })
        .to_string();
        let request = json!({
            "gensee_daemon_protocol": 1,
            "provider": PROVIDER_CLAUDE_CODE,
            "payload": payload,
            "response_mode": "fire_and_forget",
            "managed_run_id": "managed-run-1",
            "managed_operation_id": "managed-op-1",
        })
        .to_string();
        let (mut client, server) = UnixStream::pair().unwrap();

        std::thread::scope(|scope| {
            let handle = scope.spawn(|| serve_connection(server, &store));
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut acknowledgement = [0_u8; 1];
            client.read_exact(&mut acknowledgement).unwrap();
            assert_eq!(acknowledgement[0], DAEMON_MANAGED_RUN_FIRE_AND_FORGET_ACK);
            handle.join().unwrap().unwrap();
        });

        let hooks = store.list_hook_events().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].session_id.as_deref(), Some("provider-session-1"));
        let raw: Value = serde_json::from_str(&hooks[0].raw_json).unwrap();
        assert_eq!(raw.pointer("/gensee/run_id"), Some(&json!("managed-run-1")));

        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn daemon_fire_and_forget_uses_explicit_managed_identity_nack() {
        let (store, root) = test_store("managed-peer-nack");
        let payload = json!({
            "session_id": "provider-session-1",
            "hook_event_name": "PostToolUse",
            "cwd": "/tmp",
        })
        .to_string();
        let request = json!({
            "gensee_daemon_protocol": 1,
            "provider": PROVIDER_CLAUDE_CODE,
            "payload": payload,
            "response_mode": "fire_and_forget",
            "managed_run_id": "forged-run",
            "managed_operation_id": "forged-operation",
        })
        .to_string();
        let (mut client, server) = UnixStream::pair().unwrap();

        std::thread::scope(|scope| {
            let handle = scope.spawn(|| serve_connection(server, &store));
            client.write_all(request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut rejection = [0_u8; 1];
            client.read_exact(&mut rejection).unwrap();
            assert_eq!(rejection[0], DAEMON_MANAGED_RUN_FIRE_AND_FORGET_NACK);
            handle.join().unwrap().unwrap();
        });
        assert!(store.list_hook_events().unwrap().is_empty());

        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn daemon_honors_client_response_contract_when_payload_mode_disagrees() {
        let (store, root) = test_store("managed-response-contract");
        let _supervisor = managed_operation(&root, "managed-run-1", "managed-op-1");

        let required_payload = json!({
            "session_id": "provider-session-1",
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "true"},
        })
        .to_string();
        let fire_and_forget_request = json!({
            "gensee_daemon_protocol": 1,
            "provider": PROVIDER_CLAUDE_CODE,
            "payload": required_payload,
            "response_mode": "fire_and_forget",
            "managed_run_id": "managed-run-1",
            "managed_operation_id": "managed-op-1",
        })
        .to_string();
        let (mut client, server) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| serve_connection(server, &store));
            client
                .write_all(fire_and_forget_request.as_bytes())
                .unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut acknowledgement = [0_u8; 1];
            client.read_exact(&mut acknowledgement).unwrap();
            assert_eq!(acknowledgement[0], DAEMON_MANAGED_RUN_FIRE_AND_FORGET_ACK);
            handle.join().unwrap().unwrap();
        });

        let observational_payload = json!({
            "session_id": "provider-session-1",
            "hook_event_name": "PostToolUse",
            "cwd": "/tmp",
            "tool_name": "Bash",
            "tool_use_id": "tool-2",
            "tool_input": {"command": "true"},
            "tool_response": {},
        })
        .to_string();
        let required_request = json!({
            "gensee_daemon_protocol": 1,
            "provider": PROVIDER_CLAUDE_CODE,
            "payload": observational_payload,
            "response_mode": "required",
            "managed_run_id": "managed-run-1",
            "managed_operation_id": "managed-op-1",
        })
        .to_string();
        let (mut client, server) = UnixStream::pair().unwrap();
        let response = std::thread::scope(|scope| {
            let handle = scope.spawn(|| serve_connection(server, &store));
            client.write_all(required_request.as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            handle.join().unwrap().unwrap();
            response
        });
        assert_eq!(response, NO_HOOK_OUTPUT);

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_observer_request_reader_enforces_exact_byte_limit() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[b'a'; 64]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let request =
            read_tclone_observer_request(&mut server, 64, Duration::from_secs(1)).unwrap();

        assert_eq!(request.len(), 64);

        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[b'a'; 65]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let error =
            read_tclone_observer_request(&mut server, 64, Duration::from_secs(1)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 64 bytes"));
    }

    #[test]
    fn tclone_observer_request_reader_times_out_idle_clients() {
        let (mut server, _client) = UnixStream::pair().unwrap();

        let error =
            read_tclone_observer_request(&mut server, 64, Duration::from_millis(20)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn tclone_observer_connection_permits_bound_concurrency() {
        let active = Arc::new(AtomicUsize::new(0));
        let first = TcloneObserverConnectionPermit::try_acquire(Arc::clone(&active), 2).unwrap();
        let second = TcloneObserverConnectionPermit::try_acquire(Arc::clone(&active), 2).unwrap();

        assert!(TcloneObserverConnectionPermit::try_acquire(Arc::clone(&active), 2).is_none());
        assert_eq!(active.load(Ordering::Acquire), 2);

        drop(first);
        let replacement =
            TcloneObserverConnectionPermit::try_acquire(Arc::clone(&active), 2).unwrap();
        assert_eq!(active.load(Ordering::Acquire), 2);

        drop(second);
        drop(replacement);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn tclone_observer_rejects_general_daemon_requests() {
        let (store, root) = test_store("strict-protocol");
        let request = json!({
            "gensee_daemon_protocol": 1,
            "provider": "codex",
            "payload": "{}",
        });

        let error = process_tclone_observer_request(&store, request).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("only accepts authenticated"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn host_observer_authenticates_context_without_appending_an_event() {
        let (store, root) = test_store("context-auth");
        let run_id = format!(
            "observer_context_auth_{}_{}",
            std::process::id(),
            unix_millis().unwrap()
        );
        let capability = rotate_tclone_host_control_capability(&run_id).unwrap();
        let request = json!({
            "gensee_daemon_protocol": 1,
            "operation": AUTHENTICATE_TCLONE_CONTEXT,
            "input": {"run_id": &run_id, "capability": &capability},
        });

        process_tclone_observer_request(&store, request.clone()).unwrap();
        assert!(store.list_hook_events().unwrap().is_empty());

        let mut rejected = request;
        rejected["input"]["capability"] = json!("wrong-capability");
        assert_eq!(
            process_tclone_observer_request(&store, rejected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        fs::remove_dir_all(gensee_tmp_root().unwrap().join(&run_id)).ok();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn host_observer_maintenance_prunes_only_the_falco_source() {
        let (store, root) = test_store("falco-retention-backstop");
        for observed_at_ms in 1..=3 {
            store
                .append_system_event(&SystemEvent {
                    source: "linux-falco".to_string(),
                    event_type: "execve".to_string(),
                    event_kind: "ProcessExec".to_string(),
                    execution_origin: Default::default(),
                    observed_at_ms,
                    pid: Some(42),
                    ppid: Some(1),
                    process_name: Some("sh".to_string()),
                    executable_path: Some("/bin/sh".to_string()),
                    file_path: None,
                    command_line: Some("sh -c true".to_string()),
                    raw_json: format!(r#"{{"event_id":"falco-{observed_at_ms}"}}"#),
                })
                .unwrap();
        }
        store
            .append_system_event(&SystemEvent {
                source: "macos-endpoint-security".to_string(),
                event_type: "exec".to_string(),
                event_kind: "ProcessExec".to_string(),
                execution_origin: Default::default(),
                observed_at_ms: 4,
                pid: Some(43),
                ppid: Some(1),
                process_name: Some("sh".to_string()),
                executable_path: Some("/bin/sh".to_string()),
                file_path: None,
                command_line: Some("sh -c true".to_string()),
                raw_json: r#"{"event_id":"endpoint-4"}"#.to_string(),
            })
            .unwrap();

        assert_eq!(
            prune_tclone_observer_falco_retention(&store, 100, 1, 1).unwrap(),
            Some(2)
        );
        let events = store
            .list_native_system_events(None, None, i64::MIN, i64::MAX, 100)
            .unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.source == "linux-falco")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.source == "macos-endpoint-security")
                .count(),
            1
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn general_daemon_rejects_tclone_observer_operation() {
        let (store, root) = test_store("general-rejects-observer");
        let mut response = Vec::new();
        serve_event_store_request(
            &mut response,
            &store,
            &Mutex::new(ManagedRunPeerCache::default()),
            json!({
                "gensee_daemon_protocol": 1,
                "operation": EVENT_STORE_APPEND_TCLONE_HOOK,
                "input": {},
            }),
        )
        .unwrap();
        let response = serde_json::from_slice::<Value>(&response).unwrap();

        assert_eq!(response.get("ok"), Some(&json!(false)));
        assert!(response
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| error.contains("unsupported daemon event-store operation")));
        fs::remove_dir_all(root).ok();
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn daemon_session_append_invalidates_managed_subject_cache() {
        let (store, root) = test_store("session-cache-invalidation");
        let cache = Mutex::new(ManagedRunPeerCache::default());
        let cached_record = root.join("cached-record.json");
        fs::write(&cached_record, "{}").unwrap();
        let cached_record_modified_at = managed_run_record_modified_at(&cached_record).unwrap();
        cache.lock().unwrap().by_operation_id.insert(
            "managed-op-1".to_string(),
            ManagedRunSubjectIdentity {
                run_id: "managed-run-1".to_string(),
                operation_id: "managed-op-1".to_string(),
                root_pid: std::process::id(),
                root_start_time_ticks: local_process_start_time_ticks(std::process::id()).unwrap(),
                record_path: cached_record.clone(),
                record_modified_at: cached_record_modified_at,
            },
        );
        cache.lock().unwrap().by_operation_id.insert(
            "managed-op-2".to_string(),
            ManagedRunSubjectIdentity {
                run_id: "managed-run-2".to_string(),
                operation_id: "managed-op-2".to_string(),
                root_pid: std::process::id(),
                root_start_time_ticks: local_process_start_time_ticks(std::process::id()).unwrap(),
                record_path: cached_record,
                record_modified_at: cached_record_modified_at,
            },
        );
        let session = AgentSession {
            session_id: "managed-run-1".to_string(),
            agent_binary: "test-agent".to_string(),
            root_pid: std::process::id(),
            cwd: "/tmp".to_string(),
            repo_path: None,
            mode: Some("hook".to_string()),
            workspace_mode: None,
            original_workspace: None,
            staged_workspace: None,
            sandbox_profile: None,
            sandbox_profile_path: None,
            started_at_ms: unix_millis().unwrap(),
            ended_at_ms: None,
            exit_code: None,
        };
        let mut response = Vec::new();

        serve_event_store_request(
            &mut response,
            &store,
            &cache,
            json!({
                "gensee_daemon_protocol": 1,
                "operation": EVENT_STORE_APPEND_SESSION,
                "input": session,
            }),
        )
        .unwrap();

        let cache = cache.lock().unwrap();
        assert!(!cache.by_operation_id.contains_key("managed-op-1"));
        assert!(cache.by_operation_id.contains_key("managed-op-2"));
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["ok"],
            json!(true)
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn host_observation_scopes_event_to_tclone_run() {
        let mut event = AgentHookEvent {
            provider: "codex".to_string(),
            session_id: Some("agent-session".to_string()),
            hook_event_name: Some("PreToolUse".to_string()),
            cwd: Some("/workspace".to_string()),
            transcript_path: None,
            tool_name: Some("Bash".to_string()),
            tool_use_id: Some("tool-1".to_string()),
            tool_input_command: Some("true".to_string()),
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: None,
            effort_level: None,
            observed_at_ms: 1,
            raw_json: json!({"session_id": "agent-session"}).to_string(),
        };

        scope_tclone_observation_event(&mut event, "run_1").unwrap();

        assert_eq!(event.session_id.as_deref(), Some("run_1"));
        let raw = serde_json::from_str::<Value>(&event.raw_json).unwrap();
        assert_eq!(raw.pointer("/gensee/run_id"), Some(&json!("run_1")));
        assert_eq!(
            raw.pointer("/gensee/agent_session_id"),
            Some(&json!("agent-session"))
        );
    }
}
