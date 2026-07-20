use crate::*;
use hmac::{Hmac, Mac};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

const DEFAULT_TCLONE_IMAGE: &str = "ghcr.io/wuklab/webtop:ubuntu-kde";
const DEFAULT_CONTAINER_HOME: &str = "/home/gensee";
const DEFAULT_CONTAINER_WORKSPACE: &str = "/workspace";
const TCLONE_AGENT_TMUX_SESSION: &str = "gensee-agent";
const TCLONE_HOST_FORK_IN_PROGRESS_FILE: &str = "fork-in-progress";
const TCLONE_STATE_LOCK_STALE_SECS: u64 = 30;
const TCLONE_HOST_CONTROL_SOCKET_ENV: &str = "GENSEE_TCLONE_HOST_SOCKET";
const TCLONE_HOST_CONTROL_DIR_ENV: &str = "GENSEE_TCLONE_HOST_CONTROL_DIR";
const TCLONE_HOST_CONTROL_DISABLE_ENV: &str = "GENSEE_TCLONE_HOST_CONTROL_DISABLE";
const TCLONE_HOST_CONTROL_WORKSPACE_DIR: &str = ".gensee-host-control";
const TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS: u64 = 300;
const TCLONE_HOST_CONTROL_COMMAND_TIMEOUT_SECS: u64 = 300;
const TCLONE_HOST_CONTROL_AUTH_DIR: &str = "host-control-auth";
const TCLONE_HOST_CONTROL_MAX_NONCES_PER_CAPABILITY: usize = 10_000;
// A request must remain fresh longer than the file client's response wait, and
// its nonce must remain claimed beyond the full age plus accepted future skew.
const TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS: u64 = 10 * 60;
const TCLONE_HOST_CONTROL_REQUEST_FUTURE_SKEW_SECS: u64 = 30;
const TCLONE_HOST_CONTROL_NONCE_RETENTION_SECS: u64 = 12 * 60;
const _: () =
    assert!(TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS > TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS);
const _: () = assert!(
    TCLONE_HOST_CONTROL_NONCE_RETENTION_SECS
        > TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS + TCLONE_HOST_CONTROL_REQUEST_FUTURE_SKEW_SECS
);
const TCLONE_CONTAINER_HOST_CONTROL_POLL_ENV: &str = "GENSEE_TCLONE_CONTAINER_HOST_CONTROL_POLL";
const TCLONE_HOST_TMUX_SOCKET_ENV: &str = "GENSEE_HOST_TMUX_SOCKET";
const TCLONE_HOST_TMUX_TARGET_ENV: &str = "GENSEE_HOST_TMUX_TARGET";
const TCLONE_ASYNC_PROGRESS_PANE_ENV: &str = "GENSEE_TCLONE_SHOW_PROGRESS_PANE";
const TCLONE_CONTAINER_INIT_PATH: &str = "/usr/local/bin/gensee-tclone-init";
pub(crate) const TCLONE_RUN_CONTEXT_PATH: &str = "/tmp/gensee-run-context.json";
const TCLONE_ASYNC_FORK_DELAY_SECS: u64 = 2;
const TCLONE_ASYNC_FORK_READY_TIMEOUT_SECS: u64 = 120;
const TCLONE_ASYNC_JOB_TIMEOUT_SECS: u64 = 10 * 60;
const TCLONE_ASYNC_JOB_STALE_GRACE_SECS: u64 = 30;
const TCLONE_ASYNC_TIMEOUT_ESCALATION_SECS: u64 = 2;
const TCLONE_ASYNC_TIMEOUT_CLAIM_STALE_SECS: u64 = 30;
const _: () = assert!(TCLONE_ASYNC_TIMEOUT_CLAIM_STALE_SECS > TCLONE_ASYNC_TIMEOUT_ESCALATION_SECS);
const TCLONE_ASYNC_MAX_ACTIVE_JOBS: usize = 4;
const TCLONE_ASYNC_JOB_RETENTION_SECS: u64 = 24 * 60 * 60;
const TCLONE_FORK_QUIET_TIMEOUT_SECS: u64 = 120;
const TCLONE_FORK_QUIET_CPU_PERCENT: f64 = 10.0;
const TCLONE_FORK_QUIET_STABLE_SAMPLES: usize = 3;
const TCLONE_FORK_TRANSIENT_MOUNT_PREFIXES: &[&str] = &[
    "/tmp/.codex",
    "/tmp/.agents",
    "/tmp/.git",
    "/workspace/.codex",
    "/workspace/.agents",
    "/workspace/.git",
];
const TCLONE_FORK_TRANSIENT_DEVICE_MOUNTS: &[&str] = &[
    "/dev/tty",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
];
const TCLONE_ATTACH_RETRY_TIMEOUT_SECS: u64 = 15;
const TCLONE_FORK_MARKER_WAIT_TIMEOUT_SECS: u64 = 5 * 60;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TcloneHostControlRequest {
    #[serde(default)]
    caller_run_id: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    authenticator: Option<String>,
    args: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TcloneHostControlResponse {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct TcloneAsyncJob {
    id: String,
    log_path: PathBuf,
    done_path: PathBuf,
}

static TCLONE_ASYNC_SCHEDULE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TCLONE_HOST_FILE_TIMEOUT_CLAMP_WARNING: OnceLock<()> = OnceLock::new();

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

pub(crate) fn proxy_tclone_host_control_if_needed(args: &[OsString]) -> io::Result<bool> {
    if env::var_os(TCLONE_HOST_CONTROL_DISABLE_ENV).is_some() {
        return Ok(false);
    }
    if !tclone_host_control_should_proxy(args) {
        return Ok(false);
    }
    let mut request_args = Vec::new();
    for arg in args {
        let Some(value) = arg.to_str() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tclone host-control commands must be valid UTF-8",
            ));
        };
        request_args.push(value.to_string());
    }
    let context = read_tclone_run_context().ok();
    let caller_run_id = context
        .as_ref()
        .and_then(|value| value.get("run_id"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| env::var("GENSEE_RUN_ID").ok())
        .filter(|value| tclone_is_safe_token(value));
    let capability = context
        .as_ref()
        .and_then(|value| value.get("host_control_capability"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .filter(|value| tclone_is_safe_token(value));
    let nonce = Uuid::new_v4().to_string();
    let issued_at_ms = unix_millis()?;
    let authenticator = caller_run_id
        .as_deref()
        .zip(capability.as_deref())
        .map(|(caller_run_id, capability)| {
            tclone_host_control_authenticator(
                caller_run_id,
                &nonce,
                issued_at_ms,
                &request_args,
                capability,
            )
        })
        .transpose()?;
    let request = TcloneHostControlRequest {
        caller_run_id,
        nonce: Some(nonce),
        issued_at_ms: Some(issued_at_ms),
        authenticator,
        args: request_args,
    };
    let response = match tclone_host_control_socket_path() {
        Some(socket_path) => match tclone_host_control_request(&socket_path, &request) {
            Ok(response) => response,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ConnectionRefused
                ) =>
            {
                tclone_host_control_file_request(&request)?
            }
            Err(error) => return Err(error),
        },
        None if tclone_host_control_dir_path().is_some() => {
            tclone_host_control_file_request(&request)?
        }
        None => return Ok(false),
    };
    print!("{}", response.stdout);
    eprint!("{}", response.stderr);
    if let Some(error) = response.error {
        return Err(io::Error::other(error));
    }
    if response.exit_code.unwrap_or(1) == 0 {
        Ok(true)
    } else {
        Err(io::Error::other(format!(
            "host gensee exited with status {}",
            response.exit_code.unwrap_or(1)
        )))
    }
}

fn read_tclone_run_context() -> io::Result<Value> {
    let path = env::var_os("GENSEE_TCLONE_CONTEXT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(TCLONE_RUN_CONTEXT_PATH));
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid tclone run context: {error}"),
        )
    })
}

fn tclone_is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value != "."
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn tclone_host_control_capability_path(run_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(run_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tclone run id for host-control capability",
        ));
    }
    Ok(gensee_tmp_root()?
        .join(run_id)
        .join(TCLONE_HOST_CONTROL_AUTH_DIR)
        .join("capability"))
}

fn read_tclone_host_control_capability(run_id: &str) -> io::Result<String> {
    let path = tclone_host_control_capability_path(run_id)?;
    let mut file = open_nofollow_read(&path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("no valid host-control capability for tclone run {run_id}: {error}"),
        )
    })?;
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    let value = value.trim().to_string();
    if !tclone_is_safe_token(&value) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid stored tclone host-control capability",
        ));
    }
    Ok(value)
}

fn ensure_tclone_host_control_capability(run_id: &str) -> io::Result<String> {
    if let Ok(value) = read_tclone_host_control_capability(run_id) {
        return Ok(value);
    }
    rotate_tclone_host_control_capability(run_id)
}

fn rotate_tclone_host_control_capability(run_id: &str) -> io::Result<String> {
    let path = tclone_host_control_capability_path(run_id)?;
    if let Some(parent) = path.parent() {
        create_restrictive_dir_all(parent)?;
        let nonces_dir = parent.join("nonces");
        match fs::symlink_metadata(&nonces_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                fs::remove_file(&nonces_dir)?;
            }
            Ok(_) => fs::remove_dir_all(&nonces_dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let capability = Uuid::new_v4().to_string();
    write_atomic_nofollow(&path, format!("{capability}\n").as_bytes(), 0o600)?;
    Ok(capability)
}

fn revoke_tclone_host_control_capability(run_id: &str) -> io::Result<()> {
    let path = tclone_host_control_capability_path(run_id)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn create_restrictive_dir_all(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_nofollow_read(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn read_nofollow_to_string(path: &Path) -> io::Result<String> {
    let mut file = open_nofollow_read(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

fn write_atomic_nofollow(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write path has no parent",
        )
    })?;
    create_restrictive_dir_all(parent)?;
    let temp_path = parent.join(format!(".gensee-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn tclone_host_control_socket_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).map(PathBuf::from) {
        candidates.push(path);
    }
    if let Some(path) = env::var_os("GENSEE_HOME").map(PathBuf::from) {
        candidates.push(path.join("host-control/control.sock"));
    }
    if let Some(path) = env::var_os("HOME").map(PathBuf::from) {
        candidates.push(path.join(".gensee/host-control/control.sock"));
    }
    candidates.push(PathBuf::from(
        "/home/gensee/.gensee/host-control/control.sock",
    ));

    candidates.into_iter().find(|path| path.exists())
}

fn tclone_host_control_dir_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).map(PathBuf::from) {
        candidates.push(path);
    }
    if let Some(path) = env::var_os("GENSEE_WORKSPACE").map(PathBuf::from) {
        candidates.push(path.join(TCLONE_HOST_CONTROL_WORKSPACE_DIR));
    }
    candidates.push(PathBuf::from(format!(
        "{DEFAULT_CONTAINER_WORKSPACE}/{TCLONE_HOST_CONTROL_WORKSPACE_DIR}"
    )));

    candidates.into_iter().find(|path| path.exists())
}

fn tclone_host_control_should_proxy(args: &[OsString]) -> bool {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return false;
    };
    if command != "run" {
        return false;
    }
    matches!(
        args.get(1).and_then(|arg| arg.to_str()),
        Some("fork" | "fork-status" | "send" | "exec" | "list" | "attach" | "shell" | "diff")
    )
}

#[cfg(unix)]
fn tclone_host_control_request(
    socket_path: &Path,
    request: &TcloneHostControlRequest,
) -> io::Result<TcloneHostControlResponse> {
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not connect to host Gensee control socket {}: {error}",
                socket_path.display()
            ),
        )
    })?;
    serde_json::to_writer(&mut stream, request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    serde_json::from_str(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid host Gensee control response: {error}"),
        )
    })
}

#[cfg(not(unix))]
fn tclone_host_control_request(
    _socket_path: &Path,
    _request: &TcloneHostControlRequest,
) -> io::Result<TcloneHostControlResponse> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tclone host control is only supported on Unix",
    ))
}

fn tclone_host_control_file_request(
    request: &TcloneHostControlRequest,
) -> io::Result<TcloneHostControlResponse> {
    let Some(control_dir) = tclone_host_control_dir_path() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not find tclone host-control socket or workspace file bridge",
        ));
    };
    let requests_dir = control_dir.join("requests");
    let responses_dir = control_dir.join("responses");
    create_restrictive_dir_all(&requests_dir)?;
    create_restrictive_dir_all(&responses_dir)?;

    let request_id = Uuid::new_v4().to_string();
    let request_path = requests_dir.join(format!("{request_id}.json"));
    let response_path = responses_dir.join(format!("{request_id}.json"));
    let _ = fs::remove_file(&request_path);
    let _ = fs::remove_file(&response_path);

    write_atomic_nofollow(&request_path, &serde_json::to_vec(request)?, 0o600)?;

    let deadline = Instant::now() + Duration::from_secs(tclone_host_control_file_timeout_secs());
    loop {
        match open_nofollow_read(&response_path) {
            Ok(mut file) => {
                let mut text = String::new();
                file.read_to_string(&mut text)?;
                let _ = fs::remove_file(&response_path);
                let _ = fs::remove_file(&request_path);
                return serde_json::from_str(&text).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid host Gensee file-control response: {error}"),
                    )
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            let _ = fs::remove_file(&request_path);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for host Gensee file-control response in {}",
                    control_dir.display()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn tclone_host_control_file_timeout_secs() -> u64 {
    let configured = env::var("GENSEE_TCLONE_HOST_FILE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS);
    clamp_tclone_host_control_file_timeout_secs(configured)
}

fn clamp_tclone_host_control_file_timeout_secs(configured: u64) -> u64 {
    let maximum = TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS.saturating_sub(1);
    if configured > maximum {
        TCLONE_HOST_FILE_TIMEOUT_CLAMP_WARNING.get_or_init(|| {
            eprintln!(
                "gensee: warning: clamping tclone host file timeout from {configured}s to {maximum}s so requests remain fresh"
            );
        });
    }
    configured.min(maximum)
}

struct TcloneHostControlServer {
    socket_path: PathBuf,
    control_dir: PathBuf,
}

struct TcloneContainerFileControlServer;

impl TcloneHostControlServer {
    fn start(socket_path: &Path, control_dir: &Path) -> io::Result<Self> {
        create_restrictive_dir_all(control_dir)?;
        create_restrictive_dir_all(&control_dir.join("requests"))?;
        create_restrictive_dir_all(&control_dir.join("responses"))?;
        let file_exe = env::current_exe()?;
        let file_control_dir = control_dir.to_path_buf();
        thread::spawn(move || loop {
            if let Err(error) =
                drain_tclone_host_control_file_requests(&file_control_dir, &file_exe)
            {
                eprintln!("gensee: tclone host-control file bridge failed: {error}");
            }
            thread::sleep(Duration::from_millis(50));
        });

        #[cfg(unix)]
        {
            if let Some(parent) = socket_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let _ = fs::remove_file(socket_path);
            let listener = UnixListener::bind(socket_path)?;
            let exe = env::current_exe()?;
            thread::spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => handle_tclone_host_control_stream(stream, &exe),
                        Err(error) => {
                            eprintln!("gensee: tclone host-control accept failed: {error}");
                            break;
                        }
                    }
                }
            });
            Ok(Self {
                socket_path: socket_path.to_path_buf(),
                control_dir: control_dir.to_path_buf(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tclone host control is only supported on Unix",
            ))
        }
    }
}

impl TcloneContainerFileControlServer {
    fn start(
        podman: &OsString,
        container_name: &str,
        control_dir: &str,
        poll_interval: Duration,
    ) -> io::Result<Self> {
        let exe = env::current_exe()?;
        let podman = podman.clone();
        let container_name = container_name.to_string();
        let control_dir = control_dir.to_string();
        thread::spawn(move || loop {
            if let Err(error) = drain_tclone_container_host_control_file_requests(
                &podman,
                &container_name,
                &control_dir,
                &exe,
            ) {
                eprintln!("gensee: tclone container host-control bridge failed: {error}");
            }
            thread::sleep(poll_interval);
        });
        Ok(Self)
    }
}

impl Drop for TcloneHostControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_dir_all(self.control_dir.join("requests"));
        let _ = fs::remove_dir_all(self.control_dir.join("responses"));
    }
}

#[cfg(unix)]
fn handle_tclone_host_control_stream(mut stream: UnixStream, exe: &Path) {
    let response = handle_tclone_host_control_request(&mut stream, exe).unwrap_or_else(|error| {
        TcloneHostControlResponse {
            exit_code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error.to_string()),
        }
    });
    let _ = serde_json::to_writer(&mut stream, &response);
}

fn handle_tclone_host_control_request(
    stream: &mut impl Read,
    exe: &Path,
) -> io::Result<TcloneHostControlResponse> {
    let request: TcloneHostControlRequest = serde_json::from_reader(stream)?;
    execute_tclone_host_control_request(request, exe)
}

fn execute_tclone_host_control_request(
    request: TcloneHostControlRequest,
    exe: &Path,
) -> io::Result<TcloneHostControlResponse> {
    if let Err(error) = validate_tclone_host_control_request(&request) {
        return Ok(TcloneHostControlResponse {
            exit_code: Some(64),
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error.to_string()),
        });
    }
    if tclone_host_control_should_run_async(&request.args) {
        let schedule_lock = TCLONE_ASYNC_SCHEDULE_LOCK.get_or_init(|| Mutex::new(()));
        let _schedule_guard = schedule_lock
            .lock()
            .map_err(|_| io::Error::other("tclone async scheduler lock poisoned"))?;
        prune_tclone_async_jobs()?;
        let caller_run_id = request.caller_run_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "async tclone host-control request has no caller run id",
            )
        })?;
        let active_jobs = count_active_tclone_async_jobs(caller_run_id)?;
        if active_jobs >= TCLONE_ASYNC_MAX_ACTIVE_JOBS {
            return Ok(TcloneHostControlResponse {
                exit_code: Some(75),
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!(
                    "tclone run {caller_run_id} already has {active_jobs} active fork jobs; wait for one to finish"
                )),
            });
        }
        let job = tclone_async_job(&request.args)?;
        let response = tclone_host_control_async_response(&request.args, &job);
        let attach_placement = tclone_host_control_async_attach_placement(&request.args)?;
        if attach_placement.is_some() {
            ensure_host_tmux_available()?;
        }
        spawn_tclone_host_control_request(request, exe.to_path_buf(), &job)?;
        if env_flag(TCLONE_ASYNC_PROGRESS_PANE_ENV) {
            let progress_placement = attach_placement.unwrap_or(HostTmuxPlacement::Right);
            if let Err(error) = open_tclone_async_job_in_host_tmux(&job, progress_placement) {
                eprintln!("gensee: warning: could not open async tclone progress pane: {error}");
            }
        }
        return Ok(response);
    }
    execute_tclone_host_control_request_sync(request, exe)
}

fn validate_tclone_host_control_request(request: &TcloneHostControlRequest) -> io::Result<()> {
    let args = request.args.iter().map(OsString::from).collect::<Vec<_>>();
    if !tclone_host_control_should_proxy(&args) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsupported tclone host-control command",
        ));
    }
    let caller_run_id = request
        .caller_run_id
        .as_deref()
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tclone host-control request is missing a valid caller run id",
            )
        })?;
    let nonce = request
        .nonce
        .as_deref()
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tclone host-control request is missing a valid nonce",
            )
        })?;
    let issued_at_ms = request.issued_at_ms.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tclone host-control request is missing its issuance time",
        )
    })?;
    validate_tclone_host_control_request_time(issued_at_ms, unix_millis()?)?;
    let supplied_authenticator = request
        .authenticator
        .as_deref()
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tclone host-control request is missing its authenticator",
            )
        })?;
    let capability = read_tclone_host_control_capability(caller_run_id)?;
    let expected_authenticator = tclone_host_control_authenticator(
        caller_run_id,
        nonce,
        issued_at_ms,
        &request.args,
        &capability,
    )?;
    if !constant_time_bytes_eq(
        supplied_authenticator.as_bytes(),
        expected_authenticator.as_bytes(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid tclone host-control request authenticator",
        ));
    }
    let subcommand = request.args.get(1).map(String::as_str).unwrap_or_default();
    match subcommand {
        "fork" => {
            let caller = find_tclone_record(caller_run_id)?;
            if caller.role != "source" {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "only a tclone source may request a fork",
                ));
            }
            validate_tclone_host_control_target(
                &request.args[2..],
                caller_run_id,
                TcloneHostControlTargetScope::CallerOnly,
            )?;
        }
        "send" => {
            let (target_args, _) = tclone_send_split(&args[2..])?;
            validate_tclone_host_control_target_strings(
                target_args,
                caller_run_id,
                TcloneHostControlTargetScope::CallerOrDirectChild,
            )?;
        }
        "exec" => {
            let (target_args, _) = tclone_exec_split(&args[2..])?;
            validate_tclone_host_control_target_strings(
                target_args,
                caller_run_id,
                TcloneHostControlTargetScope::CallerOnly,
            )?;
        }
        "diff" => validate_tclone_host_control_target(
            &request.args[2..],
            caller_run_id,
            TcloneHostControlTargetScope::CallerOnly,
        )?,
        "fork-status" => {
            let job_id = request.args.get(2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing tclone fork job id")
            })?;
            let job = tclone_async_job_from_id(job_id)?;
            let owner = read_nofollow_to_string(&tclone_async_job_owner_path(&job))?;
            if owner.trim() != caller_run_id {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "tclone fork job belongs to a different run",
                ));
            }
        }
        // These commands either expose global run state or manipulate the host's
        // interactive terminal. They are intentionally host-only.
        "list" | "attach" | "shell" => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("`run {subcommand}` is not available through container host control"),
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsupported tclone host-control command",
            ));
        }
    }
    // Claim only authenticated, authorized requests. Since the signed issuance
    // time expires before nonce records are pruned, deleting old claims cannot
    // make a captured request replayable.
    claim_tclone_host_control_nonce(caller_run_id, nonce)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcloneHostControlTargetScope {
    CallerOnly,
    CallerOrDirectChild,
}

fn validate_tclone_host_control_target(
    args: &[String],
    caller_run_id: &str,
    scope: TcloneHostControlTargetScope,
) -> io::Result<()> {
    let args = args.iter().map(OsString::from).collect::<Vec<_>>();
    validate_tclone_host_control_target_strings(&args, caller_run_id, scope)
}

fn validate_tclone_host_control_target_strings(
    args: &[OsString],
    caller_run_id: &str,
    scope: TcloneHostControlTargetScope,
) -> io::Result<()> {
    let target = tclone_target_arg(args, "missing tclone host-control target")?;
    let target_record = find_tclone_record(&target)?;
    if !tclone_host_control_target_is_authorized(caller_run_id, &target_record, scope) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "tclone run {caller_run_id} may not control {}",
                target_record.run_id
            ),
        ));
    }
    Ok(())
}

fn tclone_host_control_target_is_authorized(
    caller_run_id: &str,
    target: &TcloneRunRecord,
    scope: TcloneHostControlTargetScope,
) -> bool {
    target.run_id == caller_run_id
        || (scope == TcloneHostControlTargetScope::CallerOrDirectChild
            && target.parent_run_id.as_deref() == Some(caller_run_id))
}

fn validate_tclone_host_control_request_time(issued_at_ms: u64, now_ms: u64) -> io::Result<()> {
    let oldest_allowed_ms = now_ms.saturating_sub(TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS * 1_000);
    let newest_allowed_ms =
        now_ms.saturating_add(TCLONE_HOST_CONTROL_REQUEST_FUTURE_SKEW_SECS * 1_000);
    if issued_at_ms < oldest_allowed_ms || issued_at_ms > newest_allowed_ms {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expired or future-dated tclone host-control request",
        ));
    }
    Ok(())
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn tclone_host_control_authenticator(
    caller_run_id: &str,
    nonce: &str,
    issued_at_ms: u64,
    args: &[String],
    capability: &str,
) -> io::Result<String> {
    let encoded_args = serde_json::to_vec(args)?;
    let mut authenticator = Hmac::<Sha256>::new_from_slice(capability.as_bytes())
        .map_err(|_| io::Error::other("could not initialize host-control authenticator"))?;
    authenticator.update(b"gensee-tclone-host-control-v2\0");
    let issued_at_bytes = issued_at_ms.to_be_bytes();
    for field in [
        caller_run_id.as_bytes(),
        nonce.as_bytes(),
        &issued_at_bytes,
        &encoded_args,
    ] {
        authenticator.update(&(field.len() as u64).to_be_bytes());
        authenticator.update(field);
    }
    Ok(authenticator
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn claim_tclone_host_control_nonce(run_id: &str, nonce: &str) -> io::Result<()> {
    if !tclone_is_safe_token(nonce) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid tclone host-control request nonce",
        ));
    }
    let capability_path = tclone_host_control_capability_path(run_id)?;
    let nonces_dir = capability_path
        .parent()
        .ok_or_else(|| io::Error::other("capability path has no parent"))?
        .join("nonces");
    create_restrictive_dir_all(&nonces_dir)?;
    prune_tclone_host_control_nonces(&nonces_dir, SystemTime::now())?;
    if fs::read_dir(&nonces_dir)?
        .take(TCLONE_HOST_CONTROL_MAX_NONCES_PER_CAPABILITY + 1)
        .count()
        >= TCLONE_HOST_CONTROL_MAX_NONCES_PER_CAPABILITY
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "tclone host-control request limit reached; rotate the run capability",
        ));
    }
    let nonce_path = nonces_dir.join(nonce);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(&nonce_path)
        .and_then(|mut file| writeln!(file, "{}", unix_millis().unwrap_or(0)))
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "replayed tclone host-control request",
                )
            } else {
                error
            }
        })
}

fn prune_tclone_host_control_nonces(nonces_dir: &Path, now: SystemTime) -> io::Result<()> {
    let entries = match fs::read_dir(nonces_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        let stale = fs::symlink_metadata(&path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age.as_secs() >= TCLONE_HOST_CONTROL_NONCE_RETENTION_SECS);
        if stale {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

fn execute_tclone_host_control_request_sync(
    request: TcloneHostControlRequest,
    exe: &Path,
) -> io::Result<TcloneHostControlResponse> {
    let mut child = Command::new(exe)
        .args(&request.args)
        .env_remove(TCLONE_HOST_CONTROL_SOCKET_ENV)
        .env_remove(TCLONE_HOST_CONTROL_DIR_ENV)
        .env(TCLONE_HOST_CONTROL_DISABLE_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("could not capture host-control stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("could not capture host-control stderr"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let timeout = env::var("GENSEE_TCLONE_HOST_COMMAND_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_HOST_CONTROL_COMMAND_TIMEOUT_SECS);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Ok(TcloneHostControlResponse {
                exit_code: Some(124),
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!(
                    "tclone host-control command timed out after {timeout}s"
                )),
            });
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("host-control stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("host-control stderr reader panicked"))??;
    Ok(TcloneHostControlResponse {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        error: None,
    })
}

fn spawn_tclone_host_control_request(
    request: TcloneHostControlRequest,
    exe: PathBuf,
    job: &TcloneAsyncJob,
) -> io::Result<()> {
    if let Some(parent) = job.log_path.parent() {
        create_restrictive_dir_all(parent)?;
    }
    let owner = request.caller_run_id.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "async tclone host-control request has no caller run id",
        )
    })?;
    write_atomic_nofollow(
        &tclone_async_job_owner_path(job),
        format!("{owner}\n").as_bytes(),
        0o600,
    )?;
    let _ = fs::remove_file(&job.done_path);
    let mut log_options = fs::OpenOptions::new();
    log_options.create(true).append(true);
    #[cfg(unix)]
    log_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut log = log_options.open(&job.log_path)?;
    if !log.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", job.log_path.display()),
        ));
    }
    writeln!(
        log,
        "gensee async job {}: {} {:?}",
        job.id,
        exe.display(),
        request.args
    )?;
    let delay_secs = tclone_async_fork_delay_secs();
    writeln!(
        log,
        "gensee async job {}: waiting {}s before host fork",
        job.id, delay_secs
    )?;
    let ready_timeout_secs = tclone_async_ready_timeout_secs();
    let job_timeout_secs = tclone_async_job_timeout_secs();
    writeln!(
        log,
        "gensee async job {}: using live clone ready timeout {}s",
        job.id, ready_timeout_secs
    )?;
    let stderr = log.try_clone()?;
    let done_path = job.done_path.clone();
    // Rust starts this non-interactive wrapper in the parent's process group,
    // so the wrapper is not a process-group leader. `setsid` therefore execs
    // the command in place, making `$!` both the child pid and new group id.
    // The main shell blocks in `wait` (and reaps promptly). It and the watchdog
    // race to atomically create a claim directory: if the watchdog wins, the
    // main shell waits for its full TERM/KILL escalation before reporting 124.
    Command::new("sh")
        .arg("-c")
        .arg(
            "job_id=$1; done_path=$2; log_path=$3; delay=$4; timeout_secs=$5; escalation_secs=$6; shift 6; \
             gensee_tmux_message() { \
               message=$1; \
               if [ -n \"${GENSEE_HOST_TMUX_SOCKET:-}\" ] && [ -n \"${GENSEE_HOST_TMUX_TARGET:-}\" ]; then \
                 tmux -S \"$GENSEE_HOST_TMUX_SOCKET\" display-message -l -d 4000 -t \"$GENSEE_HOST_TMUX_TARGET\" \"$message\" 2>/dev/null || true; \
               elif [ -n \"${TMUX:-}\" ]; then \
                 tmux display-message -l -d 4000 \"$message\" 2>/dev/null || true; \
               fi; \
             }; \
             gensee_tmux_message \"Gensee is preparing a fork; the source agent may pause briefly.\"; \
             sleep \"$delay\"; \
             if command -v setsid >/dev/null 2>&1; then setsid \"$@\" & use_group=1; else \"$@\" & use_group=0; fi; \
             command_pid=$!; claim_path=$done_path.timeout-claim.$$; rmdir \"$claim_path\" 2>/dev/null || true; \
             ( \
               sleep \"$timeout_secs\"; \
               if mkdir \"$claim_path\" 2>/dev/null; then \
                 if kill -0 \"$command_pid\" 2>/dev/null; then \
                   if [ \"$use_group\" = 1 ]; then kill -TERM \"-$command_pid\" 2>/dev/null || true; else kill -TERM \"$command_pid\" 2>/dev/null || true; fi; \
                   sleep \"$escalation_secs\"; \
                   if [ \"$use_group\" = 1 ]; then kill -KILL \"-$command_pid\" 2>/dev/null || true; else kill -KILL \"$command_pid\" 2>/dev/null || true; fi; \
                 else \
                   rmdir \"$claim_path\" 2>/dev/null || true; \
                 fi; \
               fi; \
             ) & watchdog_pid=$!; \
             wait \"$command_pid\" 2>/dev/null; status=$?; \
             timed_out=0; \
             if mkdir \"$claim_path\" 2>/dev/null; then \
               kill \"$watchdog_pid\" 2>/dev/null || true; wait \"$watchdog_pid\" 2>/dev/null || true; \
             else \
               timed_out=1; wait \"$watchdog_pid\" 2>/dev/null || true; \
             fi; \
             rmdir \"$claim_path\" 2>/dev/null || true; \
             if [ \"$timed_out\" = 1 ] && [ \"$status\" != 0 ]; then status=124; printf 'gensee async job %s: timed out after %ss\\n' \"$job_id\" \"$timeout_secs\"; fi; \
             if [ \"$status\" != 0 ]; then \
               gensee_tmux_message \"Gensee fork failed; see $log_path\"; \
             else \
               gensee_tmux_message \"Gensee fork is ready.\"; \
             fi; \
             printf 'gensee async job %s: exited status=%s\\n' \"$job_id\" \"$status\"; \
             printf '%s\\n' \"$status\" > \"$done_path\"; \
             exit \"$status\"",
        )
        .arg("gensee-tclone-async-fork")
        .arg(&job.id)
        .arg(&done_path)
        .arg(&job.log_path)
        .arg(delay_secs.to_string())
        .arg(job_timeout_secs.to_string())
        .arg(TCLONE_ASYNC_TIMEOUT_ESCALATION_SECS.to_string())
        .arg(&exe)
        .args(&request.args)
        .env_remove(TCLONE_HOST_CONTROL_SOCKET_ENV)
        .env_remove(TCLONE_HOST_CONTROL_DIR_ENV)
        .env(TCLONE_HOST_CONTROL_DISABLE_ENV, "1")
        .env("GENSEE_TCLONE_READY_TIMEOUT_SECS", ready_timeout_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    Ok(())
}

fn tclone_async_ready_timeout_secs() -> u64 {
    if let Some(timeout) = env::var("GENSEE_TCLONE_ASYNC_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        return timeout;
    }
    env::var("GENSEE_TCLONE_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_ASYNC_FORK_READY_TIMEOUT_SECS)
        .max(TCLONE_ASYNC_FORK_READY_TIMEOUT_SECS)
}

fn tclone_host_control_async_attach_placement(
    args: &[String],
) -> io::Result<Option<HostTmuxPlacement>> {
    arg_value(
        &args.iter().map(OsString::from).collect::<Vec<_>>(),
        "--attach",
    )
    .map(|value| parse_host_tmux_placement(&value))
    .transpose()
}

fn tclone_host_control_should_run_async(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("run"))
        && matches!(args.get(1).map(String::as_str), Some("fork"))
}

fn tclone_async_fork_delay_secs() -> u64 {
    env::var("GENSEE_TCLONE_ASYNC_FORK_DELAY_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_ASYNC_FORK_DELAY_SECS)
}

fn tclone_async_job_timeout_secs() -> u64 {
    env::var("GENSEE_TCLONE_ASYNC_JOB_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_ASYNC_JOB_TIMEOUT_SECS)
}

fn tclone_async_job(args: &[String]) -> io::Result<TcloneAsyncJob> {
    let target = args
        .iter()
        .skip(2)
        .find(|arg| !arg.starts_with("--"))
        .map(|arg| tclone_safe_job_component(arg))
        .unwrap_or_else(|| "tclone".to_string());
    let id = format!(
        "{}_{}_{}",
        target,
        std::process::id(),
        unix_millis().unwrap_or(0)
    );
    let log_path = gensee_tmp_root()?
        .join("tclone-async")
        .join(format!("{id}.log"));
    Ok(TcloneAsyncJob {
        done_path: log_path.with_extension("done"),
        log_path,
        id,
    })
}

fn tclone_safe_job_component(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(80)
        .collect::<String>();
    if value.is_empty() {
        "tclone".to_string()
    } else {
        value
    }
}

fn tclone_async_job_owner_path(job: &TcloneAsyncJob) -> PathBuf {
    job.log_path.with_extension("owner")
}

fn tclone_async_jobs_dir() -> io::Result<PathBuf> {
    Ok(gensee_tmp_root()?.join("tclone-async"))
}

fn count_active_tclone_async_jobs(caller_run_id: &str) -> io::Result<usize> {
    let dir = tclone_async_jobs_dir()?;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut active = 0usize;
    let now = SystemTime::now();
    let timeout_secs = tclone_async_job_timeout_secs();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("log") {
            continue;
        }
        if tclone_path_exists(&path.with_extension("done"))
            || tclone_async_job_log_is_stale(&path, now, timeout_secs)
        {
            continue;
        }
        match read_nofollow_to_string(&path.with_extension("owner")) {
            Ok(owner) if owner.trim() == caller_run_id => active += 1,
            Ok(_) => {}
            Err(error) => {
                eprintln!(
                    "gensee: warning: counting async job with unreadable owner as active ({}): {error}",
                    path.display()
                );
                active += 1;
            }
        }
    }
    Ok(active)
}

fn prune_tclone_async_jobs() -> io::Result<()> {
    let dir = tclone_async_jobs_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let now = SystemTime::now();
    for entry in entries {
        let path = entry?.path();
        if tclone_async_timeout_claim_path(&path) {
            prune_tclone_async_timeout_claim(&path, now);
            continue;
        }
        let extension = path.extension().and_then(|extension| extension.to_str());
        if !matches!(extension, Some("done" | "log" | "owner")) {
            continue;
        }
        let log_path = path.with_extension("log");
        let done_path = path.with_extension("done");
        let owner_path = path.with_extension("owner");
        if extension == Some("log")
            && !tclone_path_exists(&done_path)
            && tclone_async_job_log_is_stale(&log_path, now, tclone_async_job_timeout_secs())
        {
            if let Err(error) = write_atomic_nofollow(&done_path, b"124\n", 0o600) {
                eprintln!(
                    "gensee: warning: could not mark stale async job complete ({}): {error}",
                    done_path.display()
                );
            }
        }
        let old_enough = tclone_path_age_at_least(&path, now, TCLONE_ASYNC_JOB_RETENTION_SECS);
        let orphaned_owner = extension == Some("owner")
            && !tclone_path_exists(&log_path)
            && !tclone_path_exists(&done_path);
        if old_enough && (extension == Some("done") || orphaned_owner) {
            let _ = fs::remove_file(log_path);
            let _ = fs::remove_file(done_path);
            let _ = fs::remove_file(owner_path);
        }
    }
    Ok(())
}

fn tclone_async_timeout_claim_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".done.timeout-claim."))
}

fn prune_tclone_async_timeout_claim(path: &Path, now: SystemTime) {
    let is_stale_directory = fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.is_dir())
        && tclone_path_age_at_least(path, now, TCLONE_ASYNC_TIMEOUT_CLAIM_STALE_SECS);
    if is_stale_directory {
        if let Err(error) = fs::remove_dir(path) {
            eprintln!(
                "gensee: warning: could not prune stale async timeout claim ({}): {error}",
                path.display()
            );
        }
    }
}

fn tclone_path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn tclone_path_age_at_least(path: &Path, now: SystemTime, age_secs: u64) -> bool {
    fs::symlink_metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age.as_secs() >= age_secs)
}

fn tclone_async_job_log_is_stale(path: &Path, now: SystemTime, timeout_secs: u64) -> bool {
    tclone_path_age_at_least(
        path,
        now,
        timeout_secs.saturating_add(TCLONE_ASYNC_JOB_STALE_GRACE_SECS),
    )
}

fn tclone_async_job_from_id(job_id: &str) -> io::Result<TcloneAsyncJob> {
    let job_id = job_id.trim();
    if job_id.is_empty() || job_id.contains('/') || job_id.contains('\\') || job_id.contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run fork-status <job-id> [--json]",
        ));
    }
    let log_path = gensee_tmp_root()?
        .join("tclone-async")
        .join(format!("{job_id}.log"));
    Ok(TcloneAsyncJob {
        done_path: log_path.with_extension("done"),
        log_path,
        id: job_id.to_string(),
    })
}

fn tclone_async_job_status_command(job_id: &str) -> String {
    format!("gensee run fork-status {job_id} --json")
}

fn tclone_host_control_async_response(
    args: &[String],
    job: &TcloneAsyncJob,
) -> TcloneHostControlResponse {
    let status_command = tclone_async_job_status_command(&job.id);
    let stdout = if args.iter().any(|arg| arg == "--json") {
        format!(
            "{}\n",
            json!({
                "scheduled": true,
                "command": "run fork",
                "job_id": job.id,
                "status": "scheduled",
                "status_command": status_command,
                "poll_command": status_command,
                "message": "gensee scheduled the tclone fork on the host; poll status_command until status=succeeded, then send work to forks[0].run_id",
            })
        )
    } else {
        format!(
            "gensee: scheduled tclone fork on host job_id={}; poll with `{}`\n",
            job.id, status_command
        )
    };
    TcloneHostControlResponse {
        exit_code: Some(0),
        stdout,
        stderr: String::new(),
        error: None,
    }
}

fn parse_tclone_async_fork_payload(log_text: &str) -> Option<Value> {
    log_text.lines().rev().find_map(|line| {
        let value = serde_json::from_str::<Value>(line.trim()).ok()?;
        if value.get("source_run_id").is_some() && value.get("forks").is_some() {
            Some(value)
        } else {
            None
        }
    })
}

fn tclone_async_job_last_log_lines(log_text: &str, count: usize) -> Vec<String> {
    let mut lines = log_text
        .lines()
        .rev()
        .take(count)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    lines.reverse();
    lines
}

fn tclone_async_job_status_payload(job: &TcloneAsyncJob) -> Value {
    let log_text = read_nofollow_to_string(&job.log_path).ok();
    let done_text = read_nofollow_to_string(&job.done_path).ok();
    let mut exit_code = done_text
        .as_deref()
        .and_then(|text| text.trim().parse::<i32>().ok());
    if exit_code.is_none()
        && log_text.is_some()
        && tclone_async_job_log_is_stale(
            &job.log_path,
            SystemTime::now(),
            tclone_async_job_timeout_secs(),
        )
    {
        exit_code = Some(124);
    }
    let status = match exit_code {
        Some(0) => "succeeded",
        Some(_) => "failed",
        None if log_text.is_some() => "running",
        None => "unknown",
    };
    let mut payload = json!({
        "command": "run fork-status",
        "job_id": job.id,
        "status": status,
        "exit_code": exit_code,
    });

    if let Some(fork_payload) = log_text
        .as_deref()
        .and_then(parse_tclone_async_fork_payload)
    {
        if let Some(source_run_id) = fork_payload.get("source_run_id") {
            payload["source_run_id"] = source_run_id.clone();
        }
        if let Some(forked_at_ms) = fork_payload.get("forked_at_ms") {
            payload["forked_at_ms"] = forked_at_ms.clone();
        }
        if let Some(forks) = fork_payload.get("forks") {
            payload["forks"] = forks.clone();
        }
    }

    if status == "failed" {
        payload["last_log_lines"] = json!(log_text
            .as_deref()
            .map(|text| tclone_async_job_last_log_lines(text, 20))
            .unwrap_or_default());
    }
    if status == "running" {
        payload["message"] = json!("tclone fork job is still running; poll this command again");
    } else if status == "unknown" {
        payload["message"] =
            json!("unknown tclone fork job; no log or completion marker was found");
    } else if status == "succeeded" && payload.get("forks").is_none() {
        payload["message"] =
            json!("tclone fork job succeeded, but no fork metadata was found in the job log");
    }
    payload
}

fn drain_tclone_host_control_file_requests(control_dir: &Path, exe: &Path) -> io::Result<()> {
    let requests_dir = control_dir.join("requests");
    let responses_dir = control_dir.join("responses");
    let entries = match fs::read_dir(&requests_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if !tclone_is_safe_token(stem) {
            let _ = fs::remove_file(&path);
            continue;
        }
        let response_path = responses_dir.join(format!("{stem}.json"));
        if fs::symlink_metadata(&response_path).is_ok() {
            let _ = fs::remove_file(&path);
            continue;
        }
        let response = match open_nofollow_read(&path)
            .and_then(|file| serde_json::from_reader(file).map_err(io::Error::other))
            .and_then(|request| execute_tclone_host_control_request(request, exe))
        {
            Ok(response) => response,
            Err(error) => TcloneHostControlResponse {
                exit_code: Some(1),
                stdout: String::new(),
                stderr: String::new(),
                error: Some(error.to_string()),
            },
        };
        write_atomic_nofollow(&response_path, &serde_json::to_vec(&response)?, 0o600)?;
        let _ = fs::remove_file(&path);
    }
    Ok(())
}

fn drain_tclone_container_host_control_file_requests(
    podman: &OsString,
    container_name: &str,
    control_dir: &str,
    exe: &Path,
) -> io::Result<()> {
    let requests_dir = format!("{control_dir}/requests");
    let responses_dir = format!("{control_dir}/responses");
    let list_script = format!(
        "mkdir -p {} {}; find {} -maxdepth 1 -type f -name '*.json' -printf '%f\\n' 2>/dev/null || true",
        shell_quote(&requests_dir),
        shell_quote(&responses_dir),
        shell_quote(&requests_dir),
    );
    let output = Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("sh")
        .arg("-lc")
        .arg(&list_script)
        .output()?;
    if !output.status.success() {
        return Ok(());
    }
    for file_name in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(".json") && !line.contains('/'))
    {
        let request_path = format!("{requests_dir}/{file_name}");
        let response_path = format!("{responses_dir}/{file_name}");
        let request_json = match Command::new(podman)
            .arg("exec")
            .arg(container_name)
            .arg("sh")
            .arg("-lc")
            .arg(format!("cat {}", shell_quote(&request_path)))
            .output()
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).to_string()
            }
            _ => continue,
        };
        let response = serde_json::from_str::<TcloneHostControlRequest>(&request_json)
            .map_err(io::Error::other)
            .and_then(|request| execute_tclone_host_control_request(request, exe))
            .unwrap_or_else(|error| TcloneHostControlResponse {
                exit_code: Some(1),
                stdout: String::new(),
                stderr: String::new(),
                error: Some(error.to_string()),
            });
        write_tclone_container_host_control_response(
            podman,
            container_name,
            &request_path,
            &response_path,
            &response,
        )?;
    }
    Ok(())
}

fn write_tclone_container_host_control_response(
    podman: &OsString,
    container_name: &str,
    request_path: &str,
    response_path: &str,
    response: &TcloneHostControlResponse,
) -> io::Result<()> {
    let response_tmp = format!("{response_path}.tmp");
    let script = format!(
        "cat > {}; mv {} {}; rm -f {}",
        shell_quote(&response_tmp),
        shell_quote(&response_tmp),
        shell_quote(response_path),
        shell_quote(request_path),
    );
    let mut child = Command::new(podman)
        .arg("exec")
        .arg("-i")
        .arg(container_name)
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("could not open podman exec stdin"))?;
        stdin.write_all(&serde_json::to_vec(response)?)?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "podman exec response write failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
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
    let host_control_dir = gensee_tmp_root()?.join(&run_id).join("host-control");
    create_restrictive_dir_all(&host_control_dir)?;
    let host_control_socket = host_control_dir.join("control.sock");
    let container_workspace_host_control_dir =
        format!("{container_workspace}/{TCLONE_HOST_CONTROL_WORKSPACE_DIR}");
    if let Some((socket, target)) = infer_host_tmux_context() {
        env::set_var(TCLONE_HOST_TMUX_SOCKET_ENV, socket);
        env::set_var(TCLONE_HOST_TMUX_TARGET_ENV, target);
    }
    let _host_control = TcloneHostControlServer::start(&host_control_socket, &host_control_dir)?;

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
    fs::create_dir_all(
        staged_workspace
            .join(TCLONE_HOST_CONTROL_WORKSPACE_DIR)
            .join("requests"),
    )?;
    fs::create_dir_all(
        staged_workspace
            .join(TCLONE_HOST_CONTROL_WORKSPACE_DIR)
            .join("responses"),
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
        OsString::from("--name"),
        OsString::from(&source_container),
        OsString::from("--entrypoint"),
        OsString::from(TCLONE_CONTAINER_INIT_PATH),
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
        OsString::from("-e"),
        OsString::from(format!(
            "{TCLONE_HOST_CONTROL_DIR_ENV}={container_workspace_host_control_dir}"
        )),
        OsString::from("-e"),
        OsString::from("TERM=xterm-256color"),
        OsString::from("-w"),
        OsString::from(&container_workspace),
    ];
    if env_flag_default_on("GENSEE_TCLONE_BIND_HOST_CONTROL") {
        create_args.push(OsString::from("-v"));
        create_args.push(OsString::from(format!(
            "{}:{}:rw",
            host_control_dir.display(),
            container_workspace_host_control_dir
        )));
    }
    if let Some((name, _host, container_path)) = agent_home.as_ref() {
        create_args.push(OsString::from("-e"));
        create_args.push(OsString::from(format!("{name}={container_path}")));
    }
    let mut path_prefixes = Vec::new();
    if let Some((node_root, node_bin)) = tclone_node_mount() {
        create_args.push(OsString::from("-v"));
        create_args.push(OsString::from(format!(
            "{}:{}:ro",
            node_root.display(),
            node_root.display()
        )));
        path_prefixes.push(node_bin.to_string_lossy().to_string());
    }
    if let Some((cargo_bin, rustup_home)) = tclone_rust_mount() {
        create_args.push(OsString::from("-v"));
        create_args.push(OsString::from(format!(
            "{}:{}:ro",
            cargo_bin.display(),
            cargo_bin.display()
        )));
        path_prefixes.push(cargo_bin.to_string_lossy().to_string());
        if let Some(rustup_home) = rustup_home {
            create_args.push(OsString::from("-v"));
            create_args.push(OsString::from(format!(
                "{}:{}:ro",
                rustup_home.display(),
                rustup_home.display()
            )));
            create_args.push(OsString::from("-e"));
            create_args.push(OsString::from(format!(
                "RUSTUP_HOME={}",
                rustup_home.display()
            )));
        }
        create_args.push(OsString::from("-e"));
        create_args.push(OsString::from(format!(
            "CARGO_HOME={container_home}/.cargo"
        )));
    }
    if !path_prefixes.is_empty() {
        create_args.push(OsString::from("-e"));
        create_args.push(OsString::from(format!(
            "PATH={}",
            tclone_container_path(&path_prefixes)
        )));
    }
    create_args.push(OsString::from(&image));
    create_args.push(OsString::from("idle"));
    let agent_cmd_strings = config
        .agent_cmd
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();

    let output = run_command_capture(&podman, &create_args)?;
    let container_id = output.lines().next().map(str::trim).map(str::to_string);
    let cleanup_guard = TcloneContainerCleanup::new(&podman, &source_container);
    let source_record = TcloneRunRecord {
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
        agent_cmd: agent_cmd_strings.clone(),
        fork_base_git_head: None,
        fork_base_overlay_lowerdir: None,
        fork_overlay_upperdir: None,
        started_at_ms,
        updated_at_ms: started_at_ms,
        exit_code: None,
    };
    append_tclone_record(&source_record)?;
    eprintln!(
        "gensee: preparing tclone run {run_id} source_container={source_container} workspace={}",
        original_workspace.display()
    );

    podman_cp_contents(&podman, &seed_root, &format!("{source_container}:/"))?;
    run_command_status(
        &podman,
        &[OsString::from("start"), OsString::from(&source_container)],
    )?;
    write_tclone_run_context(&podman, &source_record)?;
    start_tclone_agent_session(&podman, &source_container, &config.agent_cmd)?;
    let _container_file_control = if env_flag(TCLONE_CONTAINER_HOST_CONTROL_POLL_ENV) {
        Some(TcloneContainerFileControlServer::start(
            &podman,
            &source_container,
            &container_workspace_host_control_dir,
            Duration::from_millis(200),
        )?)
    } else {
        None
    };
    let no_attach = env_flag("GENSEE_TCLONE_NO_ATTACH");
    wait_tclone_agent_ready(
        &podman,
        &source_container,
        &agent_cmd_strings,
        no_attach,
        tclone_agent_ready_timeout(no_attach),
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
    eprintln!("gensee: fork from another terminal with: gensee run fork {run_id}");

    if env_flag("GENSEE_TCLONE_NO_ATTACH") {
        eprintln!("gensee: tclone source left running without attach because GENSEE_TCLONE_NO_ATTACH is set");
        return Ok(());
    }

    let status = tclone_attach_container(&podman, &source_container)?;
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
        "usage: gensee run fork <run_id> [--copies N] [--name <prefix>] [--attach tmux:right|tmux:below] [--json]",
    )?;
    let fork_json = arg_flag(&args, "--json");
    let host_tmux_attach = arg_value(&args, "--attach")
        .map(|value| parse_host_tmux_placement(&value))
        .transpose()?;
    if host_tmux_attach.is_some() {
        ensure_host_tmux_available()?;
    }
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
    wait_for_tclone_source_quiet_if_requested(&podman, &source)?;
    ensure_tclone_agent_ready_for_fork(&podman, &source)?;
    let _detach_guard = TcloneForkDetachGuard::mark(&source.run_id)?;
    detach_tclone_tmux_clients(&podman, &source.container_name);
    let forked_at_ms = unix_millis()?;
    let fork_base_git_head = capture_tclone_git_head(&podman, &source).ok();
    let name_hint = arg_value(&args, "--name");
    let prefix = tclone_fork_name_prefix(&parent, name_hint.as_deref(), forked_at_ms);
    let mut capability_guard = TcloneCapabilityRotationGuard::revoke(&podman, source.clone())?;
    let output = run_tclone_clone_with_overlay_retry(&podman, copies, &prefix, &source)?;
    capability_guard.restore()?;
    let ids = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if ids.len() != copies {
        return Err(io::Error::other(format!(
            "podman returned {} cloned container id(s), expected {copies}",
            ids.len()
        )));
    }
    let mut fork_run_ids = Vec::new();
    let mut fork_records = Vec::new();
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
        let fork_record = TcloneRunRecord {
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
        };
        append_tclone_record(&fork_record)?;
        write_tclone_run_context_if_possible(&podman, &fork_record);
        if !fork_json {
            println!("{run_id} | container={container_name}");
        }
        fork_records.push(json!({
            "run_id": &run_id,
            "container": &container_name,
            "container_id": ids.get(index),
            "role": "fork",
            "source_run_id": &source.run_id,
            "workspace": &source.container_workspace,
        }));
        fork_run_ids.push(run_id);
    }
    if let Some(placement) = host_tmux_attach {
        for (index, run_id) in fork_run_ids.iter().enumerate() {
            let placement = if index == 0 {
                placement
            } else {
                HostTmuxPlacement::Below
            };
            if let Err(err) = open_tclone_attach_in_host_tmux_after_preflight(run_id, placement) {
                eprintln!(
                    "gensee: warning: fork {run_id} was created, but tmux attach failed: {err}"
                );
            }
        }
    }
    if fork_json {
        println!(
            "{}",
            json!({
                "source_run_id": &source.run_id,
                "forked_at_ms": forked_at_ms,
                "attach": host_tmux_attach.is_some(),
                "forks": fork_records,
            })
        );
    }
    Ok(())
}

pub(crate) fn tclone_fork_status(args: Vec<OsString>) -> io::Result<()> {
    let job_id = tclone_target_arg(&args, "usage: gensee run fork-status <job-id> [--json]")?;
    let as_json = arg_flag(&args, "--json");
    let job = tclone_async_job_from_id(&job_id)?;
    let payload = tclone_async_job_status_payload(&job);
    if as_json {
        println!("{payload}");
        return Ok(());
    }

    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    println!("{} | status={status}", job.id);
    if let Some(exit_code) = payload.get("exit_code").and_then(Value::as_i64) {
        println!("exit_code={exit_code}");
    }
    if let Some(forks) = payload.get("forks").and_then(Value::as_array) {
        for fork in forks {
            if let Some(run_id) = fork.get("run_id").and_then(Value::as_str) {
                let container = fork.get("container").and_then(Value::as_str).unwrap_or("-");
                println!("{run_id} | container={container}");
            }
        }
    }
    if status == "failed" {
        if let Some(lines) = payload.get("last_log_lines").and_then(Value::as_array) {
            for line in lines.iter().filter_map(Value::as_str) {
                eprintln!("{line}");
            }
        }
    } else if let Some(message) = payload.get("message").and_then(Value::as_str) {
        println!("{message}");
    }
    Ok(())
}

fn run_tclone_clone_with_overlay_retry(
    podman: &OsString,
    copies: usize,
    prefix: &str,
    source: &TcloneRunRecord,
) -> io::Result<String> {
    let use_overlay = env::var("GENSEE_TCLONE_OVERLAY_BTRFS")
        .map(|value| !matches!(value.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true);
    run_tclone_clone_attempts(podman, copies, prefix, source, use_overlay, &[])
}

fn tclone_fork_name_prefix(parent: &str, name_hint: Option<&str>, forked_at_ms: u64) -> String {
    match name_hint {
        Some(name) => format!("{}-{forked_at_ms}", name.trim_end_matches('-')),
        None => format!(
            "gensee-tclone-fork-{}-{}",
            parent.replace(['_', '/'], "-"),
            forked_at_ms
        ),
    }
}

fn run_tclone_clone_attempts(
    podman: &OsString,
    copies: usize,
    prefix: &str,
    source: &TcloneRunRecord,
    use_overlay: bool,
    extra_env: &[(&str, &str)],
) -> io::Result<String> {
    let env = tclone_clone_env(extra_env);
    let clone_args = tclone_clone_args(copies, prefix, &source.container_name, use_overlay);
    match run_command_capture_with_env(podman, &clone_args, &env) {
        Ok(output) => Ok(output),
        Err(error) if use_overlay && should_retry_tclone_without_overlay(&error.to_string()) => {
            eprintln!(
                "gensee: tclone overlay-btrfs clone failed; retrying without --tfork-overlay-btrfs"
            );
            // The failed clone may already have consumed one or more names from
            // the requested prefix. A distinct retry prefix avoids masking the
            // original failure with a secondary container-name conflict.
            let fallback_prefix = format!(
                "{prefix}-no-overlay-{}",
                unix_millis().unwrap_or(std::process::id() as u64)
            );
            let fallback_args =
                tclone_clone_args(copies, &fallback_prefix, &source.container_name, false);
            run_command_capture_with_env(podman, &fallback_args, &env)
        }
        Err(error) => Err(error),
    }
}

fn tclone_clone_env(extra_env: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = vec![
        ("PODMAN_TFORK_NO_REAP".to_string(), "1".to_string()),
        (
            "PODMAN_TFORK_CLONE_READY_TIMEOUT_SECS".to_string(),
            tclone_ready_timeout_secs_env(),
        ),
    ];
    env.extend(
        extra_env
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
    );
    env
}

fn tclone_ready_timeout_secs_env() -> String {
    env::var("GENSEE_TCLONE_READY_TIMEOUT_SECS").unwrap_or_else(|_| "300".to_string())
}

fn tclone_clone_args(
    copies: usize,
    prefix: &str,
    source_container: &str,
    overlay_btrfs: bool,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("container"),
        OsString::from("clone"),
        OsString::from("--live"),
        OsString::from(format!("--copies={copies}")),
        OsString::from("--persistent=async"),
        OsString::from("--tfork-tcp-close"),
        OsString::from("--tfork-ghost-limit=67108864"),
        OsString::from("--name"),
        OsString::from(prefix),
        OsString::from(source_container),
    ];
    if overlay_btrfs {
        args.insert(5, OsString::from("--tfork-overlay-btrfs"));
    }
    args
}

fn should_retry_tclone_without_overlay(error: &str) -> bool {
    error.contains("spawn conmon for tfork")
        || error.contains("conmon reported pid=-1")
        || error.contains("clone setup failed")
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
    if let Some(placement) = arg_value(&args, "--tmux") {
        let placement = parse_host_tmux_placement(&placement)?;
        return open_tclone_attach_in_host_tmux(&target, placement);
    }
    let record = find_tclone_record(&target)?;
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &record)?;
    let status = tclone_attach_container(&podman, &record.container_name)?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone attach exited with status {status}"
        )))
    }
}

pub(crate) fn tclone_send(args: Vec<OsString>) -> io::Result<()> {
    let (target_args, prompt_args) = tclone_send_split(&args)?;
    let target = tclone_target_arg(
        target_args,
        "usage: gensee run send <run_id-or-container> [--no-enter] [--json] -- <prompt>",
    )?;
    let enter = !arg_flag(target_args, "--no-enter");
    let send_json = arg_flag(target_args, "--json");
    let prompt = tclone_send_prompt_text(prompt_args)?;
    let record = find_tclone_record(&target)?;
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &record)?;
    write_tclone_run_context_if_possible(&podman, &record);
    let prompt = tclone_prompt_with_fork_context(&record, &prompt);
    tclone_send_prompt_to_agent(&podman, &record, &prompt, enter)?;
    if send_json {
        println!(
            "{}",
            json!({
                "run_id": record.run_id,
                "container": record.container_name,
                "session": TCLONE_AGENT_TMUX_SESSION,
                "entered": enter,
                "sent": true,
            })
        );
    } else {
        println!(
            "gensee: sent prompt to {} tmux session {}",
            record.run_id, TCLONE_AGENT_TMUX_SESSION
        );
    }
    Ok(())
}

pub(crate) fn tclone_run_exec(args: Vec<OsString>) -> io::Result<()> {
    let (target_args, command_args) = tclone_exec_split(&args)?;
    let target = tclone_target_arg(
        target_args,
        "usage: gensee run exec <run_id-or-container> [--json] -- <command> [args...]",
    )?;
    let record = find_tclone_record(&target)?;
    let podman = tclone_podman();
    ensure_tclone_container_exists(&podman, &record)?;
    let exec_json = arg_flag(target_args, "--json");
    let mut command = Command::new(&podman);
    command
        .arg("exec")
        .arg("-w")
        .arg(&record.container_workspace)
        .args(tclone_run_exec_env_args(&record))
        .arg(&record.container_name)
        .args(command_args);
    if exec_json {
        let output = command.output()?;
        println!(
            "{}",
            json!({
                "run_id": record.run_id,
                "container": record.container_name,
                "exit_code": output.status.code(),
                "success": output.status.success(),
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
            })
        );
        return Ok(());
    }
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone exec exited with status {status}"
        )))
    }
}

fn tclone_send_split(args: &[OsString]) -> io::Result<(&[OsString], &[OsString])> {
    let usage = "usage: gensee run send <run_id-or-container> [--no-enter] [--json] -- <prompt>";
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage));
    };
    if separator + 1 >= args.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, usage));
    }
    Ok((&args[..separator], &args[separator + 1..]))
}

fn tclone_send_prompt_text(args: &[OsString]) -> io::Result<String> {
    let mut parts = Vec::new();
    for arg in args {
        let Some(value) = arg.to_str() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gensee run send prompt must be valid UTF-8",
            ));
        };
        parts.push(value);
    }
    let prompt = parts.join(" ");
    if prompt.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gensee run send prompt cannot be empty",
        ));
    }
    Ok(prompt)
}

fn tclone_prompt_with_fork_context(record: &TcloneRunRecord, prompt: &str) -> String {
    if record.role == "fork" {
        format!(
            "Gensee context: this request is already running inside forked run {}. Do not create another fork for this task; continue the requested work in this fork.\n\n{}",
            record.run_id, prompt
        )
    } else {
        prompt.to_string()
    }
}

fn tclone_exec_split(args: &[OsString]) -> io::Result<(&[OsString], &[OsString])> {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run exec <run_id-or-container> [--json] -- <command> [args...]",
        ));
    };
    if separator + 1 >= args.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run exec <run_id-or-container> [--json] -- <command> [args...]",
        ));
    }
    Ok((&args[..separator], &args[separator + 1..]))
}

fn tclone_run_exec_env_args(record: &TcloneRunRecord) -> Vec<OsString> {
    let gensee_home = format!("{}/.gensee", record.container_home);
    [
        ("HOME", record.container_home.as_str()),
        ("GENSEE_HOME", gensee_home.as_str()),
        ("GENSEE_RUN_ID", record.run_id.as_str()),
        ("AGENT_SHIELD_SESSION_ID", record.run_id.as_str()),
        ("GENSEE_WORKSPACE", record.container_workspace.as_str()),
    ]
    .into_iter()
    .flat_map(|(key, value)| {
        [
            OsString::from("-e"),
            OsString::from(format!("{key}={value}")),
        ]
    })
    .collect()
}

fn tclone_run_context_payload(record: &TcloneRunRecord, capability: &str) -> Value {
    json!({
        "run_id": &record.run_id,
        "role": &record.role,
        "source_run_id": record.parent_run_id.as_deref().unwrap_or(&record.run_id),
        "workspace": &record.container_workspace,
        "host_control_capability": capability,
    })
}

fn write_tclone_run_context_if_possible(podman: &OsString, record: &TcloneRunRecord) {
    if record.role != "fork" {
        return;
    }
    if let Err(error) = write_tclone_run_context(podman, record) {
        eprintln!(
            "gensee: warning: could not write fork run context into {}: {error}",
            record.run_id
        );
    }
}

fn write_tclone_run_context(podman: &OsString, record: &TcloneRunRecord) -> io::Result<()> {
    let capability = ensure_tclone_host_control_capability(&record.run_id)?;
    let payload = serde_json::to_vec(&tclone_run_context_payload(record, &capability))?;
    let script = format!("cat > {}", shell_quote(TCLONE_RUN_CONTEXT_PATH));
    let mut child = Command::new(podman)
        .arg("exec")
        .arg("-i")
        .arg(&record.container_name)
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(io::Error::other("could not open podman exec stdin"));
    };
    stdin.write_all(&payload)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "podman exec context write failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn tclone_send_prompt_to_agent(
    podman: &OsString,
    record: &TcloneRunRecord,
    prompt: &str,
    enter: bool,
) -> io::Result<()> {
    run_command_status(
        podman,
        &[
            OsString::from("exec"),
            OsString::from(&record.container_name),
            OsString::from("tmux"),
            OsString::from("has-session"),
            OsString::from("-t"),
            OsString::from(TCLONE_AGENT_TMUX_SESSION),
        ],
    )?;
    let buffer_name = format!(
        "gensee-send-{}-{}",
        std::process::id(),
        unix_millis().unwrap_or(0)
    );
    tclone_load_tmux_buffer(podman, &record.container_name, &buffer_name, prompt)?;
    let paste_result = run_command_status(
        podman,
        &[
            OsString::from("exec"),
            OsString::from(&record.container_name),
            OsString::from("tmux"),
            OsString::from("paste-buffer"),
            OsString::from("-p"),
            OsString::from("-b"),
            OsString::from(&buffer_name),
            OsString::from("-t"),
            OsString::from(TCLONE_AGENT_TMUX_SESSION),
        ],
    );
    let delete_result = run_command_status(
        podman,
        &[
            OsString::from("exec"),
            OsString::from(&record.container_name),
            OsString::from("tmux"),
            OsString::from("delete-buffer"),
            OsString::from("-b"),
            OsString::from(&buffer_name),
        ],
    );
    paste_result?;
    let _ = delete_result;
    if enter {
        run_command_status(
            podman,
            &[
                OsString::from("exec"),
                OsString::from(&record.container_name),
                OsString::from("tmux"),
                OsString::from("send-keys"),
                OsString::from("-t"),
                OsString::from(TCLONE_AGENT_TMUX_SESSION),
                OsString::from("C-m"),
            ],
        )?;
    }
    Ok(())
}

fn tclone_load_tmux_buffer(
    podman: &OsString,
    container_name: &str,
    buffer_name: &str,
    prompt: &str,
) -> io::Result<()> {
    let mut child = Command::new(podman)
        .arg("exec")
        .arg("-i")
        .arg(container_name)
        .arg("tmux")
        .arg("load-buffer")
        .arg("-b")
        .arg(buffer_name)
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(io::Error::other("could not open tmux load-buffer stdin"));
    };
    stdin.write_all(prompt.as_bytes())?;
    drop(stdin);
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tmux load-buffer exited with status {status}"
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostTmuxPlacement {
    Right,
    Below,
}

fn parse_host_tmux_placement(value: &str) -> io::Result<HostTmuxPlacement> {
    let value = value
        .strip_prefix("tmux:")
        .unwrap_or(value)
        .to_ascii_lowercase();
    match value.as_str() {
        "right" | "split-right" | "horizontal" | "h" => Ok(HostTmuxPlacement::Right),
        "below" | "down" | "bottom" | "split-down" | "vertical" | "v" => {
            Ok(HostTmuxPlacement::Below)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown tmux placement: {other}; expected right or below"),
        )),
    }
}

fn infer_host_tmux_context() -> Option<(String, String)> {
    if let (Some(socket), Some(target)) = (
        env::var_os(TCLONE_HOST_TMUX_SOCKET_ENV),
        env::var_os(TCLONE_HOST_TMUX_TARGET_ENV),
    ) {
        return Some((
            socket.to_string_lossy().to_string(),
            target.to_string_lossy().to_string(),
        ));
    }
    if let Some(tmux) = env::var_os("TMUX") {
        if let Some(context) = host_tmux_context_from_tmux_env(&tmux) {
            return Some(context);
        }
    }
    for tmux in parent_process_tmux_envs() {
        if let Some(context) = host_tmux_context_from_tmux_env(&tmux) {
            return Some(context);
        }
    }
    let ttys = host_tmux_tty_candidates();
    for tty in ttys {
        for socket in host_tmux_socket_candidates() {
            if let Some(target) = tmux_pane_for_tty(&socket, &tty) {
                return Some((socket.to_string_lossy().to_string(), target));
            }
        }
    }
    None
}

fn host_tmux_context_from_tmux_env(tmux: &OsString) -> Option<(String, String)> {
    let tmux = tmux.to_string_lossy();
    let socket = tmux.split(',').next()?.to_string();
    if socket.is_empty() {
        return None;
    }
    let target = Command::new("tmux")
        .env("TMUX", tmux.as_ref())
        .arg("display-message")
        .arg("-p")
        .arg("#{pane_id}")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|target| !target.is_empty())?;
    Some((socket, target))
}

fn parent_process_tmux_envs() -> Vec<OsString> {
    let mut values = Vec::new();
    let mut pid = parent_pid_of(std::process::id());
    for _ in 0..4 {
        let Some(current_pid) = pid else {
            break;
        };
        if let Some(tmux) = process_env_value(current_pid, "TMUX") {
            values.push(tmux);
        }
        pid = parent_pid_of(current_pid);
    }
    values
}

fn parent_pid_of(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(") ")?;
    stat[end + 2..].split_whitespace().nth(1)?.parse().ok()
}

fn process_env_value(pid: u32, key: &str) -> Option<OsString> {
    let bytes = fs::read(format!("/proc/{pid}/environ")).ok()?;
    let prefix = format!("{key}=");
    bytes
        .split(|byte| *byte == 0)
        .filter_map(|entry| std::str::from_utf8(entry).ok())
        .find_map(|entry| {
            entry
                .strip_prefix(&prefix)
                .map(|value| OsString::from(value.to_string()))
        })
}

fn current_tty_path() -> Option<String> {
    let output = Command::new("tty").stdin(Stdio::inherit()).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let tty = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tty.is_empty() || tty == "not a tty" {
        None
    } else {
        Some(tty)
    }
}

fn host_tmux_tty_candidates() -> Vec<String> {
    let mut ttys = Vec::new();
    for key in ["TMUX_PANE_TTY", "SUDO_TTY", "SSH_TTY"] {
        if let Some(value) = env::var_os(key).map(|value| value.to_string_lossy().to_string()) {
            if !value.is_empty() {
                ttys.push(value);
            }
        }
    }
    if let Some(tty) = current_tty_path() {
        ttys.push(tty);
    }
    for pid in parent_process_ids(std::process::id(), 6) {
        if let Some(tty) = process_tty_path(pid) {
            ttys.push(tty);
        }
    }
    ttys.sort();
    ttys.dedup();
    ttys
}

fn parent_process_ids(start_pid: u32, limit: usize) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut pid = parent_pid_of(start_pid);
    for _ in 0..limit {
        let Some(current_pid) = pid else {
            break;
        };
        pids.push(current_pid);
        pid = parent_pid_of(current_pid);
    }
    pids
}

fn process_tty_path(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .arg("-o")
        .arg("tty=")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let tty = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tty.is_empty() || tty == "?" {
        return None;
    }
    if tty.starts_with('/') {
        Some(tty)
    } else {
        Some(format!("/dev/{tty}"))
    }
}

fn host_tmux_socket_candidates() -> Vec<PathBuf> {
    let Some(uid) = env::var_os("SUDO_UID").or_else(|| current_uid_string().map(OsString::from))
    else {
        return Vec::new();
    };
    let root = PathBuf::from(format!("/tmp/tmux-{}", uid.to_string_lossy()));
    let mut candidates = vec![root.join("default")];
    if let Ok(entries) = fs::read_dir(&root) {
        candidates.extend(entries.flatten().map(|entry| entry.path()));
    }
    candidates.sort();
    candidates.dedup();
    candidates
        .into_iter()
        .filter(|path| path.exists())
        .collect()
}

fn current_uid_string() -> Option<String> {
    let output = Command::new("id").arg("-u").output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn tmux_pane_for_tty(socket: &Path, tty: &str) -> Option<String> {
    let output = Command::new("tmux")
        .arg("-S")
        .arg(socket)
        .arg("list-panes")
        .arg("-a")
        .arg("-F")
        .arg("#{pane_tty}\t#{pane_id}")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(pane_tty, pane_id)| {
            if pane_tty == tty {
                Some(pane_id.to_string())
            } else {
                None
            }
        })
}

fn open_tclone_attach_in_host_tmux(target: &str, placement: HostTmuxPlacement) -> io::Result<()> {
    ensure_host_tmux_available()?;
    open_tclone_attach_in_host_tmux_after_preflight(target, placement)
}

fn open_tclone_attach_in_host_tmux_after_preflight(
    target: &str,
    placement: HostTmuxPlacement,
) -> io::Result<()> {
    let exe = env::current_exe()?;
    let command = host_tmux_attach_command(target, &exe, env::var_os("SUDO_USER").is_some());
    open_host_tmux_pane(&command, placement)
}

fn ensure_host_tmux_available() -> io::Result<()> {
    if env::var_os("TMUX").is_none()
        && (env::var_os(TCLONE_HOST_TMUX_SOCKET_ENV).is_none()
            || env::var_os(TCLONE_HOST_TMUX_TARGET_ENV).is_none())
        && infer_host_tmux_context().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tmux attach requested but no host tmux context was found; run from inside tmux or preserve TMUX through sudo",
        ));
    }
    if find_command("tmux").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "tmux attach requested but `tmux` was not found on PATH",
        ));
    }
    Ok(())
}

fn open_host_tmux_pane(command: &str, placement: HostTmuxPlacement) -> io::Result<()> {
    let split_flag = match placement {
        HostTmuxPlacement::Right => "-h",
        HostTmuxPlacement::Below => "-v",
    };
    let inferred_context = if env::var_os("TMUX").is_none()
        && (env::var_os(TCLONE_HOST_TMUX_SOCKET_ENV).is_none()
            || env::var_os(TCLONE_HOST_TMUX_TARGET_ENV).is_none())
    {
        infer_host_tmux_context()
    } else {
        None
    };
    let mut tmux = Command::new("tmux");
    if let Some(socket) = env::var_os(TCLONE_HOST_TMUX_SOCKET_ENV).or_else(|| {
        inferred_context
            .as_ref()
            .map(|(socket, _)| OsString::from(socket))
    }) {
        tmux.arg("-S").arg(socket);
    }
    tmux.arg("split-window").arg(split_flag);
    if let Some(target) = env::var_os(TCLONE_HOST_TMUX_TARGET_ENV).or_else(|| {
        inferred_context
            .as_ref()
            .map(|(_, target)| OsString::from(target))
    }) {
        tmux.arg("-t").arg(target);
    }
    if let Ok(cwd) = env::current_dir() {
        tmux.arg("-c").arg(cwd);
    }
    let status = tmux.arg(command).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tmux split-window exited with status {status}"
        )))
    }
}

fn open_tclone_async_job_in_host_tmux(
    job: &TcloneAsyncJob,
    placement: HostTmuxPlacement,
) -> io::Result<()> {
    let log_path = job.log_path.to_string_lossy();
    let done_path = job.done_path.to_string_lossy();
    let command = format!(
        "job_id={job_id}; log={log}; done={done}; \
         printf '[gensee] waiting for tclone fork job %s\\nlog: %s\\n\\n' \"$job_id\" \"$log\"; \
         while [ ! -f \"$log\" ]; do sleep 0.2; done; \
         tail -n +1 -f \"$log\" & tail_pid=$!; \
         while [ ! -f \"$done\" ]; do sleep 0.5; done; \
         sleep 0.2; \
         kill \"$tail_pid\" 2>/dev/null || true; \
         wait \"$tail_pid\" 2>/dev/null || true; \
         status=$(cat \"$done\" 2>/dev/null || printf '?'); \
         printf '\\n[gensee] tclone fork job %s finished with status %s. Press Ctrl-D to close this pane.\\n' \"$job_id\" \"$status\"; \
         exec \"${{SHELL:-/bin/sh}}\"",
        job_id = shell_quote(&job.id),
        log = shell_quote(&log_path),
        done = shell_quote(&done_path),
    );
    open_host_tmux_pane(&command, placement)
}

fn host_tmux_attach_command(target: &str, exe: &Path, use_sudo: bool) -> String {
    let mut parts = Vec::new();
    if use_sudo {
        parts.push("sudo".to_string());
    }
    parts.push("env".to_string());
    for key in TCLONE_HOST_TMUX_ENV_KEYS {
        if let Some(value) = env::var_os(key) {
            parts.push(shell_quote(&format!("{key}={}", value.to_string_lossy())));
        }
    }
    parts.push(shell_quote(&exe.to_string_lossy()));
    parts.push("run".to_string());
    parts.push("attach".to_string());
    parts.push(shell_quote(target));
    format!(
        "{}; status=$?; printf '\\n[gensee] attach exited with status %s. Press Ctrl-D to close this pane.\\n' \"$status\"; exec \"${{SHELL:-/bin/sh}}\"",
        parts.join(" ")
    )
}

const TCLONE_HOST_TMUX_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "GENSEE_HOME",
    "GENSEE_TCLONE_PODMAN",
    "GENSEE_TCLONE_IMAGE",
    "GENSEE_TCLONE_NODE_ROOT",
    "GENSEE_TCLONE_NODE_BIN",
    "GENSEE_TCLONE_READY_TIMEOUT_SECS",
    TCLONE_HOST_TMUX_SOCKET_ENV,
    TCLONE_HOST_TMUX_TARGET_ENV,
    "TERM",
];

fn tclone_attach_container(
    podman: &OsString,
    container_name: &str,
) -> io::Result<std::process::ExitStatus> {
    loop {
        let attach_started_ms = unix_millis().unwrap_or(0);
        let tmux_status = Command::new(podman)
            .arg("exec")
            .arg("-it")
            .arg(container_name)
            .arg("tmux")
            .arg("attach-session")
            .arg("-t")
            .arg(TCLONE_AGENT_TMUX_SESSION)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        match tmux_status {
            Ok(status) if status.success() => {
                if should_reattach_after_tclone_fork_marker(
                    podman,
                    container_name,
                    attach_started_ms,
                ) {
                    eprintln!("gensee: source agent paused for fork; reattaching");
                    continue;
                }
                return Ok(status);
            }
            Ok(_)
                if should_reattach_after_tclone_fork_marker(
                    podman,
                    container_name,
                    attach_started_ms,
                ) =>
            {
                eprintln!("gensee: source agent paused for fork; reattaching");
                continue;
            }
            Err(error)
                if should_reattach_after_tclone_fork_marker(
                    podman,
                    container_name,
                    attach_started_ms,
                ) =>
            {
                eprintln!("gensee: source attach interrupted during fork ({error}); reattaching");
                continue;
            }
            Ok(_) | Err(_) => {
                return Command::new(podman)
                    .arg("attach")
                    .arg(container_name)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status();
            }
        }
    }
}

fn wait_tclone_agent_ready(
    podman: &OsString,
    container_name: &str,
    agent_cmd: &[String],
    require_agent_process: bool,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<String> = None;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for tclone agent session in {container_name}: {}",
                    last_error.unwrap_or_else(|| "agent not ready".to_string())
                ),
            ));
        }
        match tclone_agent_readiness(podman, container_name, agent_cmd, require_agent_process) {
            Ok(TcloneAgentReadiness::Ready) | Ok(TcloneAgentReadiness::NoTmux) => return Ok(()),
            Ok(TcloneAgentReadiness::Starting(message)) => last_error = Some(message),
            Ok(TcloneAgentReadiness::Exited(message)) => return Err(io::Error::other(message)),
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn ensure_tclone_agent_ready_for_fork(
    podman: &OsString,
    source: &TcloneRunRecord,
) -> io::Result<()> {
    match tclone_agent_readiness(podman, &source.container_name, &source.agent_cmd, true)? {
        TcloneAgentReadiness::Ready | TcloneAgentReadiness::NoTmux => Ok(()),
        TcloneAgentReadiness::Starting(message) | TcloneAgentReadiness::Exited(message) => {
            Err(io::Error::other(format!(
                "tclone source {} is not ready to fork: {message}",
                source.run_id
            )))
        }
    }
}

fn wait_for_tclone_source_quiet_if_requested(
    podman: &OsString,
    source: &TcloneRunRecord,
) -> io::Result<()> {
    if !env_flag("GENSEE_TCLONE_WAIT_QUIET_FOR_FORK") {
        return Ok(());
    }
    let timeout = env::var("GENSEE_TCLONE_FORK_QUIET_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(TCLONE_FORK_QUIET_TIMEOUT_SECS);
    if timeout == 0 {
        return Ok(());
    }
    let cpu_threshold = env::var("GENSEE_TCLONE_FORK_QUIET_CPU_PERCENT")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(TCLONE_FORK_QUIET_CPU_PERCENT);
    let stable_samples = env::var("GENSEE_TCLONE_FORK_QUIET_STABLE_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(TCLONE_FORK_QUIET_STABLE_SAMPLES);
    let root_pid = inspect_container_pid(podman, &source.container_name)?;
    let ticks_per_second = clock_ticks_per_second()?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let interval = Duration::from_secs(1);
    let mut stable = 0usize;
    let mut last_ticks = descendant_proc_ticks(root_pid)?;
    let mut last_not_quiet_reason = String::new();
    eprintln!(
        "gensee: waiting for tclone source {} to become quiet before fork (timeout={}s cpu<{}% stable_samples={})",
        source.run_id, timeout, cpu_threshold, stable_samples
    );
    loop {
        thread::sleep(interval);
        let current_ticks = descendant_proc_ticks(root_pid)?;
        let (delta_ticks, descendant_exited) =
            descendant_proc_tick_delta(&last_ticks, &current_ticks);
        last_ticks = current_ticks;
        let cpu_percent =
            (delta_ticks as f64 / ticks_per_second as f64) / interval.as_secs_f64() * 100.0;
        if descendant_exited {
            stable = 0;
            last_not_quiet_reason = "a source process exited during the sample".to_string();
            eprintln!(
                "gensee: tclone source {} still settling after a process exit",
                source.run_id
            );
            if Instant::now() >= deadline {
                return tclone_quiet_timeout(&source.run_id, &last_not_quiet_reason);
            }
            continue;
        }
        if cpu_percent <= cpu_threshold {
            if let Some(reason) = tclone_source_quiet_probe(podman, source)? {
                // The probe itself executes in the container's process tree. Sample
                // again after it completes so probe CPU is not charged to the next
                // quiet interval.
                last_ticks = descendant_proc_ticks(root_pid)?;
                stable = 0;
                last_not_quiet_reason = reason;
                eprintln!(
                    "gensee: tclone source {} still active cpu={:.1}% reason={}",
                    source.run_id, cpu_percent, last_not_quiet_reason
                );
                if Instant::now() >= deadline {
                    return tclone_quiet_timeout(&source.run_id, &last_not_quiet_reason);
                }
                continue;
            }
            last_ticks = descendant_proc_ticks(root_pid)?;
            stable += 1;
            eprintln!(
                "gensee: tclone source {} quiet sample {}/{} cpu={:.1}%",
                source.run_id, stable, stable_samples, cpu_percent
            );
            if stable >= stable_samples {
                return Ok(());
            }
        } else {
            stable = 0;
            last_not_quiet_reason = format!("cpu={cpu_percent:.1}%");
            eprintln!(
                "gensee: tclone source {} still active cpu={:.1}%",
                source.run_id, cpu_percent
            );
        }
        if Instant::now() >= deadline {
            return tclone_quiet_timeout(&source.run_id, &last_not_quiet_reason);
        }
    }
}

fn tclone_quiet_timeout(run_id: &str, reason: &str) -> io::Result<()> {
    let detail = if reason.is_empty() {
        String::new()
    } else {
        format!(": {reason}")
    };
    let message =
        format!("timed out waiting for tclone source {run_id} to become quiet before fork{detail}");
    if env_flag("GENSEE_TCLONE_FORK_QUIET_STRICT") {
        Err(io::Error::new(io::ErrorKind::TimedOut, message))
    } else {
        eprintln!("gensee: warning: {message}; proceeding with the live fork");
        Ok(())
    }
}

fn tclone_source_quiet_probe(
    podman: &OsString,
    source: &TcloneRunRecord,
) -> io::Result<Option<String>> {
    let mut reasons = Vec::new();
    if env::var("GENSEE_TCLONE_FORK_QUIET_MOUNTS").as_deref() != Ok("0") {
        let mounts = tclone_exec_capture_env(
            podman,
            &source.container_name,
            &[],
            &["sh", "-lc", "mount | awk '{print $3}'"],
        )?;
        let transient_mounts = mounts
            .lines()
            .map(str::trim)
            .filter(|path| tclone_is_transient_fork_mount(path))
            .take(6)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !transient_mounts.is_empty() {
            reasons.push(format!("transient mounts {}", transient_mounts.join(", ")));
        }
    }

    if env::var("GENSEE_TCLONE_FORK_QUIET_PROCESSES").as_deref() != Ok("0") {
        let processes = tclone_exec_capture_env(
            podman,
            &source.container_name,
            &[],
            &["sh", "-lc", "ps -eo pid=,ppid=,stat=,args="],
        )?;
        let active_processes = processes
            .lines()
            .filter_map(parse_tclone_quiet_process_line)
            .filter(tclone_is_transient_fork_process)
            .take(4)
            .map(|process| format!("{} {}", process.pid, process.command))
            .collect::<Vec<_>>();
        if !active_processes.is_empty() {
            reasons.push(format!(
                "transient processes {}",
                active_processes.join("; ")
            ));
        }
    }

    if reasons.is_empty() {
        Ok(None)
    } else {
        Ok(Some(reasons.join("; ")))
    }
}

fn tclone_is_transient_fork_mount(path: &str) -> bool {
    TCLONE_FORK_TRANSIENT_MOUNT_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
        || TCLONE_FORK_TRANSIENT_DEVICE_MOUNTS.contains(&path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcloneQuietProcess {
    pid: u32,
    stat: String,
    command: String,
}

fn parse_tclone_quiet_process_line(line: &str) -> Option<TcloneQuietProcess> {
    let mut parts = line.split_whitespace();
    let pid = parts.next()?.parse::<u32>().ok()?;
    let _ppid = parts.next()?.parse::<u32>().ok()?;
    let stat = parts.next()?.to_string();
    let command = parts.collect::<Vec<_>>().join(" ");
    if command.is_empty() {
        return None;
    }
    Some(TcloneQuietProcess { pid, stat, command })
}

fn tclone_is_transient_fork_process(process: &TcloneQuietProcess) -> bool {
    if process.stat.contains('Z') {
        return false;
    }
    let command = process.command.as_str();
    if tclone_is_baseline_fork_process(command) {
        return false;
    }
    tclone_is_known_active_fork_process(command)
}

fn tclone_is_baseline_fork_process(command: &str) -> bool {
    command == "/bin/sleep infinity"
        || command.contains(TCLONE_CONTAINER_INIT_PATH)
        || command == "sleep 30"
        || command.contains("tmux new-session -d -s gensee-agent")
        || command.contains("tmux attach-session -t gensee-agent")
        || command.contains("ps -eo pid=,ppid=,stat=,args=")
        || command.contains("gensee hook codex")
        || command.contains("gensee run fork-status")
        || command.contains("gensee run list")
        || tclone_is_codex_agent_process(command)
}

fn tclone_is_codex_agent_process(command: &str) -> bool {
    !command.contains("codex-linux-sandbox")
        && (command == "codex"
            || command.ends_with("/bin/codex")
            || command.contains(" /bin/codex")
            || command.contains("@openai/codex")
            || command.contains("/node_modules/@openai/codex/"))
}

fn tclone_is_known_active_fork_process(command: &str) -> bool {
    const MARKERS: &[&str] = &[
        "codex-linux-sandbox",
        "bwrap ",
        "gensee hook",
        "gensee run",
        "cargo ",
        "git ",
        "npm ",
        "pnpm ",
        "yarn ",
        "python ",
        "python3 ",
        "node ",
        "bash -lc",
        "sh -lc",
        "curl ",
        "rg ",
        "grep ",
        "find ",
    ];
    MARKERS.iter().any(|marker| command.contains(marker))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcStat {
    pid: u32,
    ppid: u32,
    ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DescendantProcTicks {
    ticks_by_pid: HashMap<u32, u64>,
}

fn descendant_proc_ticks(root_pid: u32) -> io::Result<DescendantProcTicks> {
    let stats = read_proc_stats()?;
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut ticks_by_pid: HashMap<u32, u64> = HashMap::new();
    for stat in stats {
        children.entry(stat.ppid).or_default().push(stat.pid);
        ticks_by_pid.insert(stat.pid, stat.ticks);
    }
    let mut descendants = HashMap::new();
    let mut stack = vec![root_pid];
    while let Some(pid) = stack.pop() {
        if let Some(ticks) = ticks_by_pid.get(&pid) {
            descendants.insert(pid, *ticks);
        }
        if let Some(child_pids) = children.get(&pid) {
            stack.extend(child_pids.iter().copied());
        }
    }
    Ok(DescendantProcTicks {
        ticks_by_pid: descendants,
    })
}

fn descendant_proc_tick_delta(
    previous: &DescendantProcTicks,
    current: &DescendantProcTicks,
) -> (u64, bool) {
    let mut delta = 0u64;
    for (pid, current_ticks) in &current.ticks_by_pid {
        if let Some(previous_ticks) = previous.ticks_by_pid.get(pid) {
            delta = delta.saturating_add(current_ticks.saturating_sub(*previous_ticks));
        }
    }
    let descendant_exited = previous
        .ticks_by_pid
        .keys()
        .any(|pid| !current.ticks_by_pid.contains_key(pid));
    (delta, descendant_exited)
}

fn read_proc_stats() -> io::Result<Vec<ProcStat>> {
    let mut stats = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let stat_path = entry.path().join("stat");
        let Ok(contents) = fs::read_to_string(stat_path) else {
            continue;
        };
        if let Some(stat) = parse_proc_stat(pid, &contents) {
            stats.push(stat);
        }
    }
    Ok(stats)
}

fn parse_proc_stat(pid: u32, contents: &str) -> Option<ProcStat> {
    let close = contents.rfind(')')?;
    let rest = contents.get(close + 2..)?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    let ppid = fields.get(1)?.parse::<u32>().ok()?;
    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    Some(ProcStat {
        pid,
        ppid,
        ticks: utime.saturating_add(stime),
    })
}

fn clock_ticks_per_second() -> io::Result<u64> {
    Ok(env::var("GENSEE_TCLONE_HOST_CLK_TCK")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcloneAgentReadiness {
    Ready,
    NoTmux,
    Starting(String),
    Exited(String),
}

fn tclone_agent_readiness(
    podman: &OsString,
    container_name: &str,
    agent_cmd: &[String],
    require_agent_process: bool,
) -> io::Result<TcloneAgentReadiness> {
    let process_check = if require_agent_process {
        tclone_agent_process_check(agent_cmd).unwrap_or("true")
    } else {
        "true"
    };
    let script = format!(
        r#"if ! command -v tmux >/dev/null 2>&1; then
  echo no-tmux
  exit 0
fi
if ! tmux has-session -t {session} 2>/dev/null; then
  echo starting
  test -f /tmp/gensee-agent-start.log && tail -n 20 /tmp/gensee-agent-start.log
  exit 0
fi
if tmux list-panes -t {session} -F '#{{pane_dead}}' 2>/dev/null | grep -q '^1$'; then
  echo exited
  tmux capture-pane -pt {session} 2>/dev/null | tail -n 40 || true
  exit 0
fi
if ! ({process_check}); then
  echo starting
  echo agent process is not running yet
  exit 0
fi
echo ready
"#,
        session = shell_quote(TCLONE_AGENT_TMUX_SESSION),
        process_check = process_check
    );
    let output = Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} exec readiness check failed for {}: {}",
            podman.to_string_lossy(),
            container_name,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let state = lines.next().unwrap_or("").trim();
    let detail = lines.collect::<Vec<_>>().join("\n");
    match state {
        "ready" => Ok(TcloneAgentReadiness::Ready),
        "no-tmux" => Ok(TcloneAgentReadiness::NoTmux),
        "starting" => Ok(TcloneAgentReadiness::Starting(detail)),
        "exited" => Ok(TcloneAgentReadiness::Exited(detail)),
        _ => Ok(TcloneAgentReadiness::Starting(stdout.trim().to_string())),
    }
}

fn tclone_agent_process_check(agent_cmd: &[String]) -> Option<&'static str> {
    let binary = agent_cmd.first()?.to_ascii_lowercase();
    if binary.contains("codex") {
        Some("ps ax -o args= | grep -E '(^|/)(codex)( |$)|@openai/codex' | grep -v grep >/dev/null")
    } else if binary.contains("claude") {
        Some("ps ax -o args= | grep -E '(^|/)(claude)( |$)|claude-code' | grep -v grep >/dev/null")
    } else {
        None
    }
}

struct TcloneForkDetachGuard {
    marker_path: PathBuf,
}

struct TcloneCapabilityRotationGuard {
    podman: OsString,
    source: TcloneRunRecord,
    restored: bool,
}

impl TcloneCapabilityRotationGuard {
    fn revoke(podman: &OsString, source: TcloneRunRecord) -> io::Result<Self> {
        revoke_tclone_host_control_capability(&source.run_id)?;
        Ok(Self {
            podman: podman.clone(),
            source,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        rotate_tclone_host_control_capability(&self.source.run_id)?;
        write_tclone_run_context(&self.podman, &self.source)?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for TcloneCapabilityRotationGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = rotate_tclone_host_control_capability(&self.source.run_id);
            let _ = write_tclone_run_context(&self.podman, &self.source);
        }
    }
}

impl TcloneForkDetachGuard {
    fn mark(run_id: &str) -> io::Result<Self> {
        let timestamp = unix_millis()?;
        let marker_path = tclone_host_fork_marker_path(run_id)?;
        if let Some(parent) = marker_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&marker_path, format!("{timestamp}\n"))?;
        Ok(Self { marker_path })
    }
}

impl Drop for TcloneForkDetachGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.marker_path);
    }
}

fn should_reattach_after_tclone_fork_marker(
    podman: &OsString,
    container_name: &str,
    _attach_started_ms: u64,
) -> bool {
    let Ok(record) = find_tclone_record(container_name) else {
        return false;
    };
    let Ok(marker_path) = tclone_host_fork_marker_path(&record.run_id) else {
        return false;
    };
    let Some(marker_ms) = fs::read_to_string(&marker_path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
    else {
        return false;
    };
    if tclone_fork_marker_is_stale(marker_ms) {
        let _ = fs::remove_file(&marker_path);
        return false;
    }

    wait_for_tclone_fork_marker_to_clear(&marker_path, marker_ms);
    wait_tclone_container_exec_ready(
        podman,
        container_name,
        Duration::from_secs(TCLONE_ATTACH_RETRY_TIMEOUT_SECS),
    );
    true
}

fn wait_for_tclone_fork_marker_to_clear(marker_path: &Path, marker_ms: u64) {
    while marker_path.exists() && !tclone_fork_marker_is_stale(marker_ms) {
        thread::sleep(Duration::from_millis(250));
    }
    if tclone_fork_marker_is_stale(marker_ms) {
        let _ = fs::remove_file(marker_path);
    }
}

fn tclone_fork_marker_is_stale(marker_ms: u64) -> bool {
    let now_ms = unix_millis().unwrap_or(marker_ms);
    marker_ms.saturating_add(TCLONE_FORK_MARKER_WAIT_TIMEOUT_SECS * 1_000) < now_ms
}

fn tclone_host_fork_marker_path(run_id: &str) -> io::Result<PathBuf> {
    Ok(gensee_tmp_root()?
        .join(run_id)
        .join("host-control")
        .join(TCLONE_HOST_FORK_IN_PROGRESS_FILE))
}

fn wait_tclone_container_exec_ready(podman: &OsString, container_name: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tclone_exec_ready(podman, container_name) {
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn tclone_exec_ready(podman: &OsString, container_name: &str) -> bool {
    Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn detach_tclone_tmux_clients(podman: &OsString, container_name: &str) {
    let script = tclone_tmux_detach_script();
    let _ = Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    thread::sleep(Duration::from_millis(500));
}

fn tclone_tmux_detach_script() -> String {
    format!(
        r#"if command -v tmux >/dev/null 2>&1 && tmux has-session -t {session} 2>/dev/null; then
  tmux display-message -t {session} 'Gensee is forking this run; reconnecting shortly.' 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    clients="$(tmux list-clients -t {session} -F '#{{client_pid}}' 2>/dev/null || true)"
    [ -z "$clients" ] && exit 0
    tmux detach-client -a -s {session} 2>/dev/null || true
    printf '%s\n' "$clients" |
      while IFS= read -r client_pid; do
        case "$client_pid" in
          ''|*[!0-9]*) ;;
          *) kill -HUP "$client_pid" 2>/dev/null || true ;;
        esac
      done
    sleep 0.1
  done
fi
"#,
        session = shell_quote(TCLONE_AGENT_TMUX_SESSION),
    )
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
    let source_files_id = format!("gensee-source-files-{}.txt", unix_millis()?);
    let host_source_files = gensee_tmp_root()?.join(&source_files_id);
    let fork_source_files = format!("/tmp/{source_files_id}");
    fs::write(
        &host_source_files,
        tclone_source_workspace_file_list(podman, source)?,
    )?;
    let patch = (|| {
        podman_cp(
            podman,
            &host_source_files,
            &format!("{}:{fork_source_files}", fork.container_name),
        )?;
        tclone_merge_patch(podman, fork, &fork_source_files)
    })();
    let _ = fs::remove_file(&host_source_files);
    let _ = tclone_exec(
        podman,
        &fork.container_name,
        &["rm", "-f", &fork_source_files],
    );
    let patch = patch?;
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

fn tclone_source_workspace_file_list(
    podman: &OsString,
    source: &TcloneRunRecord,
) -> io::Result<String> {
    let script = r#"set -euo pipefail
cd "$GENSEE_WORKSPACE"
find . -path './.git' -prune -o -type f -printf '%P\n' | sort
"#;
    tclone_exec_capture_env(
        podman,
        &source.container_name,
        &[("GENSEE_WORKSPACE", &source.container_workspace)],
        &["bash", "-lc", script],
    )
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

    let fork_overlay = inspect_tclone_overlay_rootfs(podman, &fork.container_name)
        .or_else(|_| recorded_tclone_overlay_rootfs(fork))?;
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

    apply_tclone_overlay_merge(podman, source, &plan)?;
    append_tclone_status(&fork.run_id, "merged", None)?;
    println!(
        "gensee: merged overlay filesystem changes from {} into {}",
        fork.run_id, source.run_id
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcloneOverlayRootfs {
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
    podman: &OsString,
    source: &TcloneRunRecord,
    plan: &TcloneOverlayMergePlan,
) -> io::Result<()> {
    for change in plan.deletions() {
        let destination = format!("/{}", change.path);
        tclone_exec(
            podman,
            &source.container_name,
            &["rm", "-rf", "--", &destination],
        )?;
    }
    for change in plan.upserts() {
        let destination = format!("/{}", change.path);
        match change.op {
            TcloneOverlayMergeOp::CreateDir => {
                tclone_exec(
                    podman,
                    &source.container_name,
                    &["mkdir", "-p", "--", &destination],
                )?;
            }
            TcloneOverlayMergeOp::UpsertFile => {
                let overlay_source = change.source.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("missing overlay source for {}", change.path),
                    )
                })?;
                if let Some(parent) = Path::new(&destination).parent().and_then(Path::to_str) {
                    tclone_exec(
                        podman,
                        &source.container_name,
                        &["mkdir", "-p", "--", parent],
                    )?;
                }
                tclone_exec(
                    podman,
                    &source.container_name,
                    &["rm", "-rf", "--", &destination],
                )?;
                podman_cp(
                    podman,
                    overlay_source,
                    &format!("{}:{destination}", source.container_name),
                )?;
            }
            TcloneOverlayMergeOp::Delete => {}
        }
    }
    Ok(())
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

fn tclone_merge_patch(
    podman: &OsString,
    fork: &TcloneRunRecord,
    source_files_path: &str,
) -> io::Result<String> {
    let script = r#"set -euo pipefail
cd "$GENSEE_WORKSPACE"
if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "gensee: merge --git requires a git workspace at $GENSEE_WORKSPACE" >&2
  exit 64
fi
base="${GENSEE_GIT_MERGE_BASE:-HEAD}"
if git rev-parse --verify "$base^{commit}" >/dev/null 2>&1; then
  git diff --binary "$base" -- . \
    ':(exclude)gensee.db' \
    ':(exclude)gensee.db-wal' \
    ':(exclude)gensee.db-shm' \
    ':(exclude)gensee.key' \
    ':(exclude)telemetry.json'
else
  echo "gensee: warning: fork git merge base '$base' is unavailable; falling back to git diff HEAD" >&2
  git diff --binary HEAD -- . \
    ':(exclude)gensee.db' \
    ':(exclude)gensee.db-wal' \
    ':(exclude)gensee.db-shm' \
    ':(exclude)gensee.key' \
    ':(exclude)telemetry.json'
fi
while IFS= read -r -d '' file; do
  case "$file" in
    gensee.db|gensee.db-wal|gensee.db-shm|gensee.key|telemetry.json) continue ;;
  esac
  if grep -Fxq -- "$file" "$GENSEE_SOURCE_FILES"; then
    continue
  fi
  git diff --binary --no-index -- /dev/null "$file" || true
done < <(git ls-files --others --exclude-standard -z)
"#;
    let mut envs = vec![
        ("GENSEE_WORKSPACE", fork.container_workspace.as_str()),
        ("GENSEE_SOURCE_FILES", source_files_path),
    ];
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
    Ok(TcloneOverlayRootfs { lowerdir, upperdir })
}

fn recorded_tclone_overlay_rootfs(record: &TcloneRunRecord) -> io::Result<TcloneOverlayRootfs> {
    let lowerdir = record
        .fork_base_overlay_lowerdir
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "tclone fork {} does not have recorded overlay lowerdir metadata; recreate the fork with Gensee's tclone overlay mode",
                    record.run_id
                ),
            )
        })?;
    if !lowerdir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "recorded tclone overlay lowerdir for {} no longer exists: {}; recreate the fork before filesystem merge",
                record.run_id,
                lowerdir.display()
            ),
        ));
    }
    let upperdir = record
        .fork_overlay_upperdir
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "tclone fork {} does not have recorded overlay upperdir metadata; recreate the fork with Gensee's tclone overlay mode",
                    record.run_id
                ),
            )
        })?;
    if !upperdir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "recorded tclone overlay upperdir for {} no longer exists: {}; recreate the fork before filesystem merge",
                record.run_id,
                upperdir.display()
            ),
        ));
    }
    Ok(TcloneOverlayRootfs { lowerdir, upperdir })
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
    let target = normalize_tclone_target(target);
    list_tclone_runs()?
        .into_iter()
        .rev()
        .find(|record| {
            record.run_id == target
                || record.container_name == target
                || record.container_id.as_deref() == Some(target.as_str())
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
        return Ok(normalize_tclone_target(value));
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, usage))
}

fn normalize_tclone_target(value: &str) -> String {
    value
        .trim_matches(|ch| {
            matches!(
                ch,
                '"' | '\'' | '`' | '\u{2018}' | '\u{2019}' | '\u{201c}' | '\u{201d}'
            )
        })
        .to_string()
}

fn tclone_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "--copies" | "--name" | "--attach" | "--tmux" | "--shell" | "--to" | "--into" | "--paths"
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
    } else if lower.contains("antigravity") || lower.contains("gemini") {
        let host = env::var_os("GEMINI_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".gemini"));
        Some((
            "GEMINI_HOME".to_string(),
            host,
            format!("{DEFAULT_CONTAINER_HOME}/.gemini"),
        ))
    } else {
        None
    }
}

fn tclone_agent_start_script(agent_cmd: &[OsString]) -> String {
    let command = shell_join(agent_cmd);
    format!(
        "set -e\nexport TERM=\"${{TERM:-xterm-256color}}\"\nlog=/tmp/gensee-agent-start.log\nif command -v tmux >/dev/null 2>&1; then\n  printf 'starting tmux session %s: %s\\n' {} {} > \"$log\"\n  tmux new-session -d -s {} >> \"$log\" 2>&1\n  tmux set-option -t {} remain-on-exit on >> \"$log\" 2>&1\n  tmux send-keys -t {} -- {} C-m >> \"$log\" 2>&1\n  sleep 2\n  if ! tmux has-session -t {} 2>> \"$log\"; then\n    printf 'gensee agent tmux session disappeared during startup\\n' >> \"$log\"\n    cat \"$log\" >&2\n    exit 127\n  fi\n  if tmux list-panes -t {} -F '#{{pane_dead}}' 2>> \"$log\" | grep -q '^1$'; then\n    printf 'gensee agent exited during startup; pane follows\\n' >> \"$log\"\n    tmux capture-pane -pt {} >> \"$log\" 2>&1 || true\n    cat \"$log\" >&2\n    exit 127\n  fi\n  exit 0\nfi\nprintf 'tmux not found; starting agent directly in background: %s\\n' {} > \"$log\"\nsh -lc {} >> \"$log\" 2>&1 &\nagent_pid=$!\nsleep 2\nif ! kill -0 \"$agent_pid\" 2>/dev/null; then\n  printf 'gensee agent exited during startup\\n' >> \"$log\"\n  cat \"$log\" >&2\n  exit 127\nfi\nprintf 'gensee agent started without tmux pid=%s\\n' \"$agent_pid\" >> \"$log\"\n",
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(&command),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(&format!("exec {command}")),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(TCLONE_AGENT_TMUX_SESSION),
        shell_quote(&command),
        shell_quote(&format!("exec {command}"))
    )
}

fn start_tclone_agent_session(
    podman: &OsString,
    container_name: &str,
    agent_cmd: &[OsString],
) -> io::Result<()> {
    let script = tclone_agent_start_script(agent_cmd);
    let status = Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "tclone agent startup exited with status {status}"
        )))
    }
}

fn shell_join(args: &[OsString]) -> String {
    args.iter()
        .map(|arg| shell_quote(&arg.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn tclone_container_path(toolchain_paths: &[String]) -> String {
    let mut entries = vec!["/usr/local/sbin".to_string(), "/usr/local/bin".to_string()];
    entries.extend(toolchain_paths.iter().cloned());
    entries.extend(
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .into_iter()
            .map(str::to_string),
    );
    entries.join(":")
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
    install_tclone_init(seed_root)?;

    let workspace_seed = seed_root.join(container_relative_path(container_workspace)?);
    copy_tclone_workspace(original_workspace, &workspace_seed)?;

    if let Some((name, host_home, container_path)) = agent_home.filter(|(_, path, _)| path.exists())
    {
        copy_path_all(
            host_home,
            &seed_root.join(container_relative_path(container_path)?),
        )?;
        install_tclone_host_path_compatibility(seed_root, host_home, container_path)?;
        if name == "CODEX_HOME" {
            rewrite_tclone_codex_hooks(seed_root, container_path, container_home)?;
        }
    }
    if let Some(gensee_home) = gensee_home.filter(|path| path.exists()) {
        copy_path_all(
            gensee_home,
            &seed_root.join(container_relative_path(&format!(
                "{container_home}/.gensee"
            ))?),
        )?;
        install_tclone_gensee_home_compatibility(seed_root, gensee_home, container_home)?;
    }
    Ok(())
}

fn install_tclone_init(seed_root: &Path) -> io::Result<()> {
    let init_path = seed_root.join(container_relative_path(TCLONE_CONTAINER_INIT_PATH)?);
    if let Some(parent) = init_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &init_path,
        r#"#!/bin/sh
set -eu

term=0
sleep_pid=

shutdown() {
  term=1
  trap - TERM INT
  kill -TERM -1 2>/dev/null || true
  if [ -n "${sleep_pid:-}" ]; then
    kill -TERM "$sleep_pid" 2>/dev/null || true
  fi
}

trap shutdown TERM INT

while [ "$term" = 0 ]; do
  sleep 30 &
  sleep_pid=$!
  wait "$sleep_pid" 2>/dev/null || true
  sleep_pid=
done

wait 2>/dev/null || true
"#,
    )?;
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&init_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&init_path, permissions)?;
    }
    Ok(())
}

fn rewrite_tclone_codex_hooks(
    seed_root: &Path,
    container_codex_home: &str,
    container_home: &str,
) -> io::Result<()> {
    let hooks_path = seed_root.join(container_relative_path(&format!(
        "{container_codex_home}/hooks.json"
    ))?);
    let mut root = if hooks_path.exists() {
        let contents = fs::read_to_string(&hooks_path)?;
        if contents.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&contents).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not valid JSON: {err}", hooks_path.display()),
                )
            })?
        }
    } else {
        json!({})
    };

    let gensee_home = PathBuf::from(format!("{container_home}/.gensee"));
    let command = codex_hook_command(&gensee_home, Path::new("/usr/local/bin/gensee"));
    apply_codex_hook_settings(&mut root, &command)?;

    if let Some(parent) = hooks_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(&root)?;
    fs::write(hooks_path, format!("{serialized}\n"))
}

fn install_tclone_host_path_compatibility(
    seed_root: &Path,
    host_home: &Path,
    container_path: &str,
) -> io::Result<()> {
    let Some(host_home_parent) = host_home.parent() else {
        return Ok(());
    };
    let host_home_link = seed_root.join(container_relative_path(&host_home.to_string_lossy())?);
    if !host_home_link.exists() {
        if let Some(parent) = host_home_link.parent() {
            fs::create_dir_all(parent)?;
        }
        symlink_or_copy_marker(container_path, &host_home_link)?;
    }

    let host_cargo_bin = host_home_parent.join(".cargo/bin");
    let host_gensee = host_cargo_bin.join("gensee");
    let seed_gensee = seed_root.join(container_relative_path(&host_gensee.to_string_lossy())?);
    if !seed_gensee.exists() {
        fs::create_dir_all(seed_gensee.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid tclone compatibility path: {}",
                    seed_gensee.display()
                ),
            )
        })?)?;
        symlink_or_copy_marker("/usr/local/bin/gensee", &seed_gensee)?;
    }
    Ok(())
}

fn install_tclone_gensee_home_compatibility(
    seed_root: &Path,
    host_gensee_home: &Path,
    container_home: &str,
) -> io::Result<()> {
    let host_link = seed_root.join(container_relative_path(
        &host_gensee_home.to_string_lossy(),
    )?);
    if host_link.exists() {
        return Ok(());
    }
    if let Some(parent) = host_link.parent() {
        fs::create_dir_all(parent)?;
    }
    symlink_or_copy_marker(&format!("{container_home}/.gensee"), &host_link)
}

#[cfg(unix)]
fn symlink_or_copy_marker(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink_or_copy_marker(_target: &str, link: &Path) -> io::Result<()> {
    fs::write(
        link,
        "This tclone compatibility path requires Unix symlink support.\n",
    )
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
    matches!(
        name,
        "target"
            | "node_modules"
            | ".gensee"
            | ".gensee-dev"
            | "gensee.db"
            | "gensee.db-wal"
            | "gensee.db-shm"
            | "gensee.key"
            | "telemetry.json"
    ) || name.ends_with(".tmp")
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

fn tclone_rust_mount() -> Option<(PathBuf, Option<PathBuf>)> {
    let cargo_bin = env::var_os("GENSEE_TCLONE_CARGO_BIN")
        .map(PathBuf::from)
        .or_else(|| find_command("cargo").and_then(|path| path.parent().map(Path::to_path_buf)))?;
    if !cargo_bin.exists() {
        return None;
    }
    let rustup_home = env::var_os("GENSEE_TCLONE_RUSTUP_HOME")
        .or_else(|| env::var_os("RUSTUP_HOME"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .filter(|path| path.exists());
    Some((cargo_bin, rustup_home))
}

fn tclone_podman() -> OsString {
    env::var_os("GENSEE_TCLONE_PODMAN")
        .or_else(|| env::var_os("PODMAN_TFORK"))
        .unwrap_or_else(|| OsString::from("podman"))
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn env_flag_default_on(name: &str) -> bool {
    env::var(name)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "no" | "off"))
        .unwrap_or(true)
}

fn tclone_agent_ready_timeout(no_attach: bool) -> Duration {
    env::var("GENSEE_TCLONE_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| {
            if no_attach {
                Duration::from_secs(120)
            } else {
                Duration::from_secs(20)
            }
        })
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
    envs: &[(String, String)],
) -> io::Result<String> {
    let output = Command::new(program)
        .args(args)
        .envs(envs.iter().map(|(key, value)| (key, value)))
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

    fn tclone_test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

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

    fn signed_host_control_request(
        caller_run_id: &str,
        capability: &str,
        nonce: &str,
        args: Vec<String>,
    ) -> TcloneHostControlRequest {
        let issued_at_ms = unix_millis().unwrap();
        let authenticator = tclone_host_control_authenticator(
            caller_run_id,
            nonce,
            issued_at_ms,
            &args,
            capability,
        )
        .unwrap();
        TcloneHostControlRequest {
            caller_run_id: Some(caller_run_id.to_string()),
            nonce: Some(nonce.to_string()),
            issued_at_ms: Some(issued_at_ms),
            authenticator: Some(authenticator),
            args,
        }
    }

    #[test]
    fn tclone_host_control_socket_falls_back_to_gensee_home() {
        let _guard = tclone_test_env_lock();
        let root = temp_tree("host-control-fallback");
        let socket = root.join("host-control/control.sock");
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        fs::write(&socket, "").unwrap();

        let old_socket = env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV);
        let old_home = env::var_os("GENSEE_HOME");
        env::remove_var(TCLONE_HOST_CONTROL_SOCKET_ENV);
        env::set_var("GENSEE_HOME", &root);

        assert_eq!(
            tclone_host_control_socket_path().as_deref(),
            Some(socket.as_path())
        );

        match old_socket {
            Some(value) => env::set_var(TCLONE_HOST_CONTROL_SOCKET_ENV, value),
            None => env::remove_var(TCLONE_HOST_CONTROL_SOCKET_ENV),
        }
        match old_home {
            Some(value) => env::set_var("GENSEE_HOME", value),
            None => env::remove_var("GENSEE_HOME"),
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_host_control_disable_env_skips_proxy() {
        let _guard = tclone_test_env_lock();
        let old_disabled = env::var_os(TCLONE_HOST_CONTROL_DISABLE_ENV);
        env::set_var(TCLONE_HOST_CONTROL_DISABLE_ENV, "1");

        let args = vec![
            OsString::from("run"),
            OsString::from("fork"),
            OsString::from("run_1"),
        ];
        assert!(!proxy_tclone_host_control_if_needed(&args).unwrap());

        match old_disabled {
            Some(value) => env::set_var(TCLONE_HOST_CONTROL_DISABLE_ENV, value),
            None => env::remove_var(TCLONE_HOST_CONTROL_DISABLE_ENV),
        }
    }

    #[test]
    fn tclone_host_control_without_bridge_runs_locally() {
        let _guard = tclone_test_env_lock();
        let old_socket = env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV);
        let old_dir = env::var_os(TCLONE_HOST_CONTROL_DIR_ENV);
        let old_workspace = env::var_os("GENSEE_WORKSPACE");
        env::remove_var(TCLONE_HOST_CONTROL_SOCKET_ENV);
        env::remove_var(TCLONE_HOST_CONTROL_DIR_ENV);
        env::set_var("GENSEE_WORKSPACE", "/definitely-not-a-gensee-workspace");

        let args = vec![OsString::from("run"), OsString::from("list")];
        assert!(!proxy_tclone_host_control_if_needed(&args).unwrap());

        match old_socket {
            Some(value) => env::set_var(TCLONE_HOST_CONTROL_SOCKET_ENV, value),
            None => env::remove_var(TCLONE_HOST_CONTROL_SOCKET_ENV),
        }
        match old_dir {
            Some(value) => env::set_var(TCLONE_HOST_CONTROL_DIR_ENV, value),
            None => env::remove_var(TCLONE_HOST_CONTROL_DIR_ENV),
        }
        match old_workspace {
            Some(value) => env::set_var("GENSEE_WORKSPACE", value),
            None => env::remove_var("GENSEE_WORKSPACE"),
        }
    }

    #[test]
    fn tclone_host_control_dispatch_rejects_non_allowlisted_commands() {
        let request = TcloneHostControlRequest {
            caller_run_id: None,
            nonce: None,
            issued_at_ms: None,
            authenticator: None,
            args: vec![
                "run".to_string(),
                "--sandbox".to_string(),
                "none".to_string(),
                "--".to_string(),
                "/bin/sh".to_string(),
            ],
        };

        let response =
            execute_tclone_host_control_request(request, Path::new("/definitely/not/executed"))
                .unwrap();

        assert_eq!(response.exit_code, Some(64));
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unsupported")));
    }

    #[test]
    fn tclone_host_control_target_authority_is_command_scoped() {
        let source = test_record("run_source", "running");
        let child = test_fork_record("run_source_fork_1_0", "run_source");
        let grandchild = test_fork_record("run_source_fork_2_0", "run_source_fork_1_0");

        assert!(tclone_host_control_target_is_authorized(
            "run_source",
            &source,
            TcloneHostControlTargetScope::CallerOnly,
        ));
        assert!(!tclone_host_control_target_is_authorized(
            "run_source",
            &child,
            TcloneHostControlTargetScope::CallerOnly,
        ));
        assert!(tclone_host_control_target_is_authorized(
            "run_source",
            &child,
            TcloneHostControlTargetScope::CallerOrDirectChild,
        ));
        assert!(!tclone_host_control_target_is_authorized(
            "run_source",
            &grandchild,
            TcloneHostControlTargetScope::CallerOrDirectChild,
        ));
        assert!(!tclone_host_control_target_is_authorized(
            "run_source_fork_1_0",
            &source,
            TcloneHostControlTargetScope::CallerOrDirectChild,
        ));
    }

    #[test]
    fn tclone_host_control_authenticator_binds_args_nonce_and_time() {
        let args = vec!["run".to_string(), "diff".to_string(), "run_1".to_string()];
        let first = tclone_host_control_authenticator("run_1", "nonce-1", 1_000, &args, "secret-1")
            .unwrap();
        let second =
            tclone_host_control_authenticator("run_1", "nonce-2", 1_000, &args, "secret-1")
                .unwrap();
        let changed_args = tclone_host_control_authenticator(
            "run_1",
            "nonce-1",
            1_000,
            &["run".to_string(), "diff".to_string(), "run_2".to_string()],
            "secret-1",
        )
        .unwrap();
        let changed_time =
            tclone_host_control_authenticator("run_1", "nonce-1", 2_000, &args, "secret-1")
                .unwrap();

        assert_ne!(first, second);
        assert_ne!(first, changed_args);
        assert_ne!(first, changed_time);
        assert!(!first.contains("secret-1"));
    }

    #[test]
    fn tclone_host_control_rejects_expired_and_future_requests() {
        let now = 1_000_000;
        assert!(validate_tclone_host_control_request_time(now, now).is_ok());
        assert!(validate_tclone_host_control_request_time(
            now - TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS * 1_000 - 1,
            now,
        )
        .is_err());
        assert!(validate_tclone_host_control_request_time(
            now + TCLONE_HOST_CONTROL_REQUEST_FUTURE_SKEW_SECS * 1_000 + 1,
            now,
        )
        .is_err());
    }

    #[test]
    fn tclone_host_file_timeout_is_clamped_before_freshness_expiry() {
        assert_eq!(
            clamp_tclone_host_control_file_timeout_secs(TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS),
            TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS
        );
        assert_eq!(
            clamp_tclone_host_control_file_timeout_secs(
                TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS + 100,
            ),
            TCLONE_HOST_CONTROL_REQUEST_MAX_AGE_SECS - 1
        );
    }

    #[test]
    fn tclone_safe_token_rejects_path_traversal_components() {
        assert!(!tclone_is_safe_token("."));
        assert!(!tclone_is_safe_token(".."));
        assert!(!tclone_is_safe_token("run..source"));
        assert!(tclone_is_safe_token("run.source-1"));
    }

    #[test]
    fn tclone_host_control_nonce_is_single_use() {
        let _guard = tclone_test_env_lock();
        let run_id = format!(
            "nonce_test_{}_{}",
            std::process::id(),
            unix_millis().unwrap()
        );
        let root = gensee_tmp_root().unwrap().join(&run_id);
        rotate_tclone_host_control_capability(&run_id).unwrap();

        claim_tclone_host_control_nonce(&run_id, "nonce-1").unwrap();
        let error = claim_tclone_host_control_nonce(&run_id, "nonce-1").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let nonces_dir = tclone_host_control_capability_path(&run_id)
            .unwrap()
            .parent()
            .unwrap()
            .join("nonces");
        prune_tclone_host_control_nonces(
            &nonces_dir,
            SystemTime::now() + Duration::from_secs(TCLONE_HOST_CONTROL_NONCE_RETENTION_SECS + 1),
        )
        .unwrap();
        claim_tclone_host_control_nonce(&run_id, "nonce-1").unwrap();
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_host_control_signed_fork_send_status_flow_enforces_authority() {
        let _guard = tclone_test_env_lock();
        let unique = format!("{}_{}", std::process::id(), unix_millis().unwrap());
        let source_run_id = format!("flow_source_{unique}");
        let fork_run_id = format!("{source_run_id}_fork_1_0");
        let root = temp_tree("signed-host-control-flow");
        let old_home = env::var_os("GENSEE_HOME");
        env::set_var("GENSEE_HOME", &root);

        let source = test_record(&source_run_id, "running");
        let fork = test_fork_record(&fork_run_id, &source_run_id);
        write_tclone_runs_to_path(&root.join("tclone-runs.jsonl"), &[source, fork]).unwrap();
        let capability = rotate_tclone_host_control_capability(&source_run_id).unwrap();

        let fork_request = signed_host_control_request(
            &source_run_id,
            &capability,
            "flow-fork",
            vec!["run".to_string(), "fork".to_string(), source_run_id.clone()],
        );
        validate_tclone_host_control_request(&fork_request).unwrap();

        let send_args = vec![
            "run".to_string(),
            "send".to_string(),
            fork_run_id.clone(),
            "--".to_string(),
            "continue in the fork".to_string(),
        ];
        let send_request = signed_host_control_request(
            &source_run_id,
            &capability,
            "flow-send",
            send_args.clone(),
        );
        validate_tclone_host_control_request(&send_request).unwrap();

        let denied_exec_nonce = "flow-denied-exec";
        let exec_request = signed_host_control_request(
            &source_run_id,
            &capability,
            denied_exec_nonce,
            vec![
                "run".to_string(),
                "exec".to_string(),
                fork_run_id.clone(),
                "--".to_string(),
                "true".to_string(),
            ],
        );
        assert_eq!(
            validate_tclone_host_control_request(&exec_request)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        claim_tclone_host_control_nonce(&source_run_id, denied_exec_nonce).unwrap();

        let job_id = format!("flow_job_{unique}");
        let job = tclone_async_job_from_id(&job_id).unwrap();
        write_atomic_nofollow(
            &tclone_async_job_owner_path(&job),
            format!("{source_run_id}\n").as_bytes(),
            0o600,
        )
        .unwrap();
        let status_request = signed_host_control_request(
            &source_run_id,
            &capability,
            "flow-status",
            vec![
                "run".to_string(),
                "fork-status".to_string(),
                job_id,
                "--json".to_string(),
            ],
        );
        validate_tclone_host_control_request(&status_request).unwrap();

        let replay =
            signed_host_control_request(&source_run_id, &capability, "flow-send", send_args);
        assert_eq!(
            validate_tclone_host_control_request(&replay)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let _ = fs::remove_file(&job.log_path);
        let _ = fs::remove_file(&job.done_path);
        let _ = fs::remove_file(tclone_async_job_owner_path(&job));
        let _ = fs::remove_dir_all(gensee_tmp_root().unwrap().join(&source_run_id));
        match old_home {
            Some(value) => env::set_var("GENSEE_HOME", value),
            None => env::remove_var("GENSEE_HOME"),
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_run_context_honors_override_path() {
        let _guard = tclone_test_env_lock();
        let root = temp_tree("run-context-override");
        let context_path = root.join("context.json");
        fs::write(&context_path, r#"{"run_id":"override-run"}"#).unwrap();
        let old_context = env::var_os("GENSEE_TCLONE_CONTEXT_PATH");
        env::set_var("GENSEE_TCLONE_CONTEXT_PATH", &context_path);

        assert_eq!(read_tclone_run_context().unwrap()["run_id"], "override-run");

        match old_context {
            Some(value) => env::set_var("GENSEE_TCLONE_CONTEXT_PATH", value),
            None => env::remove_var("GENSEE_TCLONE_CONTEXT_PATH"),
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_async_job_cap_is_per_run_and_stale_logs_are_inactive() {
        let _guard = tclone_test_env_lock();
        let unique = format!("{}_{}", std::process::id(), unix_millis().unwrap());
        let owner = format!("async_owner_{unique}");
        let job = tclone_async_job_from_id(&format!("async_job_{unique}")).unwrap();
        write_atomic_nofollow(&job.log_path, b"running\n", 0o600).unwrap();
        write_atomic_nofollow(
            &tclone_async_job_owner_path(&job),
            format!("{owner}\n").as_bytes(),
            0o600,
        )
        .unwrap();

        assert_eq!(count_active_tclone_async_jobs(&owner).unwrap(), 1);
        assert_eq!(count_active_tclone_async_jobs("different-run").unwrap(), 0);
        fs::remove_file(tclone_async_job_owner_path(&job)).unwrap();
        assert!(count_active_tclone_async_jobs(&owner).unwrap() >= 1);
        assert!(count_active_tclone_async_jobs("different-run").unwrap() >= 1);
        assert!(tclone_async_job_log_is_stale(
            &job.log_path,
            SystemTime::now()
                + Duration::from_secs(
                    TCLONE_ASYNC_JOB_TIMEOUT_SECS + TCLONE_ASYNC_JOB_STALE_GRACE_SECS + 1,
                ),
            TCLONE_ASYNC_JOB_TIMEOUT_SECS,
        ));

        let _ = fs::remove_file(&job.log_path);
        let _ = fs::remove_file(&job.done_path);
        let _ = fs::remove_file(tclone_async_job_owner_path(&job));
    }

    #[test]
    fn tclone_async_prunes_stale_timeout_claim_directories() {
        let _guard = tclone_test_env_lock();
        let unique = format!("{}_{}", std::process::id(), unix_millis().unwrap());
        let claim_path = tclone_async_jobs_dir()
            .unwrap()
            .join(format!("orphan_{unique}.done.timeout-claim.123"));
        create_restrictive_dir_all(&claim_path).unwrap();

        assert!(tclone_async_timeout_claim_path(&claim_path));
        prune_tclone_async_timeout_claim(
            &claim_path,
            SystemTime::now() + Duration::from_secs(TCLONE_ASYNC_TIMEOUT_CLAIM_STALE_SECS + 1),
        );
        assert!(!tclone_path_exists(&claim_path));
    }

    #[cfg(unix)]
    #[test]
    fn tclone_atomic_response_write_replaces_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = temp_tree("nofollow-response");
        let outside = root.join("outside");
        let response = root.join("response.json");
        fs::write(&outside, "keep").unwrap();
        symlink(&outside, &response).unwrap();

        write_atomic_nofollow(&response, br#"{"ok":true}"#, 0o600).unwrap();

        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(fs::read_to_string(&response).unwrap(), r#"{"ok":true}"#);
        assert!(!fs::symlink_metadata(&response)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn tclone_proc_stat_parser_handles_comm_with_spaces() {
        let stat = parse_proc_stat(
            123,
            "123 (codex worker) S 7 1 1 0 -1 4194304 1 2 3 4 50 25 0 0 20 0 1 0 12345",
        )
        .unwrap();

        assert_eq!(stat.pid, 123);
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.ticks, 75);
    }

    #[test]
    fn tclone_proc_tick_delta_marks_disappearing_children_as_active() {
        let previous = DescendantProcTicks {
            ticks_by_pid: HashMap::from([(1, 10), (2, 500)]),
        };
        let current = DescendantProcTicks {
            ticks_by_pid: HashMap::from([(1, 12)]),
        };

        assert_eq!(descendant_proc_tick_delta(&previous, &current), (2, true));
    }

    #[test]
    fn tclone_quiet_probe_treats_codex_agent_as_baseline() {
        let process = TcloneQuietProcess {
            pid: 11,
            stat: "Ssl+".to_string(),
            command: "node /home/yiying/.nvm/versions/node/v24.18.0/bin/codex".to_string(),
        };

        assert!(!tclone_is_transient_fork_process(&process));
    }

    #[test]
    fn tclone_quiet_probe_treats_polling_as_baseline() {
        let hook = TcloneQuietProcess {
            pid: 2171,
            stat: "S".to_string(),
            command: "/usr/local/bin/gensee hook codex".to_string(),
        };
        let status = TcloneQuietProcess {
            pid: 2172,
            stat: "S".to_string(),
            command: "/usr/local/bin/gensee run fork-status job_1 --json".to_string(),
        };

        assert!(!tclone_is_transient_fork_process(&hook));
        assert!(!tclone_is_transient_fork_process(&status));
    }

    #[test]
    fn tclone_quiet_probe_treats_tclone_init_as_baseline() {
        let init = TcloneQuietProcess {
            pid: 1,
            stat: "Ss".to_string(),
            command: "/usr/bin/env bash /usr/local/bin/gensee-tclone-init idle".to_string(),
        };
        let sleeper = TcloneQuietProcess {
            pid: 12,
            stat: "S".to_string(),
            command: "sleep 30".to_string(),
        };

        assert!(!tclone_is_transient_fork_process(&init));
        assert!(!tclone_is_transient_fork_process(&sleeper));
    }

    #[test]
    fn tclone_quiet_probe_keeps_sandbox_helpers_transient() {
        let sandbox = TcloneQuietProcess {
            pid: 31,
            stat: "S".to_string(),
            command:
                "/home/gensee/.codex/tmp/arg0/codex-linux-sandbox --sandbox-policy-cwd /workspace"
                    .to_string(),
        };
        let bwrap = TcloneQuietProcess {
            pid: 32,
            stat: "S".to_string(),
            command: "bwrap --new-session --bind /tmp /tmp".to_string(),
        };

        assert!(tclone_is_transient_fork_process(&sandbox));
        assert!(tclone_is_transient_fork_process(&bwrap));
    }

    #[test]
    fn tclone_clone_args_can_disable_overlay_btrfs() {
        let overlay = tclone_clone_args(2, "fork-prefix", "source", true);
        assert!(overlay.contains(&OsString::from("--tfork-overlay-btrfs")));
        assert!(overlay.contains(&OsString::from("--copies=2")));

        let fallback = tclone_clone_args(2, "fork-prefix", "source", false);
        assert!(!fallback.contains(&OsString::from("--tfork-overlay-btrfs")));
        assert!(fallback.contains(&OsString::from("--copies=2")));
    }

    #[test]
    fn tclone_overlay_retry_detects_conmon_setup_failure() {
        assert!(should_retry_tclone_without_overlay(
            "tfork: clone setup failed (spawn conmon for tfork: conmon reported pid=-1)"
        ));
        assert!(!should_retry_tclone_without_overlay(
            "podman exited with status 125: container not found"
        ));
    }

    #[test]
    fn tclone_host_control_runs_fork_async_and_preserves_json_ack() {
        let fork_args = vec![
            "run".to_string(),
            "fork".to_string(),
            "run_1".to_string(),
            "--json".to_string(),
        ];
        let exec_args = vec!["run".to_string(), "exec".to_string(), "run_1".to_string()];

        assert!(tclone_host_control_should_run_async(&fork_args));
        assert!(!tclone_host_control_should_run_async(&exec_args));

        let job = TcloneAsyncJob {
            id: "job_1".to_string(),
            log_path: PathBuf::from("/tmp/gensee/job_1.log"),
            done_path: PathBuf::from("/tmp/gensee/job_1.done"),
        };
        let response = tclone_host_control_async_response(&fork_args, &job);
        let payload: serde_json::Value = serde_json::from_str(response.stdout.trim()).unwrap();
        assert_eq!(payload["scheduled"], true);
        assert_eq!(payload["command"], "run fork");
        assert_eq!(payload["job_id"], "job_1");
        assert_eq!(
            payload["poll_command"],
            "gensee run fork-status job_1 --json"
        );
        assert_eq!(
            payload["status_command"],
            "gensee run fork-status job_1 --json"
        );
        assert!(payload.get("log_path").is_none());
        assert!(payload.get("done_path").is_none());
    }

    #[test]
    fn tclone_async_status_parses_fork_payload_from_log() {
        let log = r#"gensee async job job_1: /tmp/gensee ["run", "fork"]
noise
{"source_run_id":"run_1","forked_at_ms":42,"attach":true,"forks":[{"run_id":"run_1_fork_42_0","container":"fork-0"}]}
gensee async job job_1: exited status=0
"#;
        let payload = parse_tclone_async_fork_payload(log).unwrap();
        assert_eq!(payload["source_run_id"], "run_1");
        assert_eq!(payload["forks"][0]["run_id"], "run_1_fork_42_0");
    }

    #[test]
    fn tclone_async_status_rejects_path_like_job_ids() {
        assert!(tclone_async_job_from_id("../job").is_err());
        assert!(tclone_async_job_from_id("dir/job").is_err());
        assert!(tclone_async_job_from_id("").is_err());
    }

    #[test]
    fn tclone_host_control_async_attach_placement_parses_attach_flag() {
        let args = vec![
            "run".to_string(),
            "fork".to_string(),
            "run_1".to_string(),
            "--attach=tmux:right".to_string(),
        ];
        assert_eq!(
            tclone_host_control_async_attach_placement(&args).unwrap(),
            Some(HostTmuxPlacement::Right)
        );

        let invalid = vec![
            "run".to_string(),
            "fork".to_string(),
            "run_1".to_string(),
            "--attach=tmux:sideways".to_string(),
        ];
        assert!(tclone_host_control_async_attach_placement(&invalid).is_err());
    }

    #[test]
    fn tclone_async_job_component_cannot_inject_tmux_formats() {
        assert_eq!(
            tclone_safe_job_component("#(touch /tmp/pwned):run"),
            "__touch__tmp_pwned__run"
        );
    }

    #[test]
    fn tclone_tmux_detach_script_drains_attached_clients() {
        let script = tclone_tmux_detach_script();
        assert!(script.contains("display-message"));
        assert!(script.contains("list-clients"));
        assert!(script.contains("client_pid"));
        assert!(script.contains("detach-client -a -s"));
        assert!(script.contains("kill -HUP"));
    }

    #[test]
    fn tclone_fork_name_hint_is_unique_prefix() {
        assert_eq!(
            tclone_fork_name_prefix("run_1", Some("try-upgrade"), 123),
            "try-upgrade-123"
        );
        assert_eq!(
            tclone_fork_name_prefix("run_1", Some("try-upgrade-"), 123),
            "try-upgrade-123"
        );
        assert_eq!(
            tclone_fork_name_prefix("run_1/2", None, 123),
            "gensee-tclone-fork-run-1-2-123"
        );
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
        assert!(should_skip_tclone_workspace_entry("gensee.db"));
        assert!(should_skip_tclone_workspace_entry("gensee.db-wal"));
        assert!(should_skip_tclone_workspace_entry("gensee.db-shm"));
        assert!(should_skip_tclone_workspace_entry("gensee.key"));
        assert!(should_skip_tclone_workspace_entry("telemetry.json"));
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
            OsString::from("--attach"),
            OsString::from("tmux:right"),
            OsString::from("run_1"),
        ];

        assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
    }

    #[test]
    fn tclone_target_arg_strips_wrapping_quotes() {
        for quoted in [
            "\"run_1\"",
            "'run_1'",
            "`run_1`",
            "\u{201c}run_1\u{201d}",
            "\u{2018}run_1\u{2019}",
        ] {
            let args = vec![
                OsString::from("--name"),
                OsString::from("fork"),
                OsString::from(quoted),
            ];

            assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
        }
    }

    #[test]
    fn tclone_target_arg_and_arg_value_handle_equals_form() {
        let args = vec![
            OsString::from("--copies=2"),
            OsString::from("--name=fork-prefix"),
            OsString::from("--attach=tmux:below"),
            OsString::from("--into=source"),
            OsString::from("run_1"),
        ];

        assert_eq!(arg_value(&args, "--copies").unwrap(), "2");
        assert_eq!(arg_value(&args, "--name").unwrap(), "fork-prefix");
        assert_eq!(arg_value(&args, "--attach").unwrap(), "tmux:below");
        assert_eq!(arg_value(&args, "--into").unwrap(), "source");
        assert_eq!(tclone_target_arg(&args, "usage").unwrap(), "run_1");
    }

    #[test]
    fn tclone_host_control_proxies_only_tclone_run_commands() {
        assert!(tclone_host_control_should_proxy(&[
            OsString::from("run"),
            OsString::from("fork"),
            OsString::from("run_1"),
        ]));
        assert!(tclone_host_control_should_proxy(&[
            OsString::from("run"),
            OsString::from("send"),
            OsString::from("run_1"),
        ]));
        assert!(tclone_host_control_should_proxy(&[
            OsString::from("run"),
            OsString::from("exec"),
            OsString::from("run_1"),
        ]));
        assert!(tclone_host_control_should_proxy(&[
            OsString::from("run"),
            OsString::from("fork-status"),
            OsString::from("job_1"),
        ]));
        assert!(!tclone_host_control_should_proxy(&[
            OsString::from("hook"),
            OsString::from("codex"),
        ]));
        assert!(!tclone_host_control_should_proxy(&[
            OsString::from("run"),
            OsString::from("--runtime"),
            OsString::from("tclone"),
        ]));
    }

    #[test]
    fn tclone_exec_split_requires_separator_and_command() {
        let missing_separator = vec![OsString::from("run_1"), OsString::from("echo")];
        assert!(tclone_exec_split(&missing_separator).is_err());

        let missing_command = vec![OsString::from("run_1"), OsString::from("--")];
        assert!(tclone_exec_split(&missing_command).is_err());
    }

    #[test]
    fn tclone_exec_split_preserves_command_args_after_separator() {
        let args = vec![
            OsString::from("run_1_fork_0"),
            OsString::from("--"),
            OsString::from("bash"),
            OsString::from("-lc"),
            OsString::from("cargo test --locked"),
        ];

        let (target_args, command_args) = tclone_exec_split(&args).unwrap();

        assert_eq!(
            tclone_target_arg(target_args, "usage").unwrap(),
            "run_1_fork_0"
        );
        assert_eq!(
            command_args,
            &[
                OsString::from("bash"),
                OsString::from("-lc"),
                OsString::from("cargo test --locked"),
            ]
        );
    }

    #[test]
    fn tclone_send_split_preserves_prompt_after_separator() {
        let args = vec![
            OsString::from("run_1_fork_0"),
            OsString::from("--no-enter"),
            OsString::from("--"),
            OsString::from("Run"),
            OsString::from("cargo test"),
        ];

        let (target_args, prompt_args) = tclone_send_split(&args).unwrap();

        assert_eq!(
            tclone_target_arg(target_args, "usage").unwrap(),
            "run_1_fork_0"
        );
        assert!(arg_flag(target_args, "--no-enter"));
        assert_eq!(
            tclone_send_prompt_text(prompt_args).unwrap(),
            "Run cargo test"
        );
    }

    #[test]
    fn tclone_send_prefixes_fork_context() {
        let fork = test_fork_record("run_1_fork_2_0", "run_1");
        let prompt = tclone_prompt_with_fork_context(&fork, "Upgrade dependencies");

        assert!(prompt.contains("already running inside forked run run_1_fork_2_0"));
        assert!(prompt.contains("Do not create another fork"));
        assert!(prompt.ends_with("Upgrade dependencies"));
    }

    #[test]
    fn tclone_send_does_not_prefix_source_context() {
        let source = test_record("run_1", "running");
        let prompt = tclone_prompt_with_fork_context(&source, "Upgrade dependencies");

        assert_eq!(prompt, "Upgrade dependencies");
    }

    #[test]
    fn tclone_send_split_requires_prompt() {
        let missing_separator = vec![OsString::from("run_1"), OsString::from("prompt")];
        assert!(tclone_send_split(&missing_separator).is_err());

        let missing_prompt = vec![OsString::from("run_1"), OsString::from("--")];
        assert!(tclone_send_split(&missing_prompt).is_err());
    }

    #[test]
    fn tclone_run_exec_env_args_include_session_and_workspace_context() {
        let mut record = test_record("run_1_fork_0", "running");
        record.container_home = "/home/gensee".to_string();
        record.container_workspace = "/workspace".to_string();

        let env_args = tclone_run_exec_env_args(&record);

        assert!(env_args.contains(&OsString::from("HOME=/home/gensee")));
        assert!(env_args.contains(&OsString::from("GENSEE_HOME=/home/gensee/.gensee")));
        assert!(env_args.contains(&OsString::from("GENSEE_RUN_ID=run_1_fork_0")));
        assert!(env_args.contains(&OsString::from("AGENT_SHIELD_SESSION_ID=run_1_fork_0")));
        assert!(env_args.contains(&OsString::from("GENSEE_WORKSPACE=/workspace")));
    }

    #[test]
    fn tclone_run_context_payload_marks_forks() {
        let fork = test_fork_record("run_1_fork_2_0", "run_1");

        let payload = tclone_run_context_payload(&fork, "capability-1");

        assert_eq!(payload["run_id"], "run_1_fork_2_0");
        assert_eq!(payload["role"], "fork");
        assert_eq!(payload["source_run_id"], "run_1");
        assert_eq!(payload["workspace"], "/workspace");
        assert_eq!(payload["host_control_capability"], "capability-1");
    }

    #[test]
    fn tclone_host_tmux_placement_parser_accepts_aliases() {
        assert_eq!(
            parse_host_tmux_placement("tmux:right").unwrap(),
            HostTmuxPlacement::Right
        );
        assert_eq!(
            parse_host_tmux_placement("split-down").unwrap(),
            HostTmuxPlacement::Below
        );
        assert!(parse_host_tmux_placement("tmux:grid").is_err());
    }

    #[test]
    fn tclone_host_tmux_attach_command_reenters_gensee_attach() {
        let command = host_tmux_attach_command("run_1_fork_0", Path::new("/tmp/gensee"), false);

        assert!(command.contains("'/tmp/gensee' run attach 'run_1_fork_0'"));
        assert!(command.starts_with("env "));
        assert!(!command.starts_with("sudo "));
        assert!(command.contains("attach exited with status"));
        assert!(command.contains("exec \"${SHELL:-/bin/sh}\""));
    }

    #[test]
    fn tclone_host_tmux_attach_command_can_reenter_with_sudo() {
        let command = host_tmux_attach_command("run_1_fork_0", Path::new("/tmp/gensee"), true);

        assert!(command.starts_with("sudo env "));
        assert!(command.contains("'/tmp/gensee' run attach 'run_1_fork_0'"));
    }

    #[test]
    fn tclone_agent_start_script_wraps_command_in_tmux_when_available() {
        let script = tclone_agent_start_script(&[
            OsString::from("codex"),
            OsString::from("--prompt"),
            OsString::from("don't panic"),
        ]);

        assert!(script.contains("tmux new-session -d -s 'gensee-agent'"));
        assert!(script.contains("codex"));
        assert!(script.contains("--prompt"));
        assert!(script.contains("don"));
        assert!(script.contains("panic"));
        assert!(script.contains("exit 0"));
        assert!(!script.contains("exec sleep infinity"));
        assert!(!script.contains("while :; do"));
    }

    #[test]
    fn tclone_container_path_prefers_container_local_gensee() {
        let path = tclone_container_path(&[
            "/home/yiying/.nvm/versions/node/v24.18.0/bin".to_string(),
            "/home/yiying/.cargo/bin".to_string(),
        ]);
        let entries = path.split(':').collect::<Vec<_>>();

        assert_eq!(entries[0], "/usr/local/sbin");
        assert_eq!(entries[1], "/usr/local/bin");
        assert!(
            entries.iter().position(|entry| *entry == "/usr/local/bin")
                < entries
                    .iter()
                    .position(|entry| *entry == "/home/yiying/.cargo/bin")
        );
    }

    #[cfg(unix)]
    #[test]
    fn tclone_seed_installs_reaping_init() {
        let root = temp_tree("reaping-init");
        let seed = root.join("seed");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), "demo").unwrap();

        prepare_tclone_seed(&seed, &workspace, None, None, "/workspace", "/home/gensee").unwrap();

        let init = seed.join("usr/local/bin/gensee-tclone-init");
        let contents = fs::read_to_string(&init).unwrap();
        assert!(contents.starts_with("#!/bin/sh\n"));
        assert!(contents.contains("kill -TERM -1"));
        assert!(!contents.contains("wait -n"));
        assert_eq!(
            fs::metadata(&init).unwrap().permissions().mode() & 0o111,
            0o111
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn tclone_seed_installs_host_path_compatibility_links() {
        let root = temp_tree("compat-links");
        let seed = root.join("seed");
        let workspace = root.join("workspace");
        let host_home = root.join("host-home/yiying/.codex");
        let gensee_home = root.join("host-home/yiying/.gensee");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), "demo").unwrap();
        fs::create_dir_all(&host_home).unwrap();
        fs::write(
            host_home.join("hooks.json"),
            r#"{"hooks":{"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"GENSEE_HOME=/home/yiying/.gensee /home/yiying/.cargo/bin/gensee hook codex"}]}]}}"#,
        )
        .unwrap();
        fs::create_dir_all(&gensee_home).unwrap();
        fs::write(gensee_home.join("policy.json"), "{}").unwrap();

        prepare_tclone_seed(
            &seed,
            &workspace,
            Some(&(
                "CODEX_HOME".to_string(),
                host_home.clone(),
                "/home/gensee/.codex".to_string(),
            )),
            Some(&gensee_home),
            "/workspace",
            "/home/gensee",
        )
        .unwrap();

        assert!(seed.join("home/gensee/.codex/hooks.json").exists());
        let hooks = fs::read_to_string(seed.join("home/gensee/.codex/hooks.json")).unwrap();
        assert!(hooks.contains("GENSEE_HOME=/home/gensee/.gensee /usr/local/bin/gensee hook codex"));
        assert!(!hooks.contains("/home/yiying/.cargo/bin/gensee hook codex"));
        assert_eq!(
            fs::read_link(seed.join(host_home.strip_prefix("/").unwrap())).unwrap(),
            PathBuf::from("/home/gensee/.codex")
        );
        assert_eq!(
            fs::read_link(
                seed.join(
                    host_home
                        .parent()
                        .unwrap()
                        .join(".cargo/bin/gensee")
                        .strip_prefix("/")
                        .unwrap()
                )
            )
            .unwrap(),
            PathBuf::from("/usr/local/bin/gensee")
        );
        assert_eq!(
            fs::read_link(seed.join(gensee_home.strip_prefix("/").unwrap())).unwrap(),
            PathBuf::from("/home/gensee/.gensee")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn tclone_seed_copies_antigravity_gemini_home() {
        let root = temp_tree("antigravity-home");
        let seed = root.join("seed");
        let workspace = root.join("workspace");
        let gemini_home = root.join("host-home/yiying/.gemini");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("README.md"), "demo").unwrap();
        fs::create_dir_all(gemini_home.join("config")).unwrap();
        fs::write(gemini_home.join("config/hooks.json"), "{}").unwrap();

        prepare_tclone_seed(
            &seed,
            &workspace,
            Some(&(
                "GEMINI_HOME".to_string(),
                gemini_home.clone(),
                "/home/gensee/.gemini".to_string(),
            )),
            None,
            "/workspace",
            "/home/gensee",
        )
        .unwrap();

        assert!(seed.join("home/gensee/.gemini/config/hooks.json").exists());
        assert_eq!(
            fs::read_link(seed.join(gemini_home.strip_prefix("/").unwrap())).unwrap(),
            PathBuf::from("/home/gensee/.gemini")
        );
        let _ = fs::remove_dir_all(root);
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
    fn tclone_overlay_merge_plan_applies_whiteout_delete() {
        let root = temp_tree("whiteout-delete");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let source = root.join("source");
        fs::create_dir_all(lower.join("workspace")).unwrap();
        fs::create_dir_all(upper.join("workspace")).unwrap();
        fs::create_dir_all(source.join("workspace")).unwrap();
        fs::write(lower.join("workspace/a.txt"), "old").unwrap();
        fs::write(upper.join("workspace/.wh.a.txt"), "").unwrap();
        fs::write(source.join("workspace/a.txt"), "old").unwrap();

        let plan = build_tclone_overlay_merge_plan(&lower, &upper, &source, &None).unwrap();

        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].path, "workspace/a.txt");
        assert_eq!(plan.changes[0].op, TcloneOverlayMergeOp::Delete);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_overlay_merge_plan_rejects_opaque_directory_marker() {
        let root = temp_tree("opaque-dir");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let source = root.join("source");
        fs::create_dir_all(&lower).unwrap();
        fs::create_dir_all(upper.join("workspace")).unwrap();
        fs::create_dir_all(&source).unwrap();
        fs::write(upper.join("workspace/.wh..wh..opq"), "").unwrap();

        let error = build_tclone_overlay_merge_plan(&lower, &upper, &source, &None).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error
            .to_string()
            .contains("overlay opaque directory marker is not supported"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_recorded_overlay_rootfs_uses_stored_layers() {
        let root = temp_tree("recorded-overlay");
        let lower = root.join("lower");
        let upper = root.join("upper");
        fs::create_dir_all(&lower).unwrap();
        fs::create_dir_all(&upper).unwrap();
        let mut record = test_fork_record("fork_1", "source_1");
        record.fork_base_overlay_lowerdir = Some(lower.to_string_lossy().to_string());
        record.fork_overlay_upperdir = Some(upper.to_string_lossy().to_string());

        let overlay = recorded_tclone_overlay_rootfs(&record).unwrap();

        assert_eq!(overlay.lowerdir, lower);
        assert_eq!(overlay.upperdir, upper);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tclone_recorded_overlay_rootfs_rejects_stale_layers() {
        let mut record = test_fork_record("fork_1", "source_1");
        record.fork_base_overlay_lowerdir = Some("/tmp/gensee-missing-lower".to_string());
        record.fork_overlay_upperdir = Some("/tmp/gensee-missing-upper".to_string());

        let error = recorded_tclone_overlay_rootfs(&record).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error
            .to_string()
            .contains("recorded tclone overlay lowerdir"));
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
