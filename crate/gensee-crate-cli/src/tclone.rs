use crate::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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
const TCLONE_HOST_TMUX_SOCKET_ENV: &str = "GENSEE_HOST_TMUX_SOCKET";
const TCLONE_HOST_TMUX_TARGET_ENV: &str = "GENSEE_HOST_TMUX_TARGET";
const TCLONE_ASYNC_FORK_DELAY_SECS: u64 = 2;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TcloneHostControlRequest {
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
}

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
    let request = TcloneHostControlRequest { args: request_args };
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
        Some("fork" | "send" | "exec" | "list" | "attach" | "shell" | "diff")
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
    fs::create_dir_all(&requests_dir)?;
    fs::create_dir_all(&responses_dir)?;

    let request_id = format!("{}_{}", std::process::id(), unix_millis().unwrap_or(0));
    let request_path = requests_dir.join(format!("{request_id}.json"));
    let request_tmp = requests_dir.join(format!("{request_id}.tmp"));
    let response_path = responses_dir.join(format!("{request_id}.json"));
    let response_tmp = responses_dir.join(format!("{request_id}.tmp"));
    let _ = fs::remove_file(&request_path);
    let _ = fs::remove_file(&request_tmp);
    let _ = fs::remove_file(&response_path);
    let _ = fs::remove_file(&response_tmp);

    fs::write(&request_tmp, serde_json::to_vec(request)?)?;
    fs::rename(&request_tmp, &request_path)?;

    let deadline = Instant::now()
        + Duration::from_secs(
            env::var("GENSEE_TCLONE_HOST_FILE_TIMEOUT_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(TCLONE_HOST_CONTROL_FILE_TIMEOUT_SECS),
        );
    loop {
        match fs::read_to_string(&response_path) {
            Ok(text) => {
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

struct TcloneHostControlServer {
    socket_path: PathBuf,
    control_dir: PathBuf,
}

struct TcloneContainerFileControlServer;

impl TcloneHostControlServer {
    fn start(socket_path: &Path, control_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(control_dir.join("requests"))?;
        fs::create_dir_all(control_dir.join("responses"))?;
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
    if !tclone_host_control_should_proxy(
        &request.args.iter().map(OsString::from).collect::<Vec<_>>(),
    ) {
        return Ok(TcloneHostControlResponse {
            exit_code: Some(64),
            stdout: String::new(),
            stderr: String::new(),
            error: Some("unsupported tclone host-control command".to_string()),
        });
    }
    if tclone_host_control_should_run_async(&request.args) {
        let job = tclone_async_job(&request.args)?;
        let response = tclone_host_control_async_response(&request.args, &job);
        spawn_tclone_host_control_request(request, exe.to_path_buf(), &job)?;
        return Ok(response);
    }
    execute_tclone_host_control_request_sync(request, exe)
}

fn execute_tclone_host_control_request_sync(
    request: TcloneHostControlRequest,
    exe: &Path,
) -> io::Result<TcloneHostControlResponse> {
    let output = Command::new(exe)
        .args(&request.args)
        .env_remove(TCLONE_HOST_CONTROL_SOCKET_ENV)
        .env_remove(TCLONE_HOST_CONTROL_DIR_ENV)
        .env(TCLONE_HOST_CONTROL_DISABLE_ENV, "1")
        .output()?;
    Ok(TcloneHostControlResponse {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        error: None,
    })
}

fn spawn_tclone_host_control_request(
    request: TcloneHostControlRequest,
    exe: PathBuf,
    job: &TcloneAsyncJob,
) -> io::Result<()> {
    if let Some(parent) = job.log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&job.log_path)?;
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
    let stderr = log.try_clone()?;
    Command::new("sh")
        .arg("-c")
        .arg("sleep \"$1\"; shift; exec \"$@\"")
        .arg("gensee-tclone-async-fork")
        .arg(delay_secs.to_string())
        .arg(&exe)
        .args(&request.args)
        .env_remove(TCLONE_HOST_CONTROL_SOCKET_ENV)
        .env_remove(TCLONE_HOST_CONTROL_DIR_ENV)
        .env(TCLONE_HOST_CONTROL_DISABLE_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    Ok(())
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

fn tclone_async_job(args: &[String]) -> io::Result<TcloneAsyncJob> {
    let target = args
        .iter()
        .skip(2)
        .find(|arg| !arg.starts_with("--"))
        .map(|arg| arg.replace(['/', ':'], "_"))
        .unwrap_or_else(|| "tclone".to_string());
    let id = format!(
        "{}_{}_{}",
        target,
        std::process::id(),
        unix_millis().unwrap_or(0)
    );
    Ok(TcloneAsyncJob {
        log_path: gensee_tmp_root()?
            .join("tclone-async")
            .join(format!("{id}.log")),
        id,
    })
}

fn tclone_host_control_async_response(
    args: &[String],
    job: &TcloneAsyncJob,
) -> TcloneHostControlResponse {
    let stdout = if args.iter().any(|arg| arg == "--json") {
        format!(
            "{}\n",
            json!({
                "scheduled": true,
                "command": "run fork",
                "job_id": job.id,
                "log_path": job.log_path,
                "message": "gensee scheduled the tclone fork on the host",
            })
        )
    } else {
        format!(
            "gensee: scheduled tclone fork on host job_id={} log_path={}\n",
            job.id,
            job.log_path.display()
        )
    };
    TcloneHostControlResponse {
        exit_code: Some(0),
        stdout,
        stderr: String::new(),
        error: None,
    }
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
        let response_path = responses_dir.join(format!("{stem}.json"));
        if response_path.exists() {
            let _ = fs::remove_file(&path);
            continue;
        }
        let response = match fs::File::open(&path)
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
        let response_tmp = responses_dir.join(format!("{stem}.tmp"));
        fs::write(&response_tmp, serde_json::to_vec(&response)?)?;
        fs::rename(response_tmp, response_path)?;
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
        let parsed_request = serde_json::from_str::<TcloneHostControlRequest>(&request_json)
            .map_err(io::Error::other);
        let response =
            match parsed_request {
                Ok(request) if tclone_host_control_should_run_async(&request.args) => {
                    let job = tclone_async_job(&request.args)?;
                    let response = tclone_host_control_async_response(&request.args, &job);
                    write_tclone_container_host_control_response(
                        podman,
                        container_name,
                        &request_path,
                        &response_path,
                        &response,
                    )?;
                    if let Err(error) =
                        spawn_tclone_host_control_request(request, exe.to_path_buf(), &job)
                    {
                        eprintln!("gensee: async tclone host command failed to start: {error}");
                    }
                    continue;
                }
                Ok(request) => execute_tclone_host_control_request_sync(request, exe)
                    .unwrap_or_else(|error| TcloneHostControlResponse {
                        exit_code: Some(1),
                        stdout: String::new(),
                        stderr: String::new(),
                        error: Some(error.to_string()),
                    }),
                Err(error) => TcloneHostControlResponse {
                    exit_code: Some(1),
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some(error.to_string()),
                },
            };
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
    fs::create_dir_all(&host_control_dir)?;
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
        OsString::from("-e"),
        OsString::from(format!(
            "{TCLONE_HOST_CONTROL_DIR_ENV}={container_workspace_host_control_dir}"
        )),
        OsString::from("-e"),
        OsString::from("TERM=xterm-256color"),
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
    create_args.push(OsString::from("infinity"));
    let agent_cmd_strings = config
        .agent_cmd
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();

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
        agent_cmd: agent_cmd_strings.clone(),
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
    start_tclone_agent_session(&podman, &source_container, &config.agent_cmd)?;
    let _container_file_control = TcloneContainerFileControlServer::start(
        &podman,
        &source_container,
        &container_workspace_host_control_dir,
        Duration::from_millis(200),
    )?;
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
    ensure_tclone_agent_ready_for_fork(&podman, &source)?;
    let _detach_guard = TcloneForkDetachGuard::mark(&source.run_id)?;
    detach_tclone_tmux_clients(&podman, &source.container_name);
    let forked_at_ms = unix_millis()?;
    let fork_base_git_head = capture_tclone_git_head(&podman, &source).ok();
    let prefix = arg_value(&args, "--name").unwrap_or_else(|| {
        format!(
            "gensee-tclone-fork-{}-{}",
            parent.replace(['_', '/'], "-"),
            forked_at_ms
        )
    });
    let output = run_tclone_clone_with_overlay_retry(&podman, copies, &prefix, &source)?;
    let ids = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
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

fn run_tclone_clone_with_overlay_retry(
    podman: &OsString,
    copies: usize,
    prefix: &str,
    source: &TcloneRunRecord,
) -> io::Result<String> {
    let use_overlay = env::var("GENSEE_TCLONE_OVERLAY_BTRFS")
        .map(|value| !matches!(value.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true);
    let clone_args = tclone_clone_args(copies, prefix, &source.container_name, use_overlay);
    match run_command_capture_with_env(podman, &clone_args, &[("PODMAN_TFORK_NO_REAP", "1")]) {
        Ok(output) => Ok(output),
        Err(error) if use_overlay && should_retry_tclone_without_overlay(&error.to_string()) => {
            eprintln!(
                "gensee: tclone overlay-btrfs clone failed; retrying without --tfork-overlay-btrfs"
            );
            let fallback_args = tclone_clone_args(copies, prefix, &source.container_name, false);
            run_command_capture_with_env(podman, &fallback_args, &[("PODMAN_TFORK_NO_REAP", "1")])
        }
        Err(error) => Err(error),
    }
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
    let tty = current_tty_path()?;
    for socket in host_tmux_socket_candidates() {
        if let Some(target) = tmux_pane_for_tty(&socket, &tty) {
            return Some((socket.to_string_lossy().to_string(), target));
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
    let mut tmux = Command::new("tmux");
    if let Some(socket) = env::var_os(TCLONE_HOST_TMUX_SOCKET_ENV) {
        tmux.arg("-S").arg(socket);
    }
    tmux.arg("split-window").arg(split_flag);
    if let Some(target) = env::var_os(TCLONE_HOST_TMUX_TARGET_ENV) {
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
                if consume_tclone_host_fork_marker(podman, container_name, attach_started_ms) {
                    eprintln!("gensee: reattaching to source after tclone fork");
                    continue;
                }
                return Ok(status);
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

fn consume_tclone_host_fork_marker(
    podman: &OsString,
    container_name: &str,
    attach_started_ms: u64,
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
    let now_ms = unix_millis().unwrap_or(marker_ms);
    if marker_ms.saturating_add(5 * 60 * 1_000) < now_ms
        || marker_ms.saturating_add(2_000) < attach_started_ms
    {
        let _ = fs::remove_file(&marker_path);
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(5 * 60);
    while Instant::now() < deadline {
        if !marker_path.exists() {
            wait_tclone_container_exec_ready(podman, container_name, Duration::from_secs(15));
            return true;
        }
        thread::sleep(Duration::from_millis(250));
    }

    wait_tclone_container_exec_ready(podman, container_name, Duration::from_secs(15));
    let _ = fs::remove_file(&marker_path);
    true
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
    let _ = Command::new(podman)
        .arg("exec")
        .arg(container_name)
        .arg("tmux")
        .arg("detach-client")
        .arg("-a")
        .arg("-s")
        .arg(TCLONE_AGENT_TMUX_SESSION)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    thread::sleep(Duration::from_millis(250));
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
        "set -e\nexport TERM=\"${{TERM:-xterm-256color}}\"\nlog=/tmp/gensee-agent-start.log\nif command -v tmux >/dev/null 2>&1; then\n  printf 'starting tmux session %s: %s\\n' {} {} > \"$log\"\n  tmux new-session -d -s {} >> \"$log\" 2>&1\n  tmux set-option -t {} remain-on-exit on >> \"$log\" 2>&1\n  tmux send-keys -t {} -- {} C-m >> \"$log\" 2>&1\n  sleep 2\n  if ! tmux has-session -t {} 2>> \"$log\"; then\n    printf 'gensee agent tmux session disappeared during startup\\n' >> \"$log\"\n    cat \"$log\" >&2\n    exit 127\n  fi\n  if tmux list-panes -t {} -F '#{{pane_dead}}' 2>> \"$log\" | grep -q '^1$'; then\n    printf 'gensee agent exited during startup; pane follows\\n' >> \"$log\"\n    tmux capture-pane -pt {} >> \"$log\" 2>&1 || true\n    cat \"$log\" >&2\n    exit 127\n  fi\n  exit 0\nfi\nprintf 'tmux not found; starting agent directly in background: %s\\n' {} > \"$log\"\nsh -lc {} >> \"$log\" 2>&1 &\n",
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
        install_tclone_host_path_compatibility(seed_root, host_home, container_path)?;
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
    fn tclone_host_control_socket_falls_back_to_gensee_home() {
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
        };
        let response = tclone_host_control_async_response(&fork_args, &job);
        let payload: serde_json::Value = serde_json::from_str(response.stdout.trim()).unwrap();
        assert_eq!(payload["scheduled"], true);
        assert_eq!(payload["command"], "run fork");
        assert_eq!(payload["job_id"], "job_1");
        assert_eq!(payload["log_path"], "/tmp/gensee/job_1.log");
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
        fs::write(host_home.join("hooks.json"), "{}").unwrap();
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
