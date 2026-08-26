use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const EFFECT_COORDINATOR_SCHEMA_VERSION: u32 = 1;
const EFFECT_REQUEST_PLACEHOLDER: &str = "{effect_request_json}";
const MAX_EFFECT_REQUEST_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_DEPTH: usize = 16;
const MAX_REQUEST_NODES: usize = 1_024;
const MAX_REQUEST_STRING_BYTES: usize = 4 * 1024;
const MAX_COMMAND_ARGS: usize = 128;
const MAX_COMMAND_ARG_BYTES: usize = 16 * 1024;
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectCoordinatorConfig {
    schema_version: u32,
    executor_label: String,
    supervisor_socket: PathBuf,
    operation_id: String,
    operation_class: String,
    effect: String,
    ttl_seconds: u64,
    command: EffectCommandTemplate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectCommandTemplate {
    executable: PathBuf,
    args: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default = "default_command_working_directory")]
    working_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectInvocationRequest {
    schema_version: u32,
    request_id: String,
    operation_class: String,
    parameters: Value,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectTransactionResult<'a> {
    schema_version: u32,
    transaction_id: &'a str,
    operation_id: &'a str,
    executor_label: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

fn default_command_working_directory() -> PathBuf {
    PathBuf::from("/")
}

pub(crate) fn run_effect_transaction(args: &[OsString]) -> io::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "effect transaction coordination requires Unix",
        ));
    }

    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "effect transaction coordination must run as root",
            ));
        }
        let config_path = effect_arg_value(args, "--config")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --config"))?;
        let request_path = effect_arg_value(args, "--request")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "missing --request"))?;
        let transaction_id = effect_arg_value(args, "--transaction")
            .filter(|value| safe_network_token(value))
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidInput, "missing or invalid --transaction")
            })?;
        reject_unknown_effect_args(args)?;

        validate_root_owned_path(&config_path, false, true)?;
        let config: EffectCoordinatorConfig =
            serde_json::from_str(&read_nofollow_to_string(&config_path)?).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid effect coordinator config: {error}"),
                )
            })?;
        validate_coordinator_config(&config, true)?;
        let request = read_effect_request(&request_path)?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let _signals = ScopedCoordinatorSignals::install(Arc::clone(&cancellation))?;
        let result = execute_effect_transaction(&config, &request, transaction_id, &cancellation)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

fn effect_arg_value<'a>(args: &'a [OsString], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then(|| pair[1].to_str()).flatten())
}

fn reject_unknown_effect_args(args: &[OsString]) -> io::Result<()> {
    if args.len() != 6
        || args.chunks(2).any(|pair| {
            !matches!(
                pair[0].to_str(),
                Some("--config" | "--request" | "--transaction")
            )
        })
        || ["--config", "--request", "--transaction"]
            .iter()
            .any(|flag| args.iter().filter(|arg| arg == flag).count() != 1)
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "usage: gensee run network transaction-execute --config FILE --request FILE --transaction ID",
        ));
    }
    Ok(())
}

fn read_effect_request(path: &Path) -> io::Result<EffectInvocationRequest> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect request must be a bounded regular non-symlink file",
        ));
    }
    let mut contents = String::new();
    file.take(MAX_EFFECT_REQUEST_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_EFFECT_REQUEST_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect request exceeds its byte limit",
        ));
    }
    let request: EffectInvocationRequest = serde_json::from_str(&contents)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    validate_effect_request(&request)?;
    Ok(request)
}

fn validate_effect_request(request: &EffectInvocationRequest) -> io::Result<()> {
    if request.schema_version != EFFECT_COORDINATOR_SCHEMA_VERSION
        || !safe_network_token(&request.request_id)
        || !safe_network_token(&request.operation_class)
        || !request.parameters.is_object()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect request must contain a valid schema version, request id, operation class, and object parameters",
        ));
    }
    let mut nodes = 0usize;
    validate_request_value(&request.parameters, 0, &mut nodes)
}

fn validate_request_value(value: &Value, depth: usize, nodes: &mut usize) -> io::Result<()> {
    *nodes = nodes.saturating_add(1);
    if depth > MAX_REQUEST_DEPTH || *nodes > MAX_REQUEST_NODES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect request exceeds its structural limits",
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_REQUEST_STRING_BYTES || value.contains('\0') => {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "effect request string exceeds its limit or contains NUL",
            ))
        }
        Value::Array(values) => {
            for value in values {
                validate_request_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.is_empty()
                    || key.len() > 128
                    || key.contains('\0')
                    || matches!(key.as_str(), "." | "..")
                {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "effect request contains an invalid parameter name",
                    ));
                }
                validate_request_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_coordinator_config(
    config: &EffectCoordinatorConfig,
    validate_privileged_paths: bool,
) -> io::Result<()> {
    if config.schema_version != EFFECT_COORDINATOR_SCHEMA_VERSION
        || !safe_network_token(&config.executor_label)
        || !safe_network_token(&config.operation_id)
        || !safe_network_token(&config.operation_class)
        || !safe_network_token(&config.effect)
        || config.ttl_seconds == 0
        || config.ttl_seconds > 86_400
        || !config.supervisor_socket.is_absolute()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect coordinator identity, operation, effect, socket, or TTL is invalid",
        ));
    }
    validate_command_template(&config.command, validate_privileged_paths)?;
    if validate_privileged_paths {
        validate_root_owned_socket(&config.supervisor_socket)?;
    }
    Ok(())
}

fn validate_command_template(
    template: &EffectCommandTemplate,
    validate_privileged_paths: bool,
) -> io::Result<()> {
    let placeholder_count = template
        .args
        .iter()
        .filter(|arg| arg.as_str() == EFFECT_REQUEST_PLACEHOLDER)
        .count();
    if !template.executable.is_absolute()
        || !template.working_directory.is_absolute()
        || template.args.is_empty()
        || template.args.len() > MAX_COMMAND_ARGS
        || placeholder_count != 1
        || template.args.iter().any(|arg| {
            arg.len() > MAX_COMMAND_ARG_BYTES
                || arg.contains('\0')
                || (arg.contains(EFFECT_REQUEST_PLACEHOLDER)
                    && arg.as_str() != EFFECT_REQUEST_PLACEHOLDER)
        })
        || template.environment.len() > 64
        || template.environment.iter().any(|(name, value)| {
            !valid_environment_name(name)
                || value.len() > MAX_COMMAND_ARG_BYTES
                || value.contains('\0')
        })
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect command must be an exact bounded argv template with one whole-argument effect request placeholder",
        ));
    }
    if validate_privileged_paths {
        validate_root_owned_path(&template.executable, false, false)?;
        validate_root_owned_path(&template.working_directory, true, false)?;
        #[cfg(unix)]
        if fs::metadata(&template.executable)?.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "effect command executable is not executable",
            ));
        }
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

#[cfg(unix)]
fn validate_root_owned_socket(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "supervisor socket has no parent")
    })?;
    validate_root_owned_path(parent, true, false)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "supervisor socket must be root-owned, non-symlink, and non-writable by other principals",
        ));
    }
    Ok(())
}

fn render_command_args(
    template: &EffectCommandTemplate,
    request: &EffectInvocationRequest,
) -> io::Result<Vec<String>> {
    let request_json = serde_json::to_string(request)?;
    Ok(template
        .args
        .iter()
        .map(|arg| {
            if arg == EFFECT_REQUEST_PLACEHOLDER {
                request_json.clone()
            } else {
                arg.clone()
            }
        })
        .collect())
}

fn execute_effect_transaction<'a>(
    config: &'a EffectCoordinatorConfig,
    request: &EffectInvocationRequest,
    transaction_id: &'a str,
    cancellation: &AtomicBool,
) -> io::Result<EffectTransactionResult<'a>> {
    validate_coordinator_config(config, false)?;
    validate_effect_request(request)?;
    if !safe_network_token(transaction_id)
        || request.request_id != transaction_id
        || request.operation_class != config.operation_class
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "effect transaction id or operation class does not match the approved request",
        ));
    }
    let args = render_command_args(&config.command, request)?;
    if let Err(error) = start_supervised_http_transaction(
        &config.supervisor_socket,
        transaction_id,
        &config.operation_id,
        &config.effect,
        config.ttl_seconds,
    ) {
        // The request may have committed even when its response was lost. An
        // immediate best-effort revoke closes that ambiguous-start window.
        let cleanup = finish_supervised_http_transaction(
            &config.supervisor_socket,
            transaction_id,
            &config.operation_id,
            false,
        );
        return Err(combine_command_and_cleanup_error(
            "cannot activate effect transaction",
            error,
            cleanup,
        ));
    }
    let mut transaction = ActiveEffectTransaction::new(
        &config.supervisor_socket,
        transaction_id,
        &config.operation_id,
    );

    let mut command = Command::new(&config.command.executable);
    command
        .args(args)
        .env_clear()
        .envs(&config.command.environment)
        .current_dir(&config.command.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|error| {
        let cleanup = transaction.revoke();
        combine_command_and_cleanup_error("cannot start effect command", error, cleanup)
    })?;
    let status = wait_for_effect_command(&mut child, cancellation).map_err(|error| {
        let cleanup = transaction.revoke();
        combine_command_and_cleanup_error("effect command was interrupted", error, cleanup)
    })?;

    if status.success() {
        transaction.end()?;
        Ok(EffectTransactionResult {
            schema_version: EFFECT_COORDINATOR_SCHEMA_VERSION,
            transaction_id,
            operation_id: &config.operation_id,
            executor_label: &config.executor_label,
            outcome: "ended",
            exit_code: status.code(),
        })
    } else {
        let command_error = io::Error::other(format!(
            "effect command failed with {}",
            exit_status_description(status)
        ));
        let cleanup = transaction.revoke();
        Err(combine_command_and_cleanup_error(
            "effect command failed",
            command_error,
            cleanup,
        ))
    }
}

fn wait_for_effect_command(child: &mut Child, cancellation: &AtomicBool) -> io::Result<ExitStatus> {
    loop {
        if cancellation.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "coordinator received a termination signal",
            ));
        }
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(COMMAND_POLL_INTERVAL);
    }
}

fn exit_status_description(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "a terminating signal".to_string())
}

fn combine_command_and_cleanup_error(
    context: &str,
    error: io::Error,
    cleanup: io::Result<()>,
) -> io::Error {
    match cleanup {
        Ok(()) => io::Error::new(error.kind(), format!("{context}: {error}")),
        Err(cleanup_error) => io::Error::new(
            error.kind(),
            format!("{context}: {error}; transaction revocation also failed: {cleanup_error}"),
        ),
    }
}

struct ActiveEffectTransaction<'a> {
    socket: &'a Path,
    transaction_id: &'a str,
    operation_id: &'a str,
    active: bool,
}

impl<'a> ActiveEffectTransaction<'a> {
    fn new(socket: &'a Path, transaction_id: &'a str, operation_id: &'a str) -> Self {
        Self {
            socket,
            transaction_id,
            operation_id,
            active: true,
        }
    }

    fn end(&mut self) -> io::Result<()> {
        self.finish(true)
    }

    fn revoke(&mut self) -> io::Result<()> {
        self.finish(false)
    }

    fn finish(&mut self, success: bool) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        finish_supervised_http_transaction(
            self.socket,
            self.transaction_id,
            self.operation_id,
            success,
        )?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ActiveEffectTransaction<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = finish_supervised_http_transaction(
                self.socket,
                self.transaction_id,
                self.operation_id,
                false,
            );
        }
    }
}

#[cfg(unix)]
static COORDINATOR_SIGNALLED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn coordinator_signal_handler(_signal: libc::c_int) {
    COORDINATOR_SIGNALLED.store(true, Ordering::Release);
}

#[cfg(unix)]
struct ScopedCoordinatorSignals {
    cancellation: Arc<AtomicBool>,
    old_interrupt: libc::sighandler_t,
    old_terminate: libc::sighandler_t,
    watcher: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl ScopedCoordinatorSignals {
    fn install(cancellation: Arc<AtomicBool>) -> io::Result<Self> {
        COORDINATOR_SIGNALLED.store(false, Ordering::Release);
        let handler = coordinator_signal_handler as *const () as libc::sighandler_t;
        let old_interrupt = unsafe { libc::signal(libc::SIGINT, handler) };
        if old_interrupt == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
        let old_terminate = unsafe { libc::signal(libc::SIGTERM, handler) };
        if old_terminate == libc::SIG_ERR {
            unsafe {
                libc::signal(libc::SIGINT, old_interrupt);
            }
            return Err(io::Error::last_os_error());
        }
        let watched = Arc::clone(&cancellation);
        let watcher = thread::spawn(move || {
            while !watched.load(Ordering::Acquire) {
                if COORDINATOR_SIGNALLED.load(Ordering::Acquire) {
                    watched.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(COMMAND_POLL_INTERVAL);
            }
        });
        Ok(Self {
            cancellation,
            old_interrupt,
            old_terminate,
            watcher: Some(watcher),
        })
    }
}

#[cfg(unix)]
impl Drop for ScopedCoordinatorSignals {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
        unsafe {
            libc::signal(libc::SIGINT, self.old_interrupt);
            libc::signal(libc::SIGTERM, self.old_terminate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn fixture_executable(name: &str) -> PathBuf {
        [format!("/usr/bin/{name}"), format!("/bin/{name}")]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .unwrap()
    }

    fn config(socket: PathBuf, executable: PathBuf, args: Vec<String>) -> EffectCoordinatorConfig {
        EffectCoordinatorConfig {
            schema_version: EFFECT_COORDINATOR_SCHEMA_VERSION,
            executor_label: "mediated_worker".to_string(),
            supervisor_socket: socket,
            operation_id: "op_external_read".to_string(),
            operation_class: "document_lookup".to_string(),
            effect: "external_http_read".to_string(),
            ttl_seconds: 30,
            command: EffectCommandTemplate {
                executable,
                args,
                environment: BTreeMap::new(),
                working_directory: PathBuf::from("/"),
            },
        }
    }

    fn request(request_id: &str) -> EffectInvocationRequest {
        EffectInvocationRequest {
            schema_version: EFFECT_COORDINATOR_SCHEMA_VERSION,
            request_id: request_id.to_string(),
            operation_class: "document_lookup".to_string(),
            parameters: serde_json::json!({
                "document_id": "doc_123",
                "query": "summary"
            }),
        }
    }

    fn fake_supervisor(
        expected_connections: usize,
    ) -> (PathBuf, Arc<Mutex<Vec<Value>>>, thread::JoinHandle<()>) {
        // Unix-domain socket paths have a small platform limit (104 bytes on
        // macOS), so keep this portable test fixture under the standard short
        // temporary root rather than the often-long TMPDIR value.
        let root = PathBuf::from("/tmp").join(format!("gdc-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("supervisor.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for _ in 0..expected_connections {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                recorded
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(&line).unwrap());
                stream.write_all(b"{\"ok\":true}\n").unwrap();
            }
        });
        (socket, requests, handle)
    }

    fn request_kinds(requests: &Arc<Mutex<Vec<Value>>>) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request["kind"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn effect_request_is_one_opaque_argv_and_cannot_inject_command_arguments() {
        let template = EffectCommandTemplate {
            executable: PathBuf::from("/usr/bin/true"),
            args: vec!["fetch".to_string(), EFFECT_REQUEST_PLACEHOLDER.to_string()],
            environment: BTreeMap::new(),
            working_directory: PathBuf::from("/"),
        };
        let rendered = render_command_args(&template, &request("tx_success")).unwrap();
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0], "fetch");
        let payload: EffectInvocationRequest = serde_json::from_str(&rendered[1]).unwrap();
        assert_eq!(payload, request("tx_success"));
        let mut with_shell_text = request("tx_success");
        with_shell_text.parameters = serde_json::json!({
            "query": "--flag; /bin/sh",
            "candidate_url": "http://untrusted.invalid/value"
        });
        let rendered = render_command_args(&template, &with_shell_text).unwrap();
        assert_eq!(rendered.len(), 2);
        assert!(rendered[1].contains("--flag; /bin/sh"));
    }

    #[test]
    fn malformed_templates_and_requests_fail_closed() {
        let mut invalid_config = config(
            PathBuf::from("/tmp/supervisor.sock"),
            PathBuf::from("/usr/bin/true"),
            vec![format!("--request={EFFECT_REQUEST_PLACEHOLDER}")],
        );
        assert!(validate_coordinator_config(&invalid_config, false).is_err());
        invalid_config.command.args = vec![EFFECT_REQUEST_PLACEHOLDER.to_string()];
        assert!(validate_coordinator_config(&invalid_config, false).is_ok());
        let mut invalid_request = request("tx_invalid");
        invalid_request.operation_class = "../escape".to_string();
        assert!(validate_effect_request(&invalid_request).is_err());
        invalid_request = request("tx_invalid");
        invalid_request.parameters = serde_json::json!({".": "invalid"});
        assert!(validate_effect_request(&invalid_request).is_err());
    }

    #[test]
    fn request_identity_and_operation_class_are_bound_before_authority_starts() {
        let config = config(
            PathBuf::from("/tmp/supervisor-that-must-not-be-opened.sock"),
            fixture_executable("true"),
            vec![EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );
        assert!(execute_effect_transaction(
            &config,
            &request("different_request"),
            "tx_expected",
            &AtomicBool::new(false),
        )
        .is_err());

        let mut wrong_class = request("tx_expected");
        wrong_class.operation_class = "different_operation".to_string();
        assert!(execute_effect_transaction(
            &config,
            &wrong_class,
            "tx_expected",
            &AtomicBool::new(false),
        )
        .is_err());
    }

    #[test]
    fn effect_request_reader_rejects_symlinks_and_oversized_files() {
        let root = PathBuf::from("/tmp").join(format!("gdc-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let oversized = root.join("oversized.json");
        fs::write(
            &oversized,
            vec![b' '; MAX_EFFECT_REQUEST_BYTES as usize + 1],
        )
        .unwrap();
        assert!(read_effect_request(&oversized).is_err());

        let real = root.join("real.json");
        fs::write(&real, serde_json::to_vec(&request("tx_reader")).unwrap()).unwrap();
        let linked = root.join("linked.json");
        symlink(&real, &linked).unwrap();
        assert!(read_effect_request(&linked).is_err());
    }

    #[test]
    fn successful_command_starts_then_ends_transaction() {
        let (socket, requests, server) = fake_supervisor(2);
        let config = config(
            socket,
            fixture_executable("true"),
            vec![EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );
        let result = execute_effect_transaction(
            &config,
            &request("tx_success"),
            "tx_success",
            &AtomicBool::new(false),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(result.outcome, "ended");
        assert_eq!(
            request_kinds(&requests),
            vec!["start_http_transaction", "end_http_transaction"]
        );
    }

    #[test]
    fn failed_command_starts_then_revokes_transaction() {
        let (socket, requests, server) = fake_supervisor(2);
        let config = config(
            socket,
            fixture_executable("false"),
            vec![EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );
        assert!(execute_effect_transaction(
            &config,
            &request("tx_failure"),
            "tx_failure",
            &AtomicBool::new(false),
        )
        .is_err());
        server.join().unwrap();
        assert_eq!(
            request_kinds(&requests),
            vec!["start_http_transaction", "revoke_http_transaction"]
        );
    }

    #[test]
    fn child_signal_crash_revokes_transaction() {
        let (socket, requests, server) = fake_supervisor(2);
        let config = config(
            socket,
            fixture_executable("sh"),
            vec![
                "-c".to_string(),
                "kill -9 $$".to_string(),
                EFFECT_REQUEST_PLACEHOLDER.to_string(),
            ],
        );
        assert!(execute_effect_transaction(
            &config,
            &request("tx_crash"),
            "tx_crash",
            &AtomicBool::new(false),
        )
        .is_err());
        server.join().unwrap();
        assert_eq!(
            request_kinds(&requests),
            vec!["start_http_transaction", "revoke_http_transaction"]
        );
    }

    #[test]
    fn spawn_failure_and_cancellation_revoke_transaction() {
        let (spawn_socket, spawn_requests, spawn_server) = fake_supervisor(2);
        let spawn_config = config(
            spawn_socket,
            PathBuf::from("/definitely/missing/gensee-command"),
            vec![EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );
        assert!(execute_effect_transaction(
            &spawn_config,
            &request("tx_spawn_failure"),
            "tx_spawn_failure",
            &AtomicBool::new(false),
        )
        .is_err());
        spawn_server.join().unwrap();
        assert_eq!(
            request_kinds(&spawn_requests),
            vec!["start_http_transaction", "revoke_http_transaction"]
        );

        let (cancel_socket, cancel_requests, cancel_server) = fake_supervisor(2);
        let cancel_config = config(
            cancel_socket,
            fixture_executable("sleep"),
            vec!["5".to_string(), EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );
        let cancellation = AtomicBool::new(true);
        assert!(execute_effect_transaction(
            &cancel_config,
            &request("tx_cancelled"),
            "tx_cancelled",
            &cancellation,
        )
        .is_err());
        cancel_server.join().unwrap();
        assert_eq!(
            request_kinds(&cancel_requests),
            vec!["start_http_transaction", "revoke_http_transaction"]
        );
    }

    #[test]
    fn lost_start_response_triggers_ambiguity_revocation() {
        let root = PathBuf::from("/tmp").join(format!("gdc-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("supervisor.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let server = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                recorded
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(&line).unwrap());
                if index == 1 {
                    stream.write_all(b"{\"ok\":true}\n").unwrap();
                }
            }
        });
        let config = config(
            socket,
            fixture_executable("true"),
            vec![EFFECT_REQUEST_PLACEHOLDER.to_string()],
        );

        assert!(execute_effect_transaction(
            &config,
            &request("tx_ambiguous_start"),
            "tx_ambiguous_start",
            &AtomicBool::new(false),
        )
        .is_err());
        server.join().unwrap();
        assert_eq!(
            request_kinds(&requests),
            vec!["start_http_transaction", "revoke_http_transaction"]
        );
    }
}
