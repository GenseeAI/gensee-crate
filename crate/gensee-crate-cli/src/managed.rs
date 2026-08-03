use crate::*;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MANAGED_PROTOCOL_VERSION: u32 = 1;
const MANAGED_STATE_FILE: &str = "managed-operations.json";
const MANAGED_ID_MAX_LEN: usize = 64;
const MANAGED_RESOURCE_ID_MAX_LEN: usize = 37;
const MANAGED_SOURCE_ID_MAX_LEN: usize = 45;
const MANAGED_STATE_LOCK_STALE_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize)]
struct ManagedResponse {
    protocol_version: u32,
    ok: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ManagedErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedErrorBody {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedOperationRecord {
    operation_id: String,
    idempotency_key: String,
    action: String,
    fingerprint: String,
    allocation_id: Option<String>,
    #[serde(default)]
    fork_id: Option<String>,
    #[serde(default)]
    expected_copies: Option<usize>,
    status: String,
    runner_pid: u32,
    child_pid: Option<u32>,
    result: Option<Value>,
    error: Option<ManagedErrorBody>,
    updated_at_ms: u64,
}

#[derive(Debug)]
struct ManagedError {
    body: ManagedErrorBody,
    kind: io::ErrorKind,
}

impl ManagedError {
    fn new(kind: io::ErrorKind, code: &str, message: impl Into<String>) -> Self {
        Self {
            body: ManagedErrorBody {
                code: code.to_string(),
                message: message.into(),
                retryable: matches!(
                    kind,
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ),
            },
            kind,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(io::ErrorKind::InvalidInput, "invalid_request", message)
    }

    fn from_io(code: &str, error: io::Error) -> Self {
        Self::new(error.kind(), code, error.to_string())
    }

    fn into_io(self) -> io::Error {
        io::Error::new(self.kind, self.body.message)
    }
}

enum BeginOperation {
    Execute,
    Cached(Value),
    InProgress(Value),
    Recover(Box<ManagedOperationRecord>),
}

pub(crate) fn validate_managed_id(label: &str, value: &str) -> io::Result<()> {
    validate_managed_id_with_limit(label, value, MANAGED_ID_MAX_LEN)
}

fn validate_managed_resource_id(label: &str, value: &str) -> io::Result<()> {
    validate_managed_id_with_limit(label, value, MANAGED_RESOURCE_ID_MAX_LEN)
}

pub(crate) fn validate_managed_source_id(label: &str, value: &str) -> io::Result<()> {
    validate_managed_id_with_limit(label, value, MANAGED_SOURCE_ID_MAX_LEN)
}

fn validate_managed_id_with_limit(label: &str, value: &str, max_len: usize) -> io::Result<()> {
    let valid = !value.is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{label} must contain only ASCII letters, digits, '-' or '_' and be at most {max_len} characters"
            ),
        ))
    }
}

pub(crate) fn run_managed(args: Vec<OsString>) -> io::Result<()> {
    let action = args
        .first()
        .and_then(|arg| arg.to_str())
        .unwrap_or("unknown")
        .replace('-', "_");
    match execute_managed(&args) {
        Ok(mut response) => {
            response.action = action;
            println!("{}", serde_json::to_string(&response)?);
            Ok(())
        }
        Err(error) => {
            let response = ManagedResponse {
                protocol_version: MANAGED_PROTOCOL_VERSION,
                ok: false,
                action,
                operation_id: option_value(&args, "--operation-id"),
                idempotency_key: option_value(&args, "--idempotency-key"),
                cached: false,
                result: None,
                error: Some(error.body.clone()),
            };
            println!("{}", serde_json::to_string(&response)?);
            Err(error.into_io())
        }
    }
}

fn execute_managed(args: &[OsString]) -> Result<ManagedResponse, ManagedError> {
    let Some(action) = args.first().and_then(|arg| arg.to_str()) else {
        return Err(ManagedError::invalid(
            "usage: gensee managed <create-source|delete-source|fork|merge|promote|discard|diff|status|list|reconcile>",
        ));
    };
    let action_args = &args[1..];
    match action {
        "create-source" => managed_mutation(action, action_args, create_source),
        "delete-source" => managed_mutation(action, action_args, delete_source),
        "fork" => managed_mutation(action, action_args, fork_source),
        "merge" => managed_mutation(action, action_args, merge_fork),
        "promote" => managed_mutation(action, action_args, promote_fork),
        "discard" => managed_mutation(action, action_args, discard_fork),
        "diff" => managed_read(action, diff_run(action_args)),
        "status" => managed_read(action, status_allocation(action_args)),
        "list" => managed_read(action, managed_list()),
        "reconcile" => managed_read(action, managed_reconcile()),
        other => Err(ManagedError::invalid(format!(
            "unknown managed action: {other}"
        ))),
    }
}

fn managed_read(
    action: &str,
    result: Result<Value, ManagedError>,
) -> Result<ManagedResponse, ManagedError> {
    Ok(ManagedResponse {
        protocol_version: MANAGED_PROTOCOL_VERSION,
        ok: true,
        action: action.replace('-', "_"),
        operation_id: None,
        idempotency_key: None,
        cached: false,
        result: Some(result?),
        error: None,
    })
}

fn managed_mutation(
    action: &str,
    args: &[OsString],
    execute: fn(&[OsString], &str) -> Result<Value, ManagedError>,
) -> Result<ManagedResponse, ManagedError> {
    let operation_id = required_id(args, "--operation-id", "operation ID")?;
    let idempotency_key = required_id(args, "--idempotency-key", "idempotency key")?;
    let allocation_id = option_value(args, "--allocation-id");
    if let Some(allocation_id) = allocation_id.as_deref() {
        validate_managed_resource_id("allocation ID", allocation_id)
            .map_err(|error| ManagedError::from_io("invalid_request", error))?;
    }
    let fork_id = option_value(args, "--fork-id");
    if action == "fork" {
        let fork_id = fork_id
            .as_deref()
            .ok_or_else(|| ManagedError::invalid("missing required option --fork-id"))?;
        validate_managed_resource_id("fork ID", fork_id)
            .map_err(|error| ManagedError::from_io("invalid_request", error))?;
    }
    let expected_copies = (action == "fork").then(|| {
        option_value(args, "--copies")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
    });
    let fingerprint = managed_fingerprint(action, args)?;
    match begin_operation(
        action,
        &operation_id,
        &idempotency_key,
        allocation_id,
        fork_id,
        expected_copies,
        &fingerprint,
    )? {
        BeginOperation::Cached(result) => {
            return Ok(ManagedResponse {
                protocol_version: MANAGED_PROTOCOL_VERSION,
                ok: true,
                action: action.replace('-', "_"),
                operation_id: Some(operation_id),
                idempotency_key: Some(idempotency_key),
                cached: true,
                result: Some(result),
                error: None,
            });
        }
        BeginOperation::InProgress(result) => {
            return Ok(ManagedResponse {
                protocol_version: MANAGED_PROTOCOL_VERSION,
                ok: true,
                action: action.replace('-', "_"),
                operation_id: Some(operation_id),
                idempotency_key: Some(idempotency_key),
                cached: true,
                result: Some(result),
                error: None,
            });
        }
        BeginOperation::Recover(record) => {
            if let Some(result) = reconcile_interrupted(&record)? {
                finish_operation(&idempotency_key, "succeeded", Some(result.clone()), None)?;
                return Ok(ManagedResponse {
                    protocol_version: MANAGED_PROTOCOL_VERSION,
                    ok: true,
                    action: action.replace('-', "_"),
                    operation_id: Some(operation_id),
                    idempotency_key: Some(idempotency_key),
                    cached: true,
                    result: Some(result),
                    error: None,
                });
            }
        }
        BeginOperation::Execute => {}
    }

    match execute(args, &operation_id) {
        Ok(result) => {
            finish_operation(&idempotency_key, "succeeded", Some(result.clone()), None)?;
            Ok(ManagedResponse {
                protocol_version: MANAGED_PROTOCOL_VERSION,
                ok: true,
                action: action.replace('-', "_"),
                operation_id: Some(operation_id),
                idempotency_key: Some(idempotency_key),
                cached: false,
                result: Some(result),
                error: None,
            })
        }
        Err(error) => {
            finish_operation(&idempotency_key, "failed", None, Some(error.body.clone()))?;
            Err(error)
        }
    }
}

fn create_source(args: &[OsString], operation_id: &str) -> Result<Value, ManagedError> {
    let allocation_id = required_resource_id(args, "--allocation-id", "allocation ID")?;
    let workspace = required_value(args, "--workspace")?;
    let agent = values_after_separator(args);
    if agent.is_empty() {
        return Err(ManagedError::invalid(
            "create-source requires an agent command after --",
        ));
    }
    let source_id = managed_source_id(&allocation_id);
    if let Some(record) = list_tclone_runs()
        .map_err(|error| ManagedError::from_io("state_read_failed", error))?
        .into_iter()
        .find(|record| record.run_id == source_id)
    {
        return Ok(source_result(&allocation_id, &record, true));
    }

    let mut command = Command::new(
        env::current_exe().map_err(|error| ManagedError::from_io("runtime_failed", error))?,
    );
    command
        .arg("run")
        .arg("--runtime")
        .arg("tclone")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--")
        .args(&agent)
        .env("GENSEE_MANAGED_SOURCE_ID", &source_id)
        .env("GENSEE_MANAGED_OPERATION_ID", operation_id)
        .env("GENSEE_TCLONE_NO_ATTACH", "1");
    run_managed_child(command, args)?;
    let record = list_tclone_runs()
        .map_err(|error| ManagedError::from_io("state_read_failed", error))?
        .into_iter()
        .find(|record| record.run_id == source_id)
        .ok_or_else(|| {
            ManagedError::new(
                io::ErrorKind::InvalidData,
                "runtime_state_missing",
                format!("source {source_id} completed without a run record"),
            )
        })?;
    Ok(source_result(&allocation_id, &record, false))
}

fn delete_source(args: &[OsString], _operation_id: &str) -> Result<Value, ManagedError> {
    let allocation_id = required_resource_id(args, "--allocation-id", "allocation ID")?;
    let source_id = managed_source_id(&allocation_id);
    if !list_tclone_runs()
        .map_err(|error| ManagedError::from_io("state_read_failed", error))?
        .iter()
        .any(|record| record.run_id == source_id)
    {
        return Ok(json!({
            "allocation_id": allocation_id,
            "source_id": source_id,
            "status": "deleted",
            "already_absent": true,
        }));
    }
    let command = managed_cli_command(&["run", "delete", &source_id])?;
    run_managed_child(command, args)?;
    Ok(json!({
        "allocation_id": allocation_id,
        "source_id": source_id,
        "status": "deleted",
        "already_absent": false,
    }))
}

fn fork_source(args: &[OsString], _operation_id: &str) -> Result<Value, ManagedError> {
    let allocation_id = required_resource_id(args, "--allocation-id", "allocation ID")?;
    let fork_id = required_resource_id(args, "--fork-id", "fork ID")?;
    let source_id = managed_source_id(&allocation_id);
    let name = managed_fork_name(&fork_id);
    let copies = option_value(args, "--copies").unwrap_or_else(|| "1".to_string());
    let mut command = managed_cli_command(&[
        "run", "fork", &source_id, "--copies", &copies, "--name", &name, "--json",
    ])?;
    command.env("GENSEE_TCLONE_EXACT_FORK_NAME", "1");
    for approach in repeated_values(args, "--approach") {
        command.arg("--approach").arg(approach);
    }
    let output = run_managed_child(command, args)?;
    parse_child_json(&output.stdout)
        .map_err(|error| ManagedError::from_io("invalid_runtime_response", error))
}

fn merge_fork(args: &[OsString], _operation_id: &str) -> Result<Value, ManagedError> {
    let source = required_value(args, "--source-id")?;
    let fork = required_value(args, "--fork-id")?;
    let mut command = managed_cli_command(&["run", "merge", &fork, "--into", &source])?;
    if has_flag(args, "--dry-run") {
        command.arg("--dry-run");
    }
    run_managed_child(command, args)?;
    Ok(json!({"source_id": source, "fork_id": fork, "status": "merged"}))
}

fn promote_fork(args: &[OsString], _operation_id: &str) -> Result<Value, ManagedError> {
    let fork = required_value(args, "--fork-id")?;
    let command = managed_cli_command(&["run", "switch", &fork])?;
    run_managed_child(command, args)?;
    Ok(json!({"fork_id": fork, "status": "promoted"}))
}

fn discard_fork(args: &[OsString], _operation_id: &str) -> Result<Value, ManagedError> {
    let fork = required_value(args, "--fork-id")?;
    let command = managed_cli_command(&["run", "discard", &fork])?;
    run_managed_child(command, args)?;
    Ok(json!({"fork_id": fork, "status": "discarded"}))
}

fn diff_run(args: &[OsString]) -> Result<Value, ManagedError> {
    let run_id = required_value(args, "--run-id")?;
    let command = managed_cli_command(&["run", "diff", &run_id, "--json"])?;
    let output = run_child_without_journal(command)?;
    parse_child_json(&output.stdout)
        .map_err(|error| ManagedError::from_io("invalid_runtime_response", error))
}

fn status_allocation(args: &[OsString]) -> Result<Value, ManagedError> {
    let allocation_id = required_resource_id(args, "--allocation-id", "allocation ID")?;
    let source_id = managed_source_id(&allocation_id);
    let record = list_tclone_runs()
        .map_err(|error| ManagedError::from_io("state_read_failed", error))?
        .into_iter()
        .find(|record| record.run_id == source_id)
        .ok_or_else(|| {
            ManagedError::new(
                io::ErrorKind::NotFound,
                "not_found",
                format!("allocation {allocation_id} has no source"),
            )
        })?;
    Ok(source_result(&allocation_id, &record, false))
}

fn managed_list() -> Result<Value, ManagedError> {
    let runs = list_tclone_runs()
        .map_err(|error| ManagedError::from_io("state_read_failed", error))?
        .iter()
        .map(tclone_run_list_entry)
        .collect::<Vec<_>>();
    Ok(json!({"runs": runs}))
}

fn managed_reconcile() -> Result<Value, ManagedError> {
    let records =
        list_tclone_runs().map_err(|error| ManagedError::from_io("state_read_failed", error))?;
    let containers = managed_container_names()?;
    let tracked = records
        .iter()
        .map(|record| record.container_name.clone())
        .collect::<HashSet<_>>();
    let missing = records
        .iter()
        .filter(|record| !containers.contains(&record.container_name))
        .map(|record| record.run_id.clone())
        .collect::<Vec<_>>();
    let orphaned = containers
        .iter()
        .filter(|name| !tracked.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    Ok(json!({
        "record_count": records.len(),
        "container_count": containers.len(),
        "missing_container_run_ids": missing,
        "orphaned_container_names": orphaned,
        "runs": records.iter().map(tclone_run_list_entry).collect::<Vec<_>>(),
    }))
}

fn source_result(allocation_id: &str, record: &TcloneRunRecord, existing: bool) -> Value {
    json!({
        "allocation_id": allocation_id,
        "source_id": record.run_id,
        "container_name": record.container_name,
        "container_id": record.container_id,
        "status": record.status,
        "existing": existing,
    })
}

fn managed_source_id(allocation_id: &str) -> String {
    format!("managed_{allocation_id}")
}

fn managed_source_container_name(allocation_id: &str) -> String {
    format!(
        "gensee-tclone-src-{}",
        managed_source_id(allocation_id).replace('_', "-")
    )
}

fn managed_fork_name(fork_id: &str) -> String {
    format!("gensee-managed-fork-{fork_id}")
}

fn managed_container_names() -> Result<HashSet<String>, ManagedError> {
    let podman = env::var_os("GENSEE_TCLONE_PODMAN").unwrap_or_else(|| OsString::from("podman"));
    let output = Command::new(podman)
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
        .map_err(|error| ManagedError::from_io("podman_failed", error))?;
    if !output.status.success() {
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        return Err(ManagedError::new(
            io::ErrorKind::Other,
            "podman_failed",
            format!("podman exited with {}", output.status),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with("gensee-tclone-") || name.starts_with("gensee-managed-"))
        .map(ToString::to_string)
        .collect())
}

fn managed_cli_command(args: &[&str]) -> Result<Command, ManagedError> {
    let exe = env::current_exe().map_err(|error| ManagedError::from_io("runtime_failed", error))?;
    let mut command = Command::new(exe);
    command.args(args);
    Ok(command)
}

fn run_managed_child(
    mut command: Command,
    request_args: &[OsString],
) -> Result<std::process::Output, ManagedError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command
        .spawn()
        .map_err(|error| ManagedError::from_io("runtime_failed", error))?;
    if let Some(key) = option_value(request_args, "--idempotency-key") {
        update_child_pid(&key, child.id())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| ManagedError::from_io("runtime_failed", error))?;
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    if output.status.success() {
        Ok(output)
    } else {
        Err(ManagedError::new(
            io::ErrorKind::Other,
            "runtime_failed",
            format!("runtime command exited with {}", output.status),
        ))
    }
}

fn run_child_without_journal(mut command: Command) -> Result<std::process::Output, ManagedError> {
    command
        .output()
        .map_err(|error| ManagedError::from_io("runtime_failed", error))
        .and_then(|output| {
            if output.status.success() {
                Ok(output)
            } else {
                if !output.stderr.is_empty() {
                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                }
                Err(ManagedError::new(
                    io::ErrorKind::Other,
                    "runtime_failed",
                    format!("runtime command exited with {}", output.status),
                ))
            }
        })
}

fn parse_child_json(stdout: &[u8]) -> io::Result<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line.trim()).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "runtime emitted no JSON result"))
}

fn begin_operation(
    action: &str,
    operation_id: &str,
    idempotency_key: &str,
    allocation_id: Option<String>,
    fork_id: Option<String>,
    expected_copies: Option<usize>,
    fingerprint: &str,
) -> Result<BeginOperation, ManagedError> {
    let _lock = ManagedStateLock::acquire()?;
    let mut records = read_managed_operations()?;
    if records.iter().any(|record| {
        record.operation_id == operation_id && record.idempotency_key != idempotency_key
    }) {
        return Err(ManagedError::new(
            io::ErrorKind::AlreadyExists,
            "operation_id_conflict",
            "operation ID was already used with another idempotency key",
        ));
    }
    if let Some(record) = records
        .iter()
        .rev()
        .find(|record| record.idempotency_key == idempotency_key)
        .cloned()
    {
        if record.fingerprint != fingerprint || record.action != action {
            return Err(ManagedError::new(
                io::ErrorKind::AlreadyExists,
                "idempotency_conflict",
                "idempotency key was already used for a different request",
            ));
        }
        return match record.status.as_str() {
            "succeeded" => Ok(BeginOperation::Cached(
                record.result.unwrap_or_else(|| json!({})),
            )),
            "failed" => Err(ManagedError {
                body: record.error.unwrap_or(ManagedErrorBody {
                    code: "operation_failed".to_string(),
                    message: "the original operation failed".to_string(),
                    retryable: false,
                }),
                kind: io::ErrorKind::Other,
            }),
            "running"
                if managed_process_exists(record.runner_pid)
                    || record.child_pid.is_some_and(managed_process_exists) =>
            {
                Ok(BeginOperation::InProgress(json!({
                    "status": "running",
                    "operation_id": record.operation_id,
                })))
            }
            _ => Ok(BeginOperation::Recover(Box::new(record))),
        };
    }
    records.push(ManagedOperationRecord {
        operation_id: operation_id.to_string(),
        idempotency_key: idempotency_key.to_string(),
        action: action.to_string(),
        fingerprint: fingerprint.to_string(),
        allocation_id,
        status: "running".to_string(),
        runner_pid: std::process::id(),
        child_pid: None,
        fork_id,
        expected_copies,
        result: None,
        error: None,
        updated_at_ms: unix_millis()
            .map_err(|error| ManagedError::from_io("state_write_failed", error))?,
    });
    write_managed_operations_locked(&records)?;
    Ok(BeginOperation::Execute)
}

fn reconcile_interrupted(record: &ManagedOperationRecord) -> Result<Option<Value>, ManagedError> {
    match record.action.as_str() {
        "create-source" => {
            let Some(allocation_id) = record.allocation_id.as_deref() else {
                return Ok(None);
            };
            let source_id = managed_source_id(allocation_id);
            let recovered = list_tclone_runs()
                .map_err(|error| ManagedError::from_io("state_read_failed", error))?
                .into_iter()
                .find(|candidate| candidate.run_id == source_id)
                .map(|candidate| source_result(allocation_id, &candidate, true));
            if recovered.is_some() {
                return Ok(recovered);
            }
            if managed_container_names()?.contains(&managed_source_container_name(allocation_id)) {
                return Err(ManagedError::new(
                    io::ErrorKind::Other,
                    "partial_operation",
                    format!("source {source_id} has a container but no run record"),
                ));
            }
            Ok(None)
        }
        "delete-source" => {
            let Some(allocation_id) = record.allocation_id.as_deref() else {
                return Ok(None);
            };
            let source_id = managed_source_id(allocation_id);
            let record_exists = list_tclone_runs()
                .map_err(|error| ManagedError::from_io("state_read_failed", error))?
                .iter()
                .any(|candidate| candidate.run_id == source_id);
            let container_exists =
                managed_container_names()?.contains(&managed_source_container_name(allocation_id));
            if record_exists != container_exists {
                return Err(ManagedError::new(
                    io::ErrorKind::Other,
                    "partial_operation",
                    format!("source {source_id} has inconsistent runtime state"),
                ));
            }
            Ok((!record_exists).then(|| {
                json!({
                    "allocation_id": allocation_id,
                    "source_id": source_id,
                    "status": "deleted",
                    "recovered": true,
                })
            }))
        }
        "fork" => {
            let (Some(allocation_id), Some(fork_id), Some(expected_copies)) = (
                record.allocation_id.as_deref(),
                record.fork_id.as_deref(),
                record.expected_copies,
            ) else {
                return Ok(None);
            };
            let source_id = managed_source_id(allocation_id);
            let fork_name = managed_fork_name(fork_id);
            let forks = list_tclone_runs()
                .map_err(|error| ManagedError::from_io("state_read_failed", error))?
                .into_iter()
                .filter(|candidate| {
                    candidate.role == "fork"
                        && candidate.parent_run_id.as_deref() == Some(&source_id)
                        && candidate.fork_prefix.as_deref() == Some(&fork_name)
                })
                .collect::<Vec<_>>();
            if forks.is_empty() {
                return Ok(None);
            }
            if forks.len() != expected_copies {
                return Err(ManagedError::new(
                    io::ErrorKind::Other,
                    "partial_operation",
                    format!(
                        "fork {fork_id} recovered {} of {expected_copies} expected copies",
                        forks.len()
                    ),
                ));
            }
            let group_id = forks.first().and_then(|fork| fork.fork_group_id.clone());
            Ok(Some(json!({
                "source_run_id": source_id,
                "group_id": group_id,
                "attach": false,
                "recovered": true,
                "forks": forks.iter().map(managed_fork_result_entry).collect::<Vec<_>>(),
            })))
        }
        _ => Err(ManagedError::new(
            io::ErrorKind::Interrupted,
            "reconciliation_required",
            format!(
                "interrupted {} operation requires explicit reconciliation before retry",
                record.action
            ),
        )),
    }
}

fn managed_fork_result_entry(record: &TcloneRunRecord) -> Value {
    json!({
        "run_id": record.run_id,
        "container": record.container_name,
        "container_id": record.container_id,
        "role": record.role,
        "source_run_id": record.parent_run_id,
        "workspace": record.container_workspace,
        "group_id": record.fork_group_id,
        "index": record.fork_index,
        "approach": record.fork_approach,
    })
}

fn finish_operation(
    idempotency_key: &str,
    status: &str,
    result: Option<Value>,
    error: Option<ManagedErrorBody>,
) -> Result<(), ManagedError> {
    let _lock = ManagedStateLock::acquire()?;
    let mut records = read_managed_operations()?;
    let record = records
        .iter_mut()
        .rev()
        .find(|record| record.idempotency_key == idempotency_key)
        .ok_or_else(|| {
            ManagedError::new(
                io::ErrorKind::NotFound,
                "state_missing",
                "operation record is missing",
            )
        })?;
    record.status = status.to_string();
    record.child_pid = None;
    record.result = result;
    record.error = error;
    record.updated_at_ms =
        unix_millis().map_err(|error| ManagedError::from_io("state_write_failed", error))?;
    write_managed_operations_locked(&records)
}

fn update_child_pid(idempotency_key: &str, child_pid: u32) -> Result<(), ManagedError> {
    let _lock = ManagedStateLock::acquire()?;
    let mut records = read_managed_operations()?;
    if let Some(record) = records
        .iter_mut()
        .rev()
        .find(|record| record.idempotency_key == idempotency_key)
    {
        record.child_pid = Some(child_pid);
        record.updated_at_ms =
            unix_millis().map_err(|error| ManagedError::from_io("state_write_failed", error))?;
        write_managed_operations_locked(&records)?;
    }
    Ok(())
}

fn managed_operations_path() -> Result<PathBuf, ManagedError> {
    Ok(default_root()
        .map_err(|error| ManagedError::from_io("state_path_failed", error))?
        .join(MANAGED_STATE_FILE))
}

fn read_managed_operations() -> Result<Vec<ManagedOperationRecord>, ManagedError> {
    let path = managed_operations_path()?;
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).map_err(|error| {
            ManagedError::new(
                io::ErrorKind::InvalidData,
                "state_corrupt",
                error.to_string(),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(ManagedError::from_io("state_read_failed", error)),
    }
}

fn write_managed_operations_locked(records: &[ManagedOperationRecord]) -> Result<(), ManagedError> {
    let path = managed_operations_path()?;
    let parent = path.parent().ok_or_else(|| {
        ManagedError::new(
            io::ErrorKind::InvalidInput,
            "state_path_failed",
            "managed state has no parent",
        )
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| ManagedError::from_io("state_write_failed", error))?;
    let temp = parent.join(format!(".managed-operations-{}.tmp", std::process::id()));
    let contents = serde_json::to_vec_pretty(records).map_err(|error| {
        ManagedError::new(
            io::ErrorKind::InvalidData,
            "state_write_failed",
            error.to_string(),
        )
    })?;
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temp)
        .map_err(|error| ManagedError::from_io("state_write_failed", error))?;
    file.write_all(&contents)
        .and_then(|_| file.sync_all())
        .map_err(|error| ManagedError::from_io("state_write_failed", error))?;
    fs::rename(temp, path).map_err(|error| ManagedError::from_io("state_write_failed", error))
}

struct ManagedStateLock {
    path: PathBuf,
}

impl ManagedStateLock {
    fn acquire() -> Result<Self, ManagedError> {
        let state_path = managed_operations_path()?;
        let parent = state_path.parent().ok_or_else(|| {
            ManagedError::new(
                io::ErrorKind::InvalidInput,
                "state_path_failed",
                "managed state has no parent",
            )
        })?;
        fs::create_dir_all(parent)
            .map_err(|error| ManagedError::from_io("state_write_failed", error))?;
        let lock_path = parent.join("managed-operations.lock");
        for _ in 0..500 {
            match fs::create_dir(&lock_path) {
                Ok(()) => {
                    fs::write(lock_path.join("pid"), std::process::id().to_string())
                        .map_err(|error| ManagedError::from_io("state_write_failed", error))?;
                    return Ok(Self { path: lock_path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if managed_lock_is_stale(&lock_path)? {
                        let _ = fs::remove_dir_all(&lock_path);
                        continue;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    return Err(ManagedError::from_io("state_write_failed", error));
                }
            }
        }
        Err(ManagedError::new(
            io::ErrorKind::WouldBlock,
            "state_busy",
            "timed out waiting for the managed operation journal lock",
        ))
    }
}

impl Drop for ManagedStateLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn managed_lock_is_stale(lock_path: &Path) -> Result<bool, ManagedError> {
    if let Some(pid) = fs::read_to_string(lock_path.join("pid"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
    {
        if !managed_process_exists(pid) {
            return Ok(true);
        }
    }
    let age = fs::metadata(lock_path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok());
    Ok(age.is_some_and(|age| age.as_secs() >= MANAGED_STATE_LOCK_STALE_SECS))
}

fn managed_fingerprint(action: &str, args: &[OsString]) -> Result<String, ManagedError> {
    let normalized = args
        .iter()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&(action, normalized)).map_err(|error| {
        ManagedError::new(
            io::ErrorKind::InvalidData,
            "invalid_request",
            error.to_string(),
        )
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(target_os = "linux")]
fn managed_process_exists(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn managed_process_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
fn managed_process_exists(_pid: u32) -> bool {
    true
}

fn required_id(args: &[OsString], name: &str, label: &str) -> Result<String, ManagedError> {
    let value = required_value(args, name)?;
    validate_managed_id(label, &value)
        .map_err(|error| ManagedError::from_io("invalid_request", error))?;
    Ok(value)
}

fn required_resource_id(
    args: &[OsString],
    name: &str,
    label: &str,
) -> Result<String, ManagedError> {
    let value = required_value(args, name)?;
    validate_managed_resource_id(label, &value)
        .map_err(|error| ManagedError::from_io("invalid_request", error))?;
    Ok(value)
}

fn required_value(args: &[OsString], name: &str) -> Result<String, ManagedError> {
    option_value(args, name)
        .ok_or_else(|| ManagedError::invalid(format!("missing required option {name}")))
}

fn option_value(args: &[OsString], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    args.iter().enumerate().find_map(|(index, arg)| {
        let value = arg.to_str()?;
        if value == name {
            args.get(index + 1)?.to_str().map(ToString::to_string)
        } else {
            value.strip_prefix(&prefix).map(ToString::to_string)
        }
    })
}

fn repeated_values(args: &[OsString], name: &str) -> Vec<String> {
    let prefix = format!("{name}=");
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index].to_str() == Some(name) {
            if let Some(value) = args.get(index + 1).and_then(|value| value.to_str()) {
                values.push(value.to_string());
                index += 2;
                continue;
            }
        } else if let Some(value) = args[index]
            .to_str()
            .and_then(|value| value.strip_prefix(&prefix))
        {
            values.push(value.to_string());
        }
        index += 1;
    }
    values
}

fn has_flag(args: &[OsString], name: &str) -> bool {
    args.iter().any(|arg| arg.to_str() == Some(name))
}

fn values_after_separator(args: &[OsString]) -> Vec<OsString> {
    args.iter()
        .position(|arg| arg.to_str() == Some("--"))
        .map(|index| args[index + 1..].to_vec())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_ids_reject_path_components() {
        assert!(validate_managed_id("allocation ID", "user-123_session_2").is_ok());
        assert!(validate_managed_id("allocation ID", "../escape").is_err());
        assert!(validate_managed_id("allocation ID", "has space").is_err());
        assert!(validate_managed_resource_id("allocation ID", &"a".repeat(37)).is_ok());
        assert!(validate_managed_resource_id("allocation ID", &"a".repeat(38)).is_err());
        assert!(validate_managed_source_id("source ID", &"a".repeat(45)).is_ok());
        assert!(validate_managed_source_id("source ID", &"a".repeat(46)).is_err());
    }

    #[test]
    fn managed_fingerprint_is_stable_and_request_specific() {
        let first = vec![
            OsString::from("--allocation-id"),
            OsString::from("a"),
            OsString::from("--operation-id"),
            OsString::from("one"),
        ];
        let second = vec![
            OsString::from("--allocation-id"),
            OsString::from("b"),
            OsString::from("--operation-id"),
            OsString::from("one"),
        ];
        assert_eq!(
            managed_fingerprint("create-source", &first).unwrap(),
            managed_fingerprint("create-source", &first).unwrap()
        );
        assert_ne!(
            managed_fingerprint("create-source", &first).unwrap(),
            managed_fingerprint("create-source", &second).unwrap()
        );
    }

    #[test]
    fn managed_source_and_fork_names_are_deterministic() {
        assert_eq!(managed_source_id("allocation-1"), "managed_allocation-1");
        assert_eq!(
            managed_source_container_name("allocation_1"),
            "gensee-tclone-src-managed-allocation-1"
        );
        assert_eq!(managed_fork_name("fork-1"), "gensee-managed-fork-fork-1");
    }
}
