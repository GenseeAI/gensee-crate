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
//! If the daemon is not running the client returns `false` and the caller falls
//! back to the in-process path, so enforcement is never silently skipped.

use crate::*;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

const NO_HOOK_OUTPUT: &str = "__gensee_no_hook_output__";
pub(crate) const EVENT_STORE_APPEND_SESSION: &str = "event_store_append_session";
pub(crate) const EVENT_STORE_APPEND_TRANSACTION: &str = "event_store_append_transaction";
const EVENT_STORE_APPEND_TCLONE_HOOK: &str = "event_store_append_tclone_hook";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaemonResponseMode {
    Required,
    Optional,
    FireAndForget,
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
    // Clear a stale socket from a previous (crashed) daemon so bind() succeeds.
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let store = Arc::new(EventStore::default_local()?);
    eprintln!("gensee daemon: listening on {}", socket.display());

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    if let Err(err) = serve_connection(stream, &store) {
                        eprintln!("gensee daemon: connection error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("gensee daemon: accept error: {err}"),
        }
    }
    Ok(())
}

/// Read one hook event from `stream`, process it against the warm store, and
/// write back any hook output `process_hook_event` produces (a PreToolUse
/// decision or an advisory counter-instruction). The client half-closes
/// its write side after sending, so `read_to_string` returns at end of request.
pub(crate) fn serve_connection(mut stream: UnixStream, store: &EventStore) -> io::Result<()> {
    let mut request = String::new();
    stream.read_to_string(&mut request)?;
    let value = serde_json::from_str::<Value>(&request).ok();
    if let Some(value) =
        value.filter(|value| value.get("operation").and_then(Value::as_str).is_some())
    {
        return serve_event_store_request(&mut stream, store, value);
    }
    let (payload, provider, tclone_context_run_id) = match daemon_request_parts(&request) {
        Ok(parts) => parts,
        Err(_) => return Ok(()), // malformed request: nothing to do, nothing to answer
    };
    let event = match build_hook_event_with_tclone_context(
        &payload,
        &provider,
        tclone_context_run_id.as_deref(),
    ) {
        Ok(event) => event,
        Err(_) => return Ok(()), // malformed payload: nothing to do, nothing to answer
    };
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
            }
        }
    }
    if let Some(decision_json) = process_hook_event(&payload, &event, store)? {
        // Best-effort: the client may have already gone away on a non-blocking
        // event; that is not an error worth failing the connection over.
        let _ = stream.write_all(decision_json.as_bytes());
    } else if daemon_response_mode(&event) == DaemonResponseMode::Required {
        let _ = stream.write_all(NO_HOOK_OUTPUT.as_bytes());
    }
    Ok(())
}

fn serve_event_store_request(
    stream: &mut impl Write,
    store: &EventStore,
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
                store.append_session(&session)
            }
            Some(EVENT_STORE_APPEND_TRANSACTION) => {
                let event =
                    serde_json::from_value::<TransactionEventInput>(input).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                store.append_transaction_event(&event).map(|_| ())
            }
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
                let run_id = input.get("run_id").and_then(Value::as_str).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tclone observation is missing its run id",
                    )
                })?;
                let capability =
                    input
                        .get("capability")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "tclone observation is missing its capability",
                            )
                        })?;
                authenticate_tclone_observation(run_id, capability)?;
                scope_tclone_observation_event(&mut event, run_id)?;
                store.append_hook_event(&event)
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
    let Some(socket) = env::var_os(TCLONE_HOST_DAEMON_SOCKET_ENV).map(PathBuf::from) else {
        return Ok(());
    };
    let Some((run_id, capability)) = current_tclone_observation_credentials()? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host observation socket is configured without a tclone run context",
        ));
    };
    dispatch_event_store_request_to_socket(
        &socket,
        EVENT_STORE_APPEND_TCLONE_HOOK,
        &json!({
            "event": event,
            "run_id": run_id,
            "capability": capability,
        }),
    )
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

pub(crate) fn daemon_append_session(session: &AgentSession) -> io::Result<()> {
    dispatch_event_store_request(EVENT_STORE_APPEND_SESSION, session)
}

pub(crate) fn daemon_append_transaction_event(event: &TransactionEventInput) -> io::Result<()> {
    dispatch_event_store_request(EVENT_STORE_APPEND_TRANSACTION, event)
}

pub(crate) fn daemon_request_parts(request: &str) -> io::Result<(String, String, Option<String>)> {
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
    Ok((payload, provider, tclone_context_run_id))
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
) -> bool {
    if let Err(error) = dispatch_tclone_hook_observation(event) {
        eprintln!("gensee hook: could not mirror tclone event to the host daemon: {error}");
    }
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
            if !response.trim().is_empty() {
                print!("{response}");
            }
            true
        }
        DaemonResponseMode::FireAndForget => {
            // Observational (PostToolUse/Stop): fire-and-forget off the critical
            // path — the daemon records it; we don't wait for the store write.
            true
        }
    }
}

pub(crate) fn daemon_response_mode(event: &AgentHookEvent) -> DaemonResponseMode {
    match event.hook_event_name.as_deref() {
        Some("PreToolUse" | "PermissionRequest") => DaemonResponseMode::Required,
        Some("UserPromptSubmit") => DaemonResponseMode::Optional,
        // A newly live-cloned fork can use Stop to force one continuation when
        // the inherited orchestration turn ends before task work begins.
        Some("Stop") if event.provider == PROVIDER_CODEX => DaemonResponseMode::Optional,
        Some("PreInvocation" | "PostToolUse" | "Stop")
            if event.provider == PROVIDER_ANTIGRAVITY =>
        {
            DaemonResponseMode::Optional
        }
        _ => DaemonResponseMode::FireAndForget,
    }
}

#[cfg(test)]
mod tclone_observation_tests {
    use super::*;

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
