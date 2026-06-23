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
//!   * **PostToolUse / UserPromptSubmit / Stop** (observational, never block):
//!     the client writes and returns immediately — the store write happens on
//!     the daemon, off the agent's critical path. Full lineage is still
//!     recorded; it just no longer costs the agent latency.
//!
//! If the daemon is not running the client returns `false` and the caller falls
//! back to the in-process path, so enforcement is never silently skipped.

use crate::*;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

const NO_HOOK_OUTPUT: &str = "__gensee_no_hook_output__";

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
/// decision or a UserPromptSubmit counter-instruction). The client half-closes
/// its write side after sending, so `read_to_string` returns at end of request.
pub(crate) fn serve_connection(mut stream: UnixStream, store: &EventStore) -> io::Result<()> {
    let mut request = String::new();
    stream.read_to_string(&mut request)?;
    let (payload, provider) = match daemon_request_parts(&request) {
        Ok(parts) => parts,
        Err(_) => return Ok(()), // malformed request: nothing to do, nothing to answer
    };
    let event = match build_hook_event(&payload, &provider) {
        Ok(event) => event,
        Err(_) => return Ok(()), // malformed payload: nothing to do, nothing to answer
    };
    if let Some(decision_json) = process_hook_event(&payload, &event, store)? {
        // Best-effort: the client may have already gone away on a non-blocking
        // event; that is not an error worth failing the connection over.
        let _ = stream.write_all(decision_json.as_bytes());
    } else if matches!(
        event.hook_event_name.as_deref(),
        Some("PreToolUse" | "PermissionRequest")
    ) {
        let _ = stream.write_all(NO_HOOK_OUTPUT.as_bytes());
    }
    Ok(())
}

pub(crate) fn daemon_request_parts(request: &str) -> io::Result<(String, String)> {
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
    Ok((payload, provider))
}

/// Client fast path. Returns `true` if the event was fully handled via the
/// daemon (and, for PreToolUse, the decision was written to stdout). Returns
/// `false` if the daemon is unreachable or the round trip failed, so the caller
/// falls back to in-process evaluation (never skipping enforcement).
pub(crate) fn dispatch_via_daemon(payload: &str, event: &AgentHookEvent) -> bool {
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
    })
    .to_string();
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    // Signal end-of-request so the daemon's read_to_string returns.
    if stream.shutdown(std::net::Shutdown::Write).is_err() {
        return false;
    }

    match event.hook_event_name.as_deref() {
        Some("PreToolUse" | "PermissionRequest") => {
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
        Some("UserPromptSubmit") => {
            // Synchronous but advisory: the daemon runs the memory/skill
            // integrity scan and returns an `additionalContext` counter-
            // instruction ONLY when poison is found. An empty response is the
            // normal clean case (not a failure), so print it if present and
            // never fall back on empty; only a read error falls back.
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_err() {
                return false;
            }
            if !response.trim().is_empty() {
                print!("{response}");
            }
            true
        }
        _ => {
            // Observational (PostToolUse/Stop): fire-and-forget off the critical
            // path — the daemon records it; we don't wait for the store write.
            true
        }
    }
}
