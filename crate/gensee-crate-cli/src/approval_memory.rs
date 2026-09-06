use crate::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;

use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;

pub(crate) const FILE_NAME: &str = "approvals.json";
pub(crate) const LOCK_FILE_NAME: &str = "approvals.lock";
const TEMP_PREFIX: &str = ".approvals-";

pub(crate) fn is_store_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == FILE_NAME || n == LOCK_FILE_NAME || n.starts_with(TEMP_PREFIX))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Approval {
    pub id: String,
    pub key: String,
    pub provider: String,
    pub project: String,
    pub path: String,
    pub rule: String,
    pub scope: String,
    pub session: String,
    pub expires_at: u64,
    pub remaining: Option<u64>,
    pub revoked: bool,
    #[serde(default)]
    pub content_digest: String,
    #[serde(default)]
    pub key_version: u32,
    #[serde(default)]
    pub read_scope: Option<String>,
    #[serde(default)]
    pub source_alert_id: Option<i64>,
    #[serde(default)]
    pub created_at: u64,
}

fn eligible(rule: &str) -> bool {
    matches!(
        rule,
        "policy_write_outside_workspace"
            | "policy_credential_content_read"
            | "policy_executable_content_unavailable"
            | "policy_unmatched_executable_modification"
            | "policy_prior_session_executable_artifact"
    )
}

// Inspect shell syntax before tokenization removes quote information. Quoted
// search patterns such as "reconnect()" are literals, not command substitution.
fn static_shell_command(command: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('\'') {
            if c == '\'' {
                quote = None;
            }
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if matches!(c, '$' | '`') {
            return false;
        }
        if quote == Some('"') {
            if c == '"' {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '\n' | '(' | ')' => return false,
            _ => {}
        }
    }
    quote.is_none() && !escaped
}

fn context(event: &AgentHookEvent, rule: &str, path: &str) -> io::Result<Approval> {
    if !eligible(rule) || !is_supported_provider(&event.provider) {
        return Err(io::Error::other(
            "This rule cannot be overridden by a remembered approval.",
        ));
    }
    let session = event
        .session_id
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| io::Error::other("No captured session identity."))?;
    let cwd = event
        .cwd
        .as_deref()
        .ok_or_else(|| io::Error::other("No captured working directory."))?;
    let command = event.tool_input_command.as_deref().unwrap_or("");
    if !static_shell_command(command) {
        return Err(io::Error::other(
            "Dynamic shell commands require a fresh approval.",
        ));
    }
    let working_directory = fs::canonicalize(cwd)?;
    let project = fs::canonicalize(leading_bash_effective_cwd(command, cwd))?;
    if project.parent().is_none() {
        return Err(io::Error::other(
            "Cannot remember an approval for the filesystem root.",
        ));
    }
    let path = gensee_crate_core::resolve_concrete_path(path)
        .ok_or_else(|| io::Error::other("The target path cannot be resolved safely."))?;
    let mut input = serde_json::from_str::<Value>(&event.raw_json)?;
    input = input
        .get("tool_input")
        .cloned()
        .ok_or_else(|| io::Error::other("No captured tool input."))?;
    if input.to_string().contains("<redacted>")
        || input.get("truncated").and_then(Value::as_bool) == Some(true)
    {
        return Err(io::Error::other(
            "Redacted or truncated tool input requires a fresh approval.",
        ));
    }
    if let Some(object) = input.as_object_mut() {
        object.remove("tool_use_id");
    }
    let digest = if rule == "policy_write_outside_workspace" {
        String::new()
    } else {
        let snapshot = read_small_artifact_content(&path.to_string_lossy())?.ok_or_else(|| {
            io::Error::other("Unreadable or oversized files cannot receive remembered approval.")
        })?;
        if snapshot.truncated {
            return Err(io::Error::other(
                "The complete file must be inspected before remembering approval.",
            ));
        }
        snapshot.digest
    };
    let key = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&json!({
            "version":2,"provider":event.provider,"tool":event.tool_name,"input":input,"rule":rule,
            "project":project,"working_directory":working_directory,"path":path,"digest":digest
        }))?)
    );
    Ok(Approval {
        id: uuid::Uuid::new_v4().to_string(),
        key,
        provider: event.provider.clone(),
        project: project.to_string_lossy().into_owned(),
        path: path.to_string_lossy().into_owned(),
        rule: rule.into(),
        scope: "once".into(),
        session,
        expires_at: 0,
        remaining: Some(1),
        revoked: false,
        content_digest: digest,
        key_version: 2,
        read_scope: None,
        source_alert_id: None,
        created_at: 0,
    })
}

const SCOPED_READ_RULE: &str = "policy_credential_content_read";

struct ReadTarget {
    provider: String,
    project: PathBuf,
    path: PathBuf,
}

fn read_target(event: &AgentHookEvent, rule: &str, path: &str) -> io::Result<ReadTarget> {
    if rule != SCOPED_READ_RULE || !is_supported_provider(&event.provider) {
        return Err(io::Error::other(
            "This finding does not support a read exception.",
        ));
    }
    let raw: Value = serde_json::from_str(&event.raw_json)?;
    let input = raw
        .get("tool_input")
        .ok_or_else(|| io::Error::other("Missing captured input."))?;
    if input.to_string().contains("<redacted>") || input.get("truncated") == Some(&json!(true)) {
        return Err(io::Error::other(
            "Incomplete input requires a fresh request.",
        ));
    }
    let command = event.tool_input_command.as_deref().unwrap_or("");
    if !static_shell_command(command) {
        return Err(io::Error::other(
            "Dynamic commands require a fresh approval.",
        ));
    }
    let cwd = event
        .cwd
        .as_deref()
        .ok_or_else(|| io::Error::other("Missing project."))?;
    // Explicit read exceptions apply to future content. A temporary file (or
    // worktree) may already be gone; resolve existing ancestors without treating
    // dangling symlinks or inaccessible paths as ordinary missing leaves.
    let project =
        gensee_crate_core::resolve_concrete_path(&leading_bash_effective_cwd(command, cwd))
            .ok_or_else(|| io::Error::other("The recorded project cannot be resolved safely."))?;
    let path = gensee_crate_core::resolve_concrete_path(path)
        .ok_or_else(|| io::Error::other("The recorded file cannot be resolved safely."))?;
    let ordinary_file = match fs::metadata(&path) {
        Ok(metadata) => metadata.is_file(),
        Err(error) => error.kind() == io::ErrorKind::NotFound,
    };
    if project.parent().is_none() || !ordinary_file {
        return Err(io::Error::other(
            "Read exceptions require a concrete file and project.",
        ));
    }
    let intents = file_intents_from_hook(event, event.tool_input_command.as_deref());
    let subjects = policy_subjects(event, &intents);
    if !subjects.iter().any(|s| {
        s.operation == "read"
            && gensee_crate_core::resolve_concrete_path(&s.path).as_ref() == Some(&path)
    }) {
        return Err(io::Error::other(
            "The original call does not establish a read of this file.",
        ));
    }
    Ok(ReadTarget {
        provider: event.provider.clone(),
        project,
        path,
    })
}

fn read_exception(
    event: &AgentHookEvent,
    captured: &Value,
    scope: &str,
    requested_path: &str,
    id: i64,
) -> io::Result<Approval> {
    let target = read_target(
        event,
        captured["rule"].as_str().unwrap_or(""),
        captured["path"].as_str().unwrap_or(""),
    )?;
    let path = gensee_crate_core::resolve_concrete_path(requested_path)
        .ok_or_else(|| io::Error::other("The exception path cannot be resolved safely."))?;
    let home = env::var("HOME").ok().and_then(|p| fs::canonicalize(p).ok());
    let valid = match scope {
        "file" => path == target.path,
        "directory" => {
            path.is_dir()
                && path.parent().is_some()
                && home.as_ref() != Some(&path)
                && path != target.path
                && target.path.starts_with(&path)
        }
        _ => false,
    };
    if !valid {
        return Err(io::Error::other(
            "Choose this file or a containing folder; filesystem and home roots are not supported.",
        ));
    }
    let key = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&json!({
            "version":3,"provider":target.provider,"project":target.project,"path":path,
            "read_scope":scope,"rule":SCOPED_READ_RULE,"source_alert_id":id
        }))?)
    );
    Ok(Approval {
        id: uuid::Uuid::new_v4().to_string(),
        key,
        provider: target.provider,
        project: target.project.to_string_lossy().into_owned(),
        path: path.to_string_lossy().into_owned(),
        rule: SCOPED_READ_RULE.into(),
        scope: "project".into(),
        session: event.session_id.clone().unwrap_or_default(),
        expires_at: 0,
        remaining: None,
        revoked: false,
        content_digest: String::new(),
        key_version: 3,
        read_scope: Some(scope.into()),
        source_alert_id: Some(id),
        created_at: 0,
    })
}

fn matches_read_exception(a: &Approval, target: &ReadTarget) -> bool {
    if a.key_version != 3
        || a.rule != SCOPED_READ_RULE
        || a.provider != target.provider
        || Path::new(&a.project) != target.project
        || a.scope != "project"
    {
        return false;
    }
    let root = Path::new(&a.path);
    // A replaced directory symlink must not redirect an existing permission.
    if fs::canonicalize(root).ok().as_deref() != Some(root) {
        return false;
    }
    match a.read_scope.as_deref() {
        Some("file") => root == target.path,
        Some("directory") => root != target.path && target.path.starts_with(root),
        _ => false,
    }
}

// A single lock covers matching and consuming one-use grants across hook processes.
// The file is local, owner-only, and never accepts symlinks. Errors retain ASK.
fn with_records<T>(
    root: &Path,
    action: impl FnOnce(&mut Vec<Approval>) -> io::Result<(T, bool)>,
) -> io::Result<T> {
    let root_meta = fs::metadata(root)?;
    if !root_meta.is_dir()
        || root_meta.uid() != unsafe { libc::geteuid() }
        || root_meta.mode() & 0o022 != 0
    {
        return Err(io::Error::other("Unsafe approval directory."));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(LOCK_FILE_NAME))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other("Unsafe approval lock permissions."));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other(
            "Approval store is busy; retry the action.",
        ));
    }
    let path = root.join(FILE_NAME);
    let mut records: Vec<Approval> = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => {
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 4_000_000
            {
                return Err(io::Error::other("Unsafe approval store."));
            }
            serde_json::from_reader(file)?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let (result, dirty) = action(&mut records)?;
    if dirty {
        let temp = root.join(format!("{TEMP_PREFIX}{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp)?;
        let save = (|| {
            let encoded = serde_json::to_vec_pretty(&records)?;
            if encoded.len() > 4_000_000 {
                return Err(io::Error::other("Approval history is full."));
            }
            file.write_all(&encoded)?;
            file.sync_all()?;
            fs::rename(&temp, &path)?;
            fs::File::open(root)?.sync_all()
        })();
        if save.is_err() {
            let _ = fs::remove_file(temp);
        }
        save?;
    }
    Ok(result)
}

fn active(a: &Approval, now: u64) -> bool {
    matches!(a.key_version, 2 | 3) && !a.revoked && a.expires_at > now && a.remaining != Some(0)
}

pub(crate) fn apply(event: &AgentHookEvent, store: &EventStore, findings: &mut [PolicyFinding]) {
    if !store.root_path().join(FILE_NAME).exists() {
        return;
    }
    if findings.iter().any(|f| f.action == PolicyAction::Block) {
        return;
    }
    let asks: Vec<_> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.action == PolicyAction::Ask
                || (f.action == PolicyAction::Warn && f.rule_id == SCOPED_READ_RULE)
        })
        .collect();
    if asks.is_empty() {
        return;
    }
    let candidates: Vec<_> = asks
        .iter()
        .map(|(i, f)| {
            (
                *i,
                f.action == PolicyAction::Ask,
                context(event, &f.rule_id, f.path.as_deref().unwrap_or("")).ok(),
                read_target(event, &f.rule_id, f.path.as_deref().unwrap_or("")).ok(),
            )
        })
        .collect();
    let now = unix_millis().unwrap_or(u64::MAX);
    let ended = store.approval_session_has_ended(event.session_id.as_deref().unwrap_or(""));
    let Ok(ended) = ended else {
        return;
    };
    let selected = with_records(store.root_path(), |records| {
        let mut selected = Vec::new();
        for (finding, is_ask, exact, read) in &candidates {
            let index = records
                .iter()
                .position(|a| {
                    active(a, now)
                        && read
                            .as_ref()
                            .is_some_and(|target| matches_read_exception(a, target))
                })
                .or_else(|| {
                    if *is_ask {
                        records.iter().position(|a| {
                            active(a, now)
                                && a.key_version == 2
                                && exact.as_ref().is_some_and(|context| {
                                    a.key == context.key
                                        && (a.scope == "project"
                                            || (!ended && a.session == context.session))
                                })
                        })
                    } else {
                        None
                    }
                });
            let Some(index) = index else {
                if *is_ask {
                    return Ok((Vec::new(), false));
                }
                continue;
            };
            selected.push((
                *finding,
                index,
                records[index].id.clone(),
                records[index].read_scope.is_some(),
            ));
        }
        let mut used = std::collections::HashSet::new();
        let mut consumed = false;
        for (_, index, _, _) in &selected {
            if used.insert(*index) {
                if let Some(remaining) = records[*index].remaining.as_mut() {
                    *remaining -= 1;
                    consumed = true;
                }
            }
        }
        Ok((selected, consumed))
    });
    if let Ok(selected) = selected {
        for (index, _, id, is_read_exception) in selected {
            findings[index].evidence["original_response"] = json!({"action":format!("{:?}", findings[index].action).to_lowercase(),"severity":findings[index].severity,"message":findings[index].message});
            if is_read_exception {
                findings[index].evidence["scoped_read_exception_id"] = json!(id);
            }
            findings[index].action = PolicyAction::Allow;
            findings[index].severity = "info".into();
            findings[index].message = format!(
                "Allowed by {}: {}",
                if is_read_exception {
                    "read exception"
                } else {
                    "remembered approval"
                },
                findings[index].path.as_deref().unwrap_or("")
            );
            findings[index].evidence["remembered_approval_id"] = json!(id);
        }
    }
}

pub(crate) fn handle(args: Vec<OsString>) -> io::Result<()> {
    let verb = args.first().and_then(|v| v.to_str()).unwrap_or("list");
    let flags = parse_named_flags(
        &args.iter().skip(1).cloned().collect::<Vec<_>>(),
        "approval",
    )?;
    if matches!(verb, "grant" | "grant-read" | "revoke") {
        require_app_caller()?;
    }
    let store = EventStore::default_local()?;
    let now = unix_millis()?;
    let value = match verb {
        "list" => {
            let ended: HashSet<_> = store
                .list_sessions()?
                .into_iter()
                .filter(|s| s.ended_at_ms.is_some())
                .map(|s| s.session_id)
                .collect();
            with_records(store.root_path(), |records| {
                Ok((
                    json!(records
                        .iter()
                        .filter(|a| active(a, now)
                            && (a.scope == "project" || !ended.contains(&a.session)))
                        .collect::<Vec<_>>()),
                    false,
                ))
            })?
        }
        "revoke" => {
            let id = flags
                .get("id")
                .ok_or_else(|| io::Error::other("Missing approval ID."))?;
            with_records(store.root_path(), |records| {
                let a = records
                    .iter_mut()
                    .find(|a| &a.id == id)
                    .ok_or_else(|| io::Error::other("Approval not found."))?;
                a.revoked = true;
                Ok((json!({"revoked":id}), true))
            })?
        }
        "preview-read" | "grant-read" => {
            let id = flags
                .get("alert-id")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or_else(|| io::Error::other("Missing alert ID."))?;
            let captured = store.approval_context(id)?;
            let event = build_unattributed_hook_event(
                &captured["payload"].to_string(),
                captured["provider"].as_str().unwrap_or(""),
            )?;
            let scope = flags
                .get("read-scope")
                .map(String::as_str)
                .unwrap_or("file");
            let path = flags
                .get("path")
                .map(String::as_str)
                .unwrap_or_else(|| captured["path"].as_str().unwrap_or(""));
            let mut approval = read_exception(&event, &captured, scope, path, id)?;
            approval.created_at = now;
            approval.expires_at = now + 30 * 86_400_000;
            if verb == "preview-read" {
                json!(approval)
            } else {
                if flags.get("expected-key") != Some(&approval.key) {
                    return Err(io::Error::other(
                        "Scope changed after preview. Review it again.",
                    ));
                }
                with_records(store.root_path(), |records| {
                    if records.len() >= 2048 {
                        return Err(io::Error::other("Approval history is full."));
                    }
                    records.push(approval.clone());
                    Ok((json!(approval), true))
                })?
            }
        }
        "preview" | "grant" => {
            let id: i64 = flags
                .get("alert-id")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| io::Error::other("Missing alert ID."))?;
            let captured = store.approval_context(id)?;
            let payload = captured["payload"].to_string();
            let provider = captured["provider"]
                .as_str()
                .ok_or_else(|| io::Error::other("No provider."))?;
            let event = build_unattributed_hook_event(&payload, provider)?;
            let mut approval = context(
                &event,
                captured["rule"].as_str().unwrap_or(""),
                captured["path"].as_str().unwrap_or(""),
            )?;
            verify_captured_digest(&approval, &captured)?;
            if verb == "preview" {
                let mut preview = json!(approval);
                preview["tool_input_preview"] =
                    json!(captured["payload"]["tool_input"].to_string());
                preview
            } else {
                if flags.get("expected-key") != Some(&approval.key) {
                    return Err(io::Error::other(
                        "The target changed after preview. Review it again.",
                    ));
                }
                approval.scope = flags.get("scope").cloned().unwrap_or_else(|| "once".into());
                let days = match approval.scope.as_str() {
                    "once" | "session" => 1,
                    "project" => 30,
                    _ => return Err(io::Error::other("Unknown approval scope.")),
                };
                approval.expires_at = now + days * 86_400_000;
                approval.remaining = (approval.scope == "once").then_some(1);
                if approval.scope != "project"
                    && store.approval_session_has_ended(&approval.session)?
                {
                    return Err(io::Error::other(
                        "This session has ended. Choose a project approval instead.",
                    ));
                }
                with_records(store.root_path(), |records| {
                    if records.len() >= 2048 {
                        return Err(io::Error::other("Approval history is full."));
                    }
                    records.push(approval.clone());
                    Ok((json!(approval), true))
                })?
            }
        }
        _ => {
            return Err(io::Error::other(
                "Use approval list, preview, grant, preview-read, grant-read, or revoke.",
            ))
        }
    };
    println!("{value}");
    Ok(())
}

fn verify_captured_digest(approval: &Approval, captured: &Value) -> io::Result<()> {
    if approval.rule != "policy_write_outside_workspace"
        && captured["approval_content_digest"].as_str() != Some(approval.content_digest.as_str())
    {
        return Err(io::Error::other("The file changed since the alert, or its original content was not fully inspected. Retry the action to capture a new approval request."));
    }
    Ok(())
}

fn require_app_caller() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut path = vec![0u8; 4096];
        let length = unsafe {
            libc::proc_pidpath(libc::getppid(), path.as_mut_ptr().cast(), path.len() as u32)
        };
        let path = if length > 0 {
            String::from_utf8_lossy(&path[..length as usize])
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };
        if path != "/Applications/Gensee Crate.app/Contents/MacOS/Gensee Crate" {
            return Err(io::Error::other(
                "Save or revoke approvals through the installed Gensee app.",
            ));
        }
        if !Command::new("/usr/bin/codesign").args(["--verify", "--strict", "-R", "=anchor apple generic and identifier \"ai.gensee.crate\" and certificate leaf[subject.OU] = \"3KWVB4M63F\"", "/Applications/Gensee Crate.app"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status()?.success() { return Err(io::Error::other("The approval caller is not the signed Gensee app.")); }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    Err(io::Error::other(
        "Approval management requires the macOS app.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn static_commands_distinguish_literal_search_patterns_from_expansion() {
        for command in [
            r#"grep -rn "health.error\|reconnect()" Host/*.swift | head"#,
            r#"grep '$HOME `literal` ()' file"#,
            r#"grep "escaped \$HOME" file"#,
            r#"sed -n 1140,1175p file; echo ---; grep updateConfiguration Host/*.swift"#,
        ] {
            assert!(static_shell_command(command), "{command}");
        }
        for command in [
            "cat $(get-path)",
            "cat `get-path`",
            "(cat file)",
            "cat $FILE",
            r#"cat "$(get-path)""#,
            r#"cat "$FILE""#,
            "cat file\ncat other",
            "cat 'unclosed",
            "cat trailing\\",
            r#"cat "\\$FILE""#,
        ] {
            assert!(!static_shell_command(command), "{command}");
        }
    }

    fn fixture() -> (EventStore, PathBuf, AgentHookEvent, PolicyFinding) {
        let root = env::temp_dir().join(format!("approval-regression-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("project");
        fs::create_dir_all(&workspace).unwrap();
        let store = EventStore::new(root.join("store")).unwrap();
        let path = workspace.join("run.py");
        fs::write(&path, "print('hello')\n").unwrap();
        let event = build_unattributed_hook_event(
            &json!({"session_id":"session-a","cwd":workspace,
            "hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"tool-1",
            "tool_input":{"command":"python3 run.py","tool_use_id":"tool-1"}})
            .to_string(),
            "claude-code",
        )
        .unwrap();
        let finding = PolicyFinding {
            action: PolicyAction::Ask,
            severity: "medium".into(),
            rule_id: "policy_unmatched_executable_modification".into(),
            message: "inspect".into(),
            path: Some(path.to_string_lossy().into_owned()),
            evidence: json!({"approval_content_digest": content_digest(b"print('hello')\n")}),
        };
        (store, workspace, event, finding)
    }
    fn grant(store: &EventStore, event: &AgentHookEvent, finding: &PolicyFinding, scope: &str) {
        let mut approval =
            context(event, &finding.rule_id, finding.path.as_deref().unwrap()).unwrap();
        approval.scope = scope.into();
        approval.expires_at = unix_millis().unwrap() + 60_000;
        approval.remaining = (scope == "once").then_some(1);
        with_records(store.root_path(), |records| {
            records.push(approval);
            Ok(((), true))
        })
        .unwrap();
    }
    fn read_fixture() -> (EventStore, PathBuf, AgentHookEvent, PolicyFinding, Approval) {
        let (store, workspace, _, _) = fixture();
        let path = workspace.join("run.py");
        let event = build_unattributed_hook_event(
            &json!({
                "session_id":"read-session", "cwd":workspace, "hook_event_name":"PreToolUse",
                "tool_name":"Read", "tool_use_id":"read-tool", "tool_input":{"file_path":path}
            })
            .to_string(),
            "claude-code",
        )
        .unwrap();
        let finding = PolicyFinding {
            action: PolicyAction::Ask,
            severity: "medium".into(),
            rule_id: SCOPED_READ_RULE.into(),
            message: "possible credential".into(),
            path: Some(path.to_string_lossy().into_owned()),
            evidence: json!({}),
        };
        let captured = json!({"rule":SCOPED_READ_RULE,"path":path});
        let mut approval = read_exception(
            &event,
            &captured,
            "directory",
            workspace.to_str().unwrap(),
            10,
        )
        .unwrap();
        approval.expires_at = unix_millis().unwrap() + 60_000;
        with_records(store.root_path(), |records| {
            records.push(approval.clone());
            Ok(((), true))
        })
        .unwrap();
        (store, workspace, event, finding, approval)
    }

    #[test]
    fn scoped_read_accepts_quoted_search_parentheses_but_rejects_substitution() {
        let (_store, workspace, _, finding, _) = read_fixture();
        for (command, accepted) in [
            (
                r#"sed -n 1,3p run.py; echo ---; grep -rn "health.error\|reconnect()" run.py | head"#,
                true,
            ),
            (r#"cat "$(echo run.py)""#, false),
        ] {
            let event = build_unattributed_hook_event(
                &json!({"session_id":"session-a","cwd":workspace,
                "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":command}})
                .to_string(),
                "claude-code",
            )
            .unwrap();
            assert_eq!(
                read_target(&event, SCOPED_READ_RULE, finding.path.as_deref().unwrap()).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn explicit_read_exception_can_target_cleaned_up_scratch_file_but_not_dangling_link() {
        let (_store, workspace, event, finding, _) = read_fixture();
        let path = finding.path.as_deref().unwrap();
        fs::remove_file(path).unwrap();
        let captured = json!({"rule":SCOPED_READ_RULE,"path":path});
        assert!(read_exception(&event, &captured, "file", path, 10).is_ok());
        assert!(read_exception(
            &event,
            &captured,
            "directory",
            workspace.to_str().unwrap(),
            10
        )
        .is_ok());
        symlink(workspace.join("absent-secret"), path).unwrap();
        assert!(read_exception(&event, &captured, "file", path, 10).is_err());
        fs::remove_file(path).unwrap();
        fs::remove_dir(&workspace).unwrap();
        assert!(read_exception(&event, &captured, "file", path, 10).is_ok());
    }

    #[test]
    fn scoped_reads_allow_changed_content_and_siblings_but_not_other_projects_or_providers() {
        let (store, workspace, event, finding, approval) = read_fixture();
        fs::write(
            workspace.join("run.py"),
            "api_key=changed-real-secret-value",
        )
        .unwrap();
        let mut findings = vec![finding.clone()];
        apply(&event, &store, &mut findings);
        assert_eq!(findings[0].action, PolicyAction::Allow);
        assert_eq!(
            findings[0].evidence["scoped_read_exception_id"],
            approval.id
        );
        assert_eq!(findings[0].evidence["original_response"]["action"], "ask");
        let sibling = workspace.join("another.txt");
        fs::write(&sibling, "another-content").unwrap();
        let mut target =
            read_target(&event, SCOPED_READ_RULE, finding.path.as_deref().unwrap()).unwrap();
        target.path = fs::canonicalize(&sibling).unwrap();
        assert!(matches_read_exception(&approval, &target));
        target.provider = "codex".into();
        assert!(!matches_read_exception(&approval, &target));
        target.provider = "claude-code".into();
        target.project = workspace.join("different-project");
        assert!(!matches_read_exception(&approval, &target));
    }

    #[test]
    fn scoped_reads_preserve_blocks_other_asks_expiry_and_revocation() {
        let (store, _, event, finding, _) = read_fixture();
        for action in [PolicyAction::Block, PolicyAction::Ask] {
            let mut unrelated = finding.clone();
            unrelated.rule_id = "policy_sensitive_egress".into();
            unrelated.action = action;
            let mut findings = vec![finding.clone(), unrelated];
            apply(&event, &store, &mut findings);
            assert_eq!(findings[0].action, PolicyAction::Ask);
            assert_eq!(findings[1].action, action);
        }
        for revoked in [true, false] {
            with_records(store.root_path(), |records| {
                records[0].revoked = revoked;
                if !revoked {
                    records[0].expires_at = 1;
                }
                Ok(((), true))
            })
            .unwrap();
            let mut findings = vec![finding.clone()];
            apply(&event, &store, &mut findings);
            assert_eq!(findings[0].action, PolicyAction::Ask);
        }
    }

    #[test]
    fn scoped_reads_reject_symlink_escape_prefix_collisions_and_non_read_calls() {
        let (store, workspace, mut event, finding, approval) = read_fixture();
        let outside = store.root_path().join("outside.txt");
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, workspace.join("escape.txt")).unwrap();
        let mut target =
            read_target(&event, SCOPED_READ_RULE, finding.path.as_deref().unwrap()).unwrap();
        target.path = fs::canonicalize(workspace.join("escape.txt")).unwrap();
        assert!(!matches_read_exception(&approval, &target));
        target.path = PathBuf::from(format!("{}-other/file", approval.path));
        assert!(!matches_read_exception(&approval, &target));
        event.tool_name = Some("Write".into());
        assert!(read_target(&event, SCOPED_READ_RULE, finding.path.as_deref().unwrap()).is_err());
        let mut findings = vec![finding];
        apply(&event, &store, &mut findings);
        assert_eq!(findings[0].action, PolicyAction::Ask);
    }

    #[test]
    fn scoped_read_preview_requires_containment_and_resolves_tmp_aliases() {
        let (_, workspace, event, finding, _) = read_fixture();
        let captured = json!({"rule":SCOPED_READ_RULE,"path":finding.path});
        assert!(read_exception(&event, &captured, "directory", "/", 10).is_err());
        assert!(read_exception(&event, &captured, "directory", "/Applications", 10).is_err());
        let file = read_exception(
            &event,
            &captured,
            "file",
            workspace.join("run.py").to_str().unwrap(),
            10,
        )
        .unwrap();
        let folder = read_exception(
            &event,
            &captured,
            "directory",
            workspace.to_str().unwrap(),
            10,
        )
        .unwrap();
        assert_ne!(file.key, folder.key);
        assert!(file.read_scope.as_deref() == Some("file"));
        #[cfg(target_os = "macos")]
        {
            let temporary = PathBuf::from(format!(
                "/private/tmp/gensee-read-alias-{}",
                uuid::Uuid::new_v4()
            ));
            fs::write(&temporary, "test").unwrap();
            let event = build_unattributed_hook_event(&json!({"session_id":"alias", "cwd":workspace,
                "hook_event_name":"PreToolUse", "tool_name":"Read", "tool_input":{"file_path":temporary}}).to_string(), "claude-code").unwrap();
            let captured = json!({"rule":SCOPED_READ_RULE,"path":temporary});
            let a = read_exception(&event, &captured, "directory", "/tmp", 10).unwrap();
            let b = read_exception(&event, &captured, "directory", "/private/tmp", 10).unwrap();
            fs::remove_file(temporary).unwrap();
            assert_eq!(a.key, b.key);
            assert_eq!(a.path, "/private/tmp");
        }
    }

    #[test]
    fn grants_without_original_content_binding_are_inactive() {
        let (store, _, event, finding) = fixture();
        grant(&store, &event, &finding, "session");
        with_records(store.root_path(), |records| {
            records[0].key_version = 0;
            assert!(!active(&records[0], unix_millis()?));
            Ok(((), true))
        })
        .unwrap();
        let mut findings = vec![finding];
        apply(&event, &store, &mut findings);
        assert_eq!(findings[0].action, PolicyAction::Ask);
    }

    #[test]
    fn grant_rejects_changed_or_uninspected_alert_content() {
        let (store, workspace, event, finding) = fixture();
        store.append_hook_event_evidence_only(&event).unwrap();
        store
            .append_policy_alert(&finding.to_policy_alert(&event))
            .unwrap();
        let id = store.dashboard_state().unwrap()["alerts"][0]["alert_id"]
            .as_i64()
            .unwrap();
        let captured = store.approval_context(id).unwrap();
        let original = context(&event, &finding.rule_id, finding.path.as_deref().unwrap()).unwrap();
        verify_captured_digest(&original, &captured).unwrap();
        fs::write(workspace.join("run.py"), "print('changed before preview')").unwrap();
        let changed = context(&event, &finding.rule_id, finding.path.as_deref().unwrap()).unwrap();
        assert!(verify_captured_digest(&changed, &captured).is_err());
        assert!(verify_captured_digest(&original, &json!({})).is_err());
        let mut write = original;
        write.rule = "policy_write_outside_workspace".into();
        verify_captured_digest(&write, &json!({})).unwrap();
    }

    #[test]
    fn remembered_approval_allowed_egress_is_accounted_once() {
        let (store, workspace, _, _) = fixture();
        let event = build_unattributed_hook_event(
            &json!({
                "session_id":"network-session", "cwd":workspace, "hook_event_name":"PreToolUse",
                "tool_name":"Bash", "tool_use_id":"network-tool",
                "tool_input":{"command":"curl https://example.com > /gensee-review-output.txt"}
            })
            .to_string(),
            "claude-code",
        )
        .unwrap();
        let intents = file_intents_from_hook(&event, event.tool_input_command.as_deref());
        let policy = Policy::embedded_default();
        let first = evaluate_pretool_policy_with_policy(&event, &intents, Some(&store), &policy);
        assert_eq!(first.action, PolicyAction::Ask, "{first:?}");
        for finding in first
            .findings
            .iter()
            .filter(|f| f.action == PolicyAction::Ask)
        {
            grant(&store, &event, finding, "session");
        }
        let allowed = evaluate_pretool_policy_with_policy(&event, &intents, Some(&store), &policy);
        assert_eq!(allowed.action, PolicyAction::Allow, "{allowed:?}");
        assert_eq!(
            allowed
                .findings
                .iter()
                .filter(|f| f.rule_id == "policy_network_egress")
                .count(),
            1
        );
    }

    #[test]
    fn persisted_capture_reconstructs_the_same_approval_key() {
        let (store, _, event, finding) = fixture();
        store.append_hook_event_evidence_only(&event).unwrap();
        store
            .append_policy_alert(&finding.to_policy_alert(&event))
            .unwrap();
        let state = store.dashboard_state().unwrap();
        let alert_id = state["alerts"][0]["alert_id"].as_i64().unwrap();
        let captured = store.approval_context(alert_id).unwrap();
        let restored = build_unattributed_hook_event(
            &captured["payload"].to_string(),
            captured["provider"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            context(&event, &finding.rule_id, finding.path.as_deref().unwrap())
                .unwrap()
                .key,
            context(
                &restored,
                &finding.rule_id,
                finding.path.as_deref().unwrap()
            )
            .unwrap()
            .key
        );
        let mut redacted = event.clone();
        redacted.raw_json = event
            .raw_json
            .replace("python3 run.py", "python3 run.py <redacted>");
        assert!(context(
            &redacted,
            &finding.rule_id,
            finding.path.as_deref().unwrap()
        )
        .is_err());
    }

    #[test]
    fn once_consumption_is_persistent_and_ignores_tool_call_id() {
        let (store, _, mut event, finding) = fixture();
        grant(&store, &event, &finding, "once");
        event.raw_json = event.raw_json.replace("tool-1", "tool-2");
        let mut findings = vec![finding.clone()];
        apply(&event, &store, &mut findings);
        assert_eq!(findings[0].action, PolicyAction::Allow);
        assert!(findings[0].evidence["remembered_approval_id"].is_string());
        let reopened = EventStore::new(store.root_path()).unwrap();
        apply(&event, &reopened, std::slice::from_mut(&mut findings[0]));
        let mut next = vec![finding];
        apply(&event, &reopened, &mut next);
        assert_eq!(next[0].action, PolicyAction::Ask);
    }
    #[test]
    fn content_command_provider_project_and_session_are_exact() {
        let (store, workspace, event, finding) = fixture();
        grant(&store, &event, &finding, "session");
        for variant in ["provider", "session", "command", "project", "content"] {
            let mut changed = event.clone();
            match variant {
                "provider" => changed.provider = "codex".into(),
                "session" => changed.session_id = Some("session-b".into()),
                "command" => {
                    changed.raw_json = changed
                        .raw_json
                        .replace("python3 run.py", "python3 run.py --extra");
                    changed.tool_input_command = Some("python3 run.py --extra".into());
                }
                "project" => {
                    let other = workspace.join("other");
                    fs::create_dir_all(&other).unwrap();
                    changed.cwd = Some(other.to_string_lossy().into_owned());
                }
                "content" => {
                    fs::write(finding.path.as_deref().unwrap(), "print('changed')").unwrap()
                }
                _ => unreachable!(),
            }
            let mut fs = vec![finding.clone()];
            apply(&changed, &store, &mut fs);
            assert_eq!(fs[0].action, PolicyAction::Ask, "{variant}");
        }
    }
    #[test]
    fn project_scope_crosses_sessions_but_never_overrides_blocks_or_other_asks() {
        let (store, _, mut event, finding) = fixture();
        grant(&store, &event, &finding, "project");
        event.session_id = Some("session-b".into());
        let mut fs = vec![finding.clone()];
        apply(&event, &store, &mut fs);
        assert_eq!(fs[0].action, PolicyAction::Allow);
        for action in [PolicyAction::Ask, PolicyAction::Block] {
            let mut other = finding.clone();
            other.rule_id = "policy_dangerous_executable_content".into();
            other.action = action;
            let mut fs = vec![finding.clone(), other];
            apply(&event, &store, &mut fs);
            assert_eq!(fs[0].action, PolicyAction::Ask);
            assert_eq!(fs[1].action, action);
        }
    }
    #[test]
    fn expired_revoked_and_insecure_stores_fail_closed() {
        let (store, _, event, finding) = fixture();
        grant(&store, &event, &finding, "session");
        for state in ["expired", "revoked", "permissions"] {
            with_records(store.root_path(), |records| {
                records[0].expires_at = if state == "expired" { 0 } else { u64::MAX };
                records[0].revoked = state == "revoked";
                Ok(((), true))
            })
            .unwrap();
            if state == "permissions" {
                fs::set_permissions(
                    store.root_path().join(FILE_NAME),
                    fs::Permissions::from_mode(0o666),
                )
                .unwrap();
            }
            let mut fs = vec![finding.clone()];
            apply(&event, &store, &mut fs);
            assert_eq!(fs[0].action, PolicyAction::Ask, "{state}");
        }
        fs::remove_file(store.root_path().join(FILE_NAME)).unwrap();
        symlink("approvals.lock", store.root_path().join(FILE_NAME)).unwrap();
        assert!(with_records(store.root_path(), |_| Ok(((), false))).is_err());
    }
    #[test]
    fn all_asks_must_match_before_consuming_one_use() {
        let (store, _, event, finding) = fixture();
        grant(&store, &event, &finding, "once");
        let mut missing = finding.clone();
        missing.path = Some("/missing.py".into());
        let mut fs = vec![finding.clone(), missing];
        apply(&event, &store, &mut fs);
        assert_eq!(fs[0].action, PolicyAction::Ask);
        let mut fs = vec![finding];
        apply(&event, &store, &mut fs);
        assert_eq!(fs[0].action, PolicyAction::Allow);
    }
    #[test]
    fn simultaneous_once_approval_cannot_be_consumed_twice() {
        let (store, _, event, finding) = fixture();
        grant(&store, &event, &finding, "once");
        let root = store.root_path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let root = root.clone();
                let event = event.clone();
                let finding = finding.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let store = EventStore::new(root).unwrap();
                    let mut findings = vec![finding];
                    barrier.wait();
                    apply(&event, &store, &mut findings);
                    findings[0].action
                })
            })
            .collect();
        let actions: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(
            actions
                .iter()
                .filter(|a| **a == PolicyAction::Allow)
                .count(),
            1
        );
    }
    #[test]
    fn ended_session_cannot_reuse_session_grant() {
        let (store, workspace, event, finding) = fixture();
        grant(&store, &event, &finding, "session");
        store
            .append_session(&gensee_crate_core::AgentSession {
                session_id: "session-a".into(),
                agent_binary: "claude".into(),
                root_pid: 123,
                cwd: workspace.to_string_lossy().into_owned(),
                repo_path: None,
                mode: None,
                workspace_mode: None,
                original_workspace: None,
                staged_workspace: None,
                sandbox_profile: None,
                sandbox_profile_path: None,
                started_at_ms: 1,
                ended_at_ms: Some(2),
                exit_code: Some(0),
            })
            .unwrap();
        let mut fs = vec![finding];
        apply(&event, &store, &mut fs);
        assert_eq!(fs[0].action, PolicyAction::Ask);
    }
    #[test]
    fn dynamic_commands_and_unreadable_artifacts_cannot_be_remembered() {
        let (_, _, mut event, finding) = fixture();
        event.tool_input_command = Some("python3 $SCRIPT".into());
        assert!(context(&event, &finding.rule_id, finding.path.as_deref().unwrap()).is_err());
        event.tool_input_command = Some("python3 run.py".into());
        fs::remove_file(finding.path.as_deref().unwrap()).unwrap();
        assert!(context(&event, &finding.rule_id, finding.path.as_deref().unwrap()).is_err());
        assert!(require_app_caller().is_err());
    }
}
