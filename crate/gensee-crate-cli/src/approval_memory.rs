use crate::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;

fn current_unix_millis() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis() as u64)
}
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;

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
    if command.contains(['$', '`', '\n', '(', ')']) {
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
            "provider":event.provider,"tool":event.tool_name,"input":input,"rule":rule,
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
    })
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
        .open(root.join("approvals.lock"))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other("Unsafe approval lock permissions."));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other(
            "Approval store is busy; retry the action.",
        ));
    }
    let path = root.join("approvals.json");
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
        let temp = root.join(format!(".approvals-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
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
    !a.revoked && a.expires_at > now && a.remaining != Some(0)
}

pub(crate) fn apply(event: &AgentHookEvent, store: &EventStore, findings: &mut [PolicyFinding]) {
    if !store.root_path().join("approvals.json").exists() {
        return;
    }
    if findings.iter().any(|f| f.action == PolicyAction::Block) {
        return;
    }
    let asks: Vec<_> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.action == PolicyAction::Ask)
        .collect();
    if asks.is_empty() {
        return;
    }
    let candidates: io::Result<Vec<_>> = asks
        .iter()
        .map(|(i, f)| context(event, &f.rule_id, f.path.as_deref().unwrap_or("")).map(|c| (*i, c)))
        .collect();
    let Ok(candidates) = candidates else {
        return;
    };
    let now = current_unix_millis().unwrap_or(u64::MAX);
    let ended = store.approval_session_has_ended(event.session_id.as_deref().unwrap_or(""));
    let Ok(ended) = ended else {
        return;
    };
    let selected = with_records(store.root_path(), |records| {
        let mut selected = Vec::new();
        for (finding, context) in &candidates {
            let Some(index) = records.iter().position(|a| {
                active(a, now)
                    && a.key == context.key
                    && (a.scope == "project" || (!ended && a.session == context.session))
            }) else {
                return Ok((Vec::new(), false));
            };
            selected.push((*finding, index, records[index].id.clone()));
        }
        let mut used = std::collections::HashSet::new();
        let mut consumed = false;
        for (_, index, _) in &selected {
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
        for (index, _, id) in selected {
            findings[index].action = PolicyAction::Allow;
            findings[index].severity = "info".into();
            findings[index].message = format!(
                "Allowed by remembered approval: {}",
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
    if matches!(verb, "grant" | "revoke") {
        require_app_caller()?;
    }
    let store = EventStore::default_local()?;
    let now = current_unix_millis()?;
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
                "Use approval list, preview, grant, or revoke.",
            ))
        }
    };
    println!("{value}");
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
            evidence: json!({}),
        };
        (store, workspace, event, finding)
    }
    fn grant(store: &EventStore, event: &AgentHookEvent, finding: &PolicyFinding, scope: &str) {
        let mut approval =
            context(event, &finding.rule_id, finding.path.as_deref().unwrap()).unwrap();
        approval.scope = scope.into();
        approval.expires_at = current_unix_millis().unwrap() + 60_000;
        approval.remaining = (scope == "once").then_some(1);
        with_records(store.root_path(), |records| {
            records.push(approval);
            Ok(((), true))
        })
        .unwrap();
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
                    store.root_path().join("approvals.json"),
                    fs::Permissions::from_mode(0o666),
                )
                .unwrap();
            }
            let mut fs = vec![finding.clone()];
            apply(&event, &store, &mut fs);
            assert_eq!(fs[0].action, PolicyAction::Ask, "{state}");
        }
        fs::remove_file(store.root_path().join("approvals.json")).unwrap();
        symlink("approvals.lock", store.root_path().join("approvals.json")).unwrap();
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
