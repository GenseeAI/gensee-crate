use crate::*;

#[derive(Debug)]
pub(crate) struct ContentSnapshot {
    pub(crate) digest: String,
    pub(crate) size_bytes: i64,
    pub(crate) content: String,
    pub(crate) truncated: bool,
}

pub(crate) fn preexec_artifact_findings(
    event: &AgentHookEvent,
    store: &EventStore,
) -> Vec<PolicyFinding> {
    let Some(command) = event.tool_input_command.as_deref() else {
        return Vec::new();
    };
    let cwd = event.cwd.as_deref().unwrap_or(".");
    let mut findings = Vec::new();
    for path in executable_targets_from_command(command, cwd) {
        findings.extend(preexec_findings_for_path(event, store, &path));
    }
    findings
}

pub(crate) fn record_write_time_artifact_observations(
    payload: &str,
    event: &AgentHookEvent,
    original_command: Option<&str>,
    store: &EventStore,
) -> io::Result<()> {
    if event.tool_response_interrupted == Some(true) {
        return Ok(());
    }

    let paths = write_time_observation_paths(payload, event, original_command);
    for path in paths {
        let Some((snapshot, findings)) = inspect_artifact_current_content(store, &path) else {
            continue;
        };
        record_artifact_snapshot_and_tags(event, store, &path, &snapshot, &findings)?;
        for finding in findings {
            store.append_policy_alert(&finding.to_policy_alert(event))?;
        }
    }

    Ok(())
}

pub(crate) fn write_time_observation_paths(
    payload: &str,
    event: &AgentHookEvent,
    original_command: Option<&str>,
) -> Vec<String> {
    let policy = Policy::global();
    let mut paths = Vec::new();

    for subject in native_policy_subjects(event) {
        if policy_subject_is_mutating(&subject.operation)
            && policy.is_registered_artifact_path(&subject.path)
        {
            paths.push(subject.path);
        }
    }

    for intent in file_intents_from_hook(event, original_command) {
        if policy_subject_is_mutating(&intent.operation)
            && policy.is_registered_artifact_path(&intent.path)
        {
            paths.push(intent.path);
        }
    }

    for path in simple_bash_write_target_paths(payload, event.cwd.as_deref().unwrap_or(".")) {
        if policy.is_registered_artifact_path(&path) {
            paths.push(path);
        }
    }

    dedupe_paths(paths)
}

/// Resolve the redirect-target paths of simple `echo`/`printf > file` writes.
/// The actual (assembled) file content is re-read at PostToolUse, so only the
/// destination path is needed here.
pub(crate) fn simple_bash_write_target_paths(payload: &str, cwd: &str) -> Vec<String> {
    let Some(command) = original_bash_command(payload) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for segment in split_shell_segments(&command) {
        let tokens = shell_words(&segment);
        let command_tokens = strip_leading_env_assignments(&tokens);
        let Some(program) = command_tokens.first().map(String::as_str) else {
            continue;
        };
        if !matches!(command_basename(program), "echo" | "printf") {
            continue;
        }
        if let Some(path) = redirection_output_path(command_tokens) {
            paths.push(normalize_intent_path(path, cwd));
        }
    }
    paths
}

pub(crate) fn redirection_output_path(tokens: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if matches!(token, ">" | ">>" | "1>" | "1>>") {
            return tokens.get(index + 1).map(String::as_str);
        }
        for operator in ["1>>", "1>", ">>", ">"] {
            if let Some(path) = token.strip_prefix(operator) {
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
        index += 1;
    }
    None
}

pub(crate) fn preexec_findings_for_path(
    event: &AgentHookEvent,
    store: &EventStore,
    path: &str,
) -> Vec<PolicyFinding> {
    let policy = Policy::global();
    if !policy.is_executable_artifact_path(path) && !Path::new(path).exists() {
        return Vec::new();
    }

    let snapshot = match read_small_artifact_content(path) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return vec![PolicyFinding {
                action: PolicyAction::Ask,
                severity: "medium".to_string(),
                rule_id: "policy_executable_content_unavailable".to_string(),
                message: format!(
                    "Ask before executing artifact whose content was not inspected: {path}"
                ),
                path: Some(path.to_string()),
                evidence: json!({
                    "source": "preexec_artifact_inspection",
                    "reason": "missing_or_too_large",
                }),
            }];
        }
        Err(error) => {
            return vec![PolicyFinding {
                action: PolicyAction::Ask,
                severity: "medium".to_string(),
                rule_id: "policy_executable_content_unavailable".to_string(),
                message: format!(
                    "Ask before executing artifact whose content could not be read: {path}"
                ),
                path: Some(path.to_string()),
                evidence: json!({
                    "source": "preexec_artifact_inspection",
                    "error": error.to_string(),
                }),
            }];
        }
    };

    if let Ok(tags) = store.artifact_risk_tags_for_file_digest(path, &snapshot.digest) {
        let content_tags = tags
            .iter()
            .filter(|tag| artifact_risk_tag_is_content_authoritative(tag))
            .collect::<Vec<_>>();
        if !content_tags.is_empty() {
            return content_tags
                .iter()
                .map(|tag| policy_finding_from_tag(tag))
                .collect();
        }
    }

    let content_findings = evaluate_artifact_snapshot(&snapshot, path, "preexec_artifact_content");
    let mut findings = content_findings.clone();
    if !content_findings
        .iter()
        .any(|finding| finding.action == PolicyAction::Block)
    {
        findings.extend(preexec_artifact_fact_findings(
            event,
            store,
            path,
            &snapshot.digest,
        ));
    }
    let _ = record_artifact_snapshot_and_tags(event, store, path, &snapshot, &content_findings);

    findings
}

pub(crate) fn artifact_risk_tag_is_content_authoritative(tag: &ArtifactRiskTagRecord) -> bool {
    if matches!(
        tag.rule_id.as_str(),
        "policy_prior_session_executable_artifact" | "policy_unmatched_executable_modification"
    ) {
        return false;
    }
    let Some(evidence) = tag.evidence.as_deref() else {
        return true;
    };
    serde_json::from_str::<Value>(evidence)
        .ok()
        .and_then(|value| {
            value
                .get("source")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_none_or(|source| source != "artifact_facts")
}

pub(crate) fn preexec_artifact_fact_findings(
    event: &AgentHookEvent,
    store: &EventStore,
    path: &str,
    current_digest: &str,
) -> Vec<PolicyFinding> {
    artifact_fact_provenance_findings(event, store, path, "execute", "executing", true)
        .into_iter()
        .map(|mut finding| {
            if let Some(evidence) = finding.evidence.as_object_mut() {
                evidence.insert(
                    "current_digest".to_string(),
                    Value::String(current_digest.to_string()),
                );
            }
            finding
        })
        .collect()
}

pub(crate) fn artifact_fact_provenance_findings(
    event: &AgentHookEvent,
    store: &EventStore,
    path: &str,
    operation: &str,
    gerund: &str,
    include_stale_risk: bool,
) -> Vec<PolicyFinding> {
    let Ok(Some(fact)) = store.artifact_fact_for_file(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let recent_modified = fact
        .last_modified_at
        .and_then(|modified_at| u64::try_from(modified_at).ok())
        .is_some_and(|modified_at| {
            event.observed_at_ms.saturating_sub(modified_at) <= ARTIFACT_FACT_RECENT_WINDOW_MS
        });
    let stale_risk = fact
        .risk_digest
        .as_deref()
        .is_some_and(|digest| include_stale_risk && Some(digest) != fact.current_digest.as_deref());

    if recent_modified && fact.is_unmatched_modified {
        findings.push(PolicyFinding {
            action: PolicyAction::Ask,
            severity: "medium".to_string(),
            rule_id: if operation == "execute" {
                "policy_unmatched_executable_modification".to_string()
            } else {
                "policy_unmatched_registered_artifact_read".to_string()
            },
            message: format!(
                "Ask before {gerund} artifact recently modified without matching agent intent: {path}"
            ),
            path: Some(path.to_string()),
            evidence: json!({
                "source": "artifact_facts",
                "operation": operation,
                "fact_uri": fact.uri.clone(),
                "last_modified_source": fact.last_modified_source.clone(),
                "last_modified_at": fact.last_modified_at,
                "recent_unmatched_effect_count": fact.recent_unmatched_effect_count,
                "risk_digest_stale": stale_risk,
            }),
        });
    }

    let different_session = match (
        fact.last_modified_session_id.as_deref(),
        event.session_id.as_deref(),
    ) {
        (Some(previous), Some(current)) => previous != current,
        (Some(_), None) => true,
        _ => false,
    };
    if recent_modified && fact.is_agent_authored && different_session {
        findings.push(PolicyFinding {
            action: PolicyAction::Ask,
            severity: "medium".to_string(),
            rule_id: if operation == "execute" {
                "policy_prior_session_executable_artifact".to_string()
            } else {
                "policy_prior_session_registered_artifact_read".to_string()
            },
            message: format!(
                "Ask before {gerund} artifact authored by the agent in another session: {path}"
            ),
            path: Some(path.to_string()),
            evidence: json!({
                "source": "artifact_facts",
                "operation": operation,
                "fact_uri": fact.uri.clone(),
                "last_modified_session_id": fact.last_modified_session_id.clone(),
                "current_session_id": event.session_id.clone(),
                "recent_cross_session_write_count": fact.recent_cross_session_write_count,
                "risk_digest_stale": stale_risk,
            }),
        });
    }

    findings
}

pub(crate) fn inspect_artifact_current_content(
    store: &EventStore,
    path: &str,
) -> Option<(ContentSnapshot, Vec<PolicyFinding>)> {
    let snapshot = read_small_artifact_content(path).ok().flatten()?;
    if let Ok(tags) = store.artifact_risk_tags_for_file_digest(path, &snapshot.digest) {
        let content_tags = tags
            .iter()
            .filter(|tag| artifact_risk_tag_is_content_authoritative(tag))
            .collect::<Vec<_>>();
        if !content_tags.is_empty() {
            let findings = content_tags
                .iter()
                .map(|tag| policy_finding_from_tag(tag))
                .collect();
            return Some((snapshot, findings));
        }
    }
    let findings = evaluate_artifact_snapshot(&snapshot, path, "write_time_artifact_content");
    Some((snapshot, findings))
}

pub(crate) fn evaluate_artifact_snapshot(
    snapshot: &ContentSnapshot,
    path: &str,
    source: &str,
) -> Vec<PolicyFinding> {
    Policy::global()
        .evaluate_content(&snapshot.content, Some(path))
        .into_iter()
        .map(|finding| policy_finding_from(finding, source))
        .collect()
}

pub(crate) fn record_artifact_snapshot_and_tags(
    event: &AgentHookEvent,
    store: &EventStore,
    path: &str,
    snapshot: &ContentSnapshot,
    findings: &[PolicyFinding],
) -> io::Result<()> {
    let tags = findings
        .iter()
        .map(|finding| ArtifactRiskTagInput {
            rule_id: finding.rule_id.clone(),
            severity: finding.severity.clone(),
            action: finding.action.alert_action().to_string(),
            message: finding.message.clone(),
            path: finding.path.clone(),
            confidence: 1.0,
            evidence: Some(json!({
                "source": finding.evidence.get("source").and_then(Value::as_str).unwrap_or("artifact_content"),
                "digest": snapshot.digest,
            })),
        })
        .collect::<Vec<_>>();
    store.record_artifact_observation_and_tags(
        &ArtifactObservationInput {
            session_id: event.session_id.clone(),
            path: path.to_string(),
            digest: snapshot.digest.clone(),
            size_bytes: snapshot.size_bytes,
            content_prefix: Some(redact_text(&snapshot.content)),
            content_truncated: snapshot.truncated,
            mutation: event.hook_event_name.as_deref() == Some("PostToolUse"),
            evidence: Some(json!({
                "source": "artifact_content_inspection",
                "hook_event_name": event.hook_event_name,
                "tool_use_id": event.tool_use_id,
            })),
            observed_at_ms: event.observed_at_ms,
        },
        &tags,
    )
}

pub(crate) fn read_small_artifact_content(path: &str) -> io::Result<Option<ContentSnapshot>> {
    read_small_artifact_content_with_timeout(
        path,
        Duration::from_millis(ARTIFACT_CONTENT_READ_TIMEOUT_MS),
    )
}

pub(crate) fn read_small_artifact_content_with_timeout(
    path: &str,
    timeout: Duration,
) -> io::Result<Option<ContentSnapshot>> {
    let (sender, receiver) = mpsc::channel();
    let path = path.to_string();
    thread::spawn(move || {
        let _ = sender.send(read_small_artifact_content_blocking(&path));
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out reading artifact content",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("artifact reader thread disconnected"))
        }
    }
}

pub(crate) fn read_small_artifact_content_blocking(
    path: &str,
) -> io::Result<Option<ContentSnapshot>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > PREEXEC_CONTENT_READ_LIMIT_BYTES {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Some(ContentSnapshot {
        digest: content_digest(&bytes),
        size_bytes: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        content,
        truncated: false,
    }))
}

pub(crate) fn content_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

pub(crate) fn executable_targets_from_command(command: &str, cwd: &str) -> Vec<String> {
    // This resolver intentionally covers common local-script execution forms in
    // the foreground hook. It is not a complete shell parser; EndpointSecurity
    // exec attribution is the durable backstop for obscure eval/subshell cases.
    let mut targets = Vec::new();
    for segment in split_shell_segments(command) {
        let tokens = shell_words(&segment);
        if tokens.is_empty() {
            continue;
        }
        collect_input_redirection_targets(&tokens, cwd, &mut targets);
        collect_direct_execution_targets(&tokens, cwd, &mut targets);
    }
    collect_piped_cat_execution_targets(command, cwd, &mut targets);
    dedupe_paths(targets)
}

pub(crate) fn collect_direct_execution_targets(
    tokens: &[String],
    cwd: &str,
    targets: &mut Vec<String>,
) {
    let command_tokens = strip_leading_env_assignments(tokens);
    let Some(program) = command_tokens.first().map(String::as_str) else {
        return;
    };
    let args = &command_tokens[1..];
    let interpreter = command_basename(program);
    match interpreter {
        "bash" | "sh" | "zsh" | "$SHELL" | "python" | "python3" | "node" | "ruby" | "perl" => {
            if let Some(path) = first_non_option_path(interpreter, args) {
                targets.push(normalize_intent_path(path, cwd));
            }
        }
        "source" | "." => {
            if let Some(path) = first_non_option_path(interpreter, args) {
                targets.push(normalize_intent_path(path, cwd));
            }
        }
        _ if program.starts_with("./") || program.starts_with('/') => {
            targets.push(normalize_intent_path(program, cwd));
        }
        _ => {}
    }
}

pub(crate) fn collect_input_redirection_targets(
    tokens: &[String],
    cwd: &str,
    targets: &mut Vec<String>,
) {
    let command_tokens = strip_leading_env_assignments(tokens);
    let Some(program) = command_tokens.first().map(String::as_str) else {
        return;
    };
    if !matches!(command_basename(program), "bash" | "sh" | "zsh" | "$SHELL") {
        return;
    }
    let mut index = 1;
    while index < command_tokens.len() {
        let token = command_tokens[index].as_str();
        if token == "<" {
            if let Some(path) = command_tokens.get(index + 1) {
                targets.push(normalize_intent_path(path, cwd));
            }
            index += 2;
            continue;
        }
        if let Some(path) = token.strip_prefix('<') {
            if !path.is_empty() {
                targets.push(normalize_intent_path(path, cwd));
            }
        }
        index += 1;
    }
}

pub(crate) fn collect_piped_cat_execution_targets(
    command: &str,
    cwd: &str,
    targets: &mut Vec<String>,
) {
    let segments = command.split('|').map(str::trim).collect::<Vec<_>>();
    for pair in segments.windows(2) {
        let left = shell_words(pair[0]);
        let right = shell_words(pair[1]);
        let left_tokens = strip_leading_env_assignments(&left);
        let right_tokens = strip_leading_env_assignments(&right);
        if left_tokens.first().map(String::as_str) != Some("cat") {
            continue;
        }
        let Some(right_program) = right_tokens.first().map(String::as_str) else {
            continue;
        };
        if !matches!(command_basename(right_program), "bash" | "sh" | "zsh") {
            continue;
        }
        for path in command_paths(&left_tokens[1..]) {
            targets.push(normalize_intent_path(&path, cwd));
        }
    }
}

pub(crate) fn first_non_option_path<'a>(
    interpreter: &str,
    tokens: &'a [String],
) -> Option<&'a str> {
    // Flags that consume a following *non-file* argument. This is interpreter
    // specific: for shells the script is simply the first non-flag token (`-e`,
    // `-r`, `-x`, … are no-arg set-options), so consuming the next token would
    // skip the very script we want to inspect (e.g. `bash -e disk_op.sh`).
    let arg_flags: &[&str] = match interpreter {
        "python" | "python3" => &["-m", "-w", "-W", "-X"],
        "ruby" => &["-e", "--eval", "-r", "--require", "-I"],
        "node" | "nodejs" => &["-e", "--eval", "-r", "--require"],
        "perl" => &["-e", "-I"],
        _ => &[], // bash/sh/zsh/source/. and unknown: script is the first non-flag
    };
    let mut skip_next = false;
    for token in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(token.as_str(), "-c" | "--command") {
            return None; // inline code, no script file to inspect
        }
        if arg_flags.contains(&token.as_str()) {
            skip_next = true;
            continue;
        }
        if token.starts_with('-') {
            continue;
        }
        if is_shell_control_token(token) {
            continue;
        }
        return Some(token);
    }
    None
}

pub(crate) fn dedupe_paths(paths: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.contains(&path) {
            deduped.push(path);
        }
    }
    deduped
}
