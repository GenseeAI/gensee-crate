use crate::*;

pub(crate) fn append_hook_event_with_policy(
    store: &EventStore,
    event: &AgentHookEvent,
) -> io::Result<()> {
    if event.hook_event_name.as_deref() != Some("PreToolUse") {
        return store.append_hook_event_with_enrichment(event, &ObservationEnrichment::default());
    }

    let operations = gensee_crate_store::hook_file_operations(event);
    let policy = Policy::cached_current();
    let mut enrichment = observation_enrichment(
        &policy,
        event.session_id.as_deref(),
        event.tool_use_id.as_deref(),
        event.observed_at_ms,
        operations
            .iter()
            .map(|operation| (operation.operation.clone(), operation.path.clone())),
        true,
    );
    enrichment.file_operations = Some(operations);
    store.append_hook_event_with_enrichment(event, &enrichment)
}

pub(crate) fn append_file_intent_with_policy(
    store: &EventStore,
    intent: &FileIntent,
) -> io::Result<()> {
    let policy = Policy::cached_current();
    let enrichment = observation_enrichment(
        &policy,
        intent.session_id.as_deref(),
        intent.tool_use_id.as_deref(),
        intent.observed_at_ms,
        [(intent.operation.clone(), intent.path.clone())],
        intent.provider != "bash-command-parser",
    );
    store.append_file_intent_with_enrichment(intent, &enrichment)
}

pub(crate) fn append_workspace_effect_with_policy(
    store: &EventStore,
    effect: &WorkspaceEffect,
) -> io::Result<()> {
    let policy = Policy::cached_current();
    let enrichment = observation_enrichment(
        &policy,
        effect.session_id.as_deref(),
        None,
        effect.observed_at_ms,
        [(effect.effect_type.clone(), effect.path.clone())],
        true,
    );
    store.append_workspace_effect_with_enrichment(effect, &enrichment)
}

pub(crate) fn append_system_event_with_policy(
    store: &EventStore,
    event: &SystemEvent,
) -> io::Result<()> {
    let policy = Policy::cached_current();
    let artifact_classifications = gensee_crate_store::system_event_paths(event)
        .into_iter()
        .map(|path| artifact_classification(&policy, path))
        .collect();
    let unmatched_system_alert =
        if !gensee_crate_store::system_event_source_can_record_unmatched_alert(&event.source)
            || !gensee_crate_store::system_event_can_record_unmatched_alert(&event.event_type)
        {
            None
        } else {
            prepare_policy_alert(&policy, unmatched_system_event_alert(event))
        };
    store.append_system_event_with_enrichment(
        event,
        &ObservationEnrichment {
            artifact_classifications,
            unmatched_system_alert,
            ..Default::default()
        },
    )
}

pub(crate) fn record_policy_alert(store: &EventStore, alert: PolicyAlert) -> io::Result<bool> {
    let policy = Policy::load_current();
    let Some(alert) = prepare_policy_alert(&policy, alert) else {
        return Ok(false);
    };
    store.append_policy_alert(&alert)?;
    Ok(true)
}

pub(crate) fn record_endpoint_policy_alert(
    store: &EventStore,
    alert: PolicyAlert,
    dedupe_key: &str,
    window_ms: u64,
) -> io::Result<bool> {
    let policy = Policy::load_current();
    let Some(alert) = prepare_policy_alert(&policy, alert) else {
        return Ok(false);
    };
    store.append_endpoint_policy_alert(&alert, dedupe_key, window_ms)
}

pub(crate) fn artifact_classification(policy: &Policy, path: String) -> ArtifactClassification {
    ArtifactClassification {
        is_memory_artifact: policy.is_memory_artifact_path(&path),
        is_persistent_target: policy.is_persistent_target_path(&path),
        is_control_plane: policy.is_control_plane_path(&path),
        path,
    }
}

fn observation_enrichment(
    policy: &Policy,
    session_id: Option<&str>,
    tool_use_id: Option<&str>,
    observed_at_ms: u64,
    operations: impl IntoIterator<Item = (String, String)>,
    include_alerts: bool,
) -> ObservationEnrichment {
    let mut enrichment = ObservationEnrichment::default();
    let mut classified_paths = HashSet::new();
    let mut recorded_alerts = HashSet::new();
    for (operation, path) in operations {
        if classified_paths.insert(path.clone()) {
            enrichment
                .artifact_classifications
                .push(artifact_classification(policy, path.clone()));
        }
        if !include_alerts {
            continue;
        }
        for finding in policy.evaluate_observation(&operation, &path) {
            let alert = PolicyAlert {
                session_id: session_id.map(str::to_string),
                tool_use_id: tool_use_id.map(str::to_string),
                severity: finding.severity,
                action: finding.action.as_str().to_string(),
                rule_id: finding.rule_id,
                message: finding.message,
                path: finding.path.or_else(|| Some(path.clone())),
                evidence: None,
                observed_at_ms,
            };
            let Some(alert) = prepare_policy_alert(policy, alert) else {
                continue;
            };
            if recorded_alerts.insert((
                alert.rule_id.clone(),
                alert.path.clone().unwrap_or_else(|| path.clone()),
            )) {
                enrichment.alerts.push(alert);
            }
        }
    }
    enrichment
}

fn prepare_policy_alert(policy: &Policy, mut alert: PolicyAlert) -> Option<PolicyAlert> {
    // Monitoring health must remain visible even when the user suppresses
    // low-severity agent findings or has tuned a legacy gap-warning rule.
    if alert.rule_id == "endpoint_security_event_gap" {
        alert.session_id = None;
        alert.tool_use_id = None;
        alert.severity = "info".into();
        alert.action = "allow".into();
        return Some(alert);
    }
    let tuned = policy.tuned_alert_values(&alert.rule_id, &alert.severity, &alert.action);
    if !policy
        .document()
        .endpoint_security
        .minimum_recorded_severity
        .includes(&tuned.severity)
    {
        return None;
    }
    if let Some(severity) = tuned.pre_review_severity {
        alert.evidence = gensee_crate_store::add_alert_evidence_field(
            alert.evidence,
            "pre_review_severity",
            Value::String(severity),
        );
    }
    if let Some(action) = tuned.pre_review_action {
        alert.evidence = gensee_crate_store::add_alert_evidence_field(
            alert.evidence,
            "pre_review_action",
            Value::String(action),
        );
    }
    alert.severity = tuned.severity;
    alert.action = tuned.action;
    Some(alert)
}

fn unmatched_system_event_alert(event: &SystemEvent) -> PolicyAlert {
    PolicyAlert {
        session_id: None,
        tool_use_id: None,
        severity: "medium".to_string(),
        action: "warn".to_string(),
        rule_id: "unmatched_system_effect".to_string(),
        message: "Filesystem effect was observed without a matching agent file intent".to_string(),
        path: event.file_path.clone(),
        evidence: Some(json!({
            "source": event.source,
            "event_type": event.event_type,
            "event_kind": event.event_kind,
            "process_name": event.process_name,
        })),
        observed_at_ms: event.observed_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_event(tool_name: &str, tool_input: Value, observed_at_ms: u64) -> AgentHookEvent {
        let raw_json = json!({
            "session_id": "session",
            "hook_event_name": "PreToolUse",
            "cwd": "/repo",
            "tool_name": tool_name,
            "tool_use_id": "tool",
            "tool_input": tool_input,
        })
        .to_string();
        AgentHookEvent {
            provider: "cursor".to_string(),
            session_id: Some("session".to_string()),
            hook_event_name: Some("PreToolUse".to_string()),
            cwd: Some("/repo".to_string()),
            transcript_path: None,
            tool_name: Some(tool_name.to_string()),
            tool_use_id: Some("tool".to_string()),
            tool_input_command: None,
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: None,
            effort_level: None,
            observed_at_ms,
            raw_json,
        }
    }

    fn policy_with(overrides: Value) -> Policy {
        let mut document: Value =
            serde_json::from_str(policy::default_policy_json()).expect("default policy parses");
        for (key, value) in overrides.as_object().expect("overrides are an object") {
            document[key] = value.clone();
        }
        Policy::from_json(&document.to_string()).expect("test policy parses")
    }

    fn alert(severity: &str, action: &str) -> PolicyAlert {
        PolicyAlert {
            session_id: Some("session".to_string()),
            tool_use_id: Some("tool".to_string()),
            severity: severity.to_string(),
            action: action.to_string(),
            rule_id: "policy_test".to_string(),
            message: "test finding".to_string(),
            path: Some("/repo/file".to_string()),
            evidence: None,
            observed_at_ms: 1,
        }
    }

    #[test]
    fn monitoring_health_bypasses_agent_severity_filter_and_attribution() {
        let policy =
            policy_with(json!({"endpoint_security": {"minimum_recorded_severity": "high"}}));
        let mut gap = alert("info", "warn");
        gap.rule_id = "endpoint_security_event_gap".into();
        let prepared = prepare_policy_alert(&policy, gap).unwrap();
        assert_eq!(prepared.action, "allow");
        assert_eq!(prepared.severity, "info");
        assert!(prepared.session_id.is_none());
        assert!(prepared.tool_use_id.is_none());
        assert!(prepare_policy_alert(&policy, alert("info", "allow")).is_none());
    }

    #[test]
    fn routine_mutations_keep_durable_alerts_and_executable_staging_stays_visible() {
        let dir = env::temp_dir().join(format!(
            "gensee-durable-housekeeping-{}",
            uuid::Uuid::new_v4()
        ));
        let store = EventStore::new(&dir).unwrap();
        for (index, path, operation, source) in [
            (0, "/repo/src/main.rs", "write", "/repo/src/main.rs"),
            (
                1,
                "/private/tmp/output.json",
                "rename",
                "/private/tmp/output.tmp",
            ),
            (
                2,
                "/private/tmp/tools/setup.py",
                "rename",
                "/private/tmp/payload.tmp",
            ),
            (
                3,
                "/private/tmp/claude-task.output",
                "delete",
                "/private/tmp/claude-task.output",
            ),
            (4, "/repo/src/deleted.rs", "delete", "/repo/src/deleted.rs"),
        ] {
            let mut alert = alert("medium", "warn");
            alert.rule_id = "hook_bypass_file_mutation".into();
            alert.path = Some(path.into());
            alert.evidence = Some(json!({"logical_operation":operation,
                "attribution":{"workspace_root":"/repo"}, "actor":{},
                "file":{"path":source, "mode":0o100644}}));
            assert!(record_endpoint_policy_alert(
                &store,
                alert,
                &format!("durable-{index}"),
                10_000
            )
            .unwrap());
        }
        assert_eq!(store.list_alerts().unwrap().len(), 5);
        let chain = store.verify_alert_chain().unwrap();
        configure_dashboard_noise_filter(&store).unwrap();
        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["alerts"].as_array().unwrap().len(), 2);
        let paths: HashSet<_> = dashboard["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["path"].as_str())
            .collect();
        assert_eq!(
            paths,
            HashSet::from(["/private/tmp/tools/setup.py", "/repo/src/deleted.rs"])
        );
        assert_eq!(store.list_alerts().unwrap().len(), 5);
        assert_eq!(store.verify_alert_chain().unwrap(), chain);
    }

    #[test]
    fn historical_housekeeping_filter_preserves_actor_source_and_block_boundaries() {
        let dir = env::temp_dir().join(format!(
            "gensee-housekeeping-dashboard-{}",
            uuid::Uuid::new_v4()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event_evidence_only(&hook_event(
                "Read",
                json!({"file_path":"/repo/file"}),
                1,
            ))
            .unwrap();
        let log = format!(
            "{}/Library/Logs/Claude/gensee-regression.log",
            env::var("HOME").unwrap()
        );
        for (actor, action, source) in [
            (true, "warn", "/tmp/from.tmp"),
            (false, "warn", "/tmp/from.tmp"),
            (true, "block", "/tmp/from.tmp"),
            (true, "warn", "/etc/passwd"),
        ] {
            let mut a = alert("medium", action);
            a.rule_id = "hook_bypass_file_mutation".into();
            a.path = Some(if source == "/etc/passwd" {
                "/tmp/out.json".into()
            } else {
                log.clone()
            });
            a.evidence = Some(
                json!({"logical_operation":if source=="/etc/passwd" {"rename"} else {"mutation"},"actor":{"team_id":if actor {"Q6L2SF6YDW"} else {"FAKE"},"signing_id":"com.anthropic.claudefordesktop"},"file":{"path":source,"mode":0o100644}}),
            );
            store.append_policy_alert(&a).unwrap();
        }
        let before = store.verify_alert_chain().unwrap();
        configure_dashboard_noise_filter(&store).unwrap();
        let state = store.dashboard_state().unwrap();
        assert_eq!(state["alerts"].as_array().unwrap().len(), 3);
        let request = state["requests"][0]["request_id"].as_i64().unwrap();
        assert_eq!(
            store.dashboard_request(request).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(store.list_alerts().unwrap().len(), 4);
        assert_eq!(store.verify_alert_chain().unwrap(), before);
    }

    #[test]
    fn approval_preview_requires_exact_captured_tool_id_and_preceding_event() {
        let dir = env::temp_dir().join(format!("gensee-approval-context-{}", uuid::Uuid::new_v4()));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event_evidence_only(&hook_event(
                "Read",
                json!({"file_path":"/repo/file"}),
                1,
            ))
            .unwrap();
        let mut a = alert("medium", "ask");
        a.rule_id = "policy_credential_content_read".into();
        a.observed_at_ms = 2;
        store.append_policy_alert(&a).unwrap();
        let id = store.dashboard_state().unwrap()["alerts"][0]["alert_id"]
            .as_i64()
            .unwrap();
        let preview = store.approval_context(id).unwrap();
        assert_eq!(preview["provider"], "cursor");
        assert_eq!(preview["payload"]["tool_input"]["file_path"], "/repo/file");
        a.tool_use_id = Some("future-tool".into());
        store.append_policy_alert(&a).unwrap();
        let mut future = hook_event("Read", json!({"file_path":"/repo/file"}), 3);
        future.tool_use_id = Some("future-tool".into());
        future.raw_json = future.raw_json.replace("\"tool\"", "\"future-tool\"");
        store.append_hook_event_evidence_only(&future).unwrap();
        let state = store.dashboard_state().unwrap();
        for alert in state["alerts"].as_array().unwrap() {
            let other = alert["alert_id"].as_i64().unwrap();
            if other != id {
                assert!(store.approval_context(other).is_err());
            }
        }
    }

    #[test]
    fn optimized_alert_projection_deduplicates_only_mutation_warnings() {
        let dir = env::temp_dir().join(format!("gensee-dashboard-dedupe-{}", uuid::Uuid::new_v4()));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event_evidence_only(&hook_event(
                "Read",
                json!({"file_path":"/repo/file"}),
                1,
            ))
            .unwrap();
        for (rule, action, time) in [
            ("hook_bypass_file_mutation", "warn", 1),
            ("hook_bypass_file_mutation", "warn", 2),
            ("hook_bypass_file_mutation", "block", 20),
            ("hook_bypass_file_mutation", "warn", 12003),
            ("policy_other", "warn", 1),
            ("policy_other", "warn", 2),
        ] {
            let mut a = alert("medium", action);
            a.rule_id = rule.into();
            a.observed_at_ms = time;
            store.append_policy_alert(&a).unwrap();
        }
        let state = store.dashboard_state().unwrap();
        let alerts = state["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 5);
        assert_eq!(alerts.iter().filter(|a| a["action"] == "block").count(), 1);
        assert_eq!(
            alerts
                .iter()
                .filter(|a| a["rule_id"] == "policy_other")
                .count(),
            2
        );
        assert_eq!(store.list_alerts().unwrap().len(), 6);
    }

    #[test]
    fn dashboard_quiets_only_routine_unmatched_mutations() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-dashboard-intent-gap-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event_evidence_only(&hook_event(
                "Read",
                json!({"file_path":"/repo/file"}),
                1,
            ))
            .unwrap();
        for (path, operation, action) in [
            ("/repo/src/main.rs", "mutation", "warn"),
            ("/tmp/gensee-output.txt", "mutation", "warn"),
            ("/repo/.env", "write", "warn"),
            ("/elsewhere/config", "write", "warn"),
            ("/repo/src/main.rs", "delete", "warn"),
            ("/repo/src/main.rs", "write", "block"),
        ] {
            let mut finding = alert("medium", action);
            finding.rule_id = "hook_bypass_file_mutation".into();
            finding.path = Some(path.into());
            finding.evidence = Some(
                json!({"logical_operation": operation, "attribution": {"workspace_root":"/repo"}}),
            );
            store.append_policy_alert(&finding).unwrap();
        }
        let chain = store.verify_alert_chain().unwrap();
        configure_dashboard_noise_filter(&store).unwrap();
        let state = store.dashboard_state().unwrap();
        assert_eq!(state["alerts"].as_array().unwrap().len(), 4);
        let id = state["requests"][0]["request_id"].as_i64().unwrap();
        assert_eq!(
            store.dashboard_request(id).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(store.list_alerts().unwrap().len(), 6);
        assert_eq!(store.verify_alert_chain().unwrap(), chain);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dashboard_quiets_historical_scratch_alerts_without_rewriting_evidence() {
        let dir =
            std::env::temp_dir().join(format!("gensee-dashboard-scratch-{}", std::process::id()));
        let store = EventStore::new(&dir).unwrap();
        store
            .append_hook_event_evidence_only(&hook_event(
                "Read",
                json!({"file_path":"/repo/file"}),
                1,
            ))
            .unwrap();
        for (rule, path, action) in [
            (
                "policy_write_outside_workspace",
                "/tmp/gensee-scratch/out.txt",
                "ask",
            ),
            (
                "policy_destructive_file_operation",
                "/tmp/gensee-scratch/out.txt",
                "warn",
            ),
            ("policy_write_outside_workspace", "/dev/null", "ask"),
            ("policy_write_outside_workspace", "/tmp/.env", "ask"),
            (
                "endpoint_security_event_gap",
                "/tmp/gensee-scratch/out.txt",
                "warn",
            ),
            (
                "policy_write_outside_workspace",
                "/tmp/gensee-scratch/blocked.txt",
                "block",
            ),
        ] {
            let mut finding = alert("high", action);
            finding.rule_id = rule.into();
            finding.path = Some(path.into());
            store.append_policy_alert(&finding).unwrap();
        }
        let before = store.list_alerts().unwrap();
        let chain_before = store.verify_alert_chain().unwrap();
        let policy = policy_with(json!({}));
        store
            .set_dashboard_noise_filter(
                &[
                    "policy_write_outside_workspace",
                    "policy_destructive_file_operation",
                ],
                move |rule, path, _, _, _| policy.is_routine_scratch_alert(rule, path),
            )
            .unwrap();
        let dashboard = store.dashboard_state().unwrap();
        assert_eq!(dashboard["alerts"].as_array().unwrap().len(), 2);
        assert_eq!(dashboard["requests"][0]["high_risk_alert_count"], 2);
        let request_id = dashboard["requests"][0]["request_id"].as_i64().unwrap();
        assert_eq!(
            store.dashboard_request(request_id).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(store.list_alerts().unwrap().len(), before.len());
        assert_eq!(store.verify_alert_chain().unwrap(), chain_before);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn preparation_applies_recording_threshold_before_store_write() {
        let policy = policy_with(json!({
            "endpoint_security": {
                "minimum_recorded_severity": "high"
            }
        }));
        assert!(prepare_policy_alert(&policy, alert("medium", "warn")).is_none());
        assert!(prepare_policy_alert(&policy, alert("high", "warn")).is_some());
    }

    #[test]
    fn preparation_applies_review_override_and_preserves_original_values() {
        let policy = policy_with(json!({
            "review_overrides": [{
                "rule_id": "policy_test",
                "severity": "low",
                "action": "warn"
            }]
        }));
        let prepared = prepare_policy_alert(&policy, alert("critical", "block"))
            .expect("default threshold includes the tuned alert");
        assert_eq!(prepared.severity, "low");
        assert_eq!(prepared.action, "warn");
        assert_eq!(
            prepared.evidence.as_ref().unwrap()["pre_review_severity"],
            "critical"
        );
        assert_eq!(
            prepared.evidence.as_ref().unwrap()["pre_review_action"],
            "block"
        );
    }

    #[test]
    fn unmatched_system_alert_respects_review_override_and_threshold() {
        let event = SystemEvent {
            source: "test-monitor".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            execution_origin: Default::default(),
            observed_at_ms: 1,
            pid: Some(42),
            ppid: Some(1),
            process_name: Some("tool".to_string()),
            executable_path: None,
            file_path: Some("/repo/out.txt".to_string()),
            command_line: None,
            raw_json: "{}".to_string(),
        };
        let policy = policy_with(json!({
            "endpoint_security": { "minimum_recorded_severity": "high" },
            "review_overrides": [{
                "rule_id": "unmatched_system_effect",
                "severity": "low",
                "action": "warn"
            }]
        }));

        assert!(prepare_policy_alert(&policy, unmatched_system_event_alert(&event)).is_none());
    }

    #[test]
    fn duplicate_rule_and_path_alerts_are_collapsed() {
        let policy = Policy::from_json(policy::default_policy_json()).unwrap();
        let path = "/Users/test/.ssh/config".to_string();
        let enrichment = observation_enrichment(
            &policy,
            Some("session"),
            Some("tool"),
            1,
            [
                ("read".to_string(), path.clone()),
                ("read".to_string(), path),
            ],
            true,
        );

        assert_eq!(enrichment.alerts.len(), 1);
        assert_eq!(enrichment.alerts[0].rule_id, "policy_sensitive_file_access");
    }

    #[test]
    fn policy_wrappers_persist_sensitive_file_intent_alerts() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-cli-store-enrichment-intent-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let intent = FileIntent {
            provider: "external-file-intent-source".to_string(),
            session_id: Some("session".to_string()),
            tool_use_id: Some("tool".to_string()),
            observed_at_ms: 1,
            operation: "read".to_string(),
            path: "/Users/test/.ssh/config".to_string(),
            source_command: "read file".to_string(),
            sensitive: true,
            confidence: "high".to_string(),
        };

        append_file_intent_with_policy(&store, &intent).unwrap();

        let alerts = store.list_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "policy_sensitive_file_access");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn policy_wrapper_prepares_unmatched_system_alert() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-cli-store-enrichment-unmatched-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let event = SystemEvent {
            source: "test-monitor".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            execution_origin: Default::default(),
            observed_at_ms: 1,
            pid: Some(42),
            ppid: Some(1),
            process_name: Some("tool".to_string()),
            executable_path: None,
            file_path: Some("/repo/out.txt".to_string()),
            command_line: None,
            raw_json: "{}".to_string(),
        };

        append_system_event_with_policy(&store, &event).unwrap();

        let alerts = store.list_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "unmatched_system_effect");
        assert_eq!(alerts[0].severity, "medium");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn notebook_tools_use_store_extraction_for_alerts_and_classification() {
        let dir = std::env::temp_dir().join(format!(
            "gensee-cli-store-enrichment-notebook-{}",
            std::process::id()
        ));
        let store = EventStore::new(&dir).unwrap();
        let secret_path = "/Users/test/.ssh/config";
        let memory_path = "/Users/test/.claude/CLAUDE.md";

        append_hook_event_with_policy(
            &store,
            &hook_event("NotebookRead", json!({ "notebook_path": secret_path }), 1),
        )
        .unwrap();
        append_hook_event_with_policy(
            &store,
            &hook_event("NotebookEdit", json!({ "notebook_path": memory_path }), 2),
        )
        .unwrap();

        assert!(store
            .list_alerts()
            .unwrap()
            .iter()
            .any(|alert| alert.rule_id == "policy_sensitive_file_access"
                && alert.path.as_deref() == Some(secret_path)));
        let fact = store.artifact_fact_for_file(memory_path).unwrap().unwrap();
        let expected = artifact_classification(Policy::global(), memory_path.to_string());
        assert_eq!(fact.is_memory_artifact, expected.is_memory_artifact);
        assert_eq!(fact.is_persistent_target, expected.is_persistent_target);
        assert_eq!(fact.is_control_plane, expected.is_control_plane);
        assert!(
            fact.is_memory_artifact || fact.is_persistent_target || fact.is_control_plane,
            "test path must exercise a non-default classification"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
