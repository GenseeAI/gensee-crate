use crate::*;

pub(crate) fn append_hook_event_with_policy(
    store: &EventStore,
    event: &AgentHookEvent,
) -> io::Result<()> {
    let policy = Policy::load_current();
    let operations = native_policy_subjects(event)
        .into_iter()
        .map(|subject| (subject.operation, subject.path));
    let enrichment = observation_enrichment(
        &policy,
        event.session_id.as_deref(),
        event.tool_use_id.as_deref(),
        event.observed_at_ms,
        operations,
    );
    store.append_hook_event_with_enrichment(event, &enrichment)
}

pub(crate) fn append_file_intent_with_policy(
    store: &EventStore,
    intent: &FileIntent,
) -> io::Result<()> {
    let policy = Policy::load_current();
    let enrichment = observation_enrichment(
        &policy,
        intent.session_id.as_deref(),
        intent.tool_use_id.as_deref(),
        intent.observed_at_ms,
        [(intent.operation.clone(), intent.path.clone())],
    );
    store.append_file_intent_with_enrichment(intent, &enrichment)
}

pub(crate) fn append_workspace_effect_with_policy(
    store: &EventStore,
    effect: &WorkspaceEffect,
) -> io::Result<()> {
    let policy = Policy::load_current();
    let enrichment = observation_enrichment(
        &policy,
        effect.session_id.as_deref(),
        None,
        effect.observed_at_ms,
        [(effect.effect_type.clone(), effect.path.clone())],
    );
    store.append_workspace_effect_with_enrichment(effect, &enrichment)
}

pub(crate) fn append_system_event_with_policy(
    store: &EventStore,
    event: &SystemEvent,
) -> io::Result<()> {
    let policy = Policy::load_current();
    let artifact_classifications = gensee_crate_store::system_event_paths(event)
        .into_iter()
        .map(|path| artifact_classification(&policy, path))
        .collect();
    store.append_system_event_with_enrichment(
        event,
        &ObservationEnrichment {
            alerts: Vec::new(),
            artifact_classifications,
        },
    )
}

pub(crate) fn record_policy_alert(store: &EventStore, alert: &PolicyAlert) -> io::Result<bool> {
    let policy = Policy::load_current();
    let Some(alert) = prepare_policy_alert(&policy, alert.clone()) else {
        return Ok(false);
    };
    store.append_policy_alert(&alert)?;
    Ok(true)
}

pub(crate) fn record_endpoint_policy_alert(
    store: &EventStore,
    alert: &PolicyAlert,
    dedupe_key: &str,
    window_ms: u64,
) -> io::Result<bool> {
    let policy = Policy::load_current();
    let Some(alert) = prepare_policy_alert(&policy, alert.clone()) else {
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
) -> ObservationEnrichment {
    let mut enrichment = ObservationEnrichment::default();
    let mut classified_paths = HashSet::new();
    for (operation, path) in operations {
        if classified_paths.insert(path.clone()) {
            enrichment
                .artifact_classifications
                .push(artifact_classification(policy, path.clone()));
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
            if let Some(alert) = prepare_policy_alert(policy, alert) {
                enrichment.alerts.push(alert);
            }
        }
    }
    enrichment
}

fn prepare_policy_alert(policy: &Policy, mut alert: PolicyAlert) -> Option<PolicyAlert> {
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
        alert.evidence = add_evidence_field(
            alert.evidence,
            "pre_review_severity",
            Value::String(severity),
        );
    }
    if let Some(action) = tuned.pre_review_action {
        alert.evidence =
            add_evidence_field(alert.evidence, "pre_review_action", Value::String(action));
    }
    alert.severity = tuned.severity;
    alert.action = tuned.action;
    Some(alert)
}

fn add_evidence_field(evidence: Option<Value>, key: &str, value: Value) -> Option<Value> {
    match evidence {
        Some(Value::Object(mut map)) => {
            map.insert(key.to_string(), value);
            Some(Value::Object(map))
        }
        Some(details) => {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), value);
            map.insert("details".to_string(), details);
            Some(Value::Object(map))
        }
        None => {
            let mut map = serde_json::Map::new();
            map.insert(key.to_string(), value);
            Some(Value::Object(map))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
