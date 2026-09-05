use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    FileOpen,
    FileWrite,
    FileDelete,
    ProcessExec,
    NetworkConnect,
}

#[derive(Debug, Clone)]
pub struct AgentAttribution {
    pub root_process_id: u32,
    pub parent_process_id: Option<u32>,
    pub process_id: u32,
    pub process_tree_id: String,
    pub agent_name: Option<String>,
    pub working_directory: Option<String>,
    pub repo_path: Option<String>,
    pub terminal_session_id: Option<String>,
    pub attribution_confidence: f32,
}

#[derive(Debug, Clone)]
pub struct AgentEvent {
    pub kind: EventKind,
    pub timestamp_ms: u64,
    pub process_name: String,
    pub file_path: Option<String>,
    pub command_args: Option<String>,
    pub network_dest: Option<String>,
    pub attribution: AgentAttribution,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemEvent {
    pub source: String,
    pub event_type: String,
    pub event_kind: String,
    pub observed_at_ms: u64,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub executable_path: Option<String>,
    pub file_path: Option<String>,
    pub command_line: Option<String>,
    pub raw_json: String,
}

/// Where an observed effect crossed into the endpoint.
///
/// This is deliberately evidence-based. Collectors must use `Unattributed`
/// when they cannot distinguish a native action from a VM or cloud bridge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionOrigin {
    HostNative,
    VmMediated,
    CloudMediated,
    #[default]
    Unattributed,
}

impl ExecutionOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostNative => "host-native",
            Self::VmMediated => "vm-mediated",
            Self::CloudMediated => "cloud-mediated",
            Self::Unattributed => "unattributed",
        }
    }
}

impl SystemEvent {
    /// Return the mandatory execution-origin label. Legacy and third-party
    /// records without one are never guessed; they read as `unattributed`.
    pub fn execution_origin(&self) -> ExecutionOrigin {
        serde_json::from_str::<Value>(&self.raw_json)
            .ok()
            .and_then(|value| value.get("execution_origin").cloned())
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }

    /// Attach an execution-origin label without discarding the collector's
    /// original JSON evidence. Non-object payloads are retained under
    /// `collector_payload`.
    pub fn with_execution_origin(mut self, origin: ExecutionOrigin) -> Self {
        let payload = serde_json::from_str::<Value>(&self.raw_json)
            .unwrap_or_else(|_| Value::String(self.raw_json.clone()));
        let mut object = match payload {
            Value::Object(object) => object,
            collector_payload => json!({ "collector_payload": collector_payload })
                .as_object()
                .expect("literal is an object")
                .clone(),
        };
        object.insert(
            "execution_origin".to_string(),
            Value::String(origin.as_str().to_string()),
        );
        self.raw_json = Value::Object(object).to_string();
        self
    }
}

#[cfg(test)]
mod execution_origin_tests {
    use super::{ExecutionOrigin, SystemEvent};
    use serde_json::Value;

    fn event(raw_json: &str) -> SystemEvent {
        SystemEvent {
            source: "test".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            observed_at_ms: 1,
            pid: Some(7),
            ppid: None,
            process_name: None,
            executable_path: None,
            file_path: None,
            command_line: None,
            raw_json: raw_json.to_string(),
        }
    }

    #[test]
    fn missing_or_unknown_origin_is_unattributed() {
        assert_eq!(
            event("{}").execution_origin(),
            ExecutionOrigin::Unattributed
        );
        assert_eq!(
            event(r#"{"execution_origin":"future-origin"}"#).execution_origin(),
            ExecutionOrigin::Unattributed
        );
    }

    #[test]
    fn attaches_origin_without_losing_collector_evidence() {
        let event =
            event(r#"{"event_id":"event-1"}"#).with_execution_origin(ExecutionOrigin::VmMediated);
        let value: Value = serde_json::from_str(&event.raw_json).unwrap();
        assert_eq!(value["event_id"], "event-1");
        assert_eq!(value["execution_origin"], "vm-mediated");
        assert_eq!(event.execution_origin(), ExecutionOrigin::VmMediated);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceEffect {
    pub source: String,
    pub session_id: Option<String>,
    pub workspace: String,
    pub path: String,
    pub effect_type: String,
    pub observed_at_ms: u64,
    pub attribution: String,
    pub confidence: String,
}
