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

    pub fn from_label(value: &str) -> Self {
        match value {
            "host-native" => Self::HostNative,
            "vm-mediated" => Self::VmMediated,
            "cloud-mediated" => Self::CloudMediated,
            _ => Self::Unattributed,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemEvent {
    pub source: String,
    pub event_type: String,
    pub event_kind: String,
    #[serde(default)]
    pub execution_origin: ExecutionOrigin,
    pub observed_at_ms: u64,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub executable_path: Option<String>,
    pub file_path: Option<String>,
    pub command_line: Option<String>,
    pub raw_json: String,
}

impl SystemEvent {
    /// Return the mandatory execution-origin label. Legacy and third-party
    /// records without one are never guessed; they read as `unattributed`.
    pub fn execution_origin(&self) -> ExecutionOrigin {
        self.execution_origin
    }
}

#[cfg(test)]
mod execution_origin_tests {
    use super::{ExecutionOrigin, SystemEvent};

    fn event(raw_json: &str) -> SystemEvent {
        SystemEvent {
            source: "test".to_string(),
            event_type: "write".to_string(),
            event_kind: "file_mutation".to_string(),
            execution_origin: ExecutionOrigin::Unattributed,
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
    fn legacy_serialized_event_defaults_to_unattributed() {
        let serialized = serde_json::to_value(event("{}")).unwrap();
        let mut object = serialized.as_object().unwrap().clone();
        object.remove("execution_origin");
        let event: SystemEvent = serde_json::from_value(object.into()).unwrap();
        assert_eq!(event.execution_origin(), ExecutionOrigin::Unattributed);
        assert_eq!(
            ExecutionOrigin::from_label("collector-controlled-value"),
            ExecutionOrigin::Unattributed
        );
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
