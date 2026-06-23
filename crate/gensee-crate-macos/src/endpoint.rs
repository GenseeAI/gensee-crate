use gensee_crate_core::{AgentAttribution, AgentEvent, EventKind};

pub struct MacOSEndpointMonitor;

pub const EXEC_EVENT_TYPES: &[&str] = &["exec", "fork", "exit"];

pub const FILE_MUTATION_EVENT_TYPES: &[&str] = &[
    "create",
    "write",
    "rename",
    "unlink",
    "close",
    "truncate",
    "clone",
    "copyfile",
    "exchangedata",
    "setextattr",
    "deleteextattr",
    "setmode",
    "setowner",
    "setflags",
    "setacl",
];

pub const FILE_OPEN_EVENT_TYPES: &[&str] = &[
    "open",
    "lookup",
    "access",
    "stat",
    "getattrlist",
    "readlink",
    "readdir",
    "getextattr",
    "listextattr",
    "fsgetpath",
];

impl MacOSEndpointMonitor {
    pub fn new() -> Self {
        Self
    }

    pub fn start_monitoring(&self) {
        // Placeholder for macOS EndpointSecurity event subscriptions.
    }

    pub fn placeholder_exec_event(&self) -> AgentEvent {
        AgentEvent {
            kind: EventKind::ProcessExec,
            timestamp_ms: 0,
            process_name: "agent-placeholder".to_string(),
            file_path: None,
            command_args: None,
            network_dest: None,
            attribution: AgentAttribution {
                root_process_id: 0,
                parent_process_id: None,
                process_id: 0,
                process_tree_id: "placeholder".to_string(),
                agent_name: None,
                working_directory: None,
                repo_path: None,
                terminal_session_id: None,
                attribution_confidence: 0.0,
            },
        }
    }
}

impl Default for MacOSEndpointMonitor {
    fn default() -> Self {
        Self::new()
    }
}
