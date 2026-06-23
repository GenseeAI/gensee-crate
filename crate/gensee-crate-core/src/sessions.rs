#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentSession {
    pub session_id: String,
    pub agent_binary: String,
    pub root_pid: u32,
    pub cwd: String,
    pub repo_path: Option<String>,
    pub mode: Option<String>,
    pub workspace_mode: Option<String>,
    pub original_workspace: Option<String>,
    pub staged_workspace: Option<String>,
    pub sandbox_profile: Option<String>,
    pub sandbox_profile_path: Option<String>,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub exit_code: Option<i32>,
}

impl AgentSession {
    pub fn is_active(&self) -> bool {
        self.ended_at_ms.is_none()
    }
}
