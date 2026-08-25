use gensee_crate_core::{AgentEvent, EventKind};

pub mod boundary_proof;
pub mod capability;
pub mod capability_broker;
pub mod capability_fault;
pub mod capability_policy;
pub mod contract_catalog;
pub mod network_boundary;
pub mod operation_context;
pub mod operation_contract;
pub mod policy;
pub mod semantic_verifier;
pub mod transactional_promotion;

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub name: &'static str,
    pub severity: &'static str,
    pub description: String,
}

pub fn sensitive_file_access(event: &AgentEvent) -> Option<RuleMatch> {
    let path = event.file_path.as_deref()?;
    let sensitive = [".env", ".ssh", ".aws", "credential", "token", "key"];

    if event.kind == EventKind::FileOpen && sensitive.iter().any(|needle| path.contains(needle)) {
        return Some(RuleMatch {
            name: "sensitive_file_access",
            severity: "high",
            description: format!("Sensitive file access: {path}"),
        });
    }

    None
}
