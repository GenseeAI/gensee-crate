//! Static, read-only security and privacy audits for coding-agent configuration.
//!
//! The first provider adapter is Codex. The crate deliberately does not launch
//! configured hooks, MCP servers, skills, plugins, or the Codex binary while
//! auditing them.

mod codex;
mod model;

pub use codex::{audit_codex, CodexAuditOptions};
pub use model::{
    Assessment, AuditFinding, AuditInventory, AuditReport, AuditSource, AuditSummary, Evidence,
    ManualCheck, McpInventory, Remediation, Ruleset, Severity, SkillInventory,
};

pub const CODEX_RULESET_ID: &str = "codex-local-v1";
pub const CODEX_RULESET_VERSION: &str = "1.0.0";
