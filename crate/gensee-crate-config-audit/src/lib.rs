//! Static, read-only security and privacy audits for coding-agent configuration.
//!
//! The first provider adapter is Codex. The crate deliberately does not launch
//! configured hooks, MCP servers, skills, plugins, or the Codex binary while
//! auditing them.

mod codex;
mod model;
mod targets;
mod vscode;

pub use codex::{audit_codex, CodexAuditOptions};
pub use model::{
    Assessment, AuditApplicability, AuditBundle, AuditFinding, AuditInventory, AuditReport,
    AuditSource, AuditSummary, Evidence, ExtensionInventory, ManualCheck, McpInventory,
    Remediation, Ruleset, Severity, SkillInventory, TargetAuditReport,
};
pub use targets::{audit_target, AuditOptions, AuditTargetName};
pub use vscode::{audit_github_copilot_vscode, audit_vscode_host, VscodeAuditOptions};

pub const CODEX_RULESET_ID: &str = "codex-local-v1";
pub const CODEX_RULESET_VERSION: &str = "1.0.0";
pub const VSCODE_RULESET_ID: &str = "vscode-local-v1";
pub const VSCODE_RULESET_VERSION: &str = "1.0.0";
pub const GITHUB_COPILOT_VSCODE_RULESET_ID: &str = "github-copilot-vscode-v1";
pub const GITHUB_COPILOT_VSCODE_RULESET_VERSION: &str = "1.0.0";
