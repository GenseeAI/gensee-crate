use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    pub fn at_least(self, threshold: Self) -> bool {
        self.rank() >= threshold.rank()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Confirmed,
    Potential,
    NotAssessable,
}

impl Assessment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Potential => "potential",
            Self::NotAssessable => "not_assessable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSource {
    pub kind: String,
    pub path: String,
    pub exists: bool,
    pub applied: bool,
    pub trusted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub suggested_values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: String,
    pub assessment: Assessment,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    pub remediation: Remediation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mappings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualCheck {
    pub check_id: String,
    pub priority: String,
    pub title: String,
    pub reason: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInventory {
    pub name: String,
    pub path: String,
    pub scope: String,
    pub enabled: bool,
    pub has_scripts: bool,
    pub review_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpInventory {
    pub id: String,
    pub transport: String,
    pub enabled: bool,
    pub has_tool_allowlist: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditInventory {
    pub skills: Vec<SkillInventory>,
    pub mcp_servers: Vec<McpInventory>,
    pub hook_commands: usize,
    pub plugin_manifests: usize,
    pub marketplace_files: usize,
    pub rule_files: usize,
    pub instruction_files: usize,
    pub managed_requirement_files: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionInventory>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub custom_agents: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInventory {
    pub id: String,
    pub version: String,
    pub path: String,
    pub enabled_state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub assessment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
    pub counts: BTreeMap<String, usize>,
    pub manual_checks: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    pub provider: String,
    pub workspace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_home: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codex_version: Option<String>,
    pub surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vscode_user_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vscode_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub schema_version: u32,
    pub ruleset: Ruleset,
    pub target: AuditTarget,
    pub summary: AuditSummary,
    pub sources: Vec<AuditSource>,
    pub effective_security_config: BTreeMap<String, serde_json::Value>,
    pub inventory: AuditInventory,
    pub findings: Vec<AuditFinding>,
    pub manual_checks: Vec<ManualCheck>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditApplicability {
    Applicable,
    Partial,
    NotDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAuditReport {
    pub target: String,
    pub applicability: AuditApplicability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicability_reason: Option<String>,
    pub report: AuditReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBundle {
    pub schema_version: u32,
    pub requested_target: String,
    pub resolved_targets: Vec<String>,
    pub summary: AuditSummary,
    pub reports: Vec<TargetAuditReport>,
}
