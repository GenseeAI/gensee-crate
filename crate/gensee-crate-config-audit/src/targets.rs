use crate::{
    audit_codex, audit_github_copilot_vscode, audit_vscode_host, Assessment, AuditApplicability,
    AuditBundle, AuditSummary, CodexAuditOptions, Severity, TargetAuditReport, VscodeAuditOptions,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditTargetName {
    Codex,
    Vscode,
    CodexCli,
    GithubCopilotVscode,
    VscodeAgentHost,
}

impl AuditTargetName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Vscode => "vscode",
            Self::CodexCli => "codex-cli",
            Self::GithubCopilotVscode => "github-copilot-vscode",
            Self::VscodeAgentHost => "vscode-agent-host",
        }
    }

    pub fn resolved(self) -> &'static [AuditTargetName] {
        match self {
            Self::Codex => &[Self::CodexCli],
            Self::Vscode => &[Self::VscodeAgentHost, Self::GithubCopilotVscode],
            Self::CodexCli => &[Self::CodexCli],
            Self::GithubCopilotVscode => &[Self::GithubCopilotVscode],
            Self::VscodeAgentHost => &[Self::VscodeAgentHost],
        }
    }
}

impl FromStr for AuditTargetName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "codex" => Ok(Self::Codex),
            "vscode" => Ok(Self::Vscode),
            "codex-cli" => Ok(Self::CodexCli),
            "github-copilot-vscode" => Ok(Self::GithubCopilotVscode),
            "vscode-agent-host" => Ok(Self::VscodeAgentHost),
            _ => Err(format!(
                "unknown audit target {value:?}; expected codex, vscode, codex-cli, github-copilot-vscode, or vscode-agent-host"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub workspace: PathBuf,
    pub codex_home: Option<PathBuf>,
    pub codex_profile: Option<String>,
    pub vscode_user_data: Option<PathBuf>,
    pub vscode_profile: Option<String>,
}

pub fn audit_target(requested: AuditTargetName, options: &AuditOptions) -> io::Result<AuditBundle> {
    let codex_options = CodexAuditOptions::discover(
        options.workspace.clone(),
        options.codex_home.clone(),
        options.codex_profile.clone(),
    );
    let vscode_options = VscodeAuditOptions::discover(
        options.workspace.clone(),
        options.vscode_user_data.clone(),
        options.vscode_profile.clone(),
    );

    let mut reports = Vec::new();
    for target in requested.resolved() {
        let report = match target {
            AuditTargetName::CodexCli => TargetAuditReport {
                target: target.as_str().to_string(),
                applicability: AuditApplicability::Applicable,
                applicability_reason: None,
                report: audit_codex(&codex_options)?,
            },
            AuditTargetName::GithubCopilotVscode => {
                let (applicability, reason) =
                    vscode_options.github_copilot_extension_applicability();
                TargetAuditReport {
                    target: target.as_str().to_string(),
                    applicability,
                    applicability_reason: Some(reason),
                    report: audit_github_copilot_vscode(&vscode_options)?,
                }
            }
            AuditTargetName::VscodeAgentHost => TargetAuditReport {
                target: target.as_str().to_string(),
                applicability: AuditApplicability::Applicable,
                applicability_reason: None,
                report: audit_vscode_host(&vscode_options)?,
            },
            AuditTargetName::Codex | AuditTargetName::Vscode => unreachable!("aliases resolve"),
        };
        reports.push(report);
    }

    let resolved_targets = reports.iter().map(|report| report.target.clone()).collect();
    let included = reports
        .iter()
        .filter(|report| report.applicability != AuditApplicability::NotDetected);
    let mut counts = severity_counts();
    let mut manual_checks = 0;
    let mut assessment = "complete";
    let mut max_severity = None;
    let mut included_any = false;
    for target_report in included {
        included_any = true;
        if target_report.applicability == AuditApplicability::Partial
            || target_report.report.summary.assessment == "partial"
        {
            assessment = "partial";
        }
        manual_checks += target_report.report.manual_checks.len();
        for finding in &target_report.report.findings {
            if finding.assessment == Assessment::NotAssessable {
                continue;
            }
            *counts
                .entry(finding.severity.as_str().to_string())
                .or_default() += 1;
            if max_severity.is_none_or(|current: Severity| finding.severity.rank() > current.rank())
            {
                max_severity = Some(finding.severity);
            }
        }
    }
    if !included_any {
        assessment = "partial";
    }

    Ok(AuditBundle {
        schema_version: 1,
        requested_target: requested.as_str().to_string(),
        resolved_targets,
        summary: AuditSummary {
            assessment: assessment.to_string(),
            max_severity,
            counts,
            manual_checks,
        },
        reports,
    })
}

fn severity_counts() -> BTreeMap<String, usize> {
    ["critical", "high", "medium", "low", "info"]
        .into_iter()
        .map(|severity| (severity.to_string(), 0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_resolve_to_expected_leaf_targets() {
        assert_eq!(
            AuditTargetName::Codex.resolved(),
            &[AuditTargetName::CodexCli]
        );
        assert_eq!(
            AuditTargetName::Vscode.resolved(),
            &[
                AuditTargetName::VscodeAgentHost,
                AuditTargetName::GithubCopilotVscode
            ]
        );
    }

    #[test]
    fn parses_leaf_and_alias_names() {
        assert_eq!("vscode".parse(), Ok(AuditTargetName::Vscode));
        assert_eq!(
            "github-copilot-vscode".parse(),
            Ok(AuditTargetName::GithubCopilotVscode)
        );
        assert!("other".parse::<AuditTargetName>().is_err());
    }
}
