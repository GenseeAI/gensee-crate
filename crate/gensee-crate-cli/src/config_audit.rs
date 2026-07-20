use std::env;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use gensee_crate_config_audit::{
    audit_target, Assessment, AuditApplicability, AuditBundle, AuditOptions, AuditReport,
    AuditTargetName, Severity,
};

const AUDIT_USAGE: &str = r#"Usage:
  gensee audit config [OPTIONS]
  gensee audit codex [OPTIONS]
  gensee audit vscode [OPTIONS]
  gensee audit codex-cli [OPTIONS]
  gensee audit github-copilot-vscode [OPTIONS]
  gensee audit vscode-agent-host [OPTIONS]

Review local coding-agent configuration without executing agents or configured
extensions.

Options:
  --target <TARGET>    Explicit alias or leaf target
  --provider <NAME>    Compatibility spelling for codex or vscode
  --workspace <PATH>   Workspace to inspect (default: current directory)
  --codex-home <PATH>  Codex home to inspect (default: CODEX_HOME or ~/.codex)
  --codex-profile <N>  Apply a named Codex profile
  --profile <NAME>     Alias for --codex-profile
  --vscode-user-data <PATH>
                       VS Code User directory containing settings.json
  --vscode-profile <ID>
                       Apply a VS Code profile ID
  --json               Emit the versioned JSON report
  --fail-on <LEVEL>    Exit 1 when a finding is at or above LEVEL
                       (critical, high, medium, low, info, none)
  -h, --help           Show this help
"#;

#[derive(Debug)]
struct AuditCliOptions {
    target: AuditTargetName,
    workspace: PathBuf,
    codex_home: Option<PathBuf>,
    codex_profile: Option<String>,
    vscode_user_data: Option<PathBuf>,
    vscode_profile: Option<String>,
    json: bool,
    fail_on: Option<Severity>,
}

pub(crate) fn handle_config_audit(args: &[OsString]) -> io::Result<()> {
    let options = match parse_options(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{AUDIT_USAGE}");
            return Ok(());
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{AUDIT_USAGE}");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        }
    };

    let report = audit_target(
        options.target,
        &AuditOptions {
            workspace: options.workspace,
            codex_home: options.codex_home,
            codex_profile: options.codex_profile,
            vscode_user_data: options.vscode_user_data,
            vscode_profile: options.vscode_profile,
        },
    )?;
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(io::Error::other)?
        );
    } else {
        print_human_bundle(&report);
    }

    if options.fail_on.is_some_and(|threshold| {
        report.reports.iter().any(|target| {
            target.applicability != AuditApplicability::NotDetected
                && target.report.findings.iter().any(|finding| {
                    finding.assessment != Assessment::NotAssessable
                        && finding.severity.at_least(threshold)
                })
        })
    }) {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_options(args: &[OsString]) -> Result<Option<AuditCliOptions>, String> {
    let mut index = 0;
    let mut target = AuditTargetName::Codex;

    if let Some(command) = args.first().and_then(|value| value.to_str()) {
        match command {
            "-h" | "--help" => return Ok(None),
            "config" => index = 1,
            "codex" | "vscode" | "codex-cli" | "github-copilot-vscode" | "vscode-agent-host" => {
                target = command.parse()?;
                index = 1;
            }
            other if other.starts_with('-') => {}
            other => return Err(format!("unknown audit command {other:?}")),
        }
    }

    let mut workspace = env::current_dir().map_err(|error| error.to_string())?;
    let mut codex_home = None;
    let mut codex_profile = None;
    let mut vscode_user_data = None;
    let mut vscode_profile = None;
    let mut json = false;
    let mut fail_on = None;

    while index < args.len() {
        let argument = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        match argument {
            "-h" | "--help" => return Ok(None),
            "--json" => json = true,
            "--provider" => {
                index += 1;
                target = required_value(args, index, "--provider")?.parse()?;
            }
            "--target" => {
                index += 1;
                target = required_value(args, index, "--target")?.parse()?;
            }
            "--workspace" => {
                index += 1;
                workspace = PathBuf::from(required_value(args, index, "--workspace")?);
            }
            "--codex-home" => {
                index += 1;
                codex_home = Some(PathBuf::from(required_value(args, index, "--codex-home")?));
            }
            "--profile" | "--codex-profile" => {
                index += 1;
                codex_profile = Some(required_value(args, index, argument)?);
            }
            "--vscode-user-data" => {
                index += 1;
                vscode_user_data = Some(PathBuf::from(required_value(
                    args,
                    index,
                    "--vscode-user-data",
                )?));
            }
            "--vscode-profile" => {
                index += 1;
                vscode_profile = Some(required_value(args, index, "--vscode-profile")?);
            }
            "--fail-on" => {
                index += 1;
                let value = required_value(args, index, "--fail-on")?;
                fail_on = match value.as_str() {
                    "none" => None,
                    "critical" => Some(Severity::Critical),
                    "high" => Some(Severity::High),
                    "medium" => Some(Severity::Medium),
                    "low" => Some(Severity::Low),
                    "info" => Some(Severity::Info),
                    _ => {
                        return Err(format!(
                            "invalid --fail-on level {value:?}; expected critical, high, medium, low, info, or none"
                        ));
                    }
                };
            }
            other => return Err(format!("unknown audit option {other:?}")),
        }
        index += 1;
    }

    Ok(Some(AuditCliOptions {
        target,
        workspace,
        codex_home,
        codex_profile,
        vscode_user_data,
        vscode_profile,
        json,
        fail_on,
    }))
}

fn required_value(args: &[OsString], index: usize, option: &str) -> Result<String, String> {
    args.get(index)
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn print_human_bundle(bundle: &AuditBundle) {
    println!("Coding-agent configuration audit");
    println!("Requested target: {}", bundle.requested_target);
    println!("Resolved targets: {}", bundle.resolved_targets.join(", "));
    println!("Assessment: {}", bundle.summary.assessment);
    println!();
    println!(
        "Findings: {} critical, {} high, {} medium, {} low, {} info",
        bundle_count(bundle, "critical"),
        bundle_count(bundle, "high"),
        bundle_count(bundle, "medium"),
        bundle_count(bundle, "low"),
        bundle_count(bundle, "info")
    );
    for target in &bundle.reports {
        println!();
        println!("=== {} ({:?}) ===", target.target, target.applicability);
        if let Some(reason) = &target.applicability_reason {
            println!("{reason}");
        }
        if target.applicability != AuditApplicability::NotDetected {
            print_human_report(&target.report);
        }
    }
}

fn print_human_report(report: &AuditReport) {
    println!("Workspace: {}", report.target.workspace);
    if let Some(codex_home) = &report.target.codex_home {
        println!("Codex home: {codex_home}");
    }
    if let Some(user_data) = &report.target.vscode_user_data {
        println!("VS Code user data: {user_data}");
    }
    println!("Ruleset: {} {}", report.ruleset.id, report.ruleset.version);
    println!("Assessment: {}", report.summary.assessment);
    println!();
    println!(
        "Findings: {} critical, {} high, {} medium, {} low, {} info",
        finding_count(report, "critical"),
        finding_count(report, "high"),
        finding_count(report, "medium"),
        finding_count(report, "low"),
        finding_count(report, "info")
    );

    if report.findings.is_empty() {
        println!("No findings.");
    } else {
        for finding in &report.findings {
            println!();
            println!(
                "[{}/{}] {} ({})",
                finding.severity.as_str().to_uppercase(),
                finding.assessment.as_str().to_uppercase(),
                finding.title,
                finding.rule_id
            );
            println!("  {}", finding.description);
            for evidence in &finding.evidence {
                let mut detail = evidence.source.clone();
                if let Some(key) = &evidence.key {
                    detail.push_str(&format!(": {key}"));
                }
                if let Some(value) = &evidence.value {
                    detail.push_str(&format!(" = {value}"));
                }
                println!("  Evidence: {detail}");
            }
            println!("  Fix: {}", finding.remediation.summary);
        }
    }

    println!();
    println!("Inventory:");
    println!("  Sources: {}", report.sources.len());
    println!("  MCP servers: {}", report.inventory.mcp_servers.len());
    println!("  Skills: {}", report.inventory.skills.len());
    println!("  Hook commands: {}", report.inventory.hook_commands);
    println!("  Plugin manifests: {}", report.inventory.plugin_manifests);
    println!(
        "  Marketplace files: {}",
        report.inventory.marketplace_files
    );
    println!("  Command rule files: {}", report.inventory.rule_files);
    println!(
        "  Agent instruction files: {}",
        report.inventory.instruction_files
    );
    println!(
        "  Managed requirement files: {}",
        report.inventory.managed_requirement_files
    );

    if !report.manual_checks.is_empty() {
        println!();
        println!("Manual checks:");
        for check in &report.manual_checks {
            println!("  - {}: {}", check.title, check.reason);
            println!("    Action: {}", check.action);
        }
    }

    if !report.limitations.is_empty() {
        println!();
        println!("Limitations:");
        for limitation in &report.limitations {
            println!("  - {limitation}");
        }
    }
}

fn finding_count(report: &AuditReport, severity: &str) -> usize {
    report.summary.counts.get(severity).copied().unwrap_or(0)
}

fn bundle_count(bundle: &AuditBundle, severity: &str) -> usize {
    bundle.summary.counts.get(severity).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_json_and_threshold() {
        let options = parse_options(&arguments(&[
            "config",
            "--provider",
            "codex",
            "--json",
            "--fail-on",
            "high",
        ]))
        .expect("valid options")
        .expect("not help");

        assert!(options.json);
        assert_eq!(options.target, AuditTargetName::Codex);
        assert_eq!(options.fail_on, Some(Severity::High));
    }

    #[test]
    fn vscode_alias_resolves_from_command() {
        let options = parse_options(&arguments(&["vscode", "--json"]))
            .expect("valid options")
            .expect("not help");
        assert_eq!(options.target, AuditTargetName::Vscode);
        assert!(options.json);
    }

    #[test]
    fn rejects_unknown_provider_level() {
        let error = parse_options(&arguments(&["codex", "--fail-on", "severe"]))
            .expect_err("invalid threshold");
        assert!(error.contains("invalid --fail-on"));
    }

    #[test]
    fn audit_is_excluded_from_telemetry_bootstrap() {
        assert!(!crate::should_bootstrap_telemetry_for_command("audit"));
    }
}
