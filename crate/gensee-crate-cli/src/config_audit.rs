use std::env;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use gensee_crate_config_audit::{
    audit_codex, Assessment, AuditReport, CodexAuditOptions, Severity,
};

const AUDIT_USAGE: &str = r#"Usage:
  gensee audit config [OPTIONS]
  gensee audit codex [OPTIONS]

Review local Codex configuration without executing Codex, MCP servers, hooks,
skills, or plugins.

Options:
  --provider <codex>   Provider to audit (default: codex)
  --workspace <PATH>   Workspace to inspect (default: current directory)
  --codex-home <PATH>  Codex home to inspect (default: CODEX_HOME or ~/.codex)
  --profile <NAME>     Apply a named Codex profile
  --json               Emit the versioned JSON report
  --fail-on <LEVEL>    Exit 1 when a finding is at or above LEVEL
                       (critical, high, medium, low, info, none)
  -h, --help           Show this help
"#;

#[derive(Debug)]
struct AuditCliOptions {
    provider: String,
    workspace: PathBuf,
    codex_home: Option<PathBuf>,
    profile: Option<String>,
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

    if options.provider != "codex" {
        let message = format!(
            "unsupported audit provider {:?}; this prototype supports only codex",
            options.provider
        );
        eprintln!("error: {message}");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    }

    let audit_options =
        CodexAuditOptions::discover(options.workspace, options.codex_home, options.profile);

    let report = audit_codex(&audit_options)?;
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(io::Error::other)?
        );
    } else {
        print_human_report(&report);
    }

    if options.fail_on.is_some_and(|threshold| {
        report.findings.iter().any(|finding| {
            finding.assessment != Assessment::NotAssessable && finding.severity.at_least(threshold)
        })
    }) {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_options(args: &[OsString]) -> Result<Option<AuditCliOptions>, String> {
    let mut index = 0;
    let mut provider = "codex".to_owned();

    if let Some(command) = args.first().and_then(|value| value.to_str()) {
        match command {
            "-h" | "--help" => return Ok(None),
            "config" => index = 1,
            "codex" => index = 1,
            other if other.starts_with('-') => {}
            other => return Err(format!("unknown audit command {other:?}")),
        }
    }

    let mut workspace = env::current_dir().map_err(|error| error.to_string())?;
    let mut codex_home = None;
    let mut profile = None;
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
                provider = required_value(args, index, "--provider")?;
            }
            "--workspace" => {
                index += 1;
                workspace = PathBuf::from(required_value(args, index, "--workspace")?);
            }
            "--codex-home" => {
                index += 1;
                codex_home = Some(PathBuf::from(required_value(args, index, "--codex-home")?));
            }
            "--profile" => {
                index += 1;
                profile = Some(required_value(args, index, "--profile")?);
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
        provider,
        workspace,
        codex_home,
        profile,
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

fn print_human_report(report: &AuditReport) {
    println!("Codex configuration audit");
    println!("Workspace: {}", report.target.workspace);
    println!("Codex home: {}", report.target.codex_home);
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
        assert_eq!(options.provider, "codex");
        assert_eq!(options.fail_on, Some(Severity::High));
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
