#[cfg(test)]
use crate::common::MAX_TEXT_FILE_BYTES;
use crate::common::{
    canonical_or_original, collect_json_commands, display_path, endpoint_must_be_redacted,
    executable_dependency_is_unpinned, finding_fingerprint, hash_bytes, insecure_remote_http,
    is_loopback_url, make_finding, normalize_secret_key, read_limited_text, sort_findings,
    source_for, summarize,
};
use crate::model::{
    Assessment, AuditFinding, AuditInventory, AuditReport, AuditSource, AuditTarget, Evidence,
    ManualCheck, McpInventory, Ruleset, Severity, SkillInventory,
};
use crate::{CODEX_RULESET_ID, CODEX_RULESET_VERSION};
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

const CONFIG_REFERENCE: &str = "https://learn.chatgpt.com/docs/config-file/config-reference";
const SECURITY_REFERENCE: &str = "https://learn.chatgpt.com/docs/agent-approvals-security";
const MCP_REFERENCE: &str = "https://learn.chatgpt.com/docs/extend/mcp";
const SKILLS_REFERENCE: &str = "https://learn.chatgpt.com/docs/build-skills";
const RULES_REFERENCE: &str = "https://learn.chatgpt.com/docs/agent-configuration/rules";
const MANAGED_CONFIG_REFERENCE: &str =
    "https://learn.chatgpt.com/docs/enterprise/managed-configuration";
const DATA_REFERENCE: &str = "https://help.openai.com/en/articles/5722486-api-data-usage-policies";

const MAX_DISCOVERY_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct CodexAuditOptions {
    pub workspace: PathBuf,
    pub codex_home: PathBuf,
    pub profile: Option<String>,
}

impl CodexAuditOptions {
    pub fn discover(
        workspace: PathBuf,
        codex_home: Option<PathBuf>,
        profile: Option<String>,
    ) -> Self {
        let codex_home = codex_home
            .or_else(|| env::var_os("CODEX_HOME").map(PathBuf::from))
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex")))
            .unwrap_or_else(|| PathBuf::from(".codex"));
        Self {
            workspace,
            codex_home,
            profile,
        }
    }
}

pub fn audit_codex(options: &CodexAuditOptions) -> io::Result<AuditReport> {
    let original_workspace = options.workspace.clone();
    let workspace = canonical_or_original(&original_workspace);
    let codex_home = canonical_or_original(&options.codex_home);
    let mut sources = Vec::new();
    let mut findings = Vec::new();
    let mut limitations = vec![
        "The audit is static: configured MCP servers, hooks, skills, plugins, and Codex itself were not executed.".to_string(),
        "Account, workspace-administration, cloud-fetched requirements, and model-training settings were not queried.".to_string(),
        "Future command-line flags and -c overrides can change the effective configuration after this audit.".to_string(),
    ];

    let user_path = codex_home.join("config.toml");
    let (mut effective, user_ok) = load_toml_layer(
        &user_path,
        "user_config",
        true,
        true,
        &mut sources,
        &mut findings,
    );
    let mut config_complete = user_ok;
    let mut config_provenance = BTreeMap::new();
    if user_ok {
        record_toml_provenance(&effective, "", &user_path, &mut config_provenance);
    }

    if let Some(profile) = &options.profile {
        let profile_path = codex_home.join(format!("{profile}.config.toml"));
        let (layer, ok) = load_toml_layer(
            &profile_path,
            "profile_config",
            true,
            true,
            &mut sources,
            &mut findings,
        );
        if !profile_path.exists() {
            config_complete = false;
            findings.push(make_finding(
                "CAX-CFG-006",
                "configuration_provenance",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Selected Codex profile does not exist",
                "The requested profile layer could not be applied, so the audited effective configuration differs from the intended invocation.",
                vec![evidence(&profile_path, None, None)],
                "Create the profile file next to config.toml or select an existing profile, then rerun the audit.",
                &[CONFIG_REFERENCE],
                &["OWASP-ASI03"],
            ));
        } else if ok {
            merge_toml(&mut effective, &layer);
            record_toml_provenance(&layer, "", &profile_path, &mut config_provenance);
        }
        config_complete &= ok && profile_path.exists();
    }

    let trusted = project_is_trusted(&effective, &original_workspace, &workspace);
    let project_path = workspace.join(".codex").join("config.toml");
    let mut ignored_project_keys = Vec::new();
    let (mut project_layer, project_ok) = if trusted {
        load_toml_layer(
            &project_path,
            "project_config",
            true,
            true,
            &mut sources,
            &mut findings,
        )
    } else {
        sources.push(source_for(&project_path, "project_config", false, false));
        (TomlValue::Table(Default::default()), true)
    };
    if project_ok && trusted {
        ignored_project_keys = remove_ignored_project_keys(&mut project_layer);
        merge_toml(&mut effective, &project_layer);
        record_toml_provenance(&project_layer, "", &project_path, &mut config_provenance);
    }
    if trusted && project_path.exists() {
        config_complete &= project_ok;
    }
    if let Some(source) = sources
        .iter_mut()
        .find(|source| source.path == display_path(&project_path))
    {
        source.ignored_keys = ignored_project_keys.clone();
    }
    if project_path.exists() && !trusted {
        limitations.push(format!(
            "Project configuration at {} was discovered but not applied because the workspace is not explicitly trusted.",
            project_path.display()
        ));
    }

    for key in ignored_project_keys {
        findings.push(make_finding(
            "CAX-CFG-002",
            "configuration_provenance",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Security-sensitive key is ignored at project scope",
            &format!("Codex ignores `{key}` in project-local configuration, so it does not affect the effective security posture."),
            vec![evidence(&project_path, Some(&key), None)],
            "Move the setting to the user-level Codex configuration or an administrator-managed requirements source.",
            &[CONFIG_REFERENCE],
            &["OWASP-ASI03"],
        ));
    }

    let mut inventory = AuditInventory::default();
    let effective_findings_start = findings.len();
    evaluate_effective_config(&effective, &user_path, &mut inventory, &mut findings);
    reattribute_config_findings(
        &mut findings[effective_findings_start..],
        &config_provenance,
        "codex defaults",
    );
    inventory.skills = discover_skills(
        &workspace,
        &codex_home,
        &effective,
        &mut sources,
        &mut findings,
    );
    evaluate_skill_review_surface(&inventory.skills, &mut findings);
    discover_rules(
        &workspace,
        &codex_home,
        trusted,
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    discover_instruction_files(&workspace, &mut sources, &mut inventory, &mut findings);
    discover_managed_requirements(
        &mut sources,
        &mut inventory,
        &mut findings,
        &mut limitations,
    );
    discover_hooks(
        &workspace,
        &codex_home,
        trusted,
        &effective,
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    discover_plugins_and_marketplaces(
        &workspace,
        &codex_home,
        trusted,
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    scan_source_integrity(&sources, &mut findings);

    let manual_checks = privacy_manual_checks();
    sort_findings(&mut findings);
    let assessment = if config_complete && sources.iter().all(|source| source.errors.is_empty()) {
        "complete"
    } else {
        "partial"
    };
    let summary = summarize(assessment, &findings, manual_checks.len());

    Ok(AuditReport {
        schema_version: 1,
        ruleset: Ruleset {
            id: CODEX_RULESET_ID.to_string(),
            version: CODEX_RULESET_VERSION.to_string(),
        },
        target: AuditTarget {
            provider: "codex".to_string(),
            workspace: display_path(&workspace),
            codex_home: Some(display_path(&codex_home)),
            profile: options.profile.clone(),
            codex_version: None,
            surfaces: vec!["cli".to_string()],
            vscode_user_data: None,
            vscode_profile: None,
        },
        summary,
        sources,
        effective_security_config: effective_security_summary(&effective, &inventory),
        inventory,
        findings,
        manual_checks,
        limitations,
    })
}

fn load_toml_layer(
    path: &Path,
    kind: &str,
    applied: bool,
    trusted: bool,
    sources: &mut Vec<AuditSource>,
    findings: &mut Vec<AuditFinding>,
) -> (TomlValue, bool) {
    let mut source = source_for(path, kind, applied, trusted);
    if !path.exists() {
        sources.push(source);
        return (TomlValue::Table(Default::default()), true);
    }
    let text = match read_limited_text(path) {
        Ok(text) => text,
        Err(error) => {
            source.errors.push(error.to_string());
            findings.push(config_read_finding(path, &error.to_string()));
            sources.push(source);
            return (TomlValue::Table(Default::default()), false);
        }
    };
    source.sha256 = Some(hash_bytes(text.as_bytes()));
    match text.parse::<TomlValue>() {
        Ok(value) => {
            sources.push(source);
            (value, true)
        }
        Err(error) => {
            source.errors.push(
                error
                    .span()
                    .map(|span| format!("TOML parse error at bytes {}..{}", span.start, span.end))
                    .unwrap_or_else(|| "TOML parse error".to_string()),
            );
            findings.push(make_finding(
                "CAX-CFG-001",
                "configuration_provenance",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Codex configuration is invalid",
                "The file could not be parsed completely. Security-sensitive settings may not take effect as expected.",
                vec![evidence(path, None, Some("<parse-error>"))],
                "Correct the TOML syntax and rerun the audit before relying on the configuration.",
                &[CONFIG_REFERENCE],
                &["OWASP-ASI03"],
            ));
            sources.push(source);
            (TomlValue::Table(Default::default()), false)
        }
    }
}

fn config_read_finding(path: &Path, error: &str) -> AuditFinding {
    make_finding(
        "CAX-CFG-003",
        "configuration_provenance",
        Severity::High,
        "high",
        Assessment::Confirmed,
        "Codex configuration could not be read",
        error,
        vec![evidence(path, None, None)],
        "Restore owner-readable permissions and verify the file is not a broken symlink.",
        &[CONFIG_REFERENCE],
        &["OWASP-ASI03"],
    )
}

fn project_is_trusted(config: &TomlValue, workspace: &Path, canonical_workspace: &Path) -> bool {
    let Some(projects) = config.get("projects").and_then(TomlValue::as_table) else {
        return false;
    };
    let candidates = [display_path(workspace), display_path(canonical_workspace)];
    candidates.iter().any(|candidate| {
        projects
            .get(candidate)
            .and_then(TomlValue::as_table)
            .and_then(|project| project.get("trust_level"))
            .and_then(TomlValue::as_str)
            == Some("trusted")
    })
}

fn remove_ignored_project_keys(value: &mut TomlValue) -> Vec<String> {
    const IGNORED: &[&str] = &[
        "openai_base_url",
        "chatgpt_base_url",
        "apps_mcp_product_sku",
        "model_provider",
        "model_providers",
        "notify",
        "profile",
        "profiles",
        "experimental_realtime_ws_base_url",
        "otel",
    ];
    let mut removed = Vec::new();
    if let Some(table) = value.as_table_mut() {
        for key in IGNORED {
            if table.remove(*key).is_some() {
                removed.push((*key).to_string());
            }
        }
    }
    removed
}

fn merge_toml(base: &mut TomlValue, overlay: &TomlValue) {
    match (base, overlay) {
        (TomlValue::Table(base), TomlValue::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(key) {
                    Some(existing) => merge_toml(existing, value),
                    None => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

fn record_toml_provenance(
    value: &TomlValue,
    prefix: &str,
    source: &Path,
    provenance: &mut BTreeMap<String, String>,
) {
    if !prefix.is_empty() {
        provenance.insert(prefix.to_string(), display_path(source));
    }
    if let TomlValue::Table(table) = value {
        for (key, child) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            record_toml_provenance(child, &path, source, provenance);
        }
    }
}

fn reattribute_config_findings(
    findings: &mut [AuditFinding],
    provenance: &BTreeMap<String, String>,
    default_source: &str,
) {
    for finding in findings {
        for item in &mut finding.evidence {
            item.source = item
                .key
                .as_deref()
                .and_then(|key| provenance_source(provenance, key))
                .unwrap_or(default_source)
                .to_string();
        }
        finding.fingerprint = finding_fingerprint(&finding.rule_id, &finding.evidence);
    }
}

fn provenance_source<'a>(provenance: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    provenance
        .iter()
        .filter(|(candidate, _)| {
            key == candidate.as_str()
                || key
                    .strip_prefix(candidate.as_str())
                    .is_some_and(|suffix| suffix.starts_with('.'))
        })
        .max_by_key(|(candidate, _)| candidate.len())
        .map(|(_, source)| source.as_str())
}

fn evaluate_effective_config(
    config: &TomlValue,
    source: &Path,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let approval = config.get("approval_policy").and_then(TomlValue::as_str);
    let sandbox = config.get("sandbox_mode").and_then(TomlValue::as_str);
    let network = get_bool(config, &["sandbox_workspace_write", "network_access"]).unwrap_or(false);

    if sandbox == Some("danger-full-access") {
        findings.push(make_finding(
            "CAX-AUT-001",
            "autonomy_and_approval",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Codex has full host access",
            "The command sandbox is disabled, so commands can access resources available to the Codex process.",
            vec![evidence(source, Some("sandbox_mode"), sandbox)],
            "Use `workspace-write` for normal development or `read-only` for review-only work.",
            &[SECURITY_REFERENCE],
            &["OWASP-ASI02", "OWASP-LLM06"],
        ));
    }
    if approval == Some("never") && sandbox == Some("danger-full-access") {
        findings.push(make_finding(
            "CAX-AUT-002",
            "autonomy_and_approval",
            Severity::Critical,
            "high",
            Assessment::Confirmed,
            "Sandbox and approvals are both bypassed",
            "Commands can execute with host access without a human approval boundary.",
            vec![
                evidence(source, Some("approval_policy"), approval),
                evidence(source, Some("sandbox_mode"), sandbox),
            ],
            "Use `sandbox_mode = \"workspace-write\"` with `approval_policy = \"on-request\"` or `\"untrusted\"`.",
            &[SECURITY_REFERENCE],
            &["OWASP-ASI02", "OWASP-ASI03", "OWASP-LLM06"],
        ));
    } else if approval == Some("never") && (sandbox == Some("workspace-write") || network) {
        findings.push(make_finding(
            "CAX-AUT-003",
            "autonomy_and_approval",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Writable execution has no approval prompts",
            "Codex can mutate workspace state without surfacing approval requests.",
            vec![evidence(source, Some("approval_policy"), approval)],
            "Use `on-request` or `untrusted` unless the invocation is deliberately noninteractive and externally isolated.",
            &[SECURITY_REFERENCE],
            &["OWASP-ASI02", "OWASP-LLM06"],
        ));
    }

    if network && !network_policy_enabled(config) {
        findings.push(make_finding(
            "CAX-NET-001",
            "network_and_external_data",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Command network access is unrestricted",
            "Workspace-write networking is enabled without the Codex network proxy or a named permission-profile policy.",
            vec![evidence(source, Some("sandbox_workspace_write.network_access"), Some("true"))],
            "Enable the network proxy with a scoped domain allowlist, or turn command network access off.",
            &[SECURITY_REFERENCE],
            &["OWASP-ASI02", "OWASP-MCP10"],
        ));
    }
    if let Some(domain_key) = global_domain_allow_key(config) {
        findings.push(make_finding(
            "CAX-NET-002",
            "network_and_external_data",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Network policy allows every public host",
            "A global `*` domain rule removes most destination scoping and increases exfiltration reach.",
            vec![evidence(source, Some(domain_key), Some("allow"))],
            "Replace the global rule with the smallest set of exact or scoped wildcard domains required.",
            &[SECURITY_REFERENCE],
            &["OWASP-ASI02", "OWASP-MCP2"],
        ));
    }
    evaluate_writable_roots(config, source, findings);
    evaluate_shell_environment(config, source, network, findings);
    evaluate_privacy_config(config, source, findings);
    evaluate_permission_profiles(config, source, findings);
    evaluate_mcp_servers(config, source, inventory, findings);
    evaluate_apps(config, source, findings);

    let multi_agent = get_bool(config, &["features", "multi_agent"]).unwrap_or(true);
    let max_threads = get_integer(config, &["agents", "max_threads"]).unwrap_or(6);
    if multi_agent && max_threads > 8 && (network || sandbox == Some("danger-full-access")) {
        findings.push(make_finding(
            "CAX-AUT-004",
            "autonomy_and_approval",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Broad permissions are amplified by high agent concurrency",
            "Multiple concurrent agents can multiply tool calls, data exposure, and the impact of an unsafe instruction.",
            vec![evidence(source, Some("agents.max_threads"), Some(&max_threads.to_string()))],
            "Reduce concurrency or apply narrower filesystem, network, and approval boundaries.",
            &[CONFIG_REFERENCE],
            &["OWASP-ASI02", "OWASP-ASI08"],
        ));
    }
}

fn evaluate_writable_roots(config: &TomlValue, source: &Path, findings: &mut Vec<AuditFinding>) {
    let Some(roots) = get_value(config, &["sandbox_workspace_write", "writable_roots"])
        .and_then(TomlValue::as_array)
    else {
        return;
    };
    for root in roots.iter().filter_map(TomlValue::as_str) {
        if is_broad_path(root) {
            findings.push(make_finding(
                "CAX-SBX-001",
                "sandbox_filesystem_environment",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Additional writable root is overly broad",
                "The workspace-write sandbox grants mutation access to a broad host path.",
                vec![evidence(
                    source,
                    Some("sandbox_workspace_write.writable_roots"),
                    Some(root),
                )],
                "Remove the root or replace it with the narrowest task-specific directory.",
                &[CONFIG_REFERENCE],
                &["OWASP-ASI03", "OWASP-LLM06"],
            ));
        }
    }
}

fn evaluate_shell_environment(
    config: &TomlValue,
    source: &Path,
    network: bool,
    findings: &mut Vec<AuditFinding>,
) {
    let ignore_excludes = get_bool(
        config,
        &["shell_environment_policy", "ignore_default_excludes"],
    )
    .unwrap_or(true);
    let inherit_all = get_str(config, &["shell_environment_policy", "inherit"]) == Some("all");
    if ignore_excludes {
        findings.push(make_finding(
            "CAX-ENV-001",
            "sandbox_filesystem_environment",
            if network {
                Severity::High
            } else {
                Severity::Medium
            },
            "high",
            Assessment::Confirmed,
            "Secret-like environment variables are retained",
            "Codex default filtering for variables containing KEY, SECRET, or TOKEN is disabled.",
            vec![evidence(
                source,
                Some("shell_environment_policy.ignore_default_excludes"),
                Some("true"),
            )],
            "Remove this override and use `include_only` for variables the agent actually needs.",
            &[CONFIG_REFERENCE],
            &["OWASP-MCP1", "OWASP-ASI03"],
        ));
    }
    if inherit_all && !has_environment_allowlist(config) {
        findings.push(make_finding(
            "CAX-ENV-002",
            "sandbox_filesystem_environment",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Subprocesses inherit the full user environment",
            "Broad environment inheritance can expose credentials and internal configuration to tools and child processes.",
            vec![evidence(source, Some("shell_environment_policy.inherit"), Some("all"))],
            "Use `core` or `none`, or define an explicit `filters` allowlist.",
            &[CONFIG_REFERENCE],
            &["OWASP-MCP1", "OWASP-ASI03"],
        ));
    }
    if let Some(set) =
        get_value(config, &["shell_environment_policy", "set"]).and_then(TomlValue::as_table)
    {
        for (key, value) in set {
            if secret_like(key, value.as_str().unwrap_or_default()) {
                findings.push(secret_finding(
                    "CAX-ENV-003",
                    "Secret is embedded in the Codex subprocess environment",
                    source,
                    &format!("shell_environment_policy.set.{key}"),
                    "Reference the credential through a narrowly scoped secret store or injected environment variable instead of config.toml.",
                ));
            }
        }
    }
}

fn has_environment_allowlist(config: &TomlValue) -> bool {
    let canonical_filter_includes = get_value(config, &["shell_environment_policy", "filters"])
        .and_then(TomlValue::as_table)
        .is_some_and(|filters| {
            filters.values().any(|value| {
                value
                    .as_str()
                    .is_some_and(|decision| decision.eq_ignore_ascii_case("include"))
            })
        });
    let legacy_include_only = get_value(config, &["shell_environment_policy", "include_only"])
        .and_then(TomlValue::as_array)
        .is_some_and(|values| !values.is_empty());
    canonical_filter_includes || legacy_include_only
}

fn evaluate_privacy_config(config: &TomlValue, source: &Path, findings: &mut Vec<AuditFinding>) {
    let log_prompt = get_bool(config, &["otel", "log_user_prompt"]).unwrap_or(false);
    let exporter = get_value(config, &["otel", "exporter"]);
    let remote_exporter = exporter.is_some_and(|value| match value {
        TomlValue::String(value) => value != "none",
        TomlValue::Table(_) => true,
        _ => false,
    });
    if log_prompt && remote_exporter {
        findings.push(make_finding(
            "CAX-PRV-003",
            "privacy_retention_telemetry",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Raw prompts are exported through OpenTelemetry",
            "Repository content, user instructions, and pasted secrets can be included in externally exported telemetry.",
            vec![evidence(source, Some("otel.log_user_prompt"), Some("true"))],
            "Set `otel.log_user_prompt = false` and verify the collector's retention and access controls.",
            &[SECURITY_REFERENCE],
            &["OWASP-MCP8", "OWASP-MCP10"],
        ));
    }
    if let Some(exporter) = exporter {
        scan_toml_for_secrets(exporter, "otel.exporter", source, findings, "CAX-PRV-004");
        for endpoint in collect_named_strings(exporter, "endpoint") {
            if endpoint.starts_with("http://") && !is_loopback_url(&endpoint) {
                findings.push(make_finding(
                    "CAX-PRV-005",
                    "privacy_retention_telemetry",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "Telemetry is sent over plaintext HTTP",
                    "Telemetry may contain prompts, tool decisions, and result snippets.",
                    vec![evidence(
                        source,
                        Some("otel.exporter.endpoint"),
                        Some(&endpoint),
                    )],
                    "Use an authenticated TLS endpoint or disable export.",
                    &[SECURITY_REFERENCE],
                    &["OWASP-MCP1", "OWASP-MCP8"],
                ));
            }
        }
    }
    if get_str(config, &["history", "persistence"]) == Some("save-all")
        && get_value(config, &["history", "max_bytes"]).is_none()
    {
        findings.push(make_finding(
            "CAX-PRV-006",
            "privacy_retention_telemetry",
            Severity::Low,
            "high",
            Assessment::Confirmed,
            "Session history has no configured size bound",
            "Local transcripts can accumulate repository content and prompts indefinitely.",
            vec![evidence(source, Some("history.persistence"), Some("save-all"))],
            "Set a history size bound or use `history.persistence = \"none\"` for sensitive workstations.",
            &[CONFIG_REFERENCE],
            &["OWASP-MCP10"],
        ));
    }
    if config.get("log_dir").is_some() {
        findings.push(make_finding(
            "CAX-PRV-007",
            "privacy_retention_telemetry",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Plaintext Codex TUI logging is enabled",
            "Setting `log_dir` opts into a plaintext `codex-tui.log` that can retain sensitive local activity.",
            vec![evidence(source, Some("log_dir"), Some("<path>"))],
            "Remove the explicit log directory unless plaintext diagnostic logging is required, and protect its permissions and retention.",
            &[CONFIG_REFERENCE],
            &["OWASP-MCP8", "OWASP-MCP10"],
        ));
    }
    if let Some(provider) = config.get("model_provider").and_then(TomlValue::as_str) {
        if !matches!(provider, "openai" | "ollama" | "lmstudio") {
            findings.push(make_finding(
                "CAX-PRV-008",
                "privacy_retention_telemetry",
                Severity::Medium,
                "high",
                Assessment::Confirmed,
                "Repository content is routed through a custom model provider",
                "A custom provider changes the party and endpoint that receive prompts and repository context.",
                vec![evidence(source, Some("model_provider"), Some(provider))],
                "Verify the provider's data handling, TLS, retention, training, and access policies.",
                &[CONFIG_REFERENCE],
                &["OWASP-MCP10", "OWASP-ASI04"],
            ));
        }
    }
    if get_str(config, &["web_search"]) == Some("live") {
        findings.push(make_finding(
            "CAX-NET-003",
            "network_and_external_data",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Unrestricted live web retrieval is enabled",
            "Live external content increases indirect prompt-injection exposure and may disclose query context.",
            vec![evidence(source, Some("web_search"), Some("live"))],
            "Prefer cached/indexed search or a domain-restricted search configuration for sensitive projects.",
            &[CONFIG_REFERENCE],
            &["OWASP-ASI01", "OWASP-MCP6"],
        ));
    }
    if get_bool(config, &["features", "memories"]).unwrap_or(false)
        && !get_bool(config, &["memories", "disable_on_external_context"]).unwrap_or(false)
    {
        findings.push(make_finding(
            "CAX-CTX-001",
            "instructions_trust_memory",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "External tool context can influence persistent memories",
            "MCP, web-search, or tool-search content can remain eligible for memory generation.",
            vec![evidence(
                source,
                Some("memories.disable_on_external_context"),
                Some("false"),
            )],
            "Set `memories.disable_on_external_context = true` when persistent memory is enabled.",
            &[CONFIG_REFERENCE],
            &["OWASP-ASI06", "OWASP-MCP10"],
        ));
    }
}

fn evaluate_permission_profiles(
    config: &TomlValue,
    source: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    let Some(profiles) = config.get("permissions").and_then(TomlValue::as_table) else {
        return;
    };
    for (name, profile) in profiles {
        let Some(table) = profile.as_table() else {
            continue;
        };
        if table
            .get("network")
            .and_then(TomlValue::as_table)
            .and_then(|network| network.get("mode"))
            .and_then(TomlValue::as_str)
            == Some("full")
        {
            findings.push(make_finding(
                "CAX-SBX-002",
                "sandbox_filesystem_environment",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Permission profile grants full network access",
                &format!("Permission profile `{name}` permits unrestricted subprocess networking."),
                vec![evidence(
                    source,
                    Some(&format!("permissions.{name}.network.mode")),
                    Some("full"),
                )],
                "Use limited network mode with an explicit domain allowlist.",
                &[CONFIG_REFERENCE],
                &["OWASP-ASI03", "OWASP-MCP2"],
            ));
        }
        for dangerous in [
            "dangerously_allow_all_unix_sockets",
            "dangerously_allow_non_loopback_proxy",
        ] {
            if table
                .get("network")
                .and_then(TomlValue::as_table)
                .and_then(|network| network.get(dangerous))
                .and_then(TomlValue::as_bool)
                == Some(true)
            {
                findings.push(make_finding(
                    "CAX-SBX-003",
                    "sandbox_filesystem_environment",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "Permission profile enables a dangerous network escape hatch",
                    &format!("Permission profile `{name}` enables `{dangerous}`."),
                    vec![evidence(source, Some(&format!("permissions.{name}.network.{dangerous}")), Some("true"))],
                    "Disable the escape hatch and allow only the exact sockets or listener destinations required.",
                    &[CONFIG_REFERENCE],
                    &["OWASP-ASI03", "OWASP-MCP2"],
                ));
            }
        }
    }
}

fn evaluate_mcp_servers(
    config: &TomlValue,
    source: &Path,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let Some(servers) = config.get("mcp_servers").and_then(TomlValue::as_table) else {
        return;
    };
    for (id, server) in servers {
        let Some(server) = server.as_table() else {
            continue;
        };
        let enabled = server
            .get("enabled")
            .and_then(TomlValue::as_bool)
            .unwrap_or(true);
        let endpoint = server
            .get("url")
            .and_then(TomlValue::as_str)
            .map(str::to_string);
        let transport = if endpoint.is_some() { "http" } else { "stdio" };
        let allowlist = server
            .get("enabled_tools")
            .and_then(TomlValue::as_array)
            .is_some();
        inventory.mcp_servers.push(McpInventory {
            id: id.clone(),
            transport: transport.to_string(),
            enabled,
            has_tool_allowlist: allowlist,
            endpoint: endpoint.as_deref().map(sanitize_endpoint),
        });
        if !enabled {
            continue;
        }
        if !allowlist {
            findings.push(make_finding(
                "CAX-MCP-001",
                "mcp_apps_connectors",
                Severity::Medium,
                "high",
                Assessment::Confirmed,
                "MCP server exposes tools without an allowlist",
                &format!("Enabled server `{id}` does not restrict its exposed tool names."),
                vec![evidence(
                    source,
                    Some(&format!("mcp_servers.{id}.enabled_tools")),
                    Some("<unset>"),
                )],
                "Set `enabled_tools` to the smallest reviewed tool set.",
                &[MCP_REFERENCE],
                &["OWASP-MCP2", "OWASP-MCP9"],
            ));
        }
        if server
            .get("default_tools_approval_mode")
            .and_then(TomlValue::as_str)
            == Some("approve")
        {
            findings.push(make_finding(
                "CAX-MCP-002",
                "mcp_apps_connectors",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "MCP tools are approved by default",
                &format!("Server `{id}` can invoke tools without the safer prompt or write-sensitive review modes."),
                vec![evidence(source, Some(&format!("mcp_servers.{id}.default_tools_approval_mode")), Some("approve"))],
                "Use `prompt` or `writes`, then add narrow per-tool exceptions only after review.",
                &[MCP_REFERENCE],
                &["OWASP-ASI02", "OWASP-MCP2"],
            ));
        }
        if let Some(url) = endpoint.as_deref() {
            if insecure_remote_http(url) {
                findings.push(make_finding(
                    "CAX-MCP-003",
                    "mcp_apps_connectors",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "Remote MCP transport is not encrypted",
                    &format!("Server `{id}` uses plaintext HTTP for tool traffic."),
                    vec![evidence(
                        source,
                        Some(&format!("mcp_servers.{id}.url")),
                        Some(url),
                    )],
                    "Use an authenticated HTTPS endpoint.",
                    &[MCP_REFERENCE],
                    &["OWASP-MCP1", "OWASP-MCP7"],
                ));
            }
        }
        if let Some(command) = server.get("command").and_then(TomlValue::as_str) {
            if is_shell_indirection(command) {
                findings.push(make_finding(
                    "CAX-MCP-004",
                    "mcp_apps_connectors",
                    Severity::High,
                    "medium",
                    Assessment::Potential,
                    "MCP server launches through a command shell",
                    &format!("Server `{id}` uses shell indirection, expanding command-injection and quoting risk."),
                    vec![evidence(source, Some(&format!("mcp_servers.{id}.command")), Some(command))],
                    "Launch a reviewed executable directly and pass arguments as an array.",
                    &[MCP_REFERENCE],
                    &["OWASP-MCP5", "OWASP-ASI05"],
                ));
            }
            let args = server
                .get("args")
                .and_then(TomlValue::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(TomlValue::as_str)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if executable_dependency_is_unpinned(command, &args) {
                findings.push(make_finding(
                    "CAX-MCP-005",
                    "skills_plugins_hooks_supply_chain",
                    Severity::High,
                    "medium",
                    Assessment::Potential,
                    "Executable MCP dependency is not pinned",
                    &format!("Server `{id}` can resolve a different package version without a configuration change."),
                    vec![evidence(source, Some(&format!("mcp_servers.{id}.args")), Some("<package-arguments>"))],
                    "Pin an exact reviewed version or immutable revision and update it deliberately.",
                    &[MCP_REFERENCE],
                    &["OWASP-MCP4", "OWASP-ASI04"],
                ));
            }
        }
        for key in ["env", "http_headers"] {
            if let Some(value) = server.get(key) {
                scan_toml_for_secrets(
                    value,
                    &format!("mcp_servers.{id}.{key}"),
                    source,
                    findings,
                    "CAX-MCP-006",
                );
            }
        }
        if let Some(scopes) = server.get("scopes").and_then(TomlValue::as_array) {
            for scope in scopes.iter().filter_map(TomlValue::as_str) {
                if risky_scope(scope) {
                    findings.push(make_finding(
                        "CAX-MCP-007",
                        "mcp_apps_connectors",
                        Severity::Medium,
                        "medium",
                        Assessment::Potential,
                        "MCP OAuth scope appears broad",
                        &format!("Server `{id}` requests a scope associated with broad write or administrative access."),
                        vec![evidence(source, Some(&format!("mcp_servers.{id}.scopes")), Some(scope))],
                        "Confirm the provider's scope semantics and request the smallest read/write scope required.",
                        &[MCP_REFERENCE],
                        &["OWASP-MCP2", "OWASP-MCP7"],
                    ));
                }
            }
        }
    }
    if let Some(callback) = config
        .get("mcp_oauth_callback_url")
        .and_then(TomlValue::as_str)
    {
        if !is_loopback_url(callback) {
            findings.push(make_finding(
                "CAX-MCP-008",
                "mcp_apps_connectors",
                Severity::Medium,
                "high",
                Assessment::Confirmed,
                "MCP OAuth callback is reachable beyond localhost",
                "Codex binds non-local callback URLs broadly so a remote callback can reach the host.",
                vec![evidence(source, Some("mcp_oauth_callback_url"), Some(callback))],
                "Prefer an ephemeral localhost callback unless remote ingress is deliberately protected.",
                &[MCP_REFERENCE],
                &["OWASP-MCP7"],
            ));
        }
    }
}

fn evaluate_apps(config: &TomlValue, source: &Path, findings: &mut Vec<AuditFinding>) {
    let Some(defaults) = config
        .get("apps")
        .and_then(TomlValue::as_table)
        .and_then(|apps| apps.get("_default"))
    else {
        return;
    };
    let destructive = defaults
        .get("destructive_enabled")
        .and_then(TomlValue::as_bool)
        == Some(true);
    let approval = defaults
        .get("default_tools_approval_mode")
        .and_then(TomlValue::as_str);
    if destructive && approval == Some("approve") {
        findings.push(make_finding(
            "CAX-APP-001",
            "mcp_apps_connectors",
            Severity::High,
            "high",
            Assessment::Confirmed,
            "Destructive app tools are enabled and approved by default",
            "The default applies broadly to app/connector tools unless a narrower override exists.",
            vec![
                evidence(
                    source,
                    Some("apps._default.destructive_enabled"),
                    Some("true"),
                ),
                evidence(
                    source,
                    Some("apps._default.default_tools_approval_mode"),
                    approval,
                ),
            ],
            "Disable destructive tools by default and require prompt or write-sensitive approval.",
            &[CONFIG_REFERENCE],
            &["OWASP-ASI02", "OWASP-MCP2"],
        ));
    }
}

fn discover_skills(
    workspace: &Path,
    codex_home: &Path,
    config: &TomlValue,
    sources: &mut Vec<AuditSource>,
    findings: &mut Vec<AuditFinding>,
) -> Vec<SkillInventory> {
    let disabled = disabled_skill_paths(config);
    let mut roots = repository_skill_roots(workspace);
    if let Some(home) = env::var_os("HOME") {
        roots.push((
            PathBuf::from(home).join(".agents/skills"),
            "user".to_string(),
        ));
    }
    roots.push((PathBuf::from("/etc/codex/skills"), "admin".to_string()));
    // Compatibility with older Codex layouts and existing installations.
    roots.push((codex_home.join("skills"), "user_legacy".to_string()));

    let mut skills = Vec::new();
    let mut names: HashMap<String, Vec<String>> = HashMap::new();
    let mut seen = HashSet::new();
    for (root, scope) in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let skill_dir = entry.path();
            let skill_file = if skill_dir.is_dir() {
                skill_dir.join("SKILL.md")
            } else {
                continue;
            };
            if !skill_file.exists() || !seen.insert(display_path(&skill_file)) {
                continue;
            }
            let mut source = source_for(&skill_file, "codex_skill", true, true);
            let text = match read_limited_text(&skill_file) {
                Ok(text) => {
                    source.sha256 = Some(hash_bytes(text.as_bytes()));
                    Some(text)
                }
                Err(error) => {
                    source.errors.push(error.to_string());
                    None
                }
            };
            let sha256 = source.sha256.clone();
            sources.push(source);
            let text = text.as_deref().unwrap_or_default();
            let name = skill_frontmatter_value(text, "name")
                .or_else(|| {
                    skill_dir
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "unknown".to_string());
            let canonical_dir = canonical_or_original(&skill_dir);
            let canonical_file = canonical_or_original(&skill_file);
            let enabled = ![
                display_path(&canonical_dir),
                display_path(&skill_dir),
                display_path(&canonical_file),
                display_path(&skill_file),
            ]
            .iter()
            .any(|path| disabled.contains(path));
            let has_scripts = skill_dir.join("scripts").is_dir();
            names
                .entry(name.clone())
                .or_default()
                .push(display_path(&skill_file));
            if enabled {
                inspect_skill_content(&name, &skill_file, &skill_dir, text, has_scripts, findings);
            }
            skills.push(SkillInventory {
                name,
                path: display_path(&skill_file),
                scope: scope.clone(),
                enabled,
                has_scripts,
                review_state: "unknown".to_string(),
                sha256,
            });
        }
    }
    for (name, paths) in names {
        if paths.len() > 1 {
            findings.push(make_finding(
                "CAX-SKL-001",
                "skills_plugins_hooks_supply_chain",
                Severity::Medium,
                "high",
                Assessment::Confirmed,
                "Duplicate skill name can shadow reviewer intent",
                &format!("The skill name `{name}` is present in multiple discovery scopes."),
                paths
                    .iter()
                    .map(|path| Evidence {
                        source: path.clone(),
                        key: Some("name".to_string()),
                        value: Some(name.clone()),
                    })
                    .collect(),
                "Rename or disable duplicates so each selected skill has unambiguous provenance.",
                &[SKILLS_REFERENCE],
                &["OWASP-ASI04", "OWASP-MCP3"],
            ));
        }
    }
    skills.sort_by(|a, b| a.path.cmp(&b.path));
    skills
}

fn inspect_skill_content(
    name: &str,
    skill_file: &Path,
    skill_dir: &Path,
    text: &str,
    has_scripts: bool,
    findings: &mut Vec<AuditFinding>,
) {
    if fs::symlink_metadata(skill_dir).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        findings.push(make_finding(
            "CAX-SKL-002",
            "skills_plugins_hooks_supply_chain",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Skill is loaded through a symlink",
            &format!("Skill `{name}` follows content whose target can change independently of its discovery path."),
            vec![evidence(skill_file, None, Some("<symlink>"))],
            "Review and pin the symlink target, or install the skill in a controlled non-symlinked directory.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI04", "OWASP-MCP4"],
        ));
    }
    let lower = text.to_ascii_lowercase();
    if contains_hidden_unicode(text)
        || lower.contains("ignore previous instructions")
        || lower.contains("ignore all previous")
    {
        findings.push(make_finding(
            "CAX-SKL-003",
            "instructions_trust_memory",
            Severity::High,
            "medium",
            Assessment::Potential,
            "Skill contains instruction-poisoning indicators",
            &format!("Skill `{name}` contains hidden-control or instruction-override patterns."),
            vec![evidence(skill_file, None, Some("<redacted-content-match>"))],
            "Review the skill manually and remove instruction overrides or invisible control characters before enabling it.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI01", "OWASP-ASI06"],
        ));
    }
    if lower.contains("curl ") && (lower.contains("| sh") || lower.contains("| bash"))
        || lower.contains("wget ") && lower.contains("| sh")
    {
        findings.push(make_finding(
            "CAX-SKL-004",
            "skills_plugins_hooks_supply_chain",
            Severity::High,
            "medium",
            Assessment::Potential,
            "Skill downloads and executes remote content",
            &format!("Skill `{name}` contains a download-to-shell pattern."),
            vec![evidence(skill_file, None, Some("<redacted-content-match>"))],
            "Replace runtime downloads with a pinned, reviewed local script or package dependency.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI04", "OWASP-ASI05", "OWASP-MCP4"],
        ));
    }
    if has_scripts {
        findings.push(make_finding(
            "CAX-SKL-005",
            "skills_plugins_hooks_supply_chain",
            Severity::Info,
            "high",
            Assessment::Confirmed,
            "Enabled skill includes executable scripts",
            &format!("Skill `{name}` can extend beyond instruction-only behavior."),
            vec![evidence(
                &skill_dir.join("scripts"),
                None,
                Some("<directory>"),
            )],
            "Review the scripts and their dependencies before considering the skill approved.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI04"],
        ));
    }
}

fn evaluate_skill_review_surface(skills: &[SkillInventory], findings: &mut Vec<AuditFinding>) {
    const LARGE_ENABLED_SKILL_SET: usize = 10;
    let enabled = skills
        .iter()
        .filter(|skill| skill.enabled)
        .collect::<Vec<_>>();
    if enabled.len() > LARGE_ENABLED_SKILL_SET {
        findings.push(make_finding(
            "CAX-SKL-006",
            "skills_plugins_hooks_supply_chain",
            Severity::Medium,
            "medium",
            Assessment::Potential,
            "Large enabled skill set has no auditable review record",
            &format!(
                "Codex can discover {} enabled skills, while local configuration records enablement but not whether each skill was reviewed or confirmed.",
                enabled.len()
            ),
            enabled
                .iter()
                .take(25)
                .map(|skill| Evidence {
                    source: skill.path.clone(),
                    key: Some("enabled".to_string()),
                    value: Some("true".to_string()),
                })
                .collect(),
            "Disable unused skills and keep an external review record for each remaining skill, especially skills with scripts or external tools.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI04", "OWASP-MCP3"],
        ));
    }
}

fn discover_rules(
    workspace: &Path,
    codex_home: &Path,
    project_trusted: bool,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let roots = [
        (codex_home.join("rules"), true, "user_rules"),
        (
            workspace.join(".codex/rules"),
            project_trusted,
            "project_rules",
        ),
    ];
    for (root, applied, kind) in roots {
        for path in find_files_with_extension(&root, "rules", MAX_DISCOVERY_DEPTH) {
            inventory.rule_files += 1;
            let mut source = source_for(&path, kind, applied, applied);
            match read_limited_text(&path) {
                Ok(text) => {
                    source.sha256 = Some(hash_bytes(text.as_bytes()));
                    if applied {
                        inspect_rule_file(&path, &text, findings);
                    }
                }
                Err(error) => source.errors.push(error.to_string()),
            }
            sources.push(source);
        }
    }
}

fn inspect_rule_file(path: &Path, text: &str, findings: &mut Vec<AuditFinding>) {
    for block in text.split("prefix_rule(").skip(1) {
        if !block.contains("decision = \"allow\"")
            && !block.contains("decision=\"allow\"")
            && !block.contains("decision = 'allow'")
            && !block.contains("decision='allow'")
        {
            continue;
        }
        let pattern = block.split("decision").next().unwrap_or(block);
        let tokens = quoted_values(pattern);
        let first = tokens.first().map(String::as_str).unwrap_or_default();
        let shell_or_interpreter = matches!(
            first,
            "bash"
                | "sh"
                | "zsh"
                | "fish"
                | "python"
                | "python3"
                | "node"
                | "ruby"
                | "perl"
                | "powershell"
                | "pwsh"
                | "cmd"
                | "sudo"
                | "env"
        );
        if shell_or_interpreter || tokens.len() <= 1 {
            findings.push(make_finding(
                "CAX-RUL-001",
                "autonomy_and_approval",
                if shell_or_interpreter {
                    Severity::High
                } else {
                    Severity::Medium
                },
                "medium",
                Assessment::Potential,
                "Command rule grants a broad approval exception",
                "An `allow` prefix for an interpreter, privilege wrapper, or single-token command can authorize many materially different commands outside the sandbox.",
                vec![evidence(path, Some("prefix_rule"), Some("<redacted-allow-rule>"))],
                "Replace the allow rule with a narrow multi-token prefix, use `prompt`, or remove it. Validate intended and unintended examples with `codex execpolicy check`.",
                &[RULES_REFERENCE],
                &["OWASP-ASI02", "OWASP-ASI03"],
            ));
        }
    }
}

fn discover_instruction_files(
    workspace: &Path,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut paths = find_named_files(workspace, "AGENTS.md", MAX_DISCOVERY_DEPTH);
    paths.extend(find_named_files(
        workspace,
        "AGENTS.override.md",
        MAX_DISCOVERY_DEPTH,
    ));
    paths.sort();
    paths.dedup();
    inventory.instruction_files = paths.len();
    for path in paths {
        let mut source = source_for(&path, "agent_instructions", true, true);
        match read_limited_text(&path) {
            Ok(text) => {
                source.sha256 = Some(hash_bytes(text.as_bytes()));
                let lower = text.to_ascii_lowercase();
                if contains_hidden_unicode(&text)
                    || lower.contains("ignore previous instructions")
                    || lower.contains("ignore all previous")
                {
                    findings.push(make_finding(
                        "CAX-INS-001",
                        "instructions_trust_memory",
                        Severity::High,
                        "medium",
                        Assessment::Potential,
                        "Agent instruction file contains poisoning indicators",
                        "The instruction chain contains invisible-control or instruction-override language that deserves human review.",
                        vec![evidence(&path, None, Some("<redacted-content-match>"))],
                        "Review the instruction file, remove hidden control characters, and express repository guidance without trying to override higher-priority instructions.",
                        &["https://learn.chatgpt.com/docs/agent-configuration/agents-md"],
                        &["OWASP-ASI01", "OWASP-ASI06"],
                    ));
                }
                if lower.contains("curl ") && (lower.contains("| sh") || lower.contains("| bash")) {
                    findings.push(make_finding(
                        "CAX-INS-002",
                        "skills_plugins_hooks_supply_chain",
                        Severity::High,
                        "medium",
                        Assessment::Potential,
                        "Agent instruction file recommends remote code execution",
                        "A download-to-shell instruction can turn mutable remote content into local execution.",
                        vec![evidence(&path, None, Some("<redacted-content-match>"))],
                        "Use a pinned, reviewed dependency or checked-in script instead of piping remote content to a shell.",
                        &["https://learn.chatgpt.com/docs/agent-configuration/agents-md"],
                        &["OWASP-ASI04", "OWASP-ASI05"],
                    ));
                }
            }
            Err(error) => source.errors.push(error.to_string()),
        }
        sources.push(source);
    }
}

fn discover_managed_requirements(
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
    limitations: &mut Vec<String>,
) {
    #[cfg(unix)]
    let paths = vec![PathBuf::from("/etc/codex/requirements.toml")];
    #[cfg(windows)]
    let mut paths = Vec::new();
    #[cfg(not(any(unix, windows)))]
    let paths: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    if let Some(program_data) = env::var_os("ProgramData") {
        paths.push(PathBuf::from(program_data).join("OpenAI/Codex/requirements.toml"));
    }
    if paths.is_empty() {
        limitations.push(
            "The platform-specific system requirements.toml location could not be resolved."
                .to_string(),
        );
    }
    for path in paths {
        let (requirements, ok) =
            load_toml_layer(&path, "managed_requirements", true, true, sources, findings);
        if !path.exists() {
            continue;
        }
        inventory.managed_requirement_files += 1;
        if !ok {
            continue;
        }
        evaluate_managed_requirements(&requirements, &path, findings);
    }
}

fn evaluate_managed_requirements(
    requirements: &TomlValue,
    source: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    for (key, risky_value, title, severity) in [
        (
            "allowed_approval_policies",
            "never",
            "Managed policy permits approval-free operation",
            Severity::Medium,
        ),
        (
            "allowed_sandbox_modes",
            "danger-full-access",
            "Managed policy permits full host access",
            Severity::High,
        ),
        (
            "allowed_web_search_modes",
            "live",
            "Managed policy permits live web retrieval",
            Severity::Medium,
        ),
    ] {
        let permits = requirements
            .get(key)
            .and_then(TomlValue::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(risky_value))
            });
        if permits {
            findings.push(make_finding(
                "CAX-MGD-001",
                "configuration_provenance",
                severity,
                "high",
                Assessment::Potential,
                title,
                "The administrator allowlist permits a relaxed mode. This does not prove that the current invocation selected it, but it leaves that posture available.",
                vec![evidence(source, Some(key), Some(risky_value))],
                "Remove the relaxed value from the managed allowlist unless a documented, externally isolated workflow requires it.",
                &[MANAGED_CONFIG_REFERENCE],
                &["OWASP-ASI03"],
            ));
        }
    }
}

fn discover_hooks(
    workspace: &Path,
    codex_home: &Path,
    project_trusted: bool,
    effective: &TomlValue,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut commands = collect_hook_commands_from_toml(effective);
    let paths = [
        (codex_home.join("hooks.json"), "user_hooks", true),
        (
            workspace.join(".codex/hooks.json"),
            "project_hooks",
            project_trusted,
        ),
    ];
    for (path, kind, applied) in paths {
        let mut source = source_for(&path, kind, applied, applied);
        if path.exists() {
            match read_limited_text(&path).and_then(|text| {
                source.sha256 = Some(hash_bytes(text.as_bytes()));
                serde_json::from_str::<JsonValue>(&text)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            }) {
                Ok(value) if applied => collect_json_commands(&value, &mut commands),
                Ok(_) => {}
                Err(error) => source.errors.push(error.to_string()),
            }
        }
        sources.push(source);
    }
    inventory.hook_commands = commands.len();
    let mut has_gensee = false;
    for command in &commands {
        if command.contains("gensee hook codex") {
            has_gensee = true;
        }
        if command.contains("curl ") && (command.contains("| sh") || command.contains("| bash")) {
            findings.push(make_finding(
                "CAX-HOK-001",
                "skills_plugins_hooks_supply_chain",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Hook downloads and executes remote content",
                "A lifecycle hook can change executable behavior without a reviewed local file change.",
                vec![Evidence { source: "effective hooks".to_string(), key: Some("command".to_string()), value: Some("<redacted-command>".to_string()) }],
                "Replace the hook with an absolute path to a reviewed, owner-controlled executable.",
                &[CONFIG_REFERENCE],
                &["OWASP-ASI04", "OWASP-ASI05"],
            ));
        }
    }
    let hooks_enabled = get_bool(effective, &["features", "hooks"]).unwrap_or(true);
    if !has_gensee || !hooks_enabled {
        findings.push(make_finding(
            "CAX-COV-001",
            "coverage_observability",
            Severity::Medium,
            "high",
            Assessment::Confirmed,
            "Gensee Codex hook coverage is inactive",
            "The effective local configuration does not expose an active `gensee hook codex` command.",
            vec![Evidence { source: "effective hooks".to_string(), key: Some("features.hooks".to_string()), value: Some(hooks_enabled.to_string()) }],
            "Run `gensee setup codex`, review the generated command, and trust it through Codex's hook review flow.",
            &[CONFIG_REFERENCE],
            &["OWASP-MCP8"],
        ));
    }
}

fn discover_plugins_and_marketplaces(
    workspace: &Path,
    codex_home: &Path,
    project_trusted: bool,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let plugin_root = codex_home.join("plugins/cache");
    let manifests = find_named_files(&plugin_root, "plugin.json", MAX_DISCOVERY_DEPTH);
    inventory.plugin_manifests = manifests.len();
    for path in manifests {
        let mut source = source_for(&path, "plugin_manifest", true, true);
        match read_limited_text(&path) {
            Ok(text) => {
                source.sha256 = Some(hash_bytes(text.as_bytes()));
                match serde_json::from_str::<JsonValue>(&text) {
                    Ok(value) => {
                        let bundled = ["skills", "mcpServers", "apps", "hooks"]
                            .iter()
                            .filter(|key| value.get(**key).is_some())
                            .count();
                        if bundled >= 3 {
                            findings.push(make_finding(
                        "CAX-PLG-001",
                        "skills_plugins_hooks_supply_chain",
                        Severity::Medium,
                        "high",
                        Assessment::Confirmed,
                        "Plugin bundles several executable or external capability surfaces",
                        "The plugin combines skills, hooks, MCP servers, or apps, increasing the impact of a compromised source.",
                        vec![evidence(&path, None, Some("<manifest>"))],
                        "Review the plugin source, publisher, pinned version, bundled commands, and connector permissions as one trust unit.",
                        &["https://learn.chatgpt.com/docs/build-plugins"],
                        &["OWASP-ASI04", "OWASP-MCP4"],
                    ));
                        }
                    }
                    Err(error) => source.errors.push(error.to_string()),
                }
            }
            Err(error) => source.errors.push(error.to_string()),
        }
        sources.push(source);
    }
    let mut marketplace_paths = Vec::new();
    if let Some(home) = env::var_os("HOME") {
        marketplace_paths.push((
            PathBuf::from(home).join(".agents/plugins/marketplace.json"),
            true,
        ));
    }
    marketplace_paths.push((
        workspace.join(".agents/plugins/marketplace.json"),
        project_trusted,
    ));
    for (path, applied) in marketplace_paths {
        let mut source = source_for(&path, "plugin_marketplace", applied, applied);
        if path.exists() {
            inventory.marketplace_files += 1;
            match read_limited_text(&path) {
                Ok(text) => {
                    source.sha256 = Some(hash_bytes(text.as_bytes()));
                    match serde_json::from_str::<JsonValue>(&text) {
                        Ok(_) => {
                            let lower = text.to_ascii_lowercase();
                            if lower.contains("\"ref\": \"main\"")
                                || lower.contains("\"ref\":\"main\"")
                                || lower.contains("@latest")
                            {
                                findings.push(make_finding(
                        "CAX-PLG-002",
                        "skills_plugins_hooks_supply_chain",
                        Severity::Medium,
                        "medium",
                        Assessment::Potential,
                        "Plugin marketplace uses a mutable source reference",
                        "A future marketplace refresh can change installed executable or instructional content without an immutable source revision.",
                        vec![evidence(&path, Some("source.ref"), Some("<mutable-ref>"))],
                        "Pin marketplace sources to a reviewed commit or immutable release revision.",
                        &["https://learn.chatgpt.com/docs/build-plugins"],
                        &["OWASP-ASI04", "OWASP-MCP4"],
                    ));
                            }
                        }
                        Err(error) => source.errors.push(error.to_string()),
                    }
                }
                Err(error) => source.errors.push(error.to_string()),
            }
        }
        sources.push(source);
    }
}

fn scan_source_integrity(sources: &[AuditSource], findings: &mut Vec<AuditFinding>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for source in sources.iter().filter(|source| source.exists) {
            let path = Path::new(&source.path);
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.mode() & 0o777;
                if mode & 0o022 != 0 {
                    findings.push(make_finding(
                        "CAX-CFG-004",
                        "configuration_provenance",
                        Severity::High,
                        "high",
                        Assessment::Confirmed,
                        "Codex control-plane file is writable by other users",
                        "Group or world write permission allows another principal to change agent behavior.",
                        vec![evidence(path, Some("mode"), Some(&format!("{mode:04o}")))],
                        "Restrict the file to owner write access, normally mode 0600 or 0644 depending on sensitivity.",
                        &[CONFIG_REFERENCE],
                        &["OWASP-ASI03", "OWASP-ASI04"],
                    ));
                }
            }
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
                findings.push(make_finding(
                    "CAX-CFG-005",
                    "configuration_provenance",
                    Severity::Medium,
                    "high",
                    Assessment::Confirmed,
                    "Codex control-plane file is a symlink",
                    "The effective content can change through a target outside the apparent configuration location.",
                    vec![evidence(path, None, Some("<symlink>"))],
                    "Verify the target owner and permissions, or use a regular file in the expected control-plane directory.",
                    &[CONFIG_REFERENCE],
                    &["OWASP-ASI04"],
                ));
            }
        }
    }
}

fn privacy_manual_checks() -> Vec<ManualCheck> {
    vec![
        ManualCheck {
            check_id: "CAX-PRV-001".to_string(),
            priority: "high".to_string(),
            title: "Verify model-training preferences".to_string(),
            reason: "ChatGPT/Codex account-side data controls are not represented in local config.toml.".to_string(),
            action: "For personal workspaces, verify that Improve the model for everyone is off if repository content must not be used for training. For business/API use, verify the organization has not opted in to data sharing.".to_string(),
            references: vec![DATA_REFERENCE.to_string()],
        },
        ManualCheck {
            check_id: "CAX-PRV-002".to_string(),
            priority: "high".to_string(),
            title: "Verify separate Codex full-environment controls".to_string(),
            reason: "OpenAI documents separate controls for allowing training on full Codex environments; local configuration cannot prove their state.".to_string(),
            action: "Review the Codex settings associated with the authenticated account and workspace.".to_string(),
            references: vec![DATA_REFERENCE.to_string()],
        },
    ]
}

fn effective_security_summary(
    config: &TomlValue,
    inventory: &AuditInventory,
) -> BTreeMap<String, JsonValue> {
    let mut summary = BTreeMap::new();
    summary.insert(
        "approval_policy".to_string(),
        json!(config
            .get("approval_policy")
            .and_then(TomlValue::as_str)
            .unwrap_or("default")),
    );
    summary.insert(
        "sandbox_mode".to_string(),
        json!(config
            .get("sandbox_mode")
            .and_then(TomlValue::as_str)
            .unwrap_or("default")),
    );
    summary.insert(
        "network_access".to_string(),
        json!(get_bool(config, &["sandbox_workspace_write", "network_access"]).unwrap_or(false)),
    );
    summary.insert(
        "history_persistence".to_string(),
        json!(get_str(config, &["history", "persistence"]).unwrap_or("default")),
    );
    summary.insert(
        "mcp_server_count".to_string(),
        json!(inventory.mcp_servers.len()),
    );
    summary.insert(
        "enabled_skill_count".to_string(),
        json!(inventory
            .skills
            .iter()
            .filter(|skill| skill.enabled)
            .count()),
    );
    summary
}

fn evidence(path: &Path, key: Option<&str>, value: Option<&str>) -> Evidence {
    Evidence {
        source: display_path(path),
        key: key.map(str::to_string),
        value: value.map(|value| sanitize_evidence_value(key, value)),
    }
}

fn secret_finding(
    rule_id: &str,
    title: &str,
    source: &Path,
    key: &str,
    remediation: &str,
) -> AuditFinding {
    make_finding(
        rule_id,
        "privacy_retention_telemetry",
        Severity::High,
        "medium",
        Assessment::Potential,
        title,
        "A secret-like value is stored directly in a Codex configuration surface.",
        vec![Evidence {
            source: display_path(source),
            key: Some(key.to_string()),
            value: Some("<redacted>".to_string()),
        }],
        remediation,
        &[CONFIG_REFERENCE],
        &["OWASP-MCP1", "OWASP-ASI03"],
    )
}

fn scan_toml_for_secrets(
    value: &TomlValue,
    prefix: &str,
    source: &Path,
    findings: &mut Vec<AuditFinding>,
    rule_id: &str,
) {
    match value {
        TomlValue::Table(table) => {
            for (key, value) in table {
                let path = format!("{prefix}.{key}");
                if value.as_str().is_some_and(|raw| secret_like(key, raw)) {
                    findings.push(secret_finding(
                        rule_id,
                        "Secret is embedded in Codex configuration",
                        source,
                        &path,
                        "Use an environment-variable reference, keyring, or provider-specific secret store instead of a literal value.",
                    ));
                } else {
                    scan_toml_for_secrets(value, &path, source, findings, rule_id);
                }
            }
        }
        TomlValue::Array(values) => {
            for value in values {
                scan_toml_for_secrets(value, prefix, source, findings, rule_id);
            }
        }
        _ => {}
    }
}

fn collect_named_strings(value: &TomlValue, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    match value {
        TomlValue::Table(table) => {
            for (key, value) in table {
                if key == name {
                    if let Some(value) = value.as_str() {
                        found.push(value.to_string());
                    }
                }
                found.extend(collect_named_strings(value, name));
            }
        }
        TomlValue::Array(values) => {
            for value in values {
                found.extend(collect_named_strings(value, name));
            }
        }
        _ => {}
    }
    found
}

fn network_policy_enabled(config: &TomlValue) -> bool {
    match get_value(config, &["features", "network_proxy"]) {
        Some(TomlValue::Boolean(enabled)) => *enabled,
        Some(TomlValue::Table(table)) => table
            .get("enabled")
            .and_then(TomlValue::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

fn global_domain_allow_key(config: &TomlValue) -> Option<&'static str> {
    let candidates = [
        (
            "features.network_proxy.domains.*",
            get_value(config, &["features", "network_proxy", "domains"]),
        ),
        (
            "experimental_network.domains.*",
            get_value(config, &["experimental_network", "domains"]),
        ),
    ];
    candidates.into_iter().find_map(|(key, value)| {
        (value
            .and_then(TomlValue::as_table)
            .and_then(|domains| domains.get("*"))
            .and_then(TomlValue::as_str)
            == Some("allow"))
        .then_some(key)
    })
}

fn repository_skill_roots(workspace: &Path) -> Vec<(PathBuf, String)> {
    let mut roots = Vec::new();
    let mut current = Some(workspace);
    while let Some(path) = current {
        roots.push((path.join(".agents/skills"), "repository".to_string()));
        if path.join(".git").exists() {
            break;
        }
        current = path.parent();
    }
    roots
}

fn disabled_skill_paths(config: &TomlValue) -> HashSet<String> {
    get_value(config, &["skills", "config"])
        .and_then(TomlValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(TomlValue::as_table)
        .filter(|entry| entry.get("enabled").and_then(TomlValue::as_bool) == Some(false))
        .filter_map(|entry| entry.get("path").and_then(TomlValue::as_str))
        .map(|path| display_path(&canonical_or_original(Path::new(path))))
        .collect()
}

fn skill_frontmatter_value(text: &str, key: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    for line in lines {
        if line.trim() == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix(&format!("{key}:")) {
            return Some(value.trim().trim_matches(['\'', '"']).to_string());
        }
    }
    None
}

fn collect_hook_commands_from_toml(value: &TomlValue) -> Vec<String> {
    value
        .get("hooks")
        .and_then(|hooks| serde_json::to_value(hooks).ok())
        .map(|hooks| {
            let mut commands = Vec::new();
            collect_json_commands(&hooks, &mut commands);
            commands
        })
        .unwrap_or_default()
}

fn find_named_files(root: &Path, name: &str, max_depth: usize) -> Vec<PathBuf> {
    fn visit(path: &Path, name: &str, depth: usize, max_depth: usize, found: &mut Vec<PathBuf>) {
        if depth > max_depth {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if !skip_discovery_directory(&path) {
                    visit(&path, name, depth + 1, max_depth, found);
                }
            } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    visit(root, name, 0, max_depth, &mut found);
    found.sort();
    found
}

fn find_files_with_extension(root: &Path, extension: &str, max_depth: usize) -> Vec<PathBuf> {
    fn visit(
        path: &Path,
        extension: &str,
        depth: usize,
        max_depth: usize,
        found: &mut Vec<PathBuf>,
    ) {
        if depth > max_depth {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if !skip_discovery_directory(&path) {
                    visit(&path, extension, depth + 1, max_depth, found);
                }
            } else if path.extension().and_then(|value| value.to_str()) == Some(extension) {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    visit(root, extension, 0, max_depth, &mut found);
    found.sort();
    found
}

fn quoted_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut quote = None;
    let mut current = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if let Some(delimiter) = quote {
            if escaped {
                current.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                values.push(std::mem::take(&mut current));
                quote = None;
            } else {
                current.push(character);
            }
        } else if character == '"' || character == '\'' {
            quote = Some(character);
        }
    }
    values
}

fn skip_discovery_directory(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some(".git" | "target" | "node_modules" | ".venv" | "vendor")
    )
}

fn is_shell_indirection(command: &str) -> bool {
    let name = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command);
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash" | "zsh" | "cmd" | "cmd.exe" | "powershell" | "powershell.exe" | "pwsh"
    )
}

fn risky_scope(scope: &str) -> bool {
    let lower = scope.to_ascii_lowercase();
    lower == "*"
        || lower.contains("admin")
        || lower.contains("write:all")
        || lower.contains("full_access")
        || lower.contains("repo") && !lower.contains("read")
}

fn secret_like(key: &str, value: &str) -> bool {
    let key = normalize_secret_key(key);
    let sensitive_key = [
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "authorization",
        "privatekey",
        "credential",
    ]
    .iter()
    .any(|needle| key.contains(needle));
    let lower = value.to_ascii_lowercase();
    sensitive_key
        && !value.is_empty()
        && !value.starts_with('$')
        && !lower.contains("${")
        && !lower.ends_with("_env_var")
        || lower.starts_with("sk-")
        || lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
}

fn sanitize_evidence_value(key: Option<&str>, value: &str) -> String {
    if key.is_some_and(|key| secret_like(key, value))
        || key.is_some_and(endpoint_key) && endpoint_must_be_redacted(value)
    {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

fn endpoint_key(key: &str) -> bool {
    let final_segment = key.rsplit('.').next().unwrap_or(key);
    let final_segment = normalize_secret_key(final_segment);
    final_segment.contains("url") || final_segment.contains("endpoint")
}

fn sanitize_endpoint(value: &str) -> String {
    if endpoint_must_be_redacted(value) {
        "<redacted-url>".to_string()
    } else {
        value.to_string()
    }
}

fn is_broad_path(path: &str) -> bool {
    let normalized = path.trim_end_matches('/');
    normalized.is_empty()
        || normalized == "/"
        || normalized == "/etc"
        || normalized == "/usr"
        || normalized == "/var"
        || normalized == env::var("HOME").unwrap_or_default()
        || normalized.ends_with("/.ssh")
        || normalized.ends_with("/.aws")
        || normalized.ends_with("/.config")
}

fn contains_hidden_unicode(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{feff}'
        )
    })
}

fn get_value<'a>(value: &'a TomlValue, path: &[&str]) -> Option<&'a TomlValue> {
    path.iter().try_fold(value, |value, key| value.get(*key))
}

fn get_bool(value: &TomlValue, path: &[&str]) -> Option<bool> {
    get_value(value, path).and_then(TomlValue::as_bool)
}

fn get_str<'a>(value: &'a TomlValue, path: &[&str]) -> Option<&'a str> {
    get_value(value, path).and_then(TomlValue::as_str)
}

fn get_integer(value: &TomlValue, path: &[&str]) -> Option<i64> {
    get_value(value, path).and_then(TomlValue::as_integer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        env::temp_dir().join(format!("gensee-config-audit-{}-{name}", std::process::id()))
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn reports_compound_full_access_without_approvals() {
        let root = temp_root("full-access");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "CAX-AUT-002" && finding.severity == Severity::Critical
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn project_provider_key_is_reported_as_ignored() {
        let root = temp_root("ignored-project-key");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            &format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                workspace.display()
            ),
        );
        write(
            &workspace.join(".codex/config.toml"),
            "model_provider = \"example\"\nsandbox_mode = \"read-only\"\n",
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-CFG-002"));
        assert_eq!(
            report.effective_security_config["sandbox_mode"],
            json!("read-only")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn project_trust_accepts_the_original_or_canonical_workspace_key() {
        let original = Path::new("/tmp/audit-workspace");
        let canonical = Path::new("/private/tmp/audit-workspace");
        for trusted_path in [original, canonical] {
            let config = format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                trusted_path.display()
            )
            .parse::<TomlValue>()
            .unwrap();
            assert!(project_is_trusted(&config, original, canonical));
        }
    }

    #[test]
    fn secret_evidence_is_redacted() {
        let root = temp_root("redaction");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "[mcp_servers.demo]\ncommand = \"demo\"\n[mcp_servers.demo.env]\nAPI_TOKEN = \"sk-super-secret\"\n",
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("sk-super-secret"));
        assert!(encoded.contains("<redacted>"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_key_ignores_url_text_in_mcp_server_ids() {
        let root = temp_root("endpoint-key-final-segment");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "[mcp_servers.url-fetcher]\ncommand = \"bash\"\n",
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let command = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-MCP-004")
            .unwrap();
        let allowlist = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-MCP-001")
            .unwrap();

        assert_eq!(command.evidence[0].value.as_deref(), Some("bash"));
        assert_eq!(allowlist.evidence[0].value.as_deref(), Some("<unset>"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hyphenated_api_key_headers_are_detected_and_redacted() {
        let root = temp_root("hyphenated-api-key");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        let secret = "opaque-review-secret-value";
        write(
            &codex_home.join("config.toml"),
            &format!(
                "[mcp_servers.demo]\ncommand = \"demo\"\n[mcp_servers.demo.http_headers]\nX-API-Key = \"{secret}\"\n"
            ),
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let serialized = serde_json::to_string(&report).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-MCP-006"));
        assert!(!serialized.contains(secret));
        assert!(serialized.contains("<redacted>"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn loopback_urls_require_an_exact_loopback_host() {
        assert!(is_loopback_url("http://localhost:3000/mcp"));
        assert!(is_loopback_url("http://127.0.0.2:3000/mcp"));
        assert!(is_loopback_url("http://[::1]:3000/mcp"));
        assert!(!is_loopback_url("http://localhost.evil.example/mcp"));
        assert!(insecure_remote_http("http://localhost.evil.example/mcp"));
    }

    #[test]
    fn effective_findings_use_the_setting_layer_that_won() {
        let root = temp_root("effective-provenance");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        let user_path = codex_home.join("config.toml");
        let project_path = workspace.join(".codex/config.toml");
        write(
            &user_path,
            &format!(
                "sandbox_mode = \"read-only\"\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                workspace.display()
            ),
        );
        write(&project_path, "sandbox_mode = \"danger-full-access\"\n");

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-AUT-001")
            .unwrap();

        assert_eq!(
            finding.evidence[0].source,
            display_path(&canonical_or_original(&project_path))
        );
        let default_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-ENV-001")
            .unwrap();
        assert_eq!(default_finding.evidence[0].source, "codex defaults");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn endpoint_credentials_and_parse_snippets_are_redacted() {
        let root = temp_root("endpoint-redaction");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "[mcp_servers.demo]\nurl = \"https://user:do-not-leak@example.com/mcp\"\n",
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace: workspace.clone(),
            codex_home: codex_home.clone(),
            profile: None,
        })
        .unwrap();
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("do-not-leak"));
        assert!(encoded.contains("<redacted-url>"));

        write(
            &codex_home.join("config.toml"),
            "password = \"do-not-leak\n",
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("do-not-leak"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn redacts_unparseable_mcp_endpoints_from_the_report() {
        for (index, endpoint) in [
            "//admin:do-not-leak@example.com/mcp",
            "example.com/mcp?token=do-not-leak",
            ":://admin:do-not-leak@example.com",
        ]
        .into_iter()
        .enumerate()
        {
            let root = temp_root(&format!("unparseable-endpoint-{index}"));
            let _ = fs::remove_dir_all(&root);
            let workspace = root.join("repo");
            let codex_home = root.join("codex");
            fs::create_dir_all(&workspace).unwrap();
            write(
                &codex_home.join("config.toml"),
                &format!("[mcp_servers.demo]\nurl = \"{endpoint}\"\n"),
            );

            let report = audit_codex(&CodexAuditOptions {
                workspace,
                codex_home,
                profile: None,
            })
            .unwrap();
            let serialized = serde_json::to_string(&report).unwrap();

            assert!(!serialized.contains("do-not-leak"), "{endpoint}");
            assert_eq!(
                report.inventory.mcp_servers[0].endpoint.as_deref(),
                Some("<redacted-url>")
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn inventory_does_not_execute_mcp_commands() {
        let root = temp_root("no-exec");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        let marker = root.join("executed");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            &format!(
                "[mcp_servers.demo]\ncommand = \"sh\"\nargs = [\"-c\", \"touch {}\"]\n",
                marker.display()
            ),
        );
        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        assert!(!marker.exists());
        assert_eq!(report.inventory.mcp_servers.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn broad_allow_rule_is_reported() {
        let root = temp_root("broad-rule");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("rules/default.rules"),
            "prefix_rule(pattern = [\"bash\"], decision = \"allow\")\n",
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-RUL-001"));
        assert_eq!(report.inventory.rule_files, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn selected_missing_profile_makes_assessment_partial() {
        let root = temp_root("missing-profile");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: Some("sensitive".to_string()),
        })
        .unwrap();

        assert_eq!(report.summary.assessment, "partial");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-CFG-006"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn large_enabled_skill_set_requires_review() {
        let root = temp_root("many-skills");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        for index in 0..11 {
            write(
                &codex_home.join(format!("skills/skill-{index}/SKILL.md")),
                &format!("---\nname: skill-{index}\n---\nReview helper.\n"),
            );
        }

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-SKL-006"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn effective_defaults_flag_secret_environment_and_unproxied_network_access() {
        let root = temp_root("effective-defaults");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "[sandbox_workspace_write]\nnetwork_access = true\n[features.network_proxy]\ndomains = { example = \"allow\" }\n",
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-NET-001"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-ENV-001"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn inclusive_environment_filters_prevent_full_inheritance_warning() {
        let config = r#"
            [shell_environment_policy]
            inherit = "all"
            filters = { PATH = "include", HOME = "include" }
        "#
        .parse::<TomlValue>()
        .unwrap();
        let mut findings = Vec::new();

        evaluate_shell_environment(&config, Path::new("config.toml"), false, &mut findings);

        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-ENV-002"));
    }

    #[test]
    fn exclude_only_environment_filters_do_not_hide_full_inheritance() {
        let config = r#"
            [shell_environment_policy]
            inherit = "all"
            filters = { AWS_SECRET_ACCESS_KEY = "exclude" }
        "#
        .parse::<TomlValue>()
        .unwrap();
        let mut findings = Vec::new();

        evaluate_shell_environment(&config, Path::new("config.toml"), false, &mut findings);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-ENV-002"));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_paths_stabilize_report_identity_and_fingerprints() {
        use std::os::unix::fs::symlink;

        let root = temp_root("canonical-report-identity");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        let workspace_alias = root.join("repo-alias");
        let codex_home_alias = root.join("codex-alias");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n",
        );
        symlink(&workspace, &workspace_alias).unwrap();
        symlink(&codex_home, &codex_home_alias).unwrap();

        let canonical = audit_codex(&CodexAuditOptions {
            workspace: workspace.clone(),
            codex_home: codex_home.clone(),
            profile: None,
        })
        .unwrap();
        let aliased = audit_codex(&CodexAuditOptions {
            workspace: workspace_alias,
            codex_home: codex_home_alias,
            profile: None,
        })
        .unwrap();
        let canonical_finding = canonical
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-AUT-002")
            .unwrap();
        let aliased_finding = aliased
            .findings
            .iter()
            .find(|finding| finding.rule_id == "CAX-AUT-002")
            .unwrap();

        assert_eq!(canonical.target.workspace, aliased.target.workspace);
        assert_eq!(canonical.target.codex_home, aliased.target.codex_home);
        assert_eq!(
            canonical_finding.evidence[0].source,
            aliased_finding.evidence[0].source
        );
        assert_eq!(canonical_finding.fingerprint, aliased_finding.fingerprint);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disabled_skill_directory_is_not_reported_as_enabled() {
        let root = temp_root("disabled-skill-directory");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        let skill_dir = codex_home.join("skills/reviewed");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &skill_dir.join("SKILL.md"),
            "---\nname: reviewed\n---\nReview helper.\n",
        );
        fs::create_dir_all(skill_dir.join("scripts")).unwrap();
        write(
            &codex_home.join("config.toml"),
            &format!(
                "[[skills.config]]\npath = {:?}\nenabled = false\n",
                skill_dir.to_string_lossy()
            ),
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();

        let skill = report
            .inventory
            .skills
            .iter()
            .find(|skill| skill.name == "reviewed")
            .unwrap();
        assert!(!skill.enabled);
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CAX-SKL-005"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_discovered_source_makes_assessment_partial() {
        let root = temp_root("oversized-rules");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        let rule_path = codex_home.join("rules/oversized.rules");
        if let Some(parent) = rule_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&rule_path, vec![b'x'; MAX_TEXT_FILE_BYTES as usize + 1]).unwrap();

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();

        let source = report
            .sources
            .iter()
            .find(|source| source.path == display_path(&canonical_or_original(&rule_path)))
            .unwrap();
        assert_eq!(report.summary.assessment, "partial");
        assert!(source.sha256.is_none());
        assert!(!source.errors.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_values_disambiguate_fingerprints() {
        let root = temp_root("fingerprints");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let codex_home = root.join("codex");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &codex_home.join("config.toml"),
            "[sandbox_workspace_write]\nwritable_roots = [\"/\", \"/etc\"]\n",
        );

        let report = audit_codex(&CodexAuditOptions {
            workspace,
            codex_home,
            profile: None,
        })
        .unwrap();
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "CAX-SBX-001")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 2);
        assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
        let _ = fs::remove_dir_all(root);
    }
}
