use crate::model::{
    Assessment, AuditApplicability, AuditFinding, AuditInventory, AuditReport, AuditSource,
    AuditSummary, AuditTarget, Evidence, ExtensionInventory, ManualCheck, McpInventory,
    Remediation, Ruleset, Severity, SkillInventory,
};
use crate::{
    GITHUB_COPILOT_VSCODE_RULESET_ID, GITHUB_COPILOT_VSCODE_RULESET_VERSION, VSCODE_RULESET_ID,
    VSCODE_RULESET_VERSION,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const SETTINGS_REFERENCE: &str = "https://code.visualstudio.com/docs/configure/settings";
const SECURITY_REFERENCE: &str = "https://code.visualstudio.com/docs/agents/security";
const APPROVALS_REFERENCE: &str = "https://code.visualstudio.com/docs/agents/approvals";
const MCP_REFERENCE: &str = "https://code.visualstudio.com/docs/agents/reference/mcp-configuration";
const SKILLS_REFERENCE: &str =
    "https://code.visualstudio.com/docs/agent-customization/agent-skills";
const HOOKS_REFERENCE: &str = "https://code.visualstudio.com/docs/agent-customization/hooks";
const COPILOT_DATA_REFERENCE: &str =
    "https://docs.github.com/en/copilot/how-tos/manage-your-account/manage-policies#model-training-and-improvements";

const MAX_TEXT_FILE_BYTES: u64 = 256 * 1024;
const MAX_DISCOVERY_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct VscodeAuditOptions {
    pub workspace: PathBuf,
    pub user_data: PathBuf,
    pub profile: Option<String>,
    extension_roots: Vec<PathBuf>,
}

impl VscodeAuditOptions {
    pub fn discover(
        workspace: PathBuf,
        user_data: Option<PathBuf>,
        profile: Option<String>,
    ) -> Self {
        let user_data = user_data.unwrap_or_else(default_user_data);
        Self {
            workspace,
            user_data,
            profile,
            extension_roots: default_extension_roots(),
        }
    }

    pub fn github_copilot_extension_applicability(&self) -> (AuditApplicability, String) {
        if self.extension_roots.iter().any(|root| {
            child_directories(root).into_iter().any(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        let name = name.to_ascii_lowercase();
                        name.starts_with("github.copilot-")
                            || name.starts_with("github.copilot-chat-")
                    })
                    || extension_id(&path)
                        .as_deref()
                        .is_some_and(is_github_copilot_extension)
            })
        }) {
            return (
                AuditApplicability::Applicable,
                "A GitHub Copilot VS Code extension was discovered in a local extension directory."
                    .to_string(),
            );
        }

        let user_settings = self.user_data.join("settings.json");
        let profile_settings = self.profile.as_ref().map(|profile| {
            self.user_data
                .join("profiles")
                .join(profile)
                .join("settings.json")
        });
        let workspace_settings = self.workspace.join(".vscode/settings.json");
        let recommendations = self.workspace.join(".vscode/extensions.json");
        let configured = [
            Some(user_settings),
            profile_settings,
            Some(workspace_settings),
        ]
        .into_iter()
        .flatten()
        .any(|path| {
            read_limited_text(&path)
                .ok()
                .is_some_and(|text| text.to_ascii_lowercase().contains("github.copilot"))
        });
        let recommended = read_limited_text(&recommendations)
            .ok()
            .is_some_and(|text| text.to_ascii_lowercase().contains("github.copilot"));
        if configured || recommended {
            return (
                AuditApplicability::Partial,
                "VS Code configuration references GitHub Copilot, but a locally installed extension could not be proven."
                    .to_string(),
            );
        }

        (
            AuditApplicability::NotDetected,
            "GitHub Copilot was not detected; its report is retained for transparency but excluded from the bundle summary."
                .to_string(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VscodeReportScope {
    AgentHost,
    GithubCopilot,
}

pub fn audit_vscode_host(options: &VscodeAuditOptions) -> io::Result<AuditReport> {
    audit_vscode_scope(options, VscodeReportScope::AgentHost)
}

pub fn audit_github_copilot_vscode(options: &VscodeAuditOptions) -> io::Result<AuditReport> {
    audit_vscode_scope(options, VscodeReportScope::GithubCopilot)
}

fn audit_vscode_scope(
    options: &VscodeAuditOptions,
    scope: VscodeReportScope,
) -> io::Result<AuditReport> {
    let workspace = canonical_or_original(&options.workspace);
    let user_data = canonical_or_original(&options.user_data);
    let mut sources = Vec::new();
    let mut findings = Vec::new();
    let mut inventory = AuditInventory::default();
    let mut limitations = vec![
        "The audit is static and did not start VS Code, extensions, MCP servers, hooks, skills, package launchers, or agent commands.".to_string(),
        "Current session permission levels, saved tool/URL approvals, Workspace Trust decisions, MCP trust, publisher trust, OAuth grants, Settings Sync, and account policies were not queried.".to_string(),
        "Remote SSH, container, WSL, Codespaces, and policy layers require their files to be locally accessible; otherwise the resolved runtime posture may differ.".to_string(),
    ];

    let mut effective = Value::Object(Map::new());
    let user_settings = user_data.join("settings.json");
    let mut effective_source = user_settings.clone();
    load_settings_layer(
        &user_settings,
        "vscode_user_settings",
        &mut effective,
        &mut sources,
        &mut findings,
    );
    if let Some(profile) = &options.profile {
        let profile_settings = user_data
            .join("profiles")
            .join(profile)
            .join("settings.json");
        load_settings_layer(
            &profile_settings,
            "vscode_profile_settings",
            &mut effective,
            &mut sources,
            &mut findings,
        );
        if profile_settings.exists() {
            effective_source = profile_settings.clone();
        }
        if !profile_settings.exists() {
            findings.push(make_finding(
                "VSC-CFG-002",
                "configuration_provenance",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "Selected VS Code profile settings were not found",
                "The requested profile ID has no settings.json, so its effective posture cannot be reconstructed.",
                vec![evidence(&profile_settings, None, None)],
                "Select the active VS Code profile ID or omit the profile option to audit the default profile.",
                &[SETTINGS_REFERENCE],
                &["OWASP-ASI03"],
            ));
        }
    }
    let workspace_settings = workspace.join(".vscode/settings.json");
    load_settings_layer(
        &workspace_settings,
        "vscode_workspace_settings",
        &mut effective,
        &mut sources,
        &mut findings,
    );
    if workspace_settings.exists() {
        effective_source = workspace_settings;
    }

    evaluate_settings(&effective, &effective_source, &mut findings);
    discover_mcp(
        &workspace,
        &user_data,
        options.profile.as_deref(),
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    discover_skills(
        &workspace,
        &user_data,
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    discover_instructions_and_agents(&workspace, &mut sources, &mut inventory, &mut findings);
    discover_hooks(
        &workspace,
        &user_data,
        &mut sources,
        &mut inventory,
        &mut findings,
    );
    discover_extensions(
        &options.extension_roots,
        &mut sources,
        &mut inventory,
        &mut findings,
        &mut limitations,
    );
    scan_source_integrity(&sources, &mut findings);
    let mut manual_checks = vscode_manual_checks();
    match scope {
        VscodeReportScope::AgentHost => {
            findings.retain(|finding| !is_copilot_privacy_rule(&finding.rule_id));
            manual_checks.retain(|check| check.check_id != "VSC-PRV-005");
        }
        VscodeReportScope::GithubCopilot => {
            findings.retain(|finding| is_copilot_privacy_rule(&finding.rule_id));
            manual_checks.retain(|check| check.check_id == "VSC-PRV-005");
            sources.retain(|source| source.kind.contains("settings"));
            inventory.skills.clear();
            inventory.mcp_servers.clear();
            inventory.hook_commands = 0;
            inventory.plugin_manifests = 0;
            inventory.marketplace_files = 0;
            inventory.rule_files = 0;
            inventory.instruction_files = 0;
            inventory.managed_requirement_files = 0;
            inventory.custom_agents = 0;
            inventory
                .extensions
                .retain(|extension| is_github_copilot_extension(&extension.id));
            limitations = vec![
                "The audit did not start GitHub Copilot or query its authenticated account, organization, runtime approvals, remote services, or retention state.".to_string(),
                "A locally installed extension can be disabled by profile or policy; installed state does not prove that GitHub Copilot is active in the current window.".to_string(),
            ];
        }
    }
    sort_findings(&mut findings);

    let summary = summarize("partial", &findings, manual_checks.len());

    let (ruleset_id, ruleset_version, provider, surface) = match scope {
        VscodeReportScope::AgentHost => (
            VSCODE_RULESET_ID,
            VSCODE_RULESET_VERSION,
            "vscode",
            "agent_host",
        ),
        VscodeReportScope::GithubCopilot => (
            GITHUB_COPILOT_VSCODE_RULESET_ID,
            GITHUB_COPILOT_VSCODE_RULESET_VERSION,
            "github-copilot",
            "vscode_extension",
        ),
    };
    let mut effective_security_config = effective_security_summary(&effective, &inventory);
    match scope {
        VscodeReportScope::AgentHost => {
            effective_security_config.retain(|key, _| !key.starts_with("github.copilot"))
        }
        VscodeReportScope::GithubCopilot => effective_security_config.retain(|key, _| {
            key.starts_with("github.copilot")
                || key == "telemetry.telemetryLevel"
                || key == "extension_count"
        }),
    }

    Ok(AuditReport {
        schema_version: 1,
        ruleset: Ruleset {
            id: ruleset_id.to_string(),
            version: ruleset_version.to_string(),
        },
        target: AuditTarget {
            provider: provider.to_string(),
            workspace: display_path(&workspace),
            codex_home: None,
            profile: None,
            codex_version: None,
            surfaces: vec![surface.to_string()],
            vscode_user_data: Some(display_path(&user_data)),
            vscode_profile: options.profile.clone(),
        },
        summary,
        sources,
        effective_security_config,
        inventory,
        findings,
        manual_checks,
        limitations,
    })
}

fn load_settings_layer(
    path: &Path,
    kind: &str,
    effective: &mut Value,
    sources: &mut Vec<AuditSource>,
    findings: &mut Vec<AuditFinding>,
) {
    let mut source = source_for(path, kind, true, true);
    if !path.exists() {
        sources.push(source);
        return;
    }
    match read_limited_text(path) {
        Ok(text) => {
            source.sha256 = Some(hash_bytes(text.as_bytes()));
            match parse_jsonc(&text) {
                Ok(layer) if layer.is_object() => merge_json(effective, &layer),
                Ok(_) => {
                    source
                        .errors
                        .push("settings root is not an object".to_string());
                    findings.push(invalid_json_finding(
                        path,
                        "The settings root must be an object.",
                    ));
                }
                Err(error) => {
                    source.errors.push(error.clone());
                    findings.push(invalid_json_finding(path, &error));
                }
            }
        }
        Err(error) => {
            source.errors.push(error.to_string());
            findings.push(invalid_json_finding(path, &error.to_string()));
        }
    }
    sources.push(source);
}

fn invalid_json_finding(path: &Path, detail: &str) -> AuditFinding {
    make_finding(
        "VSC-CFG-001",
        "configuration_provenance",
        Severity::High,
        "high",
        Assessment::Confirmed,
        "Active VS Code settings cannot be parsed",
        &format!("The settings layer cannot be evaluated: {detail}"),
        vec![evidence(path, None, None)],
        "Repair the JSON-with-comments file and rerun the audit.",
        &[SETTINGS_REFERENCE],
        &["OWASP-ASI03"],
    )
}

fn evaluate_settings(settings: &Value, source: &Path, findings: &mut Vec<AuditFinding>) {
    let global_auto = bool_setting(settings, "chat.tools.global.autoApprove") == Some(true);
    let permission = string_setting(settings, "chat.permissions.default");
    let bypass = permission
        .is_some_and(|value| matches!(normalized(value).as_str(), "bypassapprovals" | "autopilot"));
    let sandbox = string_setting(settings, "chat.agent.sandbox.enabled").unwrap_or("off");

    if global_auto {
        findings.push(setting_finding(
            "VSC-AUT-001",
            "autonomy_and_approval",
            Severity::High,
            "Global tool auto-approval is enabled",
            "Every eligible agent tool can run without a confirmation across all workspaces.",
            source,
            "chat.tools.global.autoApprove",
            "true",
            "Disable global auto-approval and grant narrowly scoped session approvals instead.",
        ));
    }
    if bypass {
        findings.push(setting_finding(
            "VSC-AUT-002",
            "autonomy_and_approval",
            Severity::High,
            "New agent sessions bypass approvals by default",
            "The default permission level removes manual review for edits, commands, and external tools.",
            source,
            "chat.permissions.default",
            permission.unwrap_or_default(),
            "Use Default Approvals as the default and elevate only a specific session when justified.",
        ));
    }
    if (global_auto || bypass) && sandbox == "off" {
        findings.push(make_finding(
            "VSC-AUT-003",
            "autonomy_and_approval",
            Severity::Critical,
            "high",
            Assessment::Confirmed,
            "Approval bypass is combined with an unsandboxed agent",
            "Agent tools or commands can execute with the VS Code process permissions without a human approval boundary.",
            vec![
                evidence(source, Some("chat.permissions.default"), permission),
                evidence(source, Some("chat.tools.global.autoApprove"), Some(if global_auto { "true" } else { "false" })),
                evidence(source, Some("chat.agent.sandbox.enabled"), Some(sandbox)),
            ],
            "Use Default Approvals and enable the agent sandbox before enabling any broad automation.",
            &[APPROVALS_REFERENCE],
            &["OWASP-ASI02", "OWASP-ASI03"],
        ));
    }

    if bool_setting(
        settings,
        "chat.tools.terminal.ignoreDefaultAutoApproveRules",
    ) == Some(true)
    {
        findings.push(setting_finding(
            "VSC-AUT-004",
            "autonomy_and_approval",
            Severity::High,
            "Built-in terminal approval protections are ignored",
            "Only user-defined terminal rules remain, removing VS Code's default risky-command deny rules.",
            source,
            "chat.tools.terminal.ignoreDefaultAutoApproveRules",
            "true",
            "Keep the built-in rules enabled and add explicit deny rules for environment-specific hazards.",
        ));
    }
    if let Some(rules) = settings
        .get("chat.tools.terminal.autoApprove")
        .and_then(Value::as_object)
    {
        for (pattern, allowed) in rules {
            if allowed == &Value::Bool(true) && broad_command_pattern(pattern) {
                findings.push(setting_finding(
                    "VSC-AUT-005",
                    "autonomy_and_approval",
                    Severity::High,
                    "Terminal auto-approval rule is overly broad",
                    "The allow rule can cover shells, interpreters, privilege wrappers, or arbitrary command lines.",
                    source,
                    &format!("chat.tools.terminal.autoApprove.{pattern}"),
                    "true",
                    "Replace the rule with narrowly anchored command and argument patterns.",
                ));
            }
        }
    }
    if sensitive_edits_autoapproved(settings) {
        findings.push(setting_finding(
            "VSC-AUT-006",
            "autonomy_and_approval",
            Severity::High,
            "Sensitive file edits can be auto-approved",
            "A broad edit approval rule can modify credential, environment, or agent-control files without review.",
            source,
            "chat.tools.edits.autoApprove",
            "<broad-allow>",
            "Require review for .env, credentials, settings, hooks, MCP, instructions, and agent configuration files.",
        ));
    }

    if bool_setting(settings, "chat.agent.sandbox.allowNetwork") == Some(true) {
        findings.push(setting_finding(
            "VSC-SBX-001",
            "sandbox_and_network",
            Severity::High,
            "Agent sandbox allows unrestricted outbound networking",
            "Filesystem restrictions remain, but commands can reach any network destination.",
            source,
            "chat.agent.sandbox.allowNetwork",
            "true",
            "Disable unrestricted networking and allow only required domains.",
        ));
    }
    if bool_setting(settings, "chat.agent.sandbox.allowUnsandboxedCommands") == Some(true)
        && sandbox == "on"
    {
        findings.push(setting_finding(
            "VSC-SBX-002",
            "sandbox_and_network",
            Severity::Medium,
            "Blocked agent commands may be retried outside the sandbox",
            "A confirmation can elevate a command to the full VS Code process boundary after sandbox failure.",
            source,
            "chat.agent.sandbox.allowUnsandboxedCommands",
            "true",
            "Disable unsandboxed retries in high-assurance workspaces.",
        ));
    }
    for key in [
        "chat.agent.sandbox.fileSystem.mac",
        "chat.agent.sandbox.fileSystem.linux",
    ] {
        if let Some(config) = settings.get(key).and_then(Value::as_object) {
            for access in ["allowRead", "allowWrite"] {
                if let Some(paths) = config.get(access).and_then(Value::as_array) {
                    for path in paths.iter().filter_map(Value::as_str) {
                        if broad_path(path) {
                            findings.push(setting_finding(
                                "VSC-SBX-003",
                                "sandbox_and_network",
                                Severity::High,
                                "Agent sandbox grants a broad filesystem exception",
                                "The additional path includes a home, system, credential, or configuration boundary.",
                                source,
                                &format!("{key}.{access}"),
                                path,
                                "Remove the broad path or replace it with the smallest task-specific directory.",
                            ));
                        }
                    }
                }
            }
        }
    }

    if bool_setting(settings, "chat.agent.networkFilter") == Some(false) && (global_auto || bypass)
    {
        findings.push(setting_finding(
            "VSC-NET-001",
            "sandbox_and_network",
            Severity::High,
            "Network filtering is disabled for an autonomous agent posture",
            "Agent fetch, browser, and eligible terminal traffic are not restricted to approved domains.",
            source,
            "chat.agent.networkFilter",
            "false",
            "Enable the network filter and maintain explicit allowed and denied domain lists.",
        ));
    }
    if array_has_wildcard(settings.get("chat.agent.allowedNetworkDomains")) {
        findings.push(setting_finding(
            "VSC-NET-002",
            "sandbox_and_network",
            Severity::High,
            "Agent network allowlist contains a global wildcard",
            "A global wildcard defeats domain scoping and increases exfiltration and prompt-injection exposure.",
            source,
            "chat.agent.allowedNetworkDomains",
            "*",
            "Replace the wildcard with exact required domains.",
        ));
    }
    if url_autoapproval_is_broad(settings.get("chat.tools.urls.autoApprove")) {
        findings.push(setting_finding(
            "VSC-NET-003",
            "sandbox_and_network",
            Severity::High,
            "URL request or response approval is globally broad",
            "Remote content can enter agent context without the normal request or prompt-injection review boundary.",
            source,
            "chat.tools.urls.autoApprove",
            "<broad-allow>",
            "Require approval for responses and use exact trusted request domains.",
        ));
    }

    if bool_setting(settings, "security.workspace.trust.enabled") == Some(false) {
        findings.push(setting_finding(
            "VSC-TRU-001",
            "workspace_and_extension_trust",
            Severity::High,
            "VS Code Workspace Trust is disabled",
            "Unfamiliar repositories no longer enter Restricted Mode before agents, tasks, settings, and extensions can act.",
            source,
            "security.workspace.trust.enabled",
            "false",
            "Enable Workspace Trust and leave unreviewed repositories in Restricted Mode.",
        ));
    }
    if extensions_override_untrusted(settings) {
        findings.push(setting_finding(
            "VSC-TRU-002",
            "workspace_and_extension_trust",
            Severity::Medium,
            "An extension is forced to run in untrusted workspaces",
            "The override bypasses the extension publisher's declared Restricted Mode support boundary.",
            source,
            "extensions.supportUntrustedWorkspaces",
            "<supported-override>",
            "Remove the override unless the specific extension version has been reviewed for Restricted Mode.",
        ));
    }

    if string_setting(settings, "telemetry.telemetryLevel") == Some("all") {
        findings.push(setting_finding(
            "VSC-PRV-001",
            "privacy_retention_telemetry",
            Severity::Low,
            "Full VS Code usage telemetry is enabled",
            "Usage, error, and crash telemetry are sent to Microsoft; extension telemetry remains separately controlled.",
            source,
            "telemetry.telemetryLevel",
            "all",
            "Select the telemetry level required by organizational policy, using off when no editor telemetry is permitted.",
        ));
    }
    if bool_setting(settings, "github.copilot.chat.otel.captureContent") == Some(true) {
        findings.push(setting_finding(
            "VSC-PRV-002",
            "privacy_retention_telemetry",
            Severity::High,
            "Copilot OpenTelemetry captures full agent content",
            "Prompts, responses, system instructions, tool schemas, arguments, and results can be exported.",
            source,
            "github.copilot.chat.otel.captureContent",
            "true",
            "Disable content capture or send it only to an approved, access-controlled collector with bounded retention.",
        ));
    }
    if let Some(endpoint) = string_setting(settings, "github.copilot.chat.otel.otlpEndpoint") {
        if insecure_remote_http(endpoint) {
            findings.push(setting_finding(
                "VSC-PRV-003",
                "privacy_retention_telemetry",
                Severity::High,
                "Copilot telemetry uses a plaintext remote collector",
                "Agent metadata or captured content can cross the network without TLS.",
                source,
                "github.copilot.chat.otel.otlpEndpoint",
                endpoint,
                "Use an authenticated HTTPS collector or a loopback-only development endpoint.",
            ));
        }
    }
    if string_setting(settings, "github.copilot.chat.otel.exporterType") == Some("file") {
        findings.push(setting_finding(
            "VSC-PRV-004",
            "privacy_retention_telemetry",
            Severity::Medium,
            "Copilot agent traces are written to a plaintext file",
            "Local trace files can contain repository identifiers and, when content capture is enabled, prompts and tool data.",
            source,
            "github.copilot.chat.otel.exporterType",
            "file",
            "Use a protected location, restrictive permissions, bounded retention, and content capture off.",
        ));
    }
}

fn discover_mcp(
    workspace: &Path,
    user_data: &Path,
    profile: Option<&str>,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut paths = vec![
        (user_data.join("mcp.json"), "vscode_user_mcp"),
        (workspace.join(".vscode/mcp.json"), "vscode_workspace_mcp"),
    ];
    if let Some(profile) = profile {
        paths.insert(
            1,
            (
                user_data.join("profiles").join(profile).join("mcp.json"),
                "vscode_profile_mcp",
            ),
        );
    }

    for (path, kind) in paths {
        let mut source = source_for(&path, kind, true, true);
        if !path.exists() {
            sources.push(source);
            continue;
        }
        let value = match read_limited_text(&path).and_then(|text| {
            source.sha256 = Some(hash_bytes(text.as_bytes()));
            parse_jsonc(&text).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        }) {
            Ok(value) => value,
            Err(error) => {
                source.errors.push(error.to_string());
                findings.push(make_finding(
                    "VSC-MCP-001",
                    "mcp_and_external_tools",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "VS Code MCP configuration cannot be parsed",
                    "Configured servers and their trust boundaries could not be evaluated.",
                    vec![evidence(&path, None, None)],
                    "Repair the JSON-with-comments MCP configuration and rerun the audit.",
                    &[MCP_REFERENCE],
                    &["OWASP-MCP1"],
                ));
                sources.push(source);
                continue;
            }
        };

        if let Some(inputs) = value.get("inputs").and_then(Value::as_array) {
            for input in inputs {
                if input.get("type").and_then(Value::as_str) == Some("command") {
                    findings.push(make_finding(
                        "VSC-MCP-002",
                        "mcp_and_external_tools",
                        Severity::High,
                        "high",
                        Assessment::Confirmed,
                        "MCP input obtains a value by executing a VS Code command",
                        "Starting an MCP server can invoke another extension command and use its output as configuration.",
                        vec![evidence(&path, Some("inputs[].type"), Some("command"))],
                        "Use promptString with password=true or an approved secret store instead of command-derived input.",
                        &[MCP_REFERENCE],
                        &["OWASP-MCP3", "OWASP-ASI04"],
                    ));
                }
            }
        }

        let sandbox = value.get("sandbox");
        if mcp_sandbox_is_broad(sandbox) {
            findings.push(make_finding(
                "VSC-MCP-003",
                "mcp_and_external_tools",
                Severity::High,
                "high",
                Assessment::Confirmed,
                "MCP sandbox grants a broad filesystem or network exception",
                "Sandboxed servers can reach a home/system path or an unrestricted network domain.",
                vec![evidence(&path, Some("sandbox"), Some("<broad-access>"))],
                "Restrict MCP filesystem and network access to the smallest required paths and domains.",
                &[MCP_REFERENCE],
                &["OWASP-MCP2", "OWASP-MCP6"],
            ));
        }

        if let Some(servers) = value.get("servers").and_then(Value::as_object) {
            for (id, server) in servers {
                inspect_mcp_server(id, server, &path, inventory, findings);
            }
        }
        sources.push(source);
    }
}

fn inspect_mcp_server(
    id: &str,
    server: &Value,
    source: &Path,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let transport = server
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if server.get("url").is_some() {
                "http"
            } else {
                "stdio"
            }
        });
    let raw_endpoint = server
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_string);
    let endpoint_has_credentials = raw_endpoint.as_deref().is_some_and(url_has_credentials);
    let inventory_endpoint = raw_endpoint.as_ref().map(|endpoint| {
        if endpoint_has_credentials {
            "<redacted-credential-url>".to_string()
        } else {
            endpoint.clone()
        }
    });
    inventory.mcp_servers.push(McpInventory {
        id: id.to_string(),
        transport: transport.to_string(),
        enabled: true,
        has_tool_allowlist: false,
        endpoint: inventory_endpoint,
    });

    if let Some(url) = raw_endpoint.as_deref() {
        if insecure_remote_http(url) {
            findings.push(mcp_finding(
                "VSC-MCP-004",
                Severity::High,
                id,
                source,
                "Remote MCP endpoint uses plaintext HTTP",
                "Tool requests, results, and authorization material can be intercepted in transit.",
                "url",
                if endpoint_has_credentials {
                    "<redacted-credential-url>"
                } else {
                    url
                },
                "Use an authenticated HTTPS endpoint.",
            ));
        }
        if endpoint_has_credentials {
            findings.push(mcp_finding(
                "VSC-MCP-005",
                Severity::High,
                id,
                source,
                "MCP endpoint embeds credentials",
                "Credentials in configuration can leak through source control, logs, backups, or reports.",
                "url",
                "<redacted>",
                "Use VS Code input variables or OAuth instead of URL credentials.",
            ));
        }
    }

    if let Some(command) = server.get("command").and_then(Value::as_str) {
        if shell_command(command) {
            findings.push(mcp_finding(
                "VSC-MCP-006",
                Severity::High,
                id,
                source,
                "MCP server launches through a shell or command interpreter",
                "Shell parsing expands the impact of mutable arguments and workspace-controlled content.",
                "command",
                command,
                "Launch a reviewed executable directly with a fixed argument array.",
            ));
        }
        let args = server
            .get("args")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if mutable_package_launcher(command, &args) {
            findings.push(mcp_finding(
                "VSC-MCP-007",
                Severity::High,
                id,
                source,
                "MCP package launcher is not pinned to an immutable version",
                "A future package release can execute with the MCP server's local privileges.",
                "args",
                "<mutable-package>",
                "Pin the package to a reviewed exact version or immutable artifact digest.",
            ));
        }
        if server.get("sandboxEnabled").and_then(Value::as_bool) != Some(true) {
            findings.push(mcp_finding(
                "VSC-MCP-008",
                Severity::Medium,
                id,
                source,
                "Local MCP server is not sandboxed",
                "The server process inherits the extension host's filesystem, process, and network permissions.",
                "sandboxEnabled",
                "false-or-unset",
                "Enable MCP sandboxing on supported platforms and define minimal filesystem and network access.",
            ));
        }
    }

    if json_contains_secret(server) {
        findings.push(mcp_finding(
            "VSC-MCP-009",
            Severity::High,
            id,
            source,
            "MCP configuration contains a secret-like literal",
            "The credential is stored in plaintext control-plane configuration.",
            "env-or-headers",
            "<redacted>",
            "Use a password input variable, OAuth, environment reference, or approved secret store.",
        ));
    }
}

fn discover_skills(
    workspace: &Path,
    user_data: &Path,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut roots = vec![
        (workspace.join(".github/skills"), "repository"),
        (workspace.join(".claude/skills"), "repository_compat"),
        (workspace.join(".agents/skills"), "repository_shared"),
        (user_data.join("skills"), "profile"),
    ];
    if let Some(home) = home_dir() {
        roots.extend([
            (home.join(".copilot/skills"), "user"),
            (home.join(".claude/skills"), "user_compat"),
            (home.join(".agents/skills"), "user_shared"),
        ]);
    }

    let mut auto_invocable_with_scripts = 0;
    let mut seen = HashSet::new();
    for (root, scope) in roots {
        for skill_file in find_named_files(&root, "SKILL.md") {
            let canonical = canonical_or_original(&skill_file);
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let mut source = source_for(&skill_file, "vscode_skill", true, true);
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
            let name = frontmatter_value(text, "name").unwrap_or_else(|| {
                skill_file
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .unwrap_or("unnamed")
                    .to_string()
            });
            let manual_only =
                frontmatter_value(text, "disable-model-invocation").as_deref() == Some("true");
            let skill_dir = skill_file.parent().unwrap_or(&root);
            let has_scripts = skill_dir.join("scripts").is_dir();
            if has_scripts && !manual_only {
                auto_invocable_with_scripts += 1;
            }
            inventory.skills.push(SkillInventory {
                name: name.clone(),
                path: display_path(&skill_file),
                scope: scope.to_string(),
                enabled: true,
                has_scripts,
                review_state: "unknown".to_string(),
                sha256,
            });

            if has_scripts {
                findings.push(make_finding(
                    "VSC-SKL-001",
                    "skills_instructions_hooks",
                    Severity::Info,
                    "high",
                    Assessment::Potential,
                    "Enabled VS Code skill includes executable scripts",
                    &format!("Skill `{name}` can direct an agent to execute code from its scripts directory."),
                    vec![evidence(&skill_file, Some("scripts"), Some("present"))],
                    "Review the scripts, dependencies, and invocation paths before approving the skill.",
                    &[SKILLS_REFERENCE],
                    &["OWASP-ASI04"],
                ));
            }
            if poisoning_indicator(text) || download_to_shell(text) {
                findings.push(make_finding(
                    "VSC-SKL-002",
                    "skills_instructions_hooks",
                    Severity::High,
                    "medium",
                    Assessment::Potential,
                    "Skill contains a prompt-poisoning or remote-execution indicator",
                    &format!("Skill `{name}` contains content that can override reviewer intent or download and execute remote code."),
                    vec![evidence(&skill_file, None, Some("<redacted-content-match>"))],
                    "Review the complete skill and referenced resources before enabling or invoking it.",
                    &[SKILLS_REFERENCE],
                    &["OWASP-ASI01", "OWASP-ASI04"],
                ));
            }
            if has_scripts && !manual_only {
                findings.push(make_finding(
                    "VSC-SKL-003",
                    "skills_instructions_hooks",
                    Severity::Medium,
                    "high",
                    Assessment::Potential,
                    "Script-bearing skill is eligible for automatic model invocation",
                    "The agent can select the skill without the user explicitly invoking its slash command.",
                    vec![evidence(&skill_file, Some("disable-model-invocation"), Some("false-or-unset"))],
                    "Set disable-model-invocation to true until the skill and its scripts have an auditable review record.",
                    &[SKILLS_REFERENCE],
                    &["OWASP-ASI02", "OWASP-ASI04"],
                ));
            }
        }
    }
    if auto_invocable_with_scripts > 10 {
        findings.push(make_finding(
            "VSC-SKL-004",
            "skills_instructions_hooks",
            Severity::Medium,
            "medium",
            Assessment::Potential,
            "Large set of script-bearing skills is auto-invocable",
            "Many executable workflows can be selected by the model without an explicit user command.",
            Vec::new(),
            "Disable model invocation for unused or unreviewed skills and maintain review records for the remainder.",
            &[SKILLS_REFERENCE],
            &["OWASP-ASI04"],
        ));
    }
    inventory
        .skills
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn discover_instructions_and_agents(
    workspace: &Path,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut candidates = vec![
        workspace.join(".github/copilot-instructions.md"),
        workspace.join("AGENTS.md"),
        workspace.join("CLAUDE.md"),
        workspace.join(".claude/CLAUDE.md"),
    ];
    candidates.extend(find_suffix_files(
        &workspace.join(".github/instructions"),
        ".instructions.md",
    ));
    let agents = find_suffix_files(&workspace.join(".github/agents"), ".agent.md");
    inventory.custom_agents = agents.len();
    candidates.extend(agents);

    for path in candidates.into_iter().filter(|path| path.exists()) {
        let kind = if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".agent.md"))
        {
            "vscode_custom_agent"
        } else {
            "vscode_instruction"
        };
        let mut source = source_for(&path, kind, true, true);
        let text = match read_limited_text(&path) {
            Ok(text) => {
                source.sha256 = Some(hash_bytes(text.as_bytes()));
                Some(text)
            }
            Err(error) => {
                source.errors.push(error.to_string());
                None
            }
        };
        sources.push(source);
        inventory.instruction_files += 1;
        let Some(text) = text else {
            continue;
        };
        if poisoning_indicator(&text) || download_to_shell(&text) {
            findings.push(make_finding(
                "VSC-INS-001",
                "skills_instructions_hooks",
                Severity::High,
                "medium",
                Assessment::Potential,
                "Agent instruction or custom-agent file contains a dangerous indicator",
                "Always-on or task-selected context can override user intent or direct remote code execution.",
                vec![evidence(&path, None, Some("<redacted-content-match>"))],
                "Review the complete file, provenance, referenced URLs, and tool scope before using it.",
                &[SECURITY_REFERENCE],
                &["OWASP-ASI01", "OWASP-ASI04"],
            ));
        }
        if kind == "vscode_custom_agent" && broad_agent_tools(&text) {
            findings.push(make_finding(
                "VSC-AGT-001",
                "autonomy_and_approval",
                Severity::Medium,
                "medium",
                Assessment::Potential,
                "Custom agent requests a broad tool surface",
                "The agent definition appears to combine terminal, edits, external tools, or broad tool wildcards.",
                vec![evidence(&path, Some("tools"), Some("<broad-tool-set>"))],
                "Limit the agent to the smallest tool set required for its role.",
                &[SECURITY_REFERENCE],
                &["OWASP-ASI02"],
            ));
        }
    }
}

fn discover_hooks(
    workspace: &Path,
    user_data: &Path,
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
) {
    let mut files = find_suffix_files(&workspace.join(".github/hooks"), ".json");
    files.extend([
        workspace.join(".claude/settings.json"),
        workspace.join(".claude/settings.local.json"),
    ]);
    files.extend(find_suffix_files(&user_data.join("hooks"), ".json"));
    if let Some(home) = home_dir() {
        files.push(home.join(".claude/settings.json"));
    }

    for path in files.into_iter().filter(|path| path.exists()) {
        let mut source = source_for(&path, "vscode_hook", true, true);
        let text = match read_limited_text(&path) {
            Ok(text) => {
                source.sha256 = Some(hash_bytes(text.as_bytes()));
                Some(text)
            }
            Err(error) => {
                source.errors.push(error.to_string());
                None
            }
        };
        let commands = text
            .as_deref()
            .map(hook_commands)
            .transpose()
            .unwrap_or_else(|error| {
                source.errors.push(error);
                None
            })
            .unwrap_or_default();
        sources.push(source);
        inventory.hook_commands += commands.len();
        for command in commands {
            if download_to_shell(&command) {
                findings.push(make_finding(
                    "VSC-HOK-001",
                    "skills_instructions_hooks",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "Agent hook downloads and executes remote content",
                    "The lifecycle hook can execute changing remote code with the VS Code agent host's permissions.",
                    vec![evidence(&path, Some("command"), Some("<redacted-command>"))],
                    "Replace the pipeline with a reviewed, pinned local executable or script.",
                    &[HOOKS_REFERENCE],
                    &["OWASP-ASI04"],
                ));
            }
        }
    }
}

fn discover_extensions(
    roots: &[PathBuf],
    sources: &mut Vec<AuditSource>,
    inventory: &mut AuditInventory,
    findings: &mut Vec<AuditFinding>,
    limitations: &mut Vec<String>,
) {
    let mut seen = HashSet::new();
    for root in roots {
        for path in child_directories(root) {
            let package = path.join("package.json");
            if !package.exists() {
                continue;
            }
            let mut source = source_for(&package, "vscode_extension_manifest", true, true);
            let text = match read_limited_text(&package) {
                Ok(text) => {
                    source.sha256 = Some(hash_bytes(text.as_bytes()));
                    text
                }
                Err(error) => {
                    source.errors.push(error.to_string());
                    sources.push(source);
                    continue;
                }
            };
            let value = match serde_json::from_str::<Value>(&text) {
                Ok(value) => value,
                Err(error) => {
                    source.errors.push(error.to_string());
                    sources.push(source);
                    continue;
                }
            };
            sources.push(source);
            let publisher = value
                .get("publisher")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let id = format!("{publisher}.{name}");
            if !seen.insert(id.clone()) {
                continue;
            }
            let version = value
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let mut capabilities = Vec::new();
            if let Some(contributes) = value.get("contributes").and_then(Value::as_object) {
                for (key, label) in [
                    ("chatSkills", "skills"),
                    ("languageModelTools", "tools"),
                    ("chatParticipants", "agents"),
                    ("mcpServerDefinitionProviders", "mcp"),
                ] {
                    if contributes.get(key).is_some() {
                        capabilities.push(label.to_string());
                    }
                }
            }
            if !capabilities.is_empty() {
                findings.push(make_finding(
                    "VSC-EXT-001",
                    "workspace_and_extension_trust",
                    Severity::Info,
                    "high",
                    Assessment::Potential,
                    "Installed extension contributes an agent capability surface",
                    &format!("Extension `{id}` contributes {} and executes with the extension host's permissions.", capabilities.join(", ")),
                    vec![evidence(&package, Some("contributes"), Some("<agent-capabilities>"))],
                    "Confirm publisher trust, version provenance, update policy, telemetry, and required permissions.",
                    &[SECURITY_REFERENCE],
                    &["OWASP-ASI04"],
                ));
            }
            inventory.extensions.push(ExtensionInventory {
                id,
                version,
                path: display_path(&path),
                enabled_state: "installed_unknown_profile_state".to_string(),
                capabilities,
            });
        }
    }
    if inventory.extensions.is_empty() {
        limitations.push(
            "No standard local extension directory was discovered; installed and active extensions may be incomplete."
                .to_string(),
        );
    }
    inventory
        .extensions
        .sort_by(|left, right| left.id.cmp(&right.id));
}

fn vscode_manual_checks() -> Vec<ManualCheck> {
    vec![
        ManualCheck {
            check_id: "VSC-PRV-005".to_string(),
            priority: "high".to_string(),
            title: "Verify GitHub Copilot model-training and data-use controls".to_string(),
            reason: "VS Code settings cannot prove the authenticated GitHub account and organization's Copilot data-use controls.".to_string(),
            action: "Review GitHub Copilot training, product-improvement, feedback sharing, retention, and enterprise policy controls for the authenticated account.".to_string(),
            references: vec![COPILOT_DATA_REFERENCE.to_string()],
        },
        ManualCheck {
            check_id: "VSC-TRU-003".to_string(),
            priority: "high".to_string(),
            title: "Review runtime trust and saved approval decisions".to_string(),
            reason: "Workspace, MCP server, extension publisher, URL response, and per-tool trust decisions are stored as runtime product state rather than stable project configuration.".to_string(),
            action: "Use VS Code's Workspace Trust, Manage Tool Approval, Reset Tool Confirmations, MCP trust, and trusted-publisher views to verify current decisions.".to_string(),
            references: vec![SECURITY_REFERENCE.to_string(), APPROVALS_REFERENCE.to_string()],
        },
        ManualCheck {
            check_id: "VSC-REM-001".to_string(),
            priority: "medium".to_string(),
            title: "Verify remote and enterprise policy layers".to_string(),
            reason: "Remote-host settings and organization/device policy can override locally visible user settings.".to_string(),
            action: "Audit the active remote host and export VS Code Policy Diagnostics when remote development or managed policy is in use.".to_string(),
            references: vec![SETTINGS_REFERENCE.to_string()],
        },
    ]
}

fn effective_security_summary(
    settings: &Value,
    inventory: &AuditInventory,
) -> BTreeMap<String, Value> {
    let mut summary = BTreeMap::new();
    for key in [
        "chat.permissions.default",
        "chat.tools.global.autoApprove",
        "chat.agent.sandbox.enabled",
        "chat.agent.sandbox.allowNetwork",
        "chat.agent.networkFilter",
        "telemetry.telemetryLevel",
        "github.copilot.chat.otel.enabled",
        "github.copilot.chat.otel.captureContent",
    ] {
        summary.insert(
            key.to_string(),
            settings.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    summary.insert(
        "mcp_server_count".to_string(),
        json!(inventory.mcp_servers.len()),
    );
    summary.insert("skill_count".to_string(), json!(inventory.skills.len()));
    summary.insert(
        "extension_count".to_string(),
        json!(inventory.extensions.len()),
    );
    summary
}

fn default_user_data() -> PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(app_data) = env::var_os("APPDATA") {
        let app_data = PathBuf::from(app_data);
        let candidates = [
            app_data.join("Code/User"),
            app_data.join("Code - Insiders/User"),
            app_data.join("VSCodium/User"),
        ];
        return candidates
            .iter()
            .find(|path| path.is_dir())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone());
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = home_dir() {
        let application_support = home.join("Library/Application Support");
        let candidates = [
            application_support.join("Code/User"),
            application_support.join("Code - Insiders/User"),
            application_support.join("VSCodium/User"),
        ];
        return candidates
            .iter()
            .find(|path| path.is_dir())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone());
    }
    if let Some(home) = home_dir() {
        let candidates = [
            home.join(".config/Code/User"),
            home.join(".config/Code - Insiders/User"),
            home.join(".config/VSCodium/User"),
        ];
        return candidates
            .iter()
            .find(|path| path.is_dir())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone());
    }
    PathBuf::from(".config/Code/User")
}

fn default_extension_roots() -> Vec<PathBuf> {
    home_dir()
        .map(|home| {
            vec![
                home.join(".vscode/extensions"),
                home.join(".vscode-insiders/extensions"),
                home.join(".vscode-oss/extensions"),
                home.join(".var/app/com.vscodium.codium/data/codium/extensions"),
            ]
        })
        .unwrap_or_default()
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn parse_jsonc(text: &str) -> Result<Value, String> {
    let without_comments = strip_json_comments(text);
    let without_trailing_commas = strip_trailing_commas(&without_comments);
    serde_json::from_str(&without_trailing_commas).map_err(|error| error.to_string())
}

fn strip_json_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < chars.len() {
        let current = chars[index];
        if in_string {
            output.push(current);
            if escaped {
                escaped = false;
            } else if current == '\\' {
                escaped = true;
            } else if current == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if current == '"' {
            in_string = true;
            output.push(current);
            index += 1;
        } else if current == '/' && chars.get(index + 1) == Some(&'/') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            output.push('\n');
            index += usize::from(index < chars.len());
        } else if current == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                if chars[index] == '\n' {
                    output.push('\n');
                }
                index += 1;
            }
            index = (index + 2).min(chars.len());
        } else {
            output.push(current);
            index += 1;
        }
    }
    output
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < chars.len() {
        let current = chars[index];
        if in_string {
            output.push(current);
            if escaped {
                escaped = false;
            } else if current == '\\' {
                escaped = true;
            } else if current == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if current == '"' {
            in_string = true;
            output.push(current);
        } else if current == ',' {
            let mut next = index + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if !matches!(chars.get(next), Some('}') | Some(']')) {
                output.push(current);
            }
        } else {
            output.push(current);
        }
        index += 1;
    }
    output
}

fn merge_json(base: &mut Value, layer: &Value) {
    match (base, layer) {
        (Value::Object(base), Value::Object(layer)) => {
            for (key, value) in layer {
                base.insert(key.clone(), value.clone());
            }
        }
        (base, layer) => *base = layer.clone(),
    }
}

fn bool_setting(settings: &Value, key: &str) -> Option<bool> {
    settings.get(key).and_then(Value::as_bool)
}

fn string_setting<'a>(settings: &'a Value, key: &str) -> Option<&'a str> {
    settings.get(key).and_then(Value::as_str)
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn broad_command_pattern(pattern: &str) -> bool {
    let lower = pattern.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "*" | "/.*/"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "python"
            | "python3"
            | "node"
            | "sudo"
            | "env"
    ) || lower.contains(".*") && !lower.starts_with("/^git ")
}

fn sensitive_edits_autoapproved(settings: &Value) -> bool {
    match settings.get("chat.tools.edits.autoApprove") {
        Some(Value::Bool(true)) => true,
        Some(Value::Object(patterns)) => patterns.iter().any(|(pattern, value)| {
            value == &Value::Bool(true) && matches!(pattern.as_str(), "*" | "**" | "**/*" | "**/**")
        }),
        _ => false,
    }
}

fn extensions_override_untrusted(settings: &Value) -> bool {
    settings
        .get("extensions.supportUntrustedWorkspaces")
        .and_then(Value::as_object)
        .is_some_and(|extensions| {
            extensions.values().any(|config| {
                config
                    .get("supported")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
        })
}

fn array_has_wildcard(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("*")))
}

fn url_autoapproval_is_broad(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::Object(patterns)) => patterns.iter().any(|(pattern, approval)| {
            matches!(pattern.as_str(), "*" | "**" | "http://*" | "https://*")
                && approval != &Value::Bool(false)
        }),
        _ => false,
    }
}

fn broad_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "/" | "~" | "${userhome}" | "c:/" | "c:\\"
    ) || normalized.ends_with("/.ssh")
        || normalized.ends_with("/.aws")
        || normalized.ends_with("/.config")
        || normalized.ends_with("/appdata")
        || normalized == "/etc"
}

fn mcp_sandbox_is_broad(value: Option<&Value>) -> bool {
    let Some(value) = value else { return false };
    let path_broad = ["allowWrite", "allowRead"].into_iter().any(|key| {
        value
            .pointer(&format!("/filesystem/{key}"))
            .and_then(Value::as_array)
            .is_some_and(|paths| paths.iter().filter_map(Value::as_str).any(broad_path))
    });
    path_broad
        || value
            .pointer("/network/allowedDomains")
            .and_then(Value::as_array)
            .is_some_and(|domains| domains.iter().any(|domain| domain.as_str() == Some("*")))
}

fn insecure_remote_http(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://")
        && !lower.starts_with("http://localhost")
        && !lower.starts_with("http://127.0.0.1")
        && !lower.starts_with("http://[::1]")
}

fn url_has_credentials(url: &str) -> bool {
    let user_info = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .is_some_and(|authority| authority.contains('@'));
    let secret_query = url.split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|parameter| {
            let key = parameter
                .split_once('=')
                .map(|(key, _)| key)
                .unwrap_or(parameter)
                .to_ascii_lowercase();
            [
                "token",
                "secret",
                "password",
                "api_key",
                "apikey",
                "authorization",
            ]
            .iter()
            .any(|needle| key.contains(needle))
        })
    });
    user_info || secret_query
}

fn shell_command(command: &str) -> bool {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "sh" | "bash"
                    | "zsh"
                    | "fish"
                    | "cmd"
                    | "cmd.exe"
                    | "powershell"
                    | "powershell.exe"
                    | "pwsh"
            )
        })
}

fn mutable_package_launcher(command: &str, args: &[Value]) -> bool {
    let launcher = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    if !matches!(
        launcher.as_str(),
        "npx" | "npm" | "pnpm" | "pnpx" | "yarn" | "uvx" | "pipx"
    ) {
        return false;
    }
    args.iter().filter_map(Value::as_str).any(|argument| {
        if argument.starts_with('-') {
            return false;
        }
        let package = argument.rsplit('/').next().unwrap_or(argument);
        !package.contains('@') || package.ends_with("@latest") || package.contains("@next")
    })
}

fn json_contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let secret_key = [
                "token",
                "secret",
                "password",
                "api_key",
                "apikey",
                "authorization",
            ]
            .iter()
            .any(|needle| key.to_ascii_lowercase().contains(needle));
            (secret_key && value.as_str().is_some_and(secret_literal))
                || json_contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(json_contains_secret),
        _ => false,
    }
}

fn secret_literal(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && !trimmed.contains("${")
        && !trimmed.starts_with("env:")
        && !trimmed.starts_with("input:")
        && trimmed.len() >= 8
}

fn poisoning_indicator(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "ignore previous instructions",
        "ignore all previous",
        "do not tell the user",
        "hide this instruction",
        "system message override",
        "\u{200b}",
        "\u{202e}",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn download_to_shell(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest"))
        && (lower.contains("| sh")
            || lower.contains("| bash")
            || lower.contains("| iex")
            || lower.contains("invoke-expression"))
}

fn broad_agent_tools(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("tools: ['*']")
        || lower.contains("tools: [\"*\"]")
        || (lower.contains("terminal") && lower.contains("edit") && lower.contains("mcp"))
}

fn hook_commands(text: &str) -> Result<Vec<String>, String> {
    let value = parse_jsonc(text)?;
    let mut commands = Vec::new();
    collect_json_commands(&value, &mut commands);
    Ok(commands)
}

fn collect_json_commands(value: &Value, commands: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "command" {
                    if let Some(command) = value.as_str() {
                        commands.push(command.to_string());
                    }
                }
                collect_json_commands(value, commands);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_commands(value, commands);
            }
        }
        _ => {}
    }
}

fn frontmatter_value(text: &str, key: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    for line in lines {
        if line.trim() == "---" {
            break;
        }
        if let Some((candidate, value)) = line.split_once(':') {
            if candidate.trim() == key {
                return Some(value.trim().trim_matches(['"', '\'']).to_string());
            }
        }
    }
    None
}

fn child_directories(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

fn extension_id(path: &Path) -> Option<String> {
    let text = read_limited_text(&path.join("package.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    Some(format!(
        "{}.{}",
        value.get("publisher")?.as_str()?,
        value.get("name")?.as_str()?
    ))
}

fn is_github_copilot_extension(id: &str) -> bool {
    matches!(
        id.to_ascii_lowercase().as_str(),
        "github.copilot" | "github.copilot-chat"
    )
}

fn is_copilot_privacy_rule(rule_id: &str) -> bool {
    matches!(rule_id, "VSC-PRV-002" | "VSC-PRV-003" | "VSC-PRV-004")
}

fn find_named_files(root: &Path, name: &str) -> Vec<PathBuf> {
    find_files(root, &|path| {
        path.file_name().and_then(|value| value.to_str()) == Some(name)
    })
}

fn find_suffix_files(root: &Path, suffix: &str) -> Vec<PathBuf> {
    find_files(root, &|path| {
        path.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.ends_with(suffix))
    })
}

fn find_files(root: &Path, predicate: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DISCOVERY_DEPTH {
            continue;
        }
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push((path, depth + 1));
            } else if metadata.is_file() && predicate(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn source_for(path: &Path, kind: &str, applied: bool, trusted: bool) -> AuditSource {
    AuditSource {
        kind: kind.to_string(),
        path: display_path(path),
        exists: path.exists(),
        applied,
        trusted,
        sha256: None,
        ignored_keys: Vec::new(),
        errors: Vec::new(),
    }
}

fn scan_source_integrity(sources: &[AuditSource], findings: &mut Vec<AuditFinding>) {
    for source in sources.iter().filter(|source| source.exists) {
        let path = Path::new(&source.path);
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            findings.push(make_finding(
                "VSC-CFG-003",
                "configuration_provenance",
                Severity::Medium,
                "high",
                Assessment::Potential,
                "VS Code control-plane file is a symlink",
                "The reviewed path can resolve to content controlled outside the expected configuration boundary.",
                vec![evidence(path, None, Some("<symlink>"))],
                "Review and pin the target or replace the symlink with a controlled regular file.",
                &[SETTINGS_REFERENCE],
                &["OWASP-ASI04"],
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o022 != 0) {
                findings.push(make_finding(
                    "VSC-CFG-004",
                    "configuration_provenance",
                    Severity::High,
                    "high",
                    Assessment::Confirmed,
                    "VS Code control-plane file is group- or world-writable",
                    "Another local principal can alter agent permissions, tools, instructions, or executable hooks.",
                    vec![evidence(path, Some("unix_mode"), Some("group-or-world-writable"))],
                    "Restrict the file to the owning user or an explicitly trusted administrative group.",
                    &[SETTINGS_REFERENCE],
                    &["OWASP-ASI04"],
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn setting_finding(
    rule_id: &str,
    category: &str,
    severity: Severity,
    title: &str,
    description: &str,
    source: &Path,
    key: &str,
    value: &str,
    remediation: &str,
) -> AuditFinding {
    make_finding(
        rule_id,
        category,
        severity,
        "high",
        Assessment::Confirmed,
        title,
        description,
        vec![evidence(source, Some(key), Some(value))],
        remediation,
        &[APPROVALS_REFERENCE],
        &["OWASP-ASI02", "OWASP-ASI03"],
    )
}

#[allow(clippy::too_many_arguments)]
fn mcp_finding(
    rule_id: &str,
    severity: Severity,
    id: &str,
    source: &Path,
    title: &str,
    description: &str,
    key: &str,
    value: &str,
    remediation: &str,
) -> AuditFinding {
    make_finding(
        rule_id,
        "mcp_and_external_tools",
        severity,
        "high",
        Assessment::Confirmed,
        title,
        &format!("MCP server `{id}`: {description}"),
        vec![evidence(
            source,
            Some(&format!("servers.{id}.{key}")),
            Some(value),
        )],
        remediation,
        &[MCP_REFERENCE],
        &["OWASP-MCP1", "OWASP-ASI04"],
    )
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    rule_id: &str,
    category: &str,
    severity: Severity,
    confidence: &str,
    assessment: Assessment,
    title: &str,
    description: &str,
    evidence_items: Vec<Evidence>,
    remediation: &str,
    references: &[&str],
    mappings: &[&str],
) -> AuditFinding {
    let mut hasher = Sha256::new();
    hash_fingerprint_part(&mut hasher, rule_id.as_bytes());
    for evidence in &evidence_items {
        hash_fingerprint_part(&mut hasher, evidence.source.as_bytes());
        hash_fingerprint_part(
            &mut hasher,
            evidence.key.as_deref().unwrap_or_default().as_bytes(),
        );
        hash_fingerprint_part(
            &mut hasher,
            evidence.value.as_deref().unwrap_or_default().as_bytes(),
        );
    }
    AuditFinding {
        fingerprint: format!("sha256:{:x}", hasher.finalize()),
        rule_id: rule_id.to_string(),
        category: category.to_string(),
        severity,
        confidence: confidence.to_string(),
        assessment,
        title: title.to_string(),
        description: description.to_string(),
        evidence: evidence_items,
        remediation: Remediation {
            summary: remediation.to_string(),
            suggested_values: BTreeMap::new(),
        },
        references: references
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        mappings: mappings.iter().map(|value| (*value).to_string()).collect(),
    }
}

fn hash_fingerprint_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn evidence(path: &Path, key: Option<&str>, value: Option<&str>) -> Evidence {
    Evidence {
        source: display_path(path),
        key: key.map(str::to_string),
        value: value.map(|value| {
            if key.is_some_and(|key| key.ends_with("otlpEndpoint")) && url_has_credentials(value) {
                "<redacted-credential-url>".to_string()
            } else {
                value.to_string()
            }
        }),
    }
}

fn summarize(assessment: &str, findings: &[AuditFinding], manual: usize) -> AuditSummary {
    let mut counts: BTreeMap<String, usize> = ["critical", "high", "medium", "low", "info"]
        .into_iter()
        .map(|severity| (severity.to_string(), 0))
        .collect();
    for finding in findings {
        *counts
            .entry(finding.severity.as_str().to_string())
            .or_default() += 1;
    }
    AuditSummary {
        assessment: assessment.to_string(),
        max_severity: findings
            .iter()
            .map(|finding| finding.severity)
            .max_by_key(|severity| severity.rank()),
        counts,
        manual_checks: manual,
    }
}

fn sort_findings(findings: &mut [AuditFinding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
}

fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_limited_text(path: &Path) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds the audit size limit", path.display()),
        ));
    }
    fs::read_to_string(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "gensee-vscode-config-audit-{}-{name}",
            std::process::id()
        ))
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn parses_jsonc_comments_and_trailing_commas() {
        let value = parse_jsonc("{ // comment\n \"enabled\": true, }").unwrap();
        assert_eq!(value["enabled"], true);
    }

    #[test]
    fn reports_unsandboxed_global_autoapproval() {
        let root = temp_root("autonomy");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &user_data.join("settings.json"),
            r#"{
                "chat.tools.global.autoApprove": true,
                "chat.agent.sandbox.enabled": "off"
            }"#,
        );

        let report = audit_vscode_host(&VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        })
        .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-AUT-003"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn inventories_mcp_without_executing_it() {
        let root = temp_root("mcp");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &workspace.join(".vscode/mcp.json"),
            r#"{"servers":{"demo":{"type":"stdio","command":"npx","args":["-y","demo-server"]}}}"#,
        );

        let report = audit_vscode_host(&VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        })
        .unwrap();

        assert_eq!(report.inventory.mcp_servers.len(), 1);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-MCP-007"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn redacts_mcp_secrets_from_findings_and_json() {
        let root = temp_root("mcp-secret-redaction");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        let secret = "Bearer audit-test-secret-value-123456";
        let endpoint_secret = "audit-endpoint-secret-987654";
        write(
            &workspace.join(".vscode/mcp.json"),
            &format!(
                r#"{{"servers":{{"demo":{{"type":"http","url":"https://example.test/mcp?token={endpoint_secret}","headers":{{"Authorization":"{secret}"}}}}}}}}"#
            ),
        );

        let report = audit_vscode_host(&VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        })
        .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-MCP-009"));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains(endpoint_secret));
        assert!(serialized.contains("<redacted>"));
        assert!(serialized.contains("<redacted-credential-url>"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn github_copilot_extension_detection_is_explicit() {
        let root = temp_root("github-copilot-extension");
        let _ = fs::remove_dir_all(&root);
        let extension = root.join("extensions/github.copilot-chat-1.2.3");
        write(
            &extension.join("package.json"),
            r#"{"publisher":"GitHub","name":"copilot-chat","version":"1.2.3"}"#,
        );
        let options = VscodeAuditOptions {
            workspace: root.join("repo"),
            user_data: root.join("User"),
            profile: None,
            extension_roots: vec![root.join("extensions")],
        };
        assert_eq!(
            options.github_copilot_extension_applicability().0,
            AuditApplicability::Applicable
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn separates_copilot_privacy_from_vscode_host_findings() {
        let root = temp_root("copilot-scope");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        write(
            &user_data.join("settings.json"),
            r#"{
                "chat.tools.global.autoApprove": true,
                "github.copilot.chat.otel.captureContent": true
            }"#,
        );
        let options = VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        };

        let host = audit_vscode_host(&options).unwrap();
        let copilot = audit_github_copilot_vscode(&options).unwrap();

        assert!(host
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-AUT-001"));
        assert!(!host
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-PRV-002"));
        assert!(copilot
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-PRV-002"));
        assert!(copilot
            .findings
            .iter()
            .all(|finding| is_copilot_privacy_rule(&finding.rule_id)));
        assert_eq!(copilot.target.provider, "github-copilot");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn redacts_copilot_telemetry_endpoint_credentials() {
        let root = temp_root("copilot-otel-redaction");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        let secret = "review-secret-value-123456";
        write(
            &user_data.join("settings.json"),
            &format!(
                r#"{{"github.copilot.chat.otel.otlpEndpoint":"http://collector.example.test/v1/traces?token={secret}"}}"#
            ),
        );

        let report = audit_github_copilot_vscode(&VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        })
        .unwrap();
        let serialized = serde_json::to_string(&report).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "VSC-PRV-003"));
        assert!(!serialized.contains(secret));
        assert!(serialized.contains("<redacted-credential-url>"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovered_control_plane_read_and_parse_errors_are_reported() {
        let root = temp_root("discovery-errors");
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("repo");
        let user_data = root.join("User");
        fs::create_dir_all(&workspace).unwrap();
        let skill_path = workspace.join(".github/skills/oversized/SKILL.md");
        if let Some(parent) = skill_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&skill_path, vec![b'x'; MAX_TEXT_FILE_BYTES as usize + 1]).unwrap();
        let hook_path = workspace.join(".github/hooks/invalid.json");
        write(&hook_path, "{ invalid json");

        let report = audit_vscode_host(&VscodeAuditOptions {
            workspace,
            user_data,
            profile: None,
            extension_roots: Vec::new(),
        })
        .unwrap();

        let skill_source = report
            .sources
            .iter()
            .find(|source| source.path == display_path(&skill_path))
            .unwrap();
        assert!(skill_source.sha256.is_none());
        assert!(!skill_source.errors.is_empty());
        let hook_source = report
            .sources
            .iter()
            .find(|source| source.path == display_path(&hook_path))
            .unwrap();
        assert!(hook_source.sha256.is_some());
        assert!(!hook_source.errors.is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
