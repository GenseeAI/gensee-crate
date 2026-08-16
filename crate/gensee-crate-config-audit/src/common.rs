use crate::model::{
    Assessment, AuditFinding, AuditSource, AuditSummary, Evidence, Remediation, Severity,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use url::{Host, Url};

pub(crate) const MAX_TEXT_FILE_BYTES: u64 = 256 * 1024;

pub(crate) fn canonical_or_original(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn read_limited_text(path: &Path) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} exceeds the {} byte audit limit",
                path.display(),
                MAX_TEXT_FILE_BYTES
            ),
        ));
    }
    fs::read_to_string(path)
}

pub(crate) fn source_for(path: &Path, kind: &str, applied: bool, trusted: bool) -> AuditSource {
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_finding(
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
    let fingerprint = finding_fingerprint(rule_id, &evidence_items);
    AuditFinding {
        fingerprint,
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

pub(crate) fn finding_fingerprint(rule_id: &str, evidence_items: &[Evidence]) -> String {
    let mut hasher = Sha256::new();
    hash_fingerprint_part(&mut hasher, rule_id.as_bytes());
    for evidence in evidence_items {
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
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_fingerprint_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

pub(crate) fn summarize(
    assessment: &str,
    findings: &[AuditFinding],
    manual: usize,
) -> AuditSummary {
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

pub(crate) fn sort_findings(findings: &mut [AuditFinding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
}

pub(crate) fn normalize_secret_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub(crate) fn secret_key_name(key: &str) -> bool {
    [
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "accesskey",
        "authorization",
        "privatekey",
        "credential",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

pub(crate) fn insecure_remote_http(value: &str) -> bool {
    Url::parse(value).map_or_else(
        |_| value.to_ascii_lowercase().starts_with("http://"),
        |url| url.scheme() == "http" && !url_host_is_loopback(&url),
    )
}

/// Returns `true` only when a parsed endpoint proves that it embeds
/// credentials. An unparseable endpoint is not evidence of credentials.
pub(crate) fn endpoint_has_credentials(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| parsed_url_has_credentials(&url))
}

/// Returns `true` when an endpoint contains URL credentials or cannot be
/// parsed safely enough to prove that it does not. Use this for serialization
/// only: redaction fails closed, while findings use `endpoint_has_credentials`
/// so malformed input is not reported as confirmed credential exposure.
pub(crate) fn endpoint_must_be_redacted(value: &str) -> bool {
    Url::parse(value).map_or(true, |url| parsed_url_has_credentials(&url))
}

pub(crate) fn endpoint_is_parseable(value: &str) -> bool {
    Url::parse(value).is_ok()
}

/// Returns a report-safe endpoint value. Confirmed credentials receive a
/// credential-specific label; malformed endpoints fail closed with a neutral
/// label because their credential posture could not be established.
pub(crate) fn endpoint_display_value(value: &str) -> String {
    if endpoint_has_credentials(value) {
        "<redacted-credential-url>".to_string()
    } else if endpoint_must_be_redacted(value) {
        "<redacted-url>".to_string()
    } else {
        value.to_string()
    }
}

fn parsed_url_has_credentials(url: &Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some()
        || url
            .query_pairs()
            .any(|(key, _)| secret_key_name(&normalize_secret_key(&key)))
}

pub(crate) fn is_loopback_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| url_host_is_loopback(&url))
}

fn url_host_is_loopback(url: &Url) -> bool {
    url.host().is_some_and(|host| match host {
        Host::Domain(domain) => domain
            .trim_end_matches('.')
            .eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    })
}

pub(crate) fn collect_json_commands(value: &Value, commands: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "command" | "commandWindows" | "command_windows"
                ) {
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

pub(crate) fn looks_like_path(value: &str) -> bool {
    if value.starts_with('@') && value.contains('/') {
        return false;
    }
    value.starts_with('.')
        || value.starts_with('/')
        || value.starts_with('~')
        || value.contains('/')
        || value.contains('\\')
        || value.chars().nth(1) == Some(':')
}

pub(crate) fn executable_dependency_is_unpinned(command: &str, args: &[&str]) -> bool {
    let launcher = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    if !matches!(
        launcher.as_str(),
        "npx" | "npm" | "pnpm" | "pnpx" | "yarn" | "bunx" | "uvx" | "pipx"
    ) {
        return false;
    }

    let positional = args
        .iter()
        .copied()
        .filter(|argument| !argument.starts_with('-'))
        .filter(|argument| !matches!(*argument, "y" | "yes"))
        .collect::<Vec<_>>();
    let package = match launcher.as_str() {
        "npx" | "pnpx" | "bunx" | "uvx" | "pipx" => positional.first().copied(),
        "npm" | "pnpm" | "yarn" => positional
            .first()
            .copied()
            .filter(|subcommand| matches!(*subcommand, "exec" | "dlx" | "x"))
            .and_then(|_| positional.get(1))
            .copied(),
        _ => None,
    };

    package.is_some_and(|package| {
        if looks_like_path(package) {
            return false;
        }
        let versioned_name = package
            .strip_prefix('@')
            .and_then(|scoped| scoped.split_once('/'))
            .map(|(_, name)| name)
            .unwrap_or(package);
        !versioned_name.contains('@')
            || versioned_name.ends_with("@latest")
            || versioned_name.ends_with("@next")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_launcher_checks_only_the_package_position() {
        assert!(!executable_dependency_is_unpinned(
            "npx",
            &["-y", "@scope/server@1.2.3", "--root", "data"]
        ));
        assert!(executable_dependency_is_unpinned(
            "npx",
            &["-y", "@scope/server"]
        ));
        assert!(!executable_dependency_is_unpinned("npm", &["run", "build"]));
        assert!(executable_dependency_is_unpinned(
            "npm",
            &["exec", "demo-server"]
        ));
        assert!(!executable_dependency_is_unpinned(
            "pnpm",
            &["dlx", "demo-server@1.2.3", "/tmp/workspace"]
        ));
    }

    #[test]
    fn path_detection_is_platform_independent() {
        for path in [
            "./server",
            "/opt/server",
            "~/server",
            "tools/server",
            r"tools\server",
            r"C:\\tools\\server",
        ] {
            assert!(
                looks_like_path(path),
                "{path} should be recognized as a path"
            );
        }
        assert!(!looks_like_path("@scope/server@1.2.3"));
        assert!(!looks_like_path("demo-server"));
    }

    #[test]
    fn endpoint_redaction_fails_closed_without_claiming_unparseable_values_have_credentials() {
        for endpoint in [
            "//admin:do-not-leak@example.com/mcp",
            "example.com/mcp?token=do-not-leak",
            ":://admin:do-not-leak@example.com",
        ] {
            assert!(endpoint_must_be_redacted(endpoint), "{endpoint}");
            assert!(!endpoint_has_credentials(endpoint), "{endpoint}");
        }
        for endpoint in [
            "https://admin:do-not-leak@example.com/mcp",
            "https://example.com/mcp?access_token=do-not-leak",
        ] {
            assert!(endpoint_must_be_redacted(endpoint), "{endpoint}");
            assert!(endpoint_has_credentials(endpoint), "{endpoint}");
        }
        assert!(!endpoint_must_be_redacted("https://example.com/mcp"));
        assert!(!endpoint_has_credentials("https://example.com/mcp"));
        assert!(endpoint_is_parseable("https://example.com/mcp"));
        assert!(!endpoint_is_parseable("example.com/mcp"));
        assert_eq!(
            endpoint_display_value("https://user:secret@example.com/mcp"),
            "<redacted-credential-url>"
        );
        assert_eq!(endpoint_display_value("example.com/mcp"), "<redacted-url>");
        assert_eq!(
            endpoint_display_value("https://example.com/mcp"),
            "https://example.com/mcp"
        );
    }

    #[test]
    fn loopback_urls_require_an_exact_loopback_host() {
        assert!(is_loopback_url("http://localhost:3000/mcp"));
        assert!(is_loopback_url("http://127.0.0.2:3000/mcp"));
        assert!(is_loopback_url("http://[::1]:3000/mcp"));
        assert!(!is_loopback_url("http://localhost.evil.example/mcp"));
    }
}
