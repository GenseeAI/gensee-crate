use crate::model::{
    Assessment, AuditFinding, AuditSource, AuditSummary, Evidence, Remediation, Severity,
};
use percent_encoding::percent_decode_str;
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

pub(crate) fn secret_literal(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && !runtime_secret_reference(trimmed) && trimmed.len() >= 8
}

pub(crate) fn insecure_remote_http(value: &str) -> bool {
    Url::parse(value).map_or_else(
        |_| value.to_ascii_lowercase().starts_with("http://"),
        |url| url.scheme() == "http" && !url_host_is_loopback(&url),
    )
}

/// Returns `true` only when an endpoint proves that it embeds credentials.
/// Scheme-less HTTP endpoints get one conservative HTTPS recovery attempt so
/// credential-bearing authority and query components are still detectable.
pub(crate) fn endpoint_has_credentials(value: &str) -> bool {
    parse_endpoint_for_credential_detection(value)
        .is_some_and(|url| parsed_url_has_credentials(&url))
}

/// Returns `true` when an endpoint contains URL credentials or cannot be
/// parsed safely enough to prove that it does not. Use this for serialization
/// only: redaction fails closed, while findings use `endpoint_has_credentials`
/// so malformed input is not reported as confirmed credential exposure.
pub(crate) fn endpoint_must_be_redacted(value: &str) -> bool {
    endpoint_has_credentials(value) || !endpoint_is_parseable(value)
}

pub(crate) fn endpoint_is_parseable(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| url.host().is_some())
}

/// Returns a report-safe endpoint value. Confirmed credentials receive a
/// credential-specific label; malformed endpoints fail closed with a neutral
/// label because their credential posture could not be established.
pub(crate) fn endpoint_display_value(value: &str) -> String {
    if matches!(value, "<redacted-credential-url>" | "<redacted-url>") {
        return value.to_string();
    }
    if endpoint_has_credentials(value) {
        "<redacted-credential-url>".to_string()
    } else if endpoint_must_be_redacted(value) {
        "<redacted-url>".to_string()
    } else {
        value.to_string()
    }
}

fn parsed_url_has_credentials(url: &Url) -> bool {
    url_userinfo_has_literal_credentials(url)
        || url.query_pairs().any(|(key, value)| {
            secret_key_name(&normalize_secret_key(&key)) && secret_value_is_literal(&value)
        })
}

fn url_userinfo_has_literal_credentials(url: &Url) -> bool {
    let Some(password) = url.password() else {
        return false;
    };
    let encoded = format!("{}:{password}", url.username());
    let Some((separator, separator_length)) = userinfo_password_separator(&encoded) else {
        return false;
    };
    secret_value_is_literal(
        &percent_decode_str(&encoded[separator + separator_length..]).decode_utf8_lossy(),
    )
}

fn userinfo_password_separator(encoded: &str) -> Option<(usize, usize)> {
    let mut index = 0;
    let mut inside_runtime_reference = false;
    let mut closed_runtime_reference = false;
    while index < encoded.len() {
        let tail = &encoded[index..];
        if !inside_runtime_reference {
            let marker_length = if tail.starts_with("${") {
                Some(2)
            } else if tail
                .get(..4)
                .is_some_and(|marker| marker.eq_ignore_ascii_case("$%7b"))
            {
                Some(4)
            } else if tail
                .get(..6)
                .is_some_and(|marker| marker.eq_ignore_ascii_case("%24%7b"))
            {
                Some(6)
            } else {
                None
            };
            if let Some(marker_length) = marker_length {
                inside_runtime_reference = true;
                closed_runtime_reference = false;
                index += marker_length;
                continue;
            }
            if tail.starts_with(':') {
                return Some((index, 1));
            }
            if closed_runtime_reference
                && tail
                    .get(..3)
                    .is_some_and(|marker| marker.eq_ignore_ascii_case("%3a"))
            {
                // `url` treats the colon inside `${input:name}` as the URL's
                // separator, then percent-encodes a real separator following
                // the placeholder as part of the parsed password.
                return Some((index, 3));
            }
        } else if tail.starts_with('}') {
            inside_runtime_reference = false;
            closed_runtime_reference = true;
            index += 1;
            continue;
        } else if tail
            .get(..3)
            .is_some_and(|marker| marker.eq_ignore_ascii_case("%7d"))
        {
            inside_runtime_reference = false;
            closed_runtime_reference = true;
            index += 3;
            continue;
        }
        index += 1;
    }
    None
}

fn parse_endpoint_for_credential_detection(value: &str) -> Option<Url> {
    let parsed = Url::parse(value).ok();
    if parsed.as_ref().is_some_and(|url| url.host().is_some()) {
        return parsed;
    }

    let value = value.trim();
    if value.is_empty() || (parsed.is_none() && has_explicit_url_scheme(value)) {
        return None;
    }

    let authority = value.trim_start_matches('/');
    if authority.is_empty() {
        return None;
    }
    Url::parse(&format!("https://{authority}"))
        .ok()
        .filter(|url| url.host().is_some())
}

fn secret_value_is_literal(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && !runtime_secret_reference(trimmed)
}

fn runtime_secret_reference(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.contains("${")
        || trimmed
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("env:"))
        || trimmed
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("input:"))
}

fn has_explicit_url_scheme(value: &str) -> bool {
    let Some(separator) = value.find(':') else {
        return false;
    };
    let scheme = &value[..separator];
    scheme
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && scheme.chars().skip(1).all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
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
    fn endpoint_redaction_recovers_scheme_less_credentials_and_fails_closed() {
        for endpoint in [
            "//admin:do-not-leak@example.com/mcp",
            "admin:do-not-leak@internal.example/mcp",
            "example.com/mcp?token=do-not-leak",
        ] {
            assert!(endpoint_must_be_redacted(endpoint), "{endpoint}");
            assert!(endpoint_has_credentials(endpoint), "{endpoint}");
            assert!(!endpoint_is_parseable(endpoint), "{endpoint}");
            assert_eq!(
                endpoint_display_value(endpoint),
                "<redacted-credential-url>"
            );
        }
        let malformed = ":://admin:do-not-leak@example.com";
        assert!(endpoint_must_be_redacted(malformed));
        assert!(!endpoint_has_credentials(malformed));
        assert!(!endpoint_is_parseable(malformed));
        assert_eq!(endpoint_display_value(malformed), "<redacted-url>");
        assert_eq!(
            endpoint_display_value("<redacted-credential-url>"),
            "<redacted-credential-url>"
        );
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
    fn endpoint_credentials_ignore_runtime_secret_references() {
        for endpoint in [
            "https://example.com/mcp?token=${input:api-key}",
            "https://${input:user}@example.com/mcp",
            "https://example.com/mcp?api_key=env:MCP_API_KEY",
        ] {
            assert!(endpoint_is_parseable(endpoint), "{endpoint}");
            assert!(!endpoint_has_credentials(endpoint), "{endpoint}");
            assert!(!endpoint_must_be_redacted(endpoint), "{endpoint}");
            assert_eq!(endpoint_display_value(endpoint), endpoint);
        }
    }

    #[test]
    fn endpoint_credentials_evaluate_password_separately_from_username() {
        let literal_password = "https://${input:user}:do-not-leak@example.com/mcp";
        assert!(endpoint_has_credentials(literal_password));
        assert!(endpoint_must_be_redacted(literal_password));
        assert_eq!(
            endpoint_display_value(literal_password),
            "<redacted-credential-url>"
        );

        for endpoint in [
            "https://admin:${input:token}@example.com/mcp",
            "https://admin@example.com/mcp",
        ] {
            assert!(endpoint_is_parseable(endpoint), "{endpoint}");
            assert!(!endpoint_has_credentials(endpoint), "{endpoint}");
            assert!(!endpoint_must_be_redacted(endpoint), "{endpoint}");
            assert_eq!(endpoint_display_value(endpoint), endpoint);
        }
    }

    #[test]
    fn loopback_urls_require_an_exact_loopback_host() {
        assert!(is_loopback_url("http://localhost:3000/mcp"));
        assert!(is_loopback_url("http://127.0.0.2:3000/mcp"));
        assert!(is_loopback_url("http://[::1]:3000/mcp"));
        assert!(!is_loopback_url("http://localhost.evil.example/mcp"));
    }
}
