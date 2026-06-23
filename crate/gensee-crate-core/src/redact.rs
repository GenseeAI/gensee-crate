//! Secret redaction for captured telemetry.
//!
//! Telemetry can carry credentials in three shapes: `KEY=value` assignments,
//! JSON fields with secret-looking names, and bare tokens recognizable by their
//! prefix. We redact all three. Redaction is intentionally fail-safe: when a
//! name or token looks remotely secret we drop the value rather than risk
//! persisting a credential. Over-redaction is acceptable; leaking is not.

use serde_json::Value;

/// Substrings (matched case-insensitively) that mark an assignment key or JSON
/// field name as secret-bearing.
const SECRET_NAME_MARKERS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "passphrase",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "credential",
    "token",
    "client_secret",
    "auth_token",
    "session_token",
    "refresh_token",
    "bearer",
];

/// Prefixes that identify a bare secret token regardless of surrounding name.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xoxe-",
    "ya29.",
    "AIza",
    "AKIA",
    "ASIA",
    "eyJ",
];

const REDACTED: &str = "<redacted>";

/// Returns true if a key or field name looks like it holds a secret.
pub fn name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_NAME_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Redact secrets from free text: `KEY=value` assignments, bare tokens, and
/// PEM private-key blocks.
pub fn redact_text(input: &str) -> String {
    let stage = redact_private_key_blocks(input);
    let stage = redact_secret_assignments(&stage);
    redact_known_tokens(&stage)
}

/// Recursively redact a parsed JSON value in place: values under secret-named
/// keys are dropped entirely, and every remaining string leaf is run through
/// [`redact_text`].
pub fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if name_is_secret(key) {
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact_value(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item);
            }
        }
        Value::String(text) => {
            *text = redact_text(text);
        }
        _ => {}
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_value_terminator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '`'
        )
}

/// Replace the value of any `KEY=value` whose key name looks secret.
fn redact_secret_assignments(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        let start = i;
        while i < chars.len() && is_ident_char(chars[i]) {
            i += 1;
        }

        if i > start && i < chars.len() && chars[i] == '=' {
            let key: String = chars[start..i].iter().collect();
            out.push_str(&key);
            out.push('=');
            i += 1; // consume '='

            if name_is_secret(key.trim_start_matches('-')) {
                out.push_str(REDACTED);
                while i < chars.len() && !is_value_terminator(chars[i]) {
                    i += 1;
                }
            }
            continue;
        }

        // Not an assignment: emit the identifier run and the next char as-is.
        for c in &chars[start..i] {
            out.push(*c);
        }
        if i < chars.len() {
            out.push(chars[i]);
            i += 1;
        }
    }

    out
}

/// Replace bare tokens recognizable by a known prefix.
fn redact_known_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut word = String::new();

    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            if is_secret_token(word) {
                out.push_str(REDACTED);
            } else {
                out.push_str(word);
            }
            word.clear();
        }
    };

    for c in input.chars() {
        if is_value_terminator(c) || c == '=' {
            flush(&mut word, &mut out);
            out.push(c);
        } else {
            word.push(c);
        }
    }
    flush(&mut word, &mut out);

    out
}

fn is_secret_token(word: &str) -> bool {
    TOKEN_PREFIXES
        .iter()
        .any(|prefix| word.starts_with(prefix) && word.len() >= prefix.len() + 8)
}

/// Redact PEM-style `-----BEGIN ... PRIVATE KEY----- ... -----END ...-----`
/// blocks, including the common `\n`-escaped single-line form.
fn redact_private_key_blocks(input: &str) -> String {
    if !input.contains("PRIVATE KEY") {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(begin) = remaining.find("-----BEGIN") {
        // Only treat it as a key block if PRIVATE KEY follows the BEGIN marker.
        let after_begin = &remaining[begin..];
        if !after_begin.starts_with("-----BEGIN")
            || !after_begin
                .get(
                    ..after_begin
                        .find("-----\n")
                        .map(|n| n + 5)
                        .unwrap_or(after_begin.len()),
                )
                .map(|h| h.contains("PRIVATE KEY"))
                .unwrap_or(false)
        {
            // Fallback: redact from BEGIN to the next END marker if present.
        }

        out.push_str(&remaining[..begin]);

        let tail = &remaining[begin..];
        let end_marker = "-----END";
        if let Some(end) = tail.find(end_marker) {
            // advance to the closing "-----" after the END marker
            let after_end = &tail[end + end_marker.len()..];
            let close = after_end
                .find("-----")
                .map(|n| n + 5)
                .unwrap_or(after_end.len());
            out.push_str(REDACTED);
            remaining = &after_end[close..];
        } else {
            out.push_str(REDACTED);
            remaining = "";
            break;
        }
    }

    out.push_str(remaining);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_assignment_for_any_secret_named_key() {
        assert_eq!(
            redact_text("NPM_TOKEN=npm_abc123 STRIPE_SECRET_KEY=sk_live_xyz PATH=/bin"),
            "NPM_TOKEN=<redacted> STRIPE_SECRET_KEY=<redacted> PATH=/bin"
        );
        assert_eq!(
            redact_text("--password=hunter2 --verbose"),
            "--password=<redacted> --verbose"
        );
    }

    #[test]
    fn keeps_non_secret_assignments() {
        assert_eq!(
            redact_text("HOME=/Users/x COUNT=3"),
            "HOME=/Users/x COUNT=3"
        );
        assert_eq!(
            redact_text("https://example.com?a=b"),
            "https://example.com?a=b"
        );
    }

    #[test]
    fn redacts_bare_tokens_by_prefix() {
        assert_eq!(
            redact_text("auth ghp_0123456789abcdef done"),
            "auth <redacted> done"
        );
        assert_eq!(
            redact_text("aws key AKIAIOSFODNN7EXAMPLE here"),
            "aws key <redacted> here"
        );
        // too short / not a token: left alone
        assert_eq!(redact_text("sk-"), "sk-");
    }

    #[test]
    fn redacts_secret_named_json_fields_and_string_leaves() {
        let mut value: Value = serde_json::from_str(
            r#"{"api_key":"sk-secret-value-123","note":"GITHUB_TOKEN=ghp_aaaaaaaaaaaa ok","count":3}"#,
        )
        .unwrap();
        redact_value(&mut value);
        let out = serde_json::to_string(&value).unwrap();
        assert!(out.contains(r#""api_key":"<redacted>""#));
        assert!(out.contains("GITHUB_TOKEN=<redacted>"));
        assert!(!out.contains("ghp_aaaaaaaaaaaa"));
        assert!(out.contains(r#""count":3"#));
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let pem = "before -----BEGIN OPENSSH PRIVATE KEY-----\\nAAAA\\n-----END OPENSSH PRIVATE KEY----- after";
        let out = redact_text(pem);
        assert!(out.contains("before "));
        assert!(out.contains(" after"));
        assert!(!out.contains("AAAA"));
        assert!(out.contains(REDACTED));
    }
}
