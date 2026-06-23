use std::collections::HashSet;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpFileIntent {
    pub operation: String,
    pub path: String,
}

pub fn parse_mcp_file_intents(tool_name: &str, input: &Value) -> Vec<McpFileIntent> {
    if !is_mcp_tool(tool_name) {
        return Vec::new();
    }

    let method = mcp_method(tool_name);
    let mut intents = Vec::new();
    collect_mcp_file_intents(input, None, method, &mut intents);
    dedupe_mcp_file_intents(intents)
}

fn is_mcp_tool(tool_name: &str) -> bool {
    tool_name.starts_with("mcp__")
}

fn mcp_method(tool_name: &str) -> &str {
    tool_name.rsplit("__").next().unwrap_or(tool_name)
}

fn collect_mcp_file_intents(
    value: &Value,
    key: Option<&str>,
    method: &str,
    intents: &mut Vec<McpFileIntent>,
) {
    match value {
        Value::String(text) => {
            if let Some(key) = key {
                push_mcp_file_intent(intents, key, method, text);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_mcp_file_intents(item, key, method, intents);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                collect_mcp_file_intents(value, Some(key), method, intents);
            }
        }
        _ => {}
    }
}

fn push_mcp_file_intent(intents: &mut Vec<McpFileIntent>, key: &str, method: &str, value: &str) {
    let Some(path) = mcp_path_value(key, value) else {
        return;
    };
    intents.push(McpFileIntent {
        operation: mcp_operation_for_key_method(key, method).to_string(),
        path,
    });
}

fn mcp_path_value(key: &str, value: &str) -> Option<String> {
    if value.trim().is_empty() || text_has_network_scheme(value) {
        return None;
    }

    let lower = key.to_ascii_lowercase();
    let looks_path_key = matches!(
        lower.as_str(),
        "file"
            | "files"
            | "filename"
            | "filenames"
            | "filepath"
            | "filepaths"
            | "file_path"
            | "file_paths"
            | "path"
            | "paths"
            | "source_path"
            | "source_paths"
            | "src_path"
            | "destination"
            | "dest"
            | "destination_path"
            | "dest_path"
            | "target_path"
            | "output_path"
            | "input_path"
            | "notebook_path"
    ) || lower.ends_with("_path")
        || lower.ends_with("_paths");

    if !looks_path_key {
        return None;
    }

    let path = value.strip_prefix("file://").unwrap_or(value).trim();
    (!path.is_empty()).then(|| path.to_string())
}

fn text_has_network_scheme(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
}

fn mcp_operation_for_key_method(key: &str, method: &str) -> &'static str {
    let key = key.to_ascii_lowercase();
    let method = method.to_ascii_lowercase();
    if key.contains("source") || key == "src_path" || key.starts_with("input") {
        return "read";
    }
    if key.contains("dest")
        || key.contains("target")
        || key.starts_with("output")
        || method_contains_any(
            &method,
            &["write", "create", "put", "save", "upload", "append"],
        )
    {
        return "write";
    }
    if method_contains_any(&method, &["delete", "remove", "unlink", "rmdir", "rmtree"]) {
        return "delete";
    }
    if method_contains_any(&method, &["edit", "update", "patch", "rename", "move"]) {
        return "edit";
    }
    "read"
}

fn method_contains_any(method: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| method.contains(needle))
}

fn dedupe_mcp_file_intents(intents: Vec<McpFileIntent>) -> Vec<McpFileIntent> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for intent in intents {
        if seen.insert((intent.operation.clone(), intent.path.clone())) {
            deduped.push(intent);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_common_mcp_file_shapes() {
        let input = serde_json::json!({
            "path": "notes.md",
            "source_path": "old.md",
            "destination_path": "new.md",
            "nested": { "file_paths": ["a.txt", "b.txt"] },
            "url": "https://example.com/data",
            "content": "mentions /etc/passwd but is not a path field"
        });

        let intents = parse_mcp_file_intents("mcp__filesystem__write_file", &input);

        for expected in [
            ("write", "notes.md"),
            ("read", "old.md"),
            ("write", "new.md"),
            ("write", "a.txt"),
            ("write", "b.txt"),
        ] {
            assert!(
                intents
                    .iter()
                    .any(|intent| intent.operation == expected.0 && intent.path == expected.1),
                "missing {expected:?} in {intents:?}"
            );
        }
        assert_eq!(intents.len(), 5);
    }

    #[test]
    fn ignores_non_mcp_tools_and_network_urls() {
        assert!(parse_mcp_file_intents("Read", &serde_json::json!({"path": "a.txt"})).is_empty());
        assert!(parse_mcp_file_intents(
            "mcp__web__fetch",
            &serde_json::json!({"url": "https://example.com"})
        )
        .is_empty());
    }
}
