use std::collections::HashSet;

use serde_json::Value;

const APPLY_PATCH_INPUT_KEYS: &[&str] = &[
    "command", "cmd", "patch", "input", "content", "text", "diff",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPatchChange {
    pub operation: String,
    pub path: String,
}

pub fn extract_apply_patch_input(input: &Value) -> Option<&str> {
    if let Some(text) = input.as_str() {
        return Some(text);
    }

    if let Some(text) = APPLY_PATCH_INPUT_KEYS
        .iter()
        .find_map(|key| input.get(*key).and_then(Value::as_str))
    {
        return Some(text);
    }

    find_patch_like_string(input)
}

pub fn parse_apply_patch_changes(input: &str) -> Vec<ApplyPatchChange> {
    let mut changes = Vec::new();
    let mut seen = HashSet::new();
    let mut pending_update: Option<(String, Option<String>)> = None;

    for line in input.lines().map(str::trim_end) {
        if let Some(path) = line.strip_prefix("*** Add File: ") {
            flush_update(&mut pending_update, &mut changes, &mut seen);
            push_change(&mut changes, &mut seen, "create", path);
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            flush_update(&mut pending_update, &mut changes, &mut seen);
            push_change(&mut changes, &mut seen, "delete", path);
        } else if let Some(path) = line.strip_prefix("*** Update File: ") {
            flush_update(&mut pending_update, &mut changes, &mut seen);
            pending_update = normalized_path(path).map(|path| (path, None));
        } else if let Some(path) = line.strip_prefix("*** Move to: ") {
            if let Some((_, move_to)) = pending_update.as_mut() {
                *move_to = normalized_path(path);
            }
        } else if line == "*** End Patch" {
            flush_update(&mut pending_update, &mut changes, &mut seen);
        }
    }

    flush_update(&mut pending_update, &mut changes, &mut seen);
    changes
}

fn find_patch_like_string(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) if looks_like_apply_patch(text) => Some(text),
        Value::Array(items) => items.iter().find_map(find_patch_like_string),
        Value::Object(map) => map.values().find_map(find_patch_like_string),
        _ => None,
    }
}

fn looks_like_apply_patch(text: &str) -> bool {
    text.contains("*** Begin Patch")
        || text.contains("*** Add File: ")
        || text.contains("*** Update File: ")
        || text.contains("*** Delete File: ")
}

fn flush_update(
    pending_update: &mut Option<(String, Option<String>)>,
    changes: &mut Vec<ApplyPatchChange>,
    seen: &mut HashSet<(String, String)>,
) {
    let Some((path, move_to)) = pending_update.take() else {
        return;
    };
    if let Some(move_to) = move_to {
        push_change(changes, seen, "delete", &path);
        push_change(changes, seen, "create", &move_to);
    } else {
        push_change(changes, seen, "edit", &path);
    }
}

fn push_change(
    changes: &mut Vec<ApplyPatchChange>,
    seen: &mut HashSet<(String, String)>,
    operation: &str,
    path: &str,
) {
    let Some(path) = normalized_path(path) else {
        return;
    };
    let operation = operation.to_string();
    if seen.insert((operation.clone(), path.clone())) {
        changes.push(ApplyPatchChange { operation, path });
    }
}

fn normalized_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apply_patch_add_update_delete_and_move() {
        let patch = r#"apply_patch <<'PATCH'
*** Begin Patch
*** Add File: src/new.rs
+fn new() {}
*** Update File: src/lib.rs
@@
-old
+new
*** Delete File: src/old.rs
*** Update File: src/from.rs
*** Move to: src/to.rs
@@
-a
+b
*** End Patch
PATCH"#;

        assert_eq!(
            parse_apply_patch_changes(patch),
            vec![
                ApplyPatchChange {
                    operation: "create".to_string(),
                    path: "src/new.rs".to_string(),
                },
                ApplyPatchChange {
                    operation: "edit".to_string(),
                    path: "src/lib.rs".to_string(),
                },
                ApplyPatchChange {
                    operation: "delete".to_string(),
                    path: "src/old.rs".to_string(),
                },
                ApplyPatchChange {
                    operation: "delete".to_string(),
                    path: "src/from.rs".to_string(),
                },
                ApplyPatchChange {
                    operation: "create".to_string(),
                    path: "src/to.rs".to_string(),
                },
            ]
        );
    }

    #[test]
    fn ignores_duplicate_patch_paths() {
        let patch = r#"*** Begin Patch
*** Update File: src/lib.rs
@@
*** Update File: src/lib.rs
@@
*** End Patch"#;

        assert_eq!(
            parse_apply_patch_changes(patch),
            vec![ApplyPatchChange {
                operation: "edit".to_string(),
                path: "src/lib.rs".to_string(),
            }]
        );
    }

    #[test]
    fn extracts_patch_from_common_tool_input_shapes() {
        let patch = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n*** End Patch";
        for input in [
            serde_json::json!(patch),
            serde_json::json!({ "command": patch }),
            serde_json::json!({ "patch": patch }),
            serde_json::json!({ "arguments": { "payload": patch } }),
        ] {
            assert_eq!(extract_apply_patch_input(&input), Some(patch));
        }
    }
}
