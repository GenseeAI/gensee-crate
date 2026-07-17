use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VscodeFileIntent {
    pub operation: String,
    pub path: String,
}

pub fn is_vscode_file_tool_name(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "editFiles"
            | "edit_files"
            | "createFile"
            | "create_file"
            | "replaceStringInFile"
            | "replace_string_in_file"
            | "insertEditIntoFile"
            | "insert_edit_into_file"
            | "readFile"
            | "read_file"
            | "deleteFile"
            | "delete_file"
    )
}

pub fn parse_vscode_file_intents(tool_name: &str, input: &Value) -> Vec<VscodeFileIntent> {
    if matches!(tool_name, "editFiles" | "edit_files") {
        return input
            .get("files")
            .and_then(Value::as_array)
            .map(|files| {
                files
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|path| VscodeFileIntent {
                        operation: "edit".to_string(),
                        path: path.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();
    }

    let operation = match tool_name {
        "createFile"
        | "create_file"
        | "replaceStringInFile"
        | "replace_string_in_file"
        | "insertEditIntoFile"
        | "insert_edit_into_file" => "write",
        "readFile" | "read_file" => "read",
        "deleteFile" | "delete_file" => "delete",
        _ => return Vec::new(),
    };
    let Some(path) = input
        .get("filePath")
        .or_else(|| input.get("file_path"))
        .or_else(|| input.get("path"))
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };

    vec![VscodeFileIntent {
        operation: operation.to_string(),
        path: path.to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_runtime_and_documented_single_file_aliases() {
        for (tool_name, operation) in [
            ("create_file", "write"),
            ("createFile", "write"),
            ("replace_string_in_file", "write"),
            ("replaceStringInFile", "write"),
            ("insert_edit_into_file", "write"),
            ("insertEditIntoFile", "write"),
            ("read_file", "read"),
            ("readFile", "read"),
            ("delete_file", "delete"),
            ("deleteFile", "delete"),
        ] {
            let intents = parse_vscode_file_intents(
                tool_name,
                &json!({ "filePath": "/workspace/src/lib.rs" }),
            );
            assert_eq!(
                intents,
                vec![VscodeFileIntent {
                    operation: operation.to_string(),
                    path: "/workspace/src/lib.rs".to_string(),
                }],
                "unexpected intent for {tool_name}"
            );
            assert!(is_vscode_file_tool_name(tool_name));
        }
    }

    #[test]
    fn parses_multi_file_aliases_and_path_key_fallbacks() {
        for tool_name in ["editFiles", "edit_files"] {
            let intents =
                parse_vscode_file_intents(tool_name, &json!({ "files": ["src/a.rs", "src/b.rs"] }));
            assert_eq!(intents.len(), 2);
            assert!(intents.iter().all(|intent| intent.operation == "edit"));
        }

        for input in [
            json!({ "file_path": "src/lib.rs" }),
            json!({ "path": "src/lib.rs" }),
        ] {
            assert_eq!(
                parse_vscode_file_intents("read_file", &input)[0].path,
                "src/lib.rs"
            );
        }
    }
}
