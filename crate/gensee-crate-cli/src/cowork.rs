use crate::*;
use chrono::DateTime;
use gensee_crate_core::ExecutionOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoworkAuditMode {
    Local,
    Cloud,
    Unknown,
}

impl CoworkAuditMode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "local" => Ok(Self::Local),
            "cloud" => Ok(Self::Cloud),
            "unknown" => Ok(Self::Unknown),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--session-mode must be local, cloud, or unknown",
            )),
        }
    }
}

pub(crate) fn ingest_cowork_audit(args: Vec<OsString>) -> io::Result<()> {
    let mode = cowork_audit_mode(&args)?;
    let store = EventStore::default_local()?;
    let mut ingested = 0_u64;
    let mut rejected = 0_u64;
    for line in io::stdin().lock().lines() {
        let line = line?;
        match system_events_from_cowork_audit_line(&line, mode) {
            Ok(events) => {
                for event in events {
                    store.append_system_event(&event)?;
                    ingested += 1;
                }
            }
            Err(error) => {
                rejected += 1;
                eprintln!("gensee cowork audit: rejected line: {error}");
            }
        }
    }
    eprintln!("gensee: ingested {ingested} Cowork boundary event(s), rejected {rejected}");
    Ok(())
}

fn cowork_audit_mode(args: &[OsString]) -> io::Result<CoworkAuditMode> {
    let mut mode = CoworkAuditMode::Unknown;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--session-mode") => {
                let value = args
                    .get(index + 1)
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--session-mode requires local, cloud, or unknown",
                        )
                    })?;
                mode = CoworkAuditMode::parse(value)?;
                index += 2;
            }
            Some(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown Cowork audit option: {other}"),
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cowork audit options must be UTF-8",
                ));
            }
        }
    }
    Ok(mode)
}

pub(crate) fn system_events_from_cowork_audit_line(
    line: &str,
    mode: CoworkAuditMode,
) -> io::Result<Vec<SystemEvent>> {
    let value: Value = serde_json::from_str(line).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Cowork audit JSON: {error}"),
        )
    })?;
    let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let session_id = value
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);
    let observed_at_ms = value
        .get("_audit_timestamp")
        .or_else(|| value.get("timestamp"))
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_millis)
        .or_else(|| unix_millis().ok())
        .unwrap_or_default();

    content
        .iter()
        .filter(|entry| entry.get("type").and_then(Value::as_str) == Some("tool_use"))
        .map(|entry| {
            let tool_name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let tool_use_id = entry.get("id").and_then(Value::as_str);
            let input = entry.get("input");
            let file_path = input
                .and_then(|input| {
                    input
                        .get("file_path")
                        .or_else(|| input.get("path"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string);
            let (origin, visibility_limit) = cowork_tool_origin(mode, tool_name);
            let raw_json = json!({
                "schema_version": 1,
                "collector": "claude-cowork-local-audit",
                "attribution": { "session_id": session_id },
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "process_name": "Claude Cowork",
                "file_path": file_path,
                "session_mode": cowork_mode_name(mode),
                "execution_origin": origin.as_str(),
                "visibility_limit": visibility_limit,
                "content_and_command_omitted": true,
            });
            Ok(SystemEvent {
                source: "claude-cowork-local-audit".to_string(),
                event_type: "cowork_tool_boundary".to_string(),
                event_kind: "agent_boundary".to_string(),
                observed_at_ms,
                pid: None,
                ppid: None,
                process_name: Some("Claude Cowork".to_string()),
                executable_path: None,
                file_path,
                command_line: None,
                raw_json: raw_json.to_string(),
            })
        })
        .collect()
}

fn cowork_tool_origin(
    mode: CoworkAuditMode,
    tool_name: &str,
) -> (ExecutionOrigin, Option<&'static str>) {
    if mode == CoworkAuditMode::Cloud {
        return (
            ExecutionOrigin::CloudMediated,
            Some("cloud execution is outside endpoint visibility"),
        );
    }
    if mode == CoworkAuditMode::Local && tool_name == "mcp__workspace__bash" {
        return (
            ExecutionOrigin::VmMediated,
            Some("guest command and process lineage are not endpoint-visible"),
        );
    }
    if mode == CoworkAuditMode::Local && is_cowork_host_tool(tool_name) {
        return (ExecutionOrigin::HostNative, None);
    }
    (
        ExecutionOrigin::Unattributed,
        Some("tool execution surface cannot be established from endpoint evidence"),
    )
}

fn is_cowork_host_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Read" | "Write" | "Edit" | "MultiEdit" | "Glob" | "Grep" | "LS"
    )
}

fn cowork_mode_name(mode: CoworkAuditMode) -> &'static str {
    match mode {
        CoworkAuditMode::Local => "local",
        CoworkAuditMode::Cloud => "cloud",
        CoworkAuditMode::Unknown => "unknown",
    }
}

fn parse_rfc3339_millis(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|timestamp| u64::try_from(timestamp.timestamp_millis()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(tool: &str) -> String {
        json!({
            "_audit_timestamp": "2026-09-05T06:56:13.198Z",
            "session_id": "cowork-session-1",
            "message": { "content": [{
                "type": "tool_use",
                "name": tool,
                "id": "tool-1",
                "input": { "file_path": "/Users/me/work/result.txt", "content": "secret" }
            }]}
        })
        .to_string()
    }

    #[test]
    fn local_file_tool_is_host_native_and_drops_content() {
        let events =
            system_events_from_cowork_audit_line(&line("Write"), CoworkAuditMode::Local).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].execution_origin(), ExecutionOrigin::HostNative);
        assert_eq!(
            events[0].file_path.as_deref(),
            Some("/Users/me/work/result.txt")
        );
        assert!(!events[0].raw_json.contains("secret"));
    }

    #[test]
    fn local_shell_is_vm_mediated_without_recording_the_command() {
        let events = system_events_from_cowork_audit_line(
            &line("mcp__workspace__bash"),
            CoworkAuditMode::Local,
        )
        .unwrap();
        assert_eq!(events[0].execution_origin(), ExecutionOrigin::VmMediated);
        assert!(events[0].raw_json.contains("guest command"));
    }

    #[test]
    fn cloud_tool_is_cloud_mediated_and_calls_out_the_blind_spot() {
        let events =
            system_events_from_cowork_audit_line(&line("Write"), CoworkAuditMode::Cloud).unwrap();
        assert_eq!(events[0].execution_origin(), ExecutionOrigin::CloudMediated);
        assert!(events[0].raw_json.contains("outside endpoint visibility"));
    }

    #[test]
    fn unknown_tool_or_mode_is_not_guessed() {
        let events = system_events_from_cowork_audit_line(
            &line("mcp__remote__service"),
            CoworkAuditMode::Unknown,
        )
        .unwrap();
        assert_eq!(events[0].execution_origin(), ExecutionOrigin::Unattributed);
    }
}
