use super::*;

const FALCO_SOURCE: &str = "linux-falco";

pub(crate) fn ingest_falco(args: Vec<OsString>) -> io::Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.to_str(), Some("--help" | "-h")))
    {
        eprintln!("usage: gensee ingest falco [--host <name>] < falco.jsonl");
        return Ok(());
    }
    let host = parse_falco_ingest_args(&args)?
        .or_else(|| env::var("HOSTNAME").ok())
        .filter(|value| !value.trim().is_empty());
    let store = EventStore::default_local()?;
    let stdin = io::stdin();
    let mut count = 0_u64;
    let mut rejected = 0_u64;

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match system_event_from_falco_line(line, unix_millis()?, host.as_deref()) {
            Ok(mut event) => {
                attribute_falco_event_to_tclone(&mut event)?;
                store.append_system_event(&event)?;
                count += 1;
            }
            Err(error) => {
                rejected += 1;
                eprintln!("gensee: rejected Falco event: {error}");
            }
        }
    }

    eprintln!("gensee: ingested {count} Falco event(s), rejected {rejected}");
    Ok(())
}

fn parse_falco_ingest_args(args: &[OsString]) -> io::Result<Option<String>> {
    let mut host = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--host") => {
                host = args
                    .get(index + 1)
                    .and_then(|arg| arg.to_str())
                    .map(ToString::to_string);
                if host.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "gensee ingest falco: --host requires a value",
                    ));
                }
                index += 2;
            }
            Some(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("gensee ingest falco: unexpected argument `{other}`"),
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gensee ingest falco: arguments must be UTF-8",
                ));
            }
        }
    }
    Ok(host)
}

pub(crate) fn system_event_from_falco_line(
    line: &str,
    observed_at_ms: u64,
    host: Option<&str>,
) -> io::Result<SystemEvent> {
    let mut value = serde_json::from_str::<Value>(line).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Falco JSON: {error}"),
        )
    })?;
    if !value.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Falco event must be a JSON object",
        ));
    }

    // Falco output may include command arguments and environment-derived data.
    // Apply the same redaction floor as native agent and Endpoint Security input
    // before extracting any structured field for persistence.
    redact_value(&mut value);
    let fields = value
        .get("output_fields")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let event_type = falco_string(&fields, &["evt.type", "evt_type"])
        .or_else(|| falco_string(&value, &["event_type"]))
        .unwrap_or_else(|| "unknown".to_string());
    let event_kind = classify_falco_event(&event_type, &fields);
    let file_path = falco_string(
        &fields,
        &[
            "fd.name",
            "evt.arg.path",
            "evt.arg.name",
            "evt.arg.filename",
            "evt.arg.pathname",
            "file.path",
        ],
    )
    .filter(|path| path.starts_with('/'));
    let network_dest = falco_network_destination(&fields);
    let cgroups = falco_string(&fields, &["thread.cgroups"]);
    let cgroup_container_id = cgroups.as_deref().and_then(container_id_from_cgroups);
    let gensee = json!({
        "schema_version": 1,
        "collector": "falco",
        "rule": value.get("rule").cloned().unwrap_or(Value::Null),
        "priority": value.get("priority").cloned().unwrap_or(Value::Null),
        "host": host,
        "container": {
            "id": falco_string(&fields, &["container.id"]).or(cgroup_container_id),
            "name": falco_string(&fields, &["container.name"]),
            "image": falco_string(
                &fields,
                &["container.image.repository", "container.image"],
            ),
        },
        "cgroups": cgroups,
        "network_dest": network_dest,
    });
    value
        .as_object_mut()
        .expect("object checked above")
        .insert("gensee".to_string(), gensee);

    Ok(SystemEvent {
        source: FALCO_SOURCE.to_string(),
        event_type,
        event_kind,
        observed_at_ms: falco_event_time_ms(&fields).unwrap_or(observed_at_ms),
        pid: falco_u32(&fields, &["proc.pid", "thread.tid"]),
        ppid: falco_u32(&fields, &["proc.ppid"]),
        process_name: falco_string(&fields, &["proc.name", "proc.pname"]),
        executable_path: falco_string(&fields, &["proc.exepath", "proc.exe"]),
        file_path,
        command_line: falco_string(&fields, &["proc.cmdline", "proc.args"]),
        raw_json: serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string()),
    })
}

fn container_id_from_cgroups(cgroups: &str) -> Option<String> {
    cgroups
        .split(|character: char| !character.is_ascii_hexdigit())
        .filter(|candidate| candidate.len() >= 12)
        .max_by_key(|candidate| candidate.len())
        .map(ToString::to_string)
}

fn falco_event_time_ms(fields: &Value) -> Option<u64> {
    // evt.rawtime is Falco's wall-clock event timestamp in nanoseconds. Using
    // it instead of stdin arrival time preserves ordering across collectors.
    falco_string(fields, &["evt.rawtime", "evt_rawtime"])
        .and_then(|value| value.parse::<u64>().ok())
        .map(|nanoseconds| nanoseconds / 1_000_000)
        .filter(|milliseconds| *milliseconds > 0)
}

fn attribute_falco_event_to_tclone(event: &mut SystemEvent) -> io::Result<()> {
    let mut value = serde_json::from_str::<Value>(&event.raw_json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let container_id = find_first_str(&value, &["container.id"]);
    let container_name = find_first_str(&value, &["container.name"]);
    let records = list_tclone_runs().unwrap_or_default();
    let matched = records.iter().rev().find(|record| {
        container_name
            .as_deref()
            .is_some_and(|name| name == record.container_name)
            || container_id.as_deref().is_some_and(|id| {
                record
                    .container_id
                    .as_deref()
                    .is_some_and(|known| known.starts_with(id) || id.starts_with(known))
            })
    });

    if let Some(record) = matched {
        let object = value.as_object_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Falco event is not an object")
        })?;
        object.insert("session_id".to_string(), json!(record.run_id));
        object.insert("tclone_role".to_string(), json!(record.role));
        object.insert(
            "tclone_parent_run_id".to_string(),
            json!(record.parent_run_id),
        );
        event.raw_json = serde_json::to_string(&value)?;
    }
    Ok(())
}

fn classify_falco_event(event_type: &str, fields: &Value) -> String {
    match event_type.to_ascii_lowercase().as_str() {
        "execve" | "execveat" | "clone" | "clone3" | "fork" | "vfork" => "ProcessExec".to_string(),
        "open" | "openat" | "openat2" | "creat" => {
            let flags = falco_string(fields, &["evt.arg.flags", "evt.args"])
                .unwrap_or_default()
                .to_ascii_uppercase();
            if ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]
                .iter()
                .any(|flag| flags.contains(flag))
            {
                "FileWrite".to_string()
            } else {
                "FileOpen".to_string()
            }
        }
        "unlink" | "unlinkat" | "rmdir" => "FileDelete".to_string(),
        "rename" | "renameat" | "renameat2" => "FileRename".to_string(),
        "mkdir" | "mkdirat" | "link" | "linkat" | "symlink" | "symlinkat" | "truncate"
        | "ftruncate" | "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "fchownat" => {
            "FileWrite".to_string()
        }
        "connect" => "NetworkConnect".to_string(),
        "accept" | "accept4" => "NetworkAccept".to_string(),
        "bind" | "listen" | "socket" => "NetworkSocket".to_string(),
        _ => "Syscall".to_string(),
    }
}

fn falco_network_destination(fields: &Value) -> Option<String> {
    if let Some(name) = falco_string(fields, &["fd.name"]).filter(|name| !name.starts_with('/')) {
        return Some(name);
    }
    let ip = falco_string(fields, &["fd.rip", "fd.cip", "fd.sip"])?;
    let port = falco_string(fields, &["fd.rport", "fd.cport", "fd.sport"]);
    Some(match port {
        Some(port) if !port.is_empty() && port != "0" => format!("{ip}:{port}"),
        _ => ip,
    })
}

fn falco_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
    })
}

fn falco_u32(value: &Value, keys: &[&str]) -> Option<u32> {
    falco_string(value, keys).and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_execution() {
        let event = system_event_from_falco_line(
            r#"{"rule":"Gensee process execution","priority":"Notice","output_fields":{"evt.rawtime":"1712345678123456789","evt.type":"execve","proc.pid":42,"proc.ppid":7,"proc.name":"pip","proc.exepath":"/usr/bin/pip","proc.cmdline":"pip install demo","container.id":"abc","container.name":"gensee-tclone-src-run-1"}}"#,
            123,
            Some("machine-a"),
        )
        .unwrap();
        assert_eq!(event.source, "linux-falco");
        assert_eq!(event.event_kind, "ProcessExec");
        assert_eq!(event.pid, Some(42));
        assert_eq!(event.observed_at_ms, 1_712_345_678_123);
        assert_eq!(event.command_line.as_deref(), Some("pip install demo"));
        assert!(event.raw_json.contains("machine-a"));
    }

    #[test]
    fn classifies_file_write_and_network_destination() {
        let write = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"openat","evt.arg.flags":"O_WRONLY|O_CREAT","fd.name":"/workspace/out.txt"}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(write.event_kind, "FileWrite");
        assert_eq!(write.file_path.as_deref(), Some("/workspace/out.txt"));

        let connect = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"connect","fd.rip":"10.20.0.2","fd.rport":8082}}"#,
            124,
            None,
        )
        .unwrap();
        assert_eq!(connect.event_kind, "NetworkConnect");
        assert!(connect.raw_json.contains("10.20.0.2:8082"));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(system_event_from_falco_line("not-json", 1, None).is_err());
    }

    #[test]
    fn extracts_container_id_from_cgroup_path() {
        let event = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"execve","thread.cgroups":"cpuset=/machine.slice/libpod-8f14e45fceea167a5a36dedd4bea2543.scope"}}"#,
            1,
            None,
        )
        .unwrap();
        let raw = serde_json::from_str::<Value>(&event.raw_json).unwrap();
        assert_eq!(
            raw["gensee"]["container"]["id"],
            "8f14e45fceea167a5a36dedd4bea2543"
        );
    }
}
