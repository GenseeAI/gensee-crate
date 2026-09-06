use super::*;
use chrono::DateTime;
use std::collections::BTreeSet;
use std::fmt;

const FALCO_SOURCE: &str = "linux-falco";
const MIN_CONTAINER_ID_PREFIX_LEN: usize = 12;
const FALCO_RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const FALCO_RETENTION_POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const EARLIEST_PLAUSIBLE_FALCO_TIMESTAMP_MS: u64 = 946_684_800_000;
const LATEST_TEST_FALLBACK_FALCO_TIMESTAMP_MS: u64 = 4_102_444_800_000;
const FALCO_FUTURE_CLOCK_SKEW_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Default)]
struct TcloneRunRegistryCache {
    initialized: bool,
    stamp: Option<(SystemTime, u64)>,
    records: Vec<TcloneRunRecord>,
}

impl TcloneRunRegistryCache {
    fn records(&mut self) -> io::Result<&[TcloneRunRecord]> {
        let path = tclone_state_path()?;
        let stamp = match fs::metadata(&path) {
            Ok(metadata) => Some((metadata.modified()?, metadata.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if !self.initialized || self.stamp != stamp {
            self.records = list_tclone_runs()?;
            self.stamp = stamp;
            self.initialized = true;
        }
        Ok(&self.records)
    }
}

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
    let _retention_worker = start_falco_retention_worker(&store)?;
    let stdin = io::stdin();
    let mut count = 0_u64;
    let mut rejected = 0_u64;
    let mut attribution_failures = 0_u64;
    let mut registry = TcloneRunRegistryCache::default();
    let mut input_error_active = false;
    let mut registry_error_active = false;
    let mut store_error_active = false;
    let mut clock_error_active = false;
    let mut attribution_error_active = false;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => {
                input_error_active = false;
                line
            }
            Err(error) => {
                rejected += 1;
                log_falco_error_once(
                    &mut input_error_active,
                    format_args!("could not read Falco event: {error}"),
                );
                continue;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ingested_at_ms = match unix_millis() {
            Ok(ingested_at_ms) => {
                clock_error_active = false;
                ingested_at_ms
            }
            Err(error) => {
                rejected += 1;
                log_falco_error_once(
                    &mut clock_error_active,
                    format_args!("could not timestamp Falco event: {error}"),
                );
                continue;
            }
        };
        match system_event_and_value_from_falco_line(line, ingested_at_ms, host.as_deref()) {
            Ok((mut event, mut value)) => {
                match registry.records() {
                    Ok(records) => {
                        registry_error_active = false;
                        if let Err(error) =
                            attribute_falco_event_to_tclone(&mut event, &mut value, records)
                        {
                            attribution_failures += 1;
                            log_falco_error_once(
                                &mut attribution_error_active,
                                format_args!("could not attribute Falco event: {error}"),
                            );
                        } else {
                            attribution_error_active = false;
                        }
                    }
                    Err(error) => {
                        attribution_failures += 1;
                        log_falco_error_once(
                            &mut registry_error_active,
                            format_args!("could not refresh Tclone run registry: {error}"),
                        );
                    }
                }
                match append_system_event_with_policy(&store, &event) {
                    Ok(()) => {
                        store_error_active = false;
                        count += 1;
                    }
                    Err(error) => {
                        rejected += 1;
                        log_falco_error_once(
                            &mut store_error_active,
                            format_args!("could not store Falco event: {error}"),
                        );
                    }
                }
            }
            Err(error) => {
                rejected += 1;
                eprintln!("gensee: rejected Falco event: {error}");
            }
        }
    }

    eprintln!(
        "gensee: ingested {count} Falco event(s), rejected {rejected}, attribution failures {attribution_failures}"
    );
    Ok(())
}

fn start_falco_retention_worker(store: &EventStore) -> io::Result<thread::JoinHandle<()>> {
    let maintenance_store = store.independent_connection()?;
    let initial_recording = Policy::load_current().document().endpoint_security.clone();
    thread::Builder::new()
        .name("gensee-falco-retention".to_string())
        .spawn(move || {
            let mut error_active = false;
            let mut recording = initial_recording;
            let mut next_policy_refresh =
                Instant::now() + FALCO_RETENTION_POLICY_REFRESH_INTERVAL;
            loop {
                if Instant::now() >= next_policy_refresh {
                    recording = Policy::load_current().document().endpoint_security.clone();
                    next_policy_refresh =
                        Instant::now() + FALCO_RETENTION_POLICY_REFRESH_INTERVAL;
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_falco_retention_once(
                        &maintenance_store,
                        recording.raw_event_retention_hours,
                        recording.max_raw_events,
                    )
                }));
                match result {
                    Ok(Ok(())) => error_active = false,
                    Ok(Err(error)) => log_falco_error_once(
                        &mut error_active,
                        format_args!("retention maintenance failed: {error}"),
                    ),
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("unknown panic");
                        eprintln!(
                            "gensee: Falco retention worker panicked ({message}); restarting after the maintenance interval"
                        );
                        error_active = true;
                    }
                }
                thread::sleep(FALCO_RETENTION_CHECK_INTERVAL);
            }
        })
}

fn run_falco_retention_once(
    store: &EventStore,
    raw_event_retention_hours: u64,
    max_raw_events: u64,
) -> io::Result<()> {
    let now_ms = unix_millis()?;
    store.prune_falco_retention_if_due(
        now_ms,
        FALCO_RETENTION_CHECK_INTERVAL.as_millis() as u64,
        raw_event_retention_hours,
        max_raw_events,
    )?;
    Ok(())
}

fn log_falco_error_once(active: &mut bool, message: fmt::Arguments<'_>) {
    if !*active {
        eprintln!("gensee: {message}; suppressing repeats until recovery");
        *active = true;
    }
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

#[cfg(test)]
pub(crate) fn system_event_from_falco_line(
    line: &str,
    observed_at_ms: u64,
    host: Option<&str>,
) -> io::Result<SystemEvent> {
    system_event_and_value_from_falco_line(line, observed_at_ms, host).map(|(event, _)| event)
}

pub(crate) fn system_event_from_persisted_falco_line(
    line: &str,
    observed_at_ms: u64,
) -> io::Result<SystemEvent> {
    let value = parse_falco_value(line)?;
    falco_system_event_from_value(value, observed_at_ms, None, false).map(|(event, _)| event)
}

fn system_event_and_value_from_falco_line(
    line: &str,
    observed_at_ms: u64,
    host: Option<&str>,
) -> io::Result<(SystemEvent, Value)> {
    let mut value = parse_falco_value(line)?;

    // Falco output may include command arguments and environment-derived data.
    // Apply the same redaction floor as native agent and Endpoint Security input
    // before extracting any structured field for persistence.
    redact_value(&mut value);
    falco_system_event_from_value(value, observed_at_ms, host, true)
}

fn parse_falco_value(line: &str) -> io::Result<Value> {
    let value = serde_json::from_str::<Value>(line).map_err(|error| {
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
    Ok(value)
}

fn falco_system_event_from_value(
    mut value: Value,
    observed_at_ms: u64,
    host: Option<&str>,
    enrich: bool,
) -> io::Result<(SystemEvent, Value)> {
    let fields = value
        .get("output_fields")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let (event_type, event_type_source) = falco_event_type(&value, &fields);
    let event_kind = classify_falco_event(&event_type, &fields);
    let file_path = falco_string(
        &fields,
        &[
            "fd.name",
            "evt.arg.path",
            "evt.arg.name",
            "evt.arg.filename",
            "evt.arg.pathname",
            "evt.arg.oldpath",
            "evt.arg.newpath",
            "evt.arg.linkpath",
            "evt.arg.target",
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
        "ingested_at_ms": observed_at_ms,
        "event_id": falco_string(&fields, &["evt.num", "evt_num"]),
        "event_type_source": event_type_source,
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
    if enrich {
        value
            .as_object_mut()
            .expect("object checked above")
            .insert("gensee".to_string(), gensee);
    }

    let event = SystemEvent {
        source: FALCO_SOURCE.to_string(),
        event_type,
        event_kind,
        execution_origin: Default::default(),
        observed_at_ms: falco_event_time_ms(&fields, observed_at_ms).unwrap_or(observed_at_ms),
        pid: falco_u32(&fields, &["proc.pid", "thread.tid"]),
        ppid: falco_u32(&fields, &["proc.ppid"]),
        process_name: falco_string(&fields, &["proc.name", "proc.pname"]),
        executable_path: falco_string(&fields, &["proc.exepath", "proc.exe"]),
        file_path,
        command_line: falco_string(&fields, &["proc.cmdline", "proc.args"]),
        raw_json: serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string()),
    };
    Ok((event, value))
}

fn container_id_from_cgroups(cgroups: &str) -> Option<String> {
    // This is deliberately a Podman/libpod fallback. Falco's structured
    // container.id field remains authoritative for Docker, containerd, CRI-O,
    // and libpod layouts that do not place the ID immediately after the marker.
    cgroups
        .match_indices("libpod")
        .filter_map(|(index, marker)| {
            let suffix = &cgroups[index + marker.len()..];
            let marker_has_boundary = index == 0
                || cgroups[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|character| matches!(character, '/' | ':' | '-' | '_'));
            if !marker_has_boundary
                || !suffix
                    .chars()
                    .next()
                    .is_some_and(|character| matches!(character, '-' | '_' | '/' | ':'))
            {
                return None;
            }
            let candidate = suffix
                .trim_start_matches(['-', '_', '/', ':'])
                .chars()
                .take_while(|character| character.is_ascii_hexdigit())
                .collect::<String>();
            (candidate.len() >= MIN_CONTAINER_ID_PREFIX_LEN).then_some(candidate)
        })
        .max_by_key(|candidate| candidate.len())
}

fn falco_event_time_ms(fields: &Value, ingested_at_ms: u64) -> Option<u64> {
    // Falco has emitted its wall-clock timestamp under several JSON field
    // names across versions and output modes. These fields are nanoseconds
    // since the Unix epoch, despite the `iso8601` name used by some outputs.
    // Prefer the rawtime spelling, then accept the compatible aliases so
    // replay and live ingestion retain the event clock instead of stdin
    // arrival time.
    for key in [
        "evt.rawtime",
        "evt_rawtime",
        "evt.time",
        "evt_time",
        "evt.time.iso8601",
        "evt_time_iso8601",
    ] {
        let Some(value) = falco_scalar_string(fields, key) else {
            continue;
        };
        let milliseconds = value
            .trim()
            .parse::<u64>()
            .ok()
            .map(|nanoseconds| nanoseconds / 1_000_000)
            .or_else(|| {
                DateTime::parse_from_rfc3339(value.trim())
                    .ok()
                    .and_then(|timestamp| u64::try_from(timestamp.timestamp_millis()).ok())
            });
        if milliseconds
            .is_some_and(|timestamp| plausible_falco_timestamp_ms(timestamp, ingested_at_ms))
        {
            return milliseconds;
        }
    }
    None
}

fn plausible_falco_timestamp_ms(timestamp_ms: u64, ingested_at_ms: u64) -> bool {
    let latest = if ingested_at_ms >= EARLIEST_PLAUSIBLE_FALCO_TIMESTAMP_MS {
        ingested_at_ms.saturating_add(FALCO_FUTURE_CLOCK_SKEW_MS)
    } else {
        LATEST_TEST_FALLBACK_FALCO_TIMESTAMP_MS
    };
    (EARLIEST_PLAUSIBLE_FALCO_TIMESTAMP_MS..=latest).contains(&timestamp_ms)
}

fn falco_event_type(value: &Value, fields: &Value) -> (String, &'static str) {
    if let Some(event_type) = falco_string(fields, &["evt.type", "evt_type"])
        .or_else(|| falco_string(value, &["event_type"]))
    {
        return (event_type, "falco_field");
    }

    if let Some(event_type) = falco_event_type_from_rule_metadata(value) {
        return (event_type.to_string(), "rule_metadata");
    }

    ("unknown".to_string(), "fallback")
}

fn falco_event_type_from_rule_metadata(value: &Value) -> Option<&'static str> {
    let categories = value
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(activity_category)
        .collect::<BTreeSet<_>>();

    // Tags are authoritative only when their complete set maps to one honest
    // observation category (or the explicitly supported network+IPC union).
    if !categories.is_empty() {
        return event_type_for_categories(&categories);
    }

    let words = value
        .get("rule")
        .and_then(Value::as_str)?
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if words.windows(2).any(|pair| pair == ["metrics", "snapshot"]) {
        return Some("metrics_snapshot");
    }
    let categories = words
        .iter()
        .filter_map(|word| activity_category(word))
        .collect::<BTreeSet<_>>();
    event_type_for_categories(&categories)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ActivityCategory {
    Process,
    File,
    Network,
    Ipc,
    Syscall,
    Capture,
}

fn activity_category(value: &str) -> Option<ActivityCategory> {
    match value.to_ascii_lowercase().as_str() {
        "process" => Some(ActivityCategory::Process),
        "file" | "filesystem" => Some(ActivityCategory::File),
        "network" => Some(ActivityCategory::Network),
        "ipc" => Some(ActivityCategory::Ipc),
        "syscall" => Some(ActivityCategory::Syscall),
        "capture" => Some(ActivityCategory::Capture),
        _ => None,
    }
}

fn event_type_for_categories(categories: &BTreeSet<ActivityCategory>) -> Option<&'static str> {
    if categories.len() == 2
        && categories.contains(&ActivityCategory::Network)
        && categories.contains(&ActivityCategory::Ipc)
    {
        return Some("network_ipc_activity");
    }
    match categories
        .iter()
        .copied()
        .next()
        .filter(|_| categories.len() == 1)?
    {
        ActivityCategory::Process => Some("process_observation"),
        ActivityCategory::File => Some("file_access"),
        ActivityCategory::Network => Some("network_activity"),
        ActivityCategory::Ipc => Some("ipc_activity"),
        ActivityCategory::Syscall => Some("syscall_activity"),
        ActivityCategory::Capture => Some("capture_state"),
    }
}

fn attribute_falco_event_to_tclone(
    event: &mut SystemEvent,
    value: &mut Value,
    records: &[TcloneRunRecord],
) -> io::Result<()> {
    let container_id = value
        .pointer("/gensee/container/id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("output_fields")
                .and_then(|fields| falco_string(fields, &["container.id"]))
        });
    let container_name = value
        .pointer("/gensee/container/name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("output_fields")
                .and_then(|fields| falco_string(fields, &["container.name"]))
        });
    let matched = records.iter().rev().find(|record| {
        container_name
            .as_deref()
            .is_some_and(|name| name == record.container_name)
            || container_id.as_deref().is_some_and(|id| {
                record
                    .container_id
                    .as_deref()
                    .is_some_and(|known| container_ids_match(id, known))
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

fn container_ids_match(observed: &str, known: &str) -> bool {
    let observed = observed.trim();
    let known = known.trim();
    observed.len() >= MIN_CONTAINER_ID_PREFIX_LEN
        && known.len() >= MIN_CONTAINER_ID_PREFIX_LEN
        && (known.starts_with(observed) || observed.starts_with(known))
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
        "process_observation" => "ProcessObservation".to_string(),
        "file_access" => "FileAccess".to_string(),
        "network_activity" => "NetworkActivity".to_string(),
        "network_ipc_activity" => "NetworkIpcActivity".to_string(),
        "ipc_activity" => "IpcActivity".to_string(),
        "metrics_snapshot" => "TelemetryMetric".to_string(),
        "capture_state" => "CollectorState".to_string(),
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
    keys.iter().find_map(|key| falco_scalar_string(value, key))
}

fn falco_scalar_string(value: &Value, key: &str) -> Option<String> {
    let value = value.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })?;
    (!value.trim().is_empty() && !matches!(value.trim(), "<NA>" | "<N/A>")).then_some(value)
}

fn falco_u32(value: &Value, keys: &[&str]) -> Option<u32> {
    falco_string(value, keys).and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tclone_record(container_id: Option<&str>, container_name: &str) -> TcloneRunRecord {
        TcloneRunRecord {
            run_id: "run_fork_1".to_string(),
            observe_only: false,
            operation_id: None,
            operation_state_root: None,
            capability_lifecycle: None,
            parent_run_id: Some("run_source_1".to_string()),
            role: "fork".to_string(),
            status: "running".to_string(),
            container_name: container_name.to_string(),
            container_id: container_id.map(ToString::to_string),
            source_container: Some("gensee-tclone-src-run-source-1".to_string()),
            host_control_owner_run_id: Some("run_source_1".to_string()),
            fork_prefix: None,
            fork_group_id: None,
            fork_index: Some(0),
            fork_count: Some(1),
            fork_approach: None,
            image: "test-image".to_string(),
            workspace: "/workspace".to_string(),
            container_workspace: "/workspace".to_string(),
            container_home: "/home/gensee".to_string(),
            agent_cmd: vec!["codex".to_string()],
            path_prefixes: Vec::new(),
            fork_base_git_head: None,
            fork_base_overlay_lowerdir: None,
            fork_overlay_upperdir: None,
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        }
    }

    #[test]
    fn parses_process_execution() {
        let event = system_event_from_falco_line(
            r#"{"rule":"Gensee process execution","priority":"Notice","output_fields":{"evt.num":99,"evt.rawtime":"1712345678123456789","evt.type":"execve","proc.pid":42,"proc.ppid":7,"proc.name":"pip","proc.exepath":"/usr/bin/pip","proc.cmdline":"pip install demo","container.id":"abc","container.name":"gensee-tclone-src-run-1"}}"#,
            123,
            Some("worker-01"),
        )
        .unwrap();
        assert_eq!(event.source, "linux-falco");
        assert_eq!(event.event_kind, "ProcessExec");
        assert_eq!(event.pid, Some(42));
        assert_eq!(event.observed_at_ms, 1_712_345_678_123);
        assert_eq!(event.command_line.as_deref(), Some("pip install demo"));
        assert!(event.raw_json.contains("worker-01"));
        assert_eq!(
            serde_json::from_str::<Value>(&event.raw_json).unwrap()["gensee"]["event_id"],
            "99"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&event.raw_json).unwrap()["gensee"]["event_type_source"],
            "falco_field"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&event.raw_json).unwrap()["gensee"]["ingested_at_ms"],
            123
        );
    }

    #[test]
    fn accepts_falco_timestamp_aliases_as_nanoseconds() {
        for (field, timestamp) in [
            ("evt.time", "1712345678123456789"),
            ("evt_time", "1712345678123456789"),
            ("evt.time.iso8601", "1712345678123456789"),
            ("evt_time_iso8601", "1712345678123456789"),
        ] {
            let line = json!({
                "output_fields": {
                    field: timestamp,
                    "evt.type": "open"
                }
            })
            .to_string();
            let event = system_event_from_falco_line(&line, 123, None).unwrap();
            assert_eq!(event.observed_at_ms, 1_712_345_678_123, "{field}");
        }
    }

    #[test]
    fn rawtime_takes_precedence_over_timestamp_aliases() {
        let event = system_event_from_falco_line(
            r#"{"output_fields":{"evt.rawtime":"1712345678123456789","evt.time":"1812345678123456789","evt.type":"open"}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(event.observed_at_ms, 1_712_345_678_123);
    }

    #[test]
    fn timestamp_aliases_are_parsed_independently_and_accept_rfc3339() {
        let event = system_event_from_falco_line(
            r#"{"output_fields":{"evt.rawtime":"not-a-clock","evt.time":"2024-04-05T19:34:38.250Z","evt.type":"open"}}"#,
            1_712_345_679_000,
            None,
        )
        .unwrap();
        assert_eq!(event.observed_at_ms, 1_712_345_678_250);
    }

    #[test]
    fn implausible_timestamp_magnitudes_fall_back_to_ingestion_time() {
        for timestamp in ["1712345678", "1712345678123", "9999999999999999999"] {
            let line = json!({
                "output_fields": {
                    "evt.rawtime": timestamp,
                    "evt.type": "open"
                }
            })
            .to_string();
            let event = system_event_from_falco_line(&line, 1_712_345_679_000, None).unwrap();
            assert_eq!(event.observed_at_ms, 1_712_345_679_000, "{timestamp}");
        }
    }

    #[test]
    fn derives_broad_event_types_from_rule_metadata() {
        let process = system_event_from_falco_line(
            r#"{"rule":"Container Process Lifecycle","tags":["observe_only","process"],"output_fields":{"evt.time":1712345678123456789,"proc.pid":42}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(process.event_type, "process_observation");
        assert_eq!(process.event_kind, "ProcessObservation");
        assert_eq!(process.observed_at_ms, 1_712_345_678_123);
        let raw = serde_json::from_str::<Value>(&process.raw_json).unwrap();
        assert_eq!(raw["gensee"]["event_type_source"], "rule_metadata");

        let network = system_event_from_falco_line(
            r#"{"rule":"Container Network And IPC","tags":["network","ipc"],"output_fields":{"fd.name":"198.51.100.10:443"}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(network.event_type, "network_ipc_activity");
        assert_eq!(network.event_kind, "NetworkIpcActivity");

        let metrics = system_event_from_falco_line(
            r#"{"rule":"Falco internal: metrics snapshot","output_fields":{"evt.time":1712345678123456789}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(metrics.event_type, "metrics_snapshot");
        assert_eq!(metrics.event_kind, "TelemetryMetric");
    }

    #[test]
    fn conflicting_tags_and_substring_names_do_not_claim_a_category() {
        let conflict = system_event_from_falco_line(
            r#"{"rule":"Mixed observation","tags":["network","process"],"output_fields":{}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(conflict.event_type, "unknown");
        assert_eq!(conflict.event_kind, "Syscall");

        let profile = system_event_from_falco_line(
            r#"{"rule":"Modify shell profile","output_fields":{}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(profile.event_type, "unknown");
    }

    #[test]
    fn explicit_event_type_takes_precedence_over_rule_metadata() {
        let event = system_event_from_falco_line(
            r#"{"rule":"Container Process Lifecycle","tags":["process"],"output_fields":{"evt.type":"connect"}}"#,
            123,
            None,
        )
        .unwrap();
        assert_eq!(event.event_type, "connect");
        assert_eq!(event.event_kind, "NetworkConnect");
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
            r#"{"output_fields":{"evt.type":"connect","fd.rip":"203.0.113.10","fd.rport":443}}"#,
            124,
            None,
        )
        .unwrap();
        assert_eq!(connect.event_kind, "NetworkConnect");
        assert!(connect.raw_json.contains("203.0.113.10:443"));
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

    #[test]
    fn ignores_unrelated_hex_runs_in_cgroup_path() {
        assert_eq!(
            container_id_from_cgroups("0::/user.slice/0123456789abcdef.scope/libpod-short.scope"),
            None
        );
        assert_eq!(
            container_id_from_cgroups("0::/notlibpod-8f14e45fceea167a5a36dedd4bea2543.scope"),
            None
        );
    }

    #[test]
    fn attributes_cgroup_derived_container_id_to_tclone_run() {
        let (mut event, mut raw) = system_event_and_value_from_falco_line(
            r#"{"output_fields":{"evt.type":"execve","thread.cgroups":"cpuset=/machine.slice/libpod-8f14e45fceea167a5a36dedd4bea2543.scope"}}"#,
            1,
            None,
        )
        .unwrap();
        let records = [tclone_record(
            Some("8f14e45fceea167a5a36dedd4bea2543d00df00d"),
            "gensee-tclone-fork-run-fork-1",
        )];

        attribute_falco_event_to_tclone(&mut event, &mut raw, &records).unwrap();

        let attributed = serde_json::from_str::<Value>(&event.raw_json).unwrap();
        assert_eq!(attributed["session_id"], "run_fork_1");
        assert_eq!(attributed["tclone_role"], "fork");
        assert_eq!(attributed["tclone_parent_run_id"], "run_source_1");
    }

    #[test]
    fn container_id_matching_rejects_empty_and_short_prefixes() {
        assert!(!container_ids_match("", "8f14e45fceea167a"));
        assert!(!container_ids_match("8f14e45f", "8f14e45fceea167a"));
        assert!(container_ids_match(
            "8f14e45fceea",
            "8f14e45fceea167a5a36dedd4bea2543"
        ));
    }

    #[test]
    fn mutation_paths_and_unresolved_network_fields_are_handled() {
        let mutation = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"renameat","fd.name":"<NA>","evt.arg.oldpath":"/workspace/old.txt"}}"#,
            1,
            None,
        )
        .unwrap();
        assert_eq!(mutation.file_path.as_deref(), Some("/workspace/old.txt"));

        let symlink = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"symlinkat","evt.arg.target":"../target.txt","evt.arg.linkpath":"/workspace/link.txt"}}"#,
            1,
            None,
        )
        .unwrap();
        assert_eq!(symlink.file_path.as_deref(), Some("/workspace/link.txt"));

        let network = system_event_from_falco_line(
            r#"{"output_fields":{"evt.type":"connect","fd.name":"<NA>","fd.rip":"<NA>","fd.rport":"<NA>"}}"#,
            1,
            None,
        )
        .unwrap();
        let raw = serde_json::from_str::<Value>(&network.raw_json).unwrap();
        assert!(raw["gensee"]["network_dest"].is_null());
    }
}
