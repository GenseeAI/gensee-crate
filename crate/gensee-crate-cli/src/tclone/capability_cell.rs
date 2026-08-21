use super::*;
use gensee_crate_rules::capability::{
    Capability, CapabilityRequest, ExecutionBoundary, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

const CELL_LEASE_SCHEMA_VERSION: u32 = 1;
// Leave time for the host-control bridge to return the result and reap the
// container before its own hard command timeout.
const CELL_LEASE_MAX_TTL_SECONDS: u64 = TCLONE_HOST_CONTROL_COMMAND_TIMEOUT_SECS - 60;
const CELL_POLL_INTERVAL_MS: u64 = 25;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CapabilityCellLease {
    schema_version: u32,
    lease_id: String,
    source_run_id: String,
    request: CapabilityRequest,
    command: Vec<String>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CapabilityCellRecord {
    schema_version: u32,
    cell_id: String,
    lease_id: String,
    source_run_id: String,
    request: CapabilityRequest,
    command: Vec<String>,
    container_name: String,
    workspace_snapshot: String,
    started_at_ms: u64,
    finished_at_ms: u64,
    exit_code: Option<i32>,
    timed_out: bool,
}

pub(crate) fn tclone_capability_lease(args: Vec<OsString>) -> io::Result<()> {
    if args.first().and_then(|arg| arg.to_str()) != Some("issue") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee run lease issue <source-run-id> --request <request.json> -- <command> [args...]",
        ));
    }
    if env::var_os(TCLONE_HOST_CONTROL_SOCKET_ENV).is_some()
        || env::var_os(TCLONE_HOST_CONTROL_DIR_ENV).is_some()
        || env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability leases are host-issued; run this command from the trusted host terminal",
        ));
    }

    let separator = args.iter().position(|arg| arg == "--").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability lease issuance requires an exact command after --",
        )
    })?;
    let options = &args[1..separator];
    let command = args[separator + 1..]
        .iter()
        .map(|arg| {
            arg.to_str().map(ToString::to_string).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command arguments must be UTF-8",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability lease command cannot be empty",
        ));
    }
    let source_run_id = tclone_target_arg(
        options,
        "usage: gensee run lease issue <source-run-id> --request <request.json> -- <command> [args...]",
    )?;
    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability leases require a running tclone source",
        ));
    }
    let request_path = arg_value(options, "--request")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --request file"))?;
    let request: CapabilityRequest = serde_json::from_str(&read_nofollow_to_string(&request_path)?)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid capability request: {error}"),
            )
        })?;
    validate_cell_request(&request)?;
    let ttl_seconds = arg_value(options, "--ttl-seconds")
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid --ttl-seconds value")
            })
        })
        .transpose()?
        .unwrap_or(request.lease_ttl_seconds)
        .min(request.lease_ttl_seconds)
        .min(CELL_LEASE_MAX_TTL_SECONDS);
    if ttl_seconds == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("lease TTL must be between 1 and {CELL_LEASE_MAX_TTL_SECONDS} seconds"),
        ));
    }

    let issued_at_ms = unix_millis()?;
    let lease_id = format!("lease_{}", Uuid::new_v4().simple());
    let lease = CapabilityCellLease {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        lease_id: lease_id.clone(),
        source_run_id,
        request,
        command,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000)),
        consumed_at_ms: None,
    };
    let path = capability_lease_path(&lease_id)?;
    if let Some(parent) = path.parent() {
        create_restrictive_dir_all(parent)?;
    }
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;

    if options.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "lease_id": lease.lease_id,
                "source_run_id": lease.source_run_id,
                "expires_at_ms": lease.expires_at_ms,
                "execution_boundary": lease.request.execution_boundary,
            }))?
        );
    } else {
        println!("issued one-use capability lease {lease_id}");
        println!(
            "execute with: gensee run cell {} --lease {lease_id}",
            lease.source_run_id
        );
    }
    Ok(())
}

pub(crate) fn tclone_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    if args.first().and_then(|arg| arg.to_str()) == Some("inspect") {
        return inspect_capability_cell(args[1..].to_vec());
    }
    let source_run_id = tclone_target_arg(
        &args,
        "usage: gensee run cell <source-run-id> --lease <lease-id> [--json]",
    )?;
    if let Some(caller) = env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER") {
        if caller != OsString::from(&source_run_id) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a tclone source may execute only its own capability lease",
            ));
        }
    }
    let lease_id = arg_value(&args, "--lease")
        .filter(|value| tclone_is_safe_token(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing valid --lease id"))?;
    let lease = consume_capability_lease(&lease_id, &source_run_id, unix_millis()?)?;
    let source = find_tclone_record(&source_run_id)?;
    if source.role != "source" || source.status != "running" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capability cells require a running tclone source",
        ));
    }
    let record = execute_capability_cell(&source, &lease)?;

    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!(
            "capability cell {} finished with exit code {:?}; inspect retained snapshot at {}",
            record.cell_id, record.exit_code, record.workspace_snapshot
        );
    }
    if record.exit_code == Some(0) {
        Ok(())
    } else {
        Err(io::Error::other(if record.timed_out {
            "capability cell lease expired during execution".to_string()
        } else {
            format!("capability cell exited with status {:?}", record.exit_code)
        }))
    }
}

fn validate_cell_request(request: &CapabilityRequest) -> io::Result<()> {
    if request.schema_version != CAPABILITY_REQUEST_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported capability request schema version",
        ));
    }
    if request.execution_boundary != ExecutionBoundary::IsolatedCell
        || !request.source_must_not_execute
        || !request.inspect_before_commit
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell requests must require isolated execution and inspect-before-commit",
        ));
    }
    if request.capabilities.is_empty()
        || !request.capabilities.contains(&Capability::ProcessExecution)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell requests must include process_execution",
        ));
    }
    if !request.scope.read_paths.is_empty()
        && !request.capabilities.contains(&Capability::FilesystemRead)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read_paths require filesystem_read capability",
        ));
    }
    if !request.scope.write_paths.is_empty()
        && !request.capabilities.contains(&Capability::FilesystemWrite)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "write_paths require filesystem_write capability",
        ));
    }
    for unsupported in [
        Capability::NetworkEgress,
        Capability::IdentityUse,
        Capability::PrivilegedExecution,
        Capability::ExternalMutation,
    ] {
        if request.capabilities.contains(&unsupported) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "capability {unsupported:?} requires a broker and is not available to fresh cells"
                ),
            ));
        }
    }
    validate_scope_paths(&request.scope.read_paths)?;
    validate_scope_paths(&request.scope.write_paths)?;
    if request
        .scope
        .read_paths
        .iter()
        .any(|read| request.scope.write_paths.iter().any(|write| read == write))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the same path cannot be mounted both read-only and writable",
        ));
    }
    if !request.scope.network_hosts.is_empty()
        || !request.scope.identities.is_empty()
        || !request.scope.external_targets.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fresh cells currently accept only filesystem resource selectors",
        ));
    }
    Ok(())
}

fn validate_scope_paths(paths: &[String]) -> io::Result<()> {
    for value in paths {
        let path = Path::new(value);
        if value.is_empty()
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("capability path must be workspace-relative without traversal: {value}"),
            ));
        }
    }
    Ok(())
}

fn consume_capability_lease(
    lease_id: &str,
    source_run_id: &str,
    now_ms: u64,
) -> io::Result<CapabilityCellLease> {
    let path = capability_lease_path(lease_id)?;
    let _lock = TcloneStateLock::acquire(&path)?;
    let mut lease: CapabilityCellLease = serde_json::from_str(&read_nofollow_to_string(&path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if lease.schema_version != CELL_LEASE_SCHEMA_VERSION
        || lease.lease_id != lease_id
        || lease.source_run_id != source_run_id
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability lease does not match this source",
        ));
    }
    if lease.consumed_at_ms.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability lease has already been consumed",
        ));
    }
    if now_ms < lease.issued_at_ms || now_ms >= lease.expires_at_ms {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "capability lease has expired",
        ));
    }
    validate_cell_request(&lease.request)?;
    lease.consumed_at_ms = Some(now_ms);
    write_atomic_nofollow(&path, &serde_json::to_vec_pretty(&lease)?, 0o600)?;
    Ok(lease)
}

fn execute_capability_cell(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
) -> io::Result<CapabilityCellRecord> {
    let cell_id = format!("cell_{}", Uuid::new_v4().simple());
    let container_name = format!("gensee-tclone-{cell_id}");
    let cell_root = capability_cell_path(&cell_id)?;
    let snapshot = cell_root.join("workspace");
    create_restrictive_dir_all(&snapshot)?;
    let podman = tclone_podman();
    copy_capability_scope(&podman, source, lease, &snapshot)?;

    let mut run_args =
        capability_cell_run_args(source, lease, &container_name, &snapshot, unix_millis()?)?;
    run_args.extend(lease.command.iter().skip(1).map(OsString::from));
    let cleanup = TcloneContainerCleanup::new(&podman, &container_name);
    let started_at_ms = unix_millis()?;
    let mut child = Command::new(&podman).args(&run_args).spawn()?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if unix_millis()? >= lease.expires_at_ms {
            timed_out = true;
            let _ = Command::new(&podman)
                .args(["kill", &container_name])
                .status();
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(CELL_POLL_INTERVAL_MS));
    };
    drop(cleanup);
    let record = CapabilityCellRecord {
        schema_version: CELL_LEASE_SCHEMA_VERSION,
        cell_id,
        lease_id: lease.lease_id.clone(),
        source_run_id: source.run_id.clone(),
        request: lease.request.clone(),
        command: lease.command.clone(),
        container_name,
        workspace_snapshot: snapshot.to_string_lossy().to_string(),
        started_at_ms,
        finished_at_ms: unix_millis()?,
        exit_code: status.code(),
        timed_out,
    };
    write_atomic_nofollow(
        &cell_root.join("record.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
    )?;
    Ok(record)
}

fn capability_cell_run_args(
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    container_name: &str,
    snapshot: &Path,
    now_ms: u64,
) -> io::Result<Vec<OsString>> {
    let remaining_ms = lease.expires_at_ms.saturating_sub(now_ms);
    if remaining_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "capability lease expired while preparing the cell",
        ));
    }
    let remaining_seconds = remaining_ms.saturating_add(999) / 1_000;
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--name"),
        OsString::from(container_name),
        OsString::from("--timeout"),
        OsString::from(remaining_seconds.to_string()),
        OsString::from("--network"),
        OsString::from("none"),
        OsString::from("--read-only"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--security-opt"),
        OsString::from("no-new-privileges"),
        OsString::from("--pids-limit"),
        OsString::from("256"),
        OsString::from("--cpus"),
        OsString::from("2"),
        OsString::from("--memory"),
        OsString::from("2g"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp:rw,noexec,nosuid,nodev,size=512m"),
        OsString::from("--tmpfs"),
        OsString::from("/run:rw,noexec,nosuid,nodev,size=64m"),
        OsString::from("--workdir"),
        OsString::from(&source.container_workspace),
        OsString::from("-e"),
        OsString::from("HOME=/tmp"),
        OsString::from("-e"),
        OsString::from(format!("GENSEE_CAPABILITY_LEASE_ID={}", lease.lease_id)),
        OsString::from("--entrypoint"),
        OsString::from(&lease.command[0]),
    ];
    for path in &lease.request.scope.read_paths {
        add_scope_mount(&mut args, snapshot, &source.container_workspace, path, "ro")?;
    }
    for path in &lease.request.scope.write_paths {
        add_scope_mount(&mut args, snapshot, &source.container_workspace, path, "rw")?;
    }
    args.push(OsString::from(&source.image));
    Ok(args)
}

fn copy_capability_scope(
    podman: &OsString,
    source: &TcloneRunRecord,
    lease: &CapabilityCellLease,
    snapshot: &Path,
) -> io::Result<()> {
    let paths = lease
        .request
        .scope
        .read_paths
        .iter()
        .chain(&lease.request.scope.write_paths)
        .collect::<BTreeSet<_>>();
    for relative in paths {
        let destination = snapshot.join(relative);
        if relative == "." {
            run_command_status(
                podman,
                &[
                    OsString::from("cp"),
                    OsString::from(format!(
                        "{}:{}/.",
                        source.container_name, source.container_workspace
                    )),
                    OsString::from(snapshot),
                ],
            )?;
            continue;
        }
        if destination.exists() {
            continue;
        }
        if let Some(parent) = destination.parent() {
            create_restrictive_dir_all(parent)?;
        }
        run_command_status(
            podman,
            &[
                OsString::from("cp"),
                OsString::from(format!(
                    "{}:{}/{}",
                    source.container_name, source.container_workspace, relative
                )),
                OsString::from(&destination),
            ],
        )?;
    }
    Ok(())
}

fn add_scope_mount(
    args: &mut Vec<OsString>,
    snapshot: &Path,
    container_workspace: &str,
    relative: &str,
    mode: &str,
) -> io::Result<()> {
    let host_path = snapshot.join(relative);
    let canonical = fs::canonicalize(&host_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("capability path does not exist in source snapshot: {relative}"),
        )
    })?;
    let canonical_snapshot = fs::canonicalize(snapshot)?;
    if !canonical.starts_with(&canonical_snapshot) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("capability path resolves outside source snapshot: {relative}"),
        ));
    }
    let target = Path::new(container_workspace).join(relative);
    args.push(OsString::from("-v"));
    args.push(OsString::from(format!(
        "{}:{}:{mode},Z",
        canonical.display(),
        target.display()
    )));
    Ok(())
}

fn inspect_capability_cell(args: Vec<OsString>) -> io::Result<()> {
    if env::var_os("GENSEE_TCLONE_HOST_CONTROL_CALLER").is_some() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cell inspection is host-only",
        ));
    }
    let cell_id = tclone_target_arg(&args, "usage: gensee run cell inspect <cell-id> [--json]")?;
    let record = read_nofollow_to_string(&capability_cell_path(&cell_id)?.join("record.json"))?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{record}");
    } else {
        let parsed: CapabilityCellRecord = serde_json::from_str(&record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        println!("cell: {}", parsed.cell_id);
        println!("source: {}", parsed.source_run_id);
        println!("lease: {}", parsed.lease_id);
        println!(
            "exit: {:?} timed_out={}",
            parsed.exit_code, parsed.timed_out
        );
        println!("snapshot: {}", parsed.workspace_snapshot);
    }
    Ok(())
}

fn capability_lease_path(lease_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(lease_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid lease id",
        ));
    }
    Ok(default_root()?
        .join("tclone-capability-leases")
        .join(format!("{lease_id}.json")))
}

fn capability_cell_path(cell_id: &str) -> io::Result<PathBuf> {
    if !tclone_is_safe_token(cell_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cell id",
        ));
    }
    Ok(default_root()?
        .join("tclone-capability-cells")
        .join(cell_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gensee_crate_rules::capability::{CapabilityScope, EffectScope};

    fn request() -> CapabilityRequest {
        CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
            operation_class: "workspace_mutation".to_string(),
            effect_scope: EffectScope::ReversibleLocal,
            execution_boundary: ExecutionBoundary::IsolatedCell,
            capabilities: vec![
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
                Capability::ProcessExecution,
            ],
            scope: CapabilityScope {
                read_paths: vec!["Cargo.toml".to_string()],
                write_paths: vec!["Cargo.lock".to_string()],
                ..CapabilityScope::default()
            },
            lease_ttl_seconds: 300,
            source_must_not_execute: true,
            inspect_before_commit: true,
        }
    }

    fn source_record() -> TcloneRunRecord {
        TcloneRunRecord {
            run_id: "run_1".to_string(),
            parent_run_id: None,
            role: "source".to_string(),
            status: "running".to_string(),
            container_name: "source".to_string(),
            container_id: None,
            source_container: None,
            host_control_owner_run_id: None,
            fork_prefix: None,
            fork_group_id: None,
            fork_index: None,
            fork_count: None,
            fork_approach: None,
            image: "image".to_string(),
            workspace: "/repo".to_string(),
            container_workspace: "/workspace".to_string(),
            container_home: "/home/gensee".to_string(),
            agent_cmd: vec![],
            fork_base_git_head: None,
            fork_base_overlay_lowerdir: None,
            fork_overlay_upperdir: None,
            started_at_ms: 1,
            updated_at_ms: 1,
            exit_code: None,
        }
    }

    #[test]
    fn cell_request_rejects_unbrokered_authority() {
        for capability in [
            Capability::NetworkEgress,
            Capability::IdentityUse,
            Capability::PrivilegedExecution,
            Capability::ExternalMutation,
        ] {
            let mut request = request();
            request.capabilities.push(capability);
            assert_eq!(
                validate_cell_request(&request).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn cell_request_rejects_path_traversal() {
        let mut request = request();
        request.scope.write_paths = vec!["../outside".to_string()];
        assert_eq!(
            validate_cell_request(&request).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn whole_workspace_selector_copies_contents_even_when_snapshot_root_exists() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("gensee-cell-dot-scope-{}", Uuid::new_v4()));
        let snapshot = root.join("snapshot");
        fs::create_dir_all(&snapshot).unwrap();
        let fake_podman = root.join("podman");
        fs::write(
            &fake_podman,
            "#!/bin/sh\nif [ \"$1\" = cp ]; then printf copied > \"$3/copied.txt\"; fi\n",
        )
        .unwrap();
        fs::set_permissions(&fake_podman, fs::Permissions::from_mode(0o700)).unwrap();
        let mut request = request();
        request.scope.read_paths = vec![".".to_string()];
        request.scope.write_paths.clear();
        request
            .capabilities
            .retain(|capability| *capability != Capability::FilesystemWrite);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_dot".to_string(),
            source_run_id: "run_1".to_string(),
            request,
            command: vec!["true".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: None,
        };

        copy_capability_scope(
            &fake_podman.into_os_string(),
            &source_record(),
            &lease,
            &snapshot,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(snapshot.join("copied.txt")).unwrap(),
            "copied"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_lease_is_source_bound_expiring_and_single_use() {
        let _guard = crate::cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-cell-lease-{}", Uuid::new_v4()));
        env::set_var("GENSEE_HOME", &root);
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_one".to_string(),
            source_run_id: "run_one".to_string(),
            request: request(),
            command: vec!["true".to_string()],
            issued_at_ms: 100,
            expires_at_ms: 200,
            consumed_at_ms: None,
        };
        let path = capability_lease_path(&lease.lease_id).unwrap();
        create_restrictive_dir_all(path.parent().unwrap()).unwrap();
        write_atomic_nofollow(&path, &serde_json::to_vec(&lease).unwrap(), 0o600).unwrap();

        let consumed = consume_capability_lease("lease_one", "run_one", 150).unwrap();
        assert_eq!(consumed.consumed_at_ms, Some(150));
        assert_eq!(
            consume_capability_lease("lease_one", "run_one", 151)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cell_plan_is_fresh_confined_and_scope_mounted() {
        let root = env::temp_dir().join(format!("gensee-cell-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        let request = request();
        let lease = CapabilityCellLease {
            schema_version: CELL_LEASE_SCHEMA_VERSION,
            lease_id: "lease_1".to_string(),
            source_run_id: "run_1".to_string(),
            request,
            command: vec!["cargo".to_string(), "check".to_string()],
            issued_at_ms: 1,
            expires_at_ms: 2,
            consumed_at_ms: Some(1),
        };
        let source = source_record();

        let args = capability_cell_run_args(&source, &lease, "cell", &root, 1).unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--network", "none"]));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("--rm")));
        assert!(rendered.windows(2).any(|pair| pair == ["--timeout", "1"]));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("--read-only")));
        assert!(rendered.contains(&std::borrow::Cow::Borrowed("ALL")));
        assert!(rendered
            .windows(2)
            .any(|pair| pair == ["--entrypoint", "cargo"]));
        assert!(!rendered.iter().any(|arg| arg.contains("unconfined")));
        assert!(rendered.iter().any(|arg| arg.ends_with("/Cargo.toml:ro,Z")));
        assert!(rendered.iter().any(|arg| arg.ends_with("/Cargo.lock:rw,Z")));
        assert!(!rendered.iter().any(|arg| arg.contains(".codex")));
        fs::remove_dir_all(root).ok();
    }
}
