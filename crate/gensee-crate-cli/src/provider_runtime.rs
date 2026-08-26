use crate::*;
use gensee_crate_rules::capability_broker::{BrokerGatewayEffectKind, BrokerResourceKind};
use gensee_crate_rules::provider_runtime::{
    ProviderAdapterResult, ProviderDecision, ProviderDispatchReceipt, ProviderInvocation,
    ProviderOperation, ProviderRuntimeConfig, PROVIDER_INVOCATION_SCHEMA_VERSION,
};
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Child;

const MAX_PROVIDER_BYTES: u64 = 1024 * 1024;

pub(crate) fn handle_generic_provider(args: &[OsString]) -> io::Result<()> {
    let (command, rest) = args.split_first().ok_or_else(provider_usage_error)?;
    match command.to_str() {
        Some("dispatch") => dispatch(rest),
        Some("--help" | "-h") => {
            print_provider_usage();
            Ok(())
        }
        _ => Err(provider_usage_error()),
    }
}

fn dispatch(args: &[OsString]) -> io::Result<()> {
    reject_provider_options(args, &["--config", "--lease", "--request", "--output"])?;
    let config_path = required_provider_path(args, "--config")?;
    validate_trusted_config_path(&config_path)?;
    let config: ProviderRuntimeConfig = read_provider_json(&config_path)?;
    let invocation: ProviderInvocation =
        read_provider_json(&required_provider_path(args, "--request")?)?;
    let lease_id = required_provider_string(args, "--lease")?;
    if invocation.lease_id != lease_id {
        return Err(denied("provider invocation lease does not match command"));
    }
    let lease = load_active_broker_lease(&lease_id)?;
    if lease.operation_id != invocation.operation_id
        || lease.resource_kind != invocation.resource_kind()
    {
        return Err(denied(
            "provider invocation is not bound to the active lease",
        ));
    }
    let scope = lease
        .typed_scope
        .as_ref()
        .ok_or_else(|| denied("active lease has no typed scope"))?;
    invocation.validate_against(scope).map_err(denied)?;
    validate_provider_config(&config, lease.resource_kind, &lease.adapter_id)?;
    let result = execute_provider(&config, &invocation)?;
    verify_provider_result(&invocation, &result)?;
    let mut receipt = ProviderDispatchReceipt {
        schema_version: PROVIDER_INVOCATION_SCHEMA_VERSION,
        invocation,
        lease_digest: json_digest(&lease)?,
        adapter_id: config.adapter_id,
        adapter_executable_digest: config.executable_sha256,
        result,
        host_signature: String::new(),
    };
    receipt.host_signature = sign_host_evidence(
        "generic-provider-dispatch-v1",
        &serde_json::to_vec(&receipt).map_err(json_error)?,
    )?;
    write_provider_json(&required_provider_path(args, "--output")?, &receipt)
}

fn validate_trusted_config_path(path: &Path) -> io::Result<()> {
    let canonical = fs::canonicalize(path)?;
    validate_trusted_file(
        &canonical,
        &hash_provider_file(&canonical, MAX_PROVIDER_BYTES)?,
    )?;
    validate_trusted_ancestry(&canonical)?;
    Ok(())
}

fn validate_provider_config(
    config: &ProviderRuntimeConfig,
    kind: BrokerResourceKind,
    expected_adapter_id: &str,
) -> io::Result<()> {
    if !safe_catalog_token(&config.adapter_id)
        || config.adapter_id != expected_adapter_id
        || config.resource_kind != kind
        || config.max_runtime_seconds == 0
        || config.max_runtime_seconds > 900
        || config.args.len() > 64
        || config
            .args
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > 256 || arg.bytes().any(|b| b == 0))
    {
        return Err(denied(
            "provider runtime config is not the adapter selected by the lease",
        ));
    }
    let executable = Path::new(&config.executable);
    let working = Path::new(&config.working_directory);
    if !executable.is_absolute() || !working.is_absolute() {
        return Err(denied(
            "provider executable and working directory must be absolute",
        ));
    }
    validate_trusted_file(executable, &config.executable_sha256)?;
    validate_trusted_ancestry(executable)?;
    validate_trusted_directory(working)?;
    validate_trusted_ancestry(working)
}

fn validate_trusted_ancestry(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if unsafe { libc::geteuid() } == 0 {
            let mut ancestor = path.parent();
            while let Some(path) = ancestor {
                let metadata = fs::symlink_metadata(path)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(denied("provider path has an untrusted filesystem ancestor"));
                }
                ancestor = path.parent();
            }
        }
    }
    Ok(())
}

fn validate_trusted_file(path: &Path, expected: &str) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024 * 1024
    {
        return Err(denied("provider executable is not a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 || (unsafe { libc::geteuid() } == 0 && metadata.uid() != 0)
        {
            return Err(denied("provider executable is not trusted"));
        }
    }
    let digest = hash_provider_file(path, 1024 * 1024 * 1024)?;
    if digest != expected {
        return Err(denied("provider executable digest changed"));
    }
    Ok(())
}

fn validate_trusted_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(denied("provider working directory is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 || (unsafe { libc::geteuid() } == 0 && metadata.uid() != 0)
        {
            return Err(denied("provider working directory is not trusted"));
        }
    }
    Ok(())
}

fn execute_provider(
    config: &ProviderRuntimeConfig,
    invocation: &ProviderInvocation,
) -> io::Result<ProviderAdapterResult> {
    let mut execution_subject = ProviderExecutionSubject::prepare(&invocation.invocation_id)?;
    let runtime = default_root()?
        .join("provider-runtime")
        .join(&invocation.invocation_id);
    fs::create_dir_all(&runtime)?;
    #[cfg(unix)]
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    let executable_snapshot = snapshot_provider_executable(config, &runtime)?;
    let output_path = runtime.join("adapter-output.json");
    let output = File::create(&output_path)?;
    let mut command = Command::new(&executable_snapshot);
    command
        .args(&config.args)
        .current_dir(&config.working_directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        #[cfg(target_os = "linux")]
        let cgroup_procs = execution_subject.cgroup_procs_cstring()?;
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == 0 {
                #[cfg(target_os = "linux")]
                attach_provider_child_to_cgroup(&cgroup_procs)?;
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let child = command.spawn()?;
    let mut child = ProviderChildGuard::new(child);
    if let Some(mut input) = child.child_mut().stdin.take() {
        serde_json::to_writer(&mut input, invocation).map_err(json_error)?;
    }
    let deadline = Instant::now() + Duration::from_secs(config.max_runtime_seconds);
    let status = loop {
        if let Some(status) = child.child_mut().try_wait()? {
            child.mark_reaped();
            break status;
        }
        if Instant::now() >= deadline {
            execution_subject.drain()?;
            let _ = child.child_mut().wait();
            child.mark_reaped();
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "provider adapter exceeded its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    execution_subject.drain()?;
    if !status.success() {
        return Err(denied("provider adapter failed"));
    }
    let result = read_provider_json(&output_path)?;
    let _ = fs::remove_dir_all(runtime);
    Ok(result)
}

struct ProviderChildGuard {
    child: Child,
    reaped: bool,
}

impl ProviderChildGuard {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for ProviderChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// A provider adapter may create descendants, so the direct child's process
/// group is not a sufficient lifetime boundary. Linux dispatch therefore
/// creates a private cgroup before spawn, attaches the child before `exec`, and
/// recursively kills and verifies that cgroup empty before accepting any
/// adapter result. Other platforms fail closed until they have an equivalent
/// non-escapable execution-subject implementation.
struct ProviderExecutionSubject {
    #[cfg(target_os = "linux")]
    cgroup_path: PathBuf,
    drained: bool,
}

impl ProviderExecutionSubject {
    fn prepare(invocation_id: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let subject_id = format!("provider-{invocation_id}-{}", uuid::Uuid::new_v4().simple());
            let cgroup_path = gensee_crate_linux::default_agent_cgroup_path(&subject_id);
            gensee_crate_linux::create_agent_cgroup(&cgroup_path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("cannot create provider execution cgroup: {error}"),
                )
            })?;
            Ok(Self {
                cgroup_path,
                drained: false,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = invocation_id;
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "provider dispatch requires a Linux cgroup-v2 execution subject",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn cgroup_procs_cstring(&self) -> io::Result<CString> {
        use std::os::unix::ffi::OsStrExt;

        CString::new(self.cgroup_path.join("cgroup.procs").as_os_str().as_bytes())
            .map_err(|_| denied("provider cgroup path contains an interior NUL"))
    }

    fn drain(&mut self) -> io::Result<()> {
        if self.drained {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            if !gensee_crate_linux::kill_and_drain_agent_cgroup(
                &self.cgroup_path,
                Duration::from_secs(2),
            )? {
                return Err(denied("provider execution cgroup did not drain"));
            }
            gensee_crate_linux::remove_agent_cgroup(&self.cgroup_path)?;
            self.drained = true;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "provider dispatch requires a Linux cgroup-v2 execution subject",
            ))
        }
    }
}

impl Drop for ProviderExecutionSubject {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if !self.drained {
            let _ = gensee_crate_linux::kill_and_drain_agent_cgroup(
                &self.cgroup_path,
                Duration::from_secs(2),
            );
            let _ = gensee_crate_linux::remove_agent_cgroup(&self.cgroup_path);
        }
    }
}

#[cfg(target_os = "linux")]
fn attach_provider_child_to_cgroup(cgroup_procs: &CString) -> io::Result<()> {
    // This runs after fork and before exec, so use only async-signal-safe libc
    // calls. Writing PID 0 to cgroup.procs attaches the writing process.
    let fd = unsafe {
        libc::open(
            cgroup_procs.as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = b"0\n";
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    let write_error = (written != bytes.len() as isize).then(io::Error::last_os_error);
    let close_result = unsafe { libc::close(fd) };
    if let Some(error) = write_error {
        return Err(error);
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn snapshot_provider_executable(
    config: &ProviderRuntimeConfig,
    runtime: &Path,
) -> io::Result<PathBuf> {
    let mut input = File::open(&config.executable)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 * 1024 {
        return Err(denied("provider executable is not a bounded regular file"));
    }
    let snapshot = runtime.join("adapter-executable");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o500);
    let mut output = options.open(&snapshot)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| denied("provider executable size overflow"))?;
        if total > 1024 * 1024 * 1024 {
            return Err(denied("provider executable exceeds limit"));
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    let digest = format!("sha256:{:x}", hasher.finalize());
    if digest != config.executable_sha256 {
        return Err(denied(
            "provider executable changed before it could be pinned",
        ));
    }
    output.sync_all()?;
    drop(output);
    #[cfg(unix)]
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o500))?;
    File::open(runtime)?.sync_all()?;
    Ok(snapshot)
}

fn verify_provider_result(
    invocation: &ProviderInvocation,
    result: &ProviderAdapterResult,
) -> io::Result<()> {
    let (kind, target, action) = expected_effect(&invocation.operation);
    if result.schema_version != PROVIDER_INVOCATION_SCHEMA_VERSION
        || result.invocation_id != invocation.invocation_id
        || result.request_digest != invocation.request_digest
        || result.effect_kind != kind
        || result.target != target
        || result.action != action
        || result.decision != ProviderDecision::Completed
        || result
            .output_digest
            .as_deref()
            .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err(denied(
            "provider result is not bound to the authorized invocation",
        ));
    }
    Ok(())
}

fn expected_effect(operation: &ProviderOperation) -> (BrokerGatewayEffectKind, String, String) {
    match operation {
        ProviderOperation::CredentialUse { audience, action } => (
            BrokerGatewayEffectKind::SecretAccess,
            audience.clone(),
            action.clone(),
        ),
        ProviderOperation::HttpApiCall {
            origin,
            method,
            path,
            ..
        } => (
            BrokerGatewayEffectKind::ApiRequest,
            format!("{origin}{path}"),
            method.clone(),
        ),
        ProviderOperation::BrowserSession { origin, action, .. } => (
            BrokerGatewayEffectKind::BrowserAction,
            origin.clone(),
            action.clone(),
        ),
        ProviderOperation::DatabaseTransaction {
            service,
            database,
            action,
            ..
        } => (
            BrokerGatewayEffectKind::DatabaseRequest,
            format!("{service}/{database}"),
            action.clone(),
        ),
        ProviderOperation::MessageDelivery {
            channel,
            destination,
            action,
        } => (
            BrokerGatewayEffectKind::MessageDelivery,
            format!("{channel}:{destination}"),
            action.clone(),
        ),
        ProviderOperation::CiJobInvocation {
            runner, workflow, ..
        } => (
            BrokerGatewayEffectKind::CiJobInvocation,
            format!("{runner}/{workflow}"),
            "invoke".into(),
        ),
        ProviderOperation::SecretRead { handle, .. } => (
            BrokerGatewayEffectKind::SecretAccess,
            handle.clone(),
            "read".into(),
        ),
        ProviderOperation::FilesystemMutation {
            root,
            path,
            operation,
        } => (
            BrokerGatewayEffectKind::FilesystemMutation,
            format!("{root}{path}"),
            operation.clone(),
        ),
        ProviderOperation::CloudControlAction {
            provider,
            resource,
            action,
        } => (
            BrokerGatewayEffectKind::CloudAction,
            format!("{provider}:{resource}"),
            action.clone(),
        ),
    }
}

fn hash_provider_file(path: &Path, max: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max {
            return Err(denied("provider executable exceeds limit"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
fn json_digest(value: &impl Serialize) -> io::Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(json_error)?)
    ))
}
fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn read_provider_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_PROVIDER_BYTES
    {
        return Err(denied("provider JSON is not a bounded regular file"));
    }
    serde_json::from_reader(File::open(path)?).map_err(json_error)
}
fn write_provider_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    write_atomic_nofollow(
        path,
        &serde_json::to_vec_pretty(value).map_err(json_error)?,
        0o600,
    )
}
fn reject_provider_options(args: &[OsString], valued: &[&str]) -> io::Result<()> {
    let mut i = 0;
    while i < args.len() {
        let value = args[i].to_str().ok_or_else(provider_usage_error)?;
        if valued.contains(&value) && i + 1 < args.len() {
            i += 2
        } else {
            return Err(provider_usage_error());
        }
    }
    Ok(())
}
fn required_provider_string(args: &[OsString], name: &str) -> io::Result<String> {
    let i = args
        .iter()
        .position(|v| v == name)
        .ok_or_else(provider_usage_error)?;
    args.get(i + 1)
        .and_then(|v| v.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(provider_usage_error)
}
fn required_provider_path(args: &[OsString], name: &str) -> io::Result<PathBuf> {
    required_provider_string(args, name).map(PathBuf::from)
}
fn denied(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, message.into())
}
fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error)
}
fn provider_usage_error() -> io::Error {
    io::Error::new(ErrorKind::InvalidInput,"usage: gensee boundary provider dispatch --config <config.json> --lease <id> --request <request.json> --output <receipt.json>")
}
fn print_provider_usage() {
    println!("gensee boundary provider\n\nUSAGE:\n  gensee boundary provider dispatch --config <config.json> --lease <id> --request <request.json> --output <receipt.json>");
}

#[cfg(test)]
mod tests {
    use super::*;
    use gensee_crate_rules::capability_broker::BrokerCapabilityScope;

    #[test]
    fn provider_config_must_match_the_adapter_selected_by_the_lease() {
        let config = ProviderRuntimeConfig {
            adapter_id: "different_adapter".into(),
            resource_kind: BrokerResourceKind::CloudControlAction,
            executable: "/does/not/matter".into(),
            executable_sha256: format!("sha256:{}", "11".repeat(32)),
            args: Vec::new(),
            working_directory: "/does/not/matter".into(),
            max_runtime_seconds: 1,
        };
        assert_eq!(
            validate_provider_config(
                &config,
                BrokerResourceKind::CloudControlAction,
                "selected_adapter"
            )
            .unwrap_err()
            .kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn invocation_cannot_expand_any_typed_scope() {
        let scope = BrokerCapabilityScope::CloudControlAction {
            provider: "cloud".into(),
            resource: "project/a".into(),
            actions: vec!["read".into()],
        };
        let request = ProviderInvocation {
            schema_version: 1,
            invocation_id: "invoke".into(),
            operation_id: "op".into(),
            lease_id: "lease".into(),
            request_digest: format!("sha256:{}", "11".repeat(32)),
            operation: ProviderOperation::CloudControlAction {
                provider: "cloud".into(),
                resource: "project/b".into(),
                action: "delete".into(),
            },
        };
        assert!(request.validate_against(&scope).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_adapter_executes_without_shell_selection_or_ambient_environment() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0
            || !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
        {
            return;
        }
        let _guard = cli_test_env_lock();
        let root = env::temp_dir().join(format!("gensee-provider-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("GENSEE_HOME", root.join("state"));
        let executable = root.join("adapter.sh");
        let request_digest = format!("sha256:{}", "11".repeat(32));
        let result = ProviderAdapterResult {
            schema_version: 1,
            invocation_id: "invoke_test".into(),
            decision: ProviderDecision::Completed,
            effect_kind: BrokerGatewayEffectKind::CloudAction,
            target: "cloud:project/a".into(),
            action: "read".into(),
            request_digest: request_digest.clone(),
            output_digest: None,
            occurred_at_ms: 1,
        };
        let script = format!(
            "#!/bin/sh\ncat >/dev/null\nif [ -n \"${{SHOULD_NOT_LEAK:-}}\" ]; then exit 7; fi\nprintf '%s\\n' '{}'\n",
            serde_json::to_string(&result)
                .unwrap()
                .replace('\'', "'\\''")
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        env::set_var("SHOULD_NOT_LEAK", "secret");
        let config = ProviderRuntimeConfig {
            adapter_id: "adapter".into(),
            resource_kind: BrokerResourceKind::CloudControlAction,
            executable: executable.to_string_lossy().into_owned(),
            executable_sha256: hash_provider_file(&executable, MAX_PROVIDER_BYTES).unwrap(),
            args: Vec::new(),
            working_directory: root.to_string_lossy().into_owned(),
            max_runtime_seconds: 5,
        };
        let invocation = ProviderInvocation {
            schema_version: 1,
            invocation_id: "invoke_test".into(),
            operation_id: "op_test".into(),
            lease_id: "lease_test".into(),
            request_digest,
            operation: ProviderOperation::CloudControlAction {
                provider: "cloud".into(),
                resource: "project/a".into(),
                action: "read".into(),
            },
        };
        let observed = execute_provider(&config, &invocation).unwrap();
        verify_provider_result(&invocation, &observed).unwrap();
        env::remove_var("SHOULD_NOT_LEAK");
        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_adapter_cannot_leave_detached_descendant() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } != 0
            || !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
        {
            return;
        }
        let _guard = cli_test_env_lock();
        let root = env::temp_dir().join(format!(
            "gensee-provider-detached-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("GENSEE_HOME", root.join("state"));
        let executable = root.join("adapter.sh");
        let marker = root.join("descendant.marker");
        let pid_file = root.join("descendant.pid");
        let request_digest = format!("sha256:{}", "61".repeat(32));
        let result = ProviderAdapterResult {
            schema_version: 1,
            invocation_id: "invoke_detached".into(),
            decision: ProviderDecision::Completed,
            effect_kind: BrokerGatewayEffectKind::CloudAction,
            target: "cloud:project/a".into(),
            action: "read".into(),
            request_digest: request_digest.clone(),
            output_digest: None,
            occurred_at_ms: 1,
        };
        let script = format!(
            "#!/bin/sh\nsetsid sh -c 'while :; do printf x >>\"$1\"; sleep 0.02; done' sh '{}' >/dev/null 2>&1 &\nprintf '%s\\n' \"$!\" >'{}'\ni=0\nwhile [ ! -s '{}' ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done\nwhile IFS= read -r _; do :; done\nprintf '%s\\n' '{}'\n",
            marker.display(),
            pid_file.display(),
            marker.display(),
            serde_json::to_string(&result)
                .unwrap()
                .replace('\'', "'\\''")
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        let config = ProviderRuntimeConfig {
            adapter_id: "adapter".into(),
            resource_kind: BrokerResourceKind::CloudControlAction,
            executable: executable.to_string_lossy().into_owned(),
            executable_sha256: hash_provider_file(&executable, MAX_PROVIDER_BYTES).unwrap(),
            args: Vec::new(),
            working_directory: root.to_string_lossy().into_owned(),
            max_runtime_seconds: 5,
        };
        let invocation = ProviderInvocation {
            schema_version: 1,
            invocation_id: "invoke_detached".into(),
            operation_id: "op_detached".into(),
            lease_id: "lease_detached".into(),
            request_digest,
            operation: ProviderOperation::CloudControlAction {
                provider: "cloud".into(),
                resource: "project/a".into(),
                action: "read".into(),
            },
        };

        let observed = execute_provider(&config, &invocation).unwrap();
        verify_provider_result(&invocation, &observed).unwrap();
        let size = fs::metadata(&marker).unwrap().len();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(fs::metadata(&marker).unwrap().len(), size);
        let pid = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0);

        env::remove_var("GENSEE_HOME");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn provider_snapshot_executes_admitted_bytes_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            env::temp_dir().join(format!("gensee-provider-snapshot-{}", uuid::Uuid::new_v4()));
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = root.join("adapter.sh");
        fs::write(&executable, b"#!/bin/sh\necho admitted\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        let config = ProviderRuntimeConfig {
            adapter_id: "adapter".into(),
            resource_kind: BrokerResourceKind::CloudControlAction,
            executable: executable.to_string_lossy().into_owned(),
            executable_sha256: hash_provider_file(&executable, MAX_PROVIDER_BYTES).unwrap(),
            args: Vec::new(),
            working_directory: root.to_string_lossy().into_owned(),
            max_runtime_seconds: 5,
        };
        let snapshot = snapshot_provider_executable(&config, &runtime).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&executable, b"#!/bin/sh\necho replaced\n").unwrap();
        let output = Command::new(snapshot).output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"admitted\n");
        fs::remove_dir_all(root).unwrap();
    }
}
