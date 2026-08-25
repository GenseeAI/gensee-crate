use crate::*;
use gensee_crate_rules::capability_broker::{BrokerGatewayEffectKind, BrokerResourceKind};
use gensee_crate_rules::provider_runtime::{
    ProviderAdapterResult, ProviderDecision, ProviderInvocation, ProviderOperation,
    PROVIDER_INVOCATION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_PROVIDER_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderRuntimeConfig {
    adapter_id: String,
    resource_kind: BrokerResourceKind,
    executable: String,
    executable_sha256: String,
    #[serde(default)]
    args: Vec<String>,
    working_directory: String,
    max_runtime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDispatchReceipt {
    schema_version: u32,
    invocation: ProviderInvocation,
    lease_digest: String,
    adapter_id: String,
    adapter_executable_digest: String,
    result: ProviderAdapterResult,
    host_signature: String,
}

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
    validate_provider_config(&config, lease.resource_kind)?;
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if unsafe { libc::geteuid() } == 0 {
            let mut ancestor = canonical.parent();
            while let Some(path) = ancestor {
                let metadata = fs::symlink_metadata(path)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(denied(
                        "provider config has an untrusted filesystem ancestor",
                    ));
                }
                ancestor = path.parent();
            }
        }
    }
    Ok(())
}

fn validate_provider_config(
    config: &ProviderRuntimeConfig,
    kind: BrokerResourceKind,
) -> io::Result<()> {
    if !safe_catalog_token(&config.adapter_id)
        || config.resource_kind != kind
        || config.max_runtime_seconds == 0
        || config.max_runtime_seconds > 900
        || config.args.len() > 64
        || config
            .args
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > 256 || arg.bytes().any(|b| b == 0))
    {
        return Err(denied("provider runtime config is invalid for the lease"));
    }
    let executable = Path::new(&config.executable);
    let working = Path::new(&config.working_directory);
    if !executable.is_absolute() || !working.is_absolute() {
        return Err(denied(
            "provider executable and working directory must be absolute",
        ));
    }
    validate_trusted_file(executable, &config.executable_sha256)?;
    validate_trusted_directory(working)
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
    let runtime = default_root()?
        .join("provider-runtime")
        .join(&invocation.invocation_id);
    fs::create_dir_all(&runtime)?;
    #[cfg(unix)]
    fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let output_path = runtime.join("adapter-output.json");
    let output = File::create(&output_path)?;
    let mut command = Command::new(&config.executable);
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
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn()?;
    if let Some(mut input) = child.stdin.take() {
        serde_json::to_writer(&mut input, invocation).map_err(json_error)?;
    }
    let deadline = Instant::now() + Duration::from_secs(config.max_runtime_seconds);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_provider_group(child.id());
            let _ = child.wait();
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "provider adapter exceeded its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        terminate_provider_group(child.id());
        return Err(denied("provider adapter failed"));
    }
    let result = read_provider_json(&output_path)?;
    let _ = fs::remove_dir_all(runtime);
    Ok(result)
}

#[cfg(unix)]
fn terminate_provider_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}
#[cfg(not(unix))]
fn terminate_provider_group(_pid: u32) {}

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

    #[cfg(unix)]
    #[test]
    fn exact_adapter_executes_without_shell_selection_or_ambient_environment() {
        use std::os::unix::fs::PermissionsExt;
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
}
