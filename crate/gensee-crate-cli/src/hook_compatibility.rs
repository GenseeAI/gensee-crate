use crate::*;

pub(crate) const NATIVE_HOOK_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub(crate) const NATIVE_HOOK_EVIDENCE_TTL_MS: u64 = 60_000;
pub(crate) const NATIVE_HOOK_EVIDENCE_DIR: &str = "native-hook-invocations";

pub(crate) const HOOK_COMPATIBILITY_NOTICE_SCHEMA_VERSION: u32 = 1;
pub(crate) const HOOK_COMPATIBILITY_NOTICE_INTERVAL_MS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const HOOK_COMPATIBILITY_NOTICE_FILE: &str = "hook-compatibility-notices.json";

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct NativeHookInvocationKey {
    pub(crate) provider: String,
    pub(crate) session_id: String,
    pub(crate) event_name: String,
    pub(crate) tool_use_id: Option<String>,
    pub(crate) invocation_id: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct NativeHookInvocationEvidence {
    schema_version: u32,
    observed_at_ms: u64,
    key: NativeHookInvocationKey,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct HookCompatibilityNoticeState {
    schema_version: u32,
    last_notice_at_ms: BTreeMap<String, u64>,
}

impl Default for HookCompatibilityNoticeState {
    fn default() -> Self {
        Self {
            schema_version: HOOK_COMPATIBILITY_NOTICE_SCHEMA_VERSION,
            last_notice_at_ms: BTreeMap::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HookInvocationRoute<'a> {
    ProcessAs(&'a str),
    Suppress { native_provider: &'static str },
}

fn nonempty_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalized_event_name(provider: &str, value: &Value) -> Option<String> {
    let raw = nonempty_string(value, "hook_event_name")?;
    if provider != PROVIDER_CURSOR {
        return Some(raw);
    }
    Some(normalize_cursor_hook_event_name(&raw).to_string())
}

pub(crate) fn native_hook_invocation_key(
    provider: &str,
    payload: &str,
) -> Option<NativeHookInvocationKey> {
    if !matches!(provider, PROVIDER_CURSOR | PROVIDER_VSCODE) {
        return None;
    }
    let value = serde_json::from_str::<Value>(payload).ok()?;
    let session_id = if provider == PROVIDER_CURSOR {
        nonempty_string(&value, "conversation_id").or_else(|| nonempty_string(&value, "session_id"))
    } else {
        nonempty_string(&value, "session_id")
    }?;
    let event_name = normalized_event_name(provider, &value)?;
    let tool_use_id = nonempty_string(&value, "tool_use_id");
    let invocation_id = if tool_use_id.is_none() {
        nonempty_string(&value, "generation_id").or_else(|| nonempty_string(&value, "timestamp"))
    } else {
        None
    };

    // Without either a tool-call ID or a host-generated invocation ID, an old
    // marker for a repeated lifecycle event could suppress a different event.
    // Prefer a harmless duplicate over that fail-open ambiguity.
    if tool_use_id.is_none() && invocation_id.is_none() {
        return None;
    }

    Some(NativeHookInvocationKey {
        provider: provider.to_string(),
        session_id,
        event_name,
        tool_use_id,
        invocation_id,
    })
}

fn evidence_dir(root: &Path) -> PathBuf {
    root.join(NATIVE_HOOK_EVIDENCE_DIR)
}

fn ensure_evidence_dir(root: &Path) -> io::Result<PathBuf> {
    let dir = evidence_dir(root);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::metadata(&dir)?.permissions();
        if permissions.mode() & 0o777 != 0o700 {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(dir)
}

fn evidence_path(root: &Path, key: &NativeHookInvocationKey) -> io::Result<PathBuf> {
    let encoded = serde_json::to_vec(key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let digest = Sha256::digest(encoded);
    Ok(evidence_dir(root).join(format!("{digest:x}.json")))
}

fn evidence_is_recent(evidence: &NativeHookInvocationEvidence, now_ms: u64) -> bool {
    evidence.schema_version == NATIVE_HOOK_EVIDENCE_SCHEMA_VERSION
        && now_ms >= evidence.observed_at_ms
        && now_ms - evidence.observed_at_ms <= NATIVE_HOOK_EVIDENCE_TTL_MS
}

fn prune_native_hook_invocation_evidence(root: &Path, now_ms: u64) -> io::Result<()> {
    let dir = evidence_dir(root);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if path.extension().and_then(|extension| extension.to_str()) != Some("json")
            && !name.contains(".claim.")
        {
            continue;
        }
        let keep = fs::read_to_string(&path)
            .ok()
            .and_then(|contents| {
                serde_json::from_str::<NativeHookInvocationEvidence>(&contents).ok()
            })
            .is_some_and(|evidence| evidence_is_recent(&evidence, now_ms));
        if !keep {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

pub(crate) fn record_native_hook_invocation_evidence_at(
    root: &Path,
    provider: &str,
    payload: &str,
    now_ms: u64,
) -> io::Result<bool> {
    let Some(key) = native_hook_invocation_key(provider, payload) else {
        return Ok(false);
    };
    ensure_evidence_dir(root)?;
    let _ = prune_native_hook_invocation_evidence(root, now_ms);
    let path = evidence_path(root, &key)?;
    let evidence = NativeHookInvocationEvidence {
        schema_version: NATIVE_HOOK_EVIDENCE_SCHEMA_VERSION,
        observed_at_ms: now_ms,
        key,
    };
    let contents = serde_json::to_string_pretty(&evidence)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        + "\n";
    write_file_atomically(&path, contents.as_bytes(), Some(0o600))?;
    Ok(true)
}

pub(crate) fn take_recent_native_hook_invocation_evidence_at(
    root: &Path,
    provider: &str,
    payload: &str,
    now_ms: u64,
) -> io::Result<bool> {
    let Some(key) = native_hook_invocation_key(provider, payload) else {
        return Ok(false);
    };
    let path = evidence_path(root, &key)?;
    let claim_path = path.with_file_name(format!(
        ".{}.claim.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("native-hook-evidence"),
        std::process::id(),
        now_ms
    ));
    match fs::rename(&path, &claim_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let contents = match fs::read_to_string(&claim_path) {
        Ok(contents) => contents,
        Err(error) => {
            let _ = fs::remove_file(claim_path);
            return Err(error);
        }
    };
    let evidence = match serde_json::from_str::<NativeHookInvocationEvidence>(&contents) {
        Ok(evidence) => evidence,
        Err(_) => {
            let _ = fs::remove_file(claim_path);
            return Ok(false);
        }
    };
    let _ = fs::remove_file(claim_path);
    if evidence.key != key || !evidence_is_recent(&evidence, now_ms) {
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn record_native_hook_invocation_evidence(
    provider: &str,
    payload: &str,
) -> io::Result<bool> {
    record_native_hook_invocation_evidence_at(&default_root()?, provider, payload, unix_millis()?)
}

pub(crate) fn take_recent_native_hook_invocation_evidence(
    provider: &str,
    payload: &str,
) -> io::Result<bool> {
    take_recent_native_hook_invocation_evidence_at(
        &default_root()?,
        provider,
        payload,
        unix_millis()?,
    )
}

pub(crate) fn route_hook_invocation<'a>(
    provider: &'a str,
    payload: &str,
    native_hook_observed: impl FnOnce(&'static str, &str) -> bool,
) -> HookInvocationRoute<'a> {
    let Some(native_provider) = compatibility_payload_provider(payload) else {
        return HookInvocationRoute::ProcessAs(provider);
    };
    if native_provider == provider {
        return HookInvocationRoute::ProcessAs(provider);
    }
    if native_hook_observed(native_provider, payload) {
        HookInvocationRoute::Suppress { native_provider }
    } else {
        HookInvocationRoute::ProcessAs(native_provider)
    }
}

pub(crate) fn hook_compatibility_notice_due(
    root: &Path,
    native_provider: &str,
    now_ms: u64,
) -> io::Result<bool> {
    fs::create_dir_all(root)?;
    let path = root.join(HOOK_COMPATIBILITY_NOTICE_FILE);
    let mut state = match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str::<HookCompatibilityNoticeState>(&contents)
            .ok()
            .filter(|state| state.schema_version == HOOK_COMPATIBILITY_NOTICE_SCHEMA_VERSION)
            .unwrap_or_default(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            HookCompatibilityNoticeState::default()
        }
        Err(error) => return Err(error),
    };

    if state
        .last_notice_at_ms
        .get(native_provider)
        .is_some_and(|last_notice_ms| {
            now_ms >= *last_notice_ms
                && now_ms - *last_notice_ms < HOOK_COMPATIBILITY_NOTICE_INTERVAL_MS
        })
    {
        return Ok(false);
    }

    state
        .last_notice_at_ms
        .insert(native_provider.to_string(), now_ms);
    let contents = serde_json::to_string_pretty(&state)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        + "\n";
    write_file_atomically(&path, contents.as_bytes(), Some(0o600))?;
    Ok(true)
}

pub(crate) fn hook_compatibility_suppression_warning(
    source_provider: &str,
    native_provider: &str,
) -> String {
    format!(
        "gensee hook: warning: suppressed a {source_provider} compatibility invocation after observing the matching native {native_provider} invocation. If the native event is missing from Gensee, inspect the host hook log. This notice repeats at most once every 24 hours per native provider."
    )
}

pub(crate) fn warn_hook_compatibility_suppressed(source_provider: &str, native_provider: &str) {
    let warning = hook_compatibility_suppression_warning(source_provider, native_provider);
    let result = default_root()
        .and_then(|root| hook_compatibility_notice_due(&root, native_provider, unix_millis()?));
    match result {
        Ok(true) => eprintln!("{warning}"),
        Ok(false) => {}
        Err(error) => eprintln!("{warning} Notice rate limiting could not be persisted: {error}"),
    }
}
