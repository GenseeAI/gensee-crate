use crate::*;
use serde::{Deserialize, Serialize};

const TELEMETRY_SCHEMA_VERSION: u32 = 1;
const DEFAULT_BATCH_SIZE: usize = 200;
const DEFAULT_ENDPOINT: &str = "https://agent-telemetry.gensee.ai/v1/telemetry/batch";
const TELEMETRY_BATCH_FILE: &str = "telemetry-events-upload.jsonl";
const TELEMETRY_FLUSH_LOCK_FILE: &str = "telemetry-flush.lock";
const TELEMETRY_PRIVACY_NOTICE: &str =
    "Telemetry is completely anonymized and only aggregated statistics are collected.";
const TELEMETRY_SUPPORT_NOTICE: &str = "This helps us better support your needs.";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelemetryConfig {
    schema_version: u32,
    install_id: String,
    collection_enabled: bool,
    remote_enabled: bool,
    consent_state: ConsentState,
    endpoint: String,
    api_key: Option<String>,
    batch_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentState {
    Unknown,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelemetryEvent {
    event_id: String,
    event_name: String,
    ts_ms: u64,
    install_id: String,
    app_version: String,
    platform: String,
    props: Value,
}

#[derive(Debug, Serialize)]
struct TelemetryBatch {
    schema_version: u32,
    install_id: String,
    app_version: String,
    platform: String,
    sent_at_ms: u64,
    idempotency_key: String,
    events: Vec<TelemetryEvent>,
}

pub(crate) struct TelemetryClient {
    root: PathBuf,
    config: TelemetryConfig,
}

struct TelemetryFlushLock {
    path: PathBuf,
}

impl Drop for TelemetryFlushLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl TelemetryConfig {
    fn new() -> Self {
        let endpoint = env::var("GENSEE_TELEMETRY_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let api_key = env::var("GENSEE_TELEMETRY_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            install_id: uuid::Uuid::new_v4().to_string(),
            collection_enabled: true,
            remote_enabled: telemetry_remote_enabled_default(),
            consent_state: telemetry_consent_default(),
            endpoint,
            api_key,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

fn telemetry_remote_enabled_default() -> bool {
    #[cfg(test)]
    {
        false
    }

    #[cfg(not(test))]
    {
        true
    }
}

fn telemetry_consent_default() -> ConsentState {
    if telemetry_remote_enabled_default() {
        ConsentState::Unknown
    } else {
        ConsentState::Disabled
    }
}

impl TelemetryClient {
    pub(crate) fn load_default() -> io::Result<Self> {
        let root = default_root()?;
        Self::load_for_root(root)
    }

    fn load_for_root(root: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        let path = telemetry_config_path(&root);
        let mut config = if path.exists() {
            let text = fs::read_to_string(&path)?;
            serde_json::from_str::<TelemetryConfig>(&text)
                .unwrap_or_else(|_| TelemetryConfig::new())
        } else {
            TelemetryConfig::new()
        };
        apply_env_overrides(&mut config);
        let client = Self { root, config };
        client.save_config()?;
        Ok(client)
    }

    fn save_config(&self) -> io::Result<()> {
        let path = telemetry_config_path(&self.root);
        let serialized = serde_json::to_string_pretty(&self.config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        fs::write(path, format!("{serialized}\n"))
    }

    fn queue_path(&self) -> PathBuf {
        self.root.join("telemetry-events.jsonl")
    }

    fn batch_path(&self) -> PathBuf {
        self.root.join(TELEMETRY_BATCH_FILE)
    }

    fn flush_lock_path(&self) -> PathBuf {
        self.root.join(TELEMETRY_FLUSH_LOCK_FILE)
    }

    fn try_acquire_flush_lock(&self) -> io::Result<Option<TelemetryFlushLock>> {
        let path = self.flush_lock_path();
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(Some(TelemetryFlushLock { path })),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn prepare_batch_for_upload(&self) -> io::Result<Option<PathBuf>> {
        let batch_path = self.batch_path();
        if batch_path.exists() {
            let text = fs::read_to_string(&batch_path)?;
            if text.trim().is_empty() {
                let _ = fs::remove_file(&batch_path);
                return Ok(None);
            }
            return Ok(Some(batch_path));
        }

        let queue_path = self.queue_path();
        if !queue_path.exists() {
            return Ok(None);
        }

        let queue_text = fs::read_to_string(&queue_path)?;
        if queue_text.trim().is_empty() {
            return Ok(None);
        }

        match fs::rename(&queue_path, &batch_path) {
            Ok(()) => Ok(Some(batch_path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn flush_in_background(&self) {
        if !self.config.collection_enabled || !self.config.remote_enabled {
            return;
        }
        let worker = Self {
            root: self.root.clone(),
            config: self.config.clone(),
        };
        let _ = thread::Builder::new()
            .name("gensee-telemetry-flush".to_string())
            .spawn(move || {
                let _ = worker.flush_once();
            });
    }

    fn record_event(&self, event_name: &str, props: Value) -> io::Result<()> {
        if !self.config.collection_enabled {
            return Ok(());
        }
        let props = redact_telemetry_props(event_name, props);
        let event = TelemetryEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_name: event_name.to_string(),
            ts_ms: unix_millis()?,
            install_id: self.config.install_id.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
            props,
        };
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.queue_path())?;
        let line = serde_json::to_string(&event)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        writeln!(file, "{line}")
    }

    fn flush_once(&self) -> io::Result<usize> {
        if !self.config.collection_enabled || !self.config.remote_enabled {
            return Ok(0);
        }
        let Some(_flush_lock) = self.try_acquire_flush_lock()? else {
            return Ok(0);
        };

        let Some(batch_path) = self.prepare_batch_for_upload()? else {
            return Ok(0);
        };

        let text = fs::read_to_string(&batch_path)?;
        if text.trim().is_empty() {
            let _ = fs::remove_file(&batch_path);
            return Ok(0);
        }

        let mut parsed = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<TelemetryEvent>(line) {
                parsed.push(event);
            }
        }
        if parsed.is_empty() {
            let _ = fs::remove_file(&batch_path);
            return Ok(0);
        }

        let count = parsed.len().min(self.config.batch_size.max(1));
        let batch = TelemetryBatch {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            install_id: self.config.install_id.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
            sent_at_ms: unix_millis()?,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            events: parsed[..count].to_vec(),
        };

        let mut request = ureq::post(&self.config.endpoint)
            .set("Content-Type", "application/json")
            .set("X-Idempotency-Key", &batch.idempotency_key)
            .set("User-Agent", "gensee-telemetry-client/0.1");
        if let Some(api_key) = self.config.api_key.as_deref() {
            request = request.set("X-API-Key", api_key);
        }

        let payload = serde_json::to_value(&batch)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        match request.send_json(payload) {
            Ok(response) if (200..300).contains(&response.status()) => {
                let remaining = parsed.into_iter().skip(count).collect::<Vec<_>>();
                if remaining.is_empty() {
                    let _ = fs::remove_file(&batch_path);
                } else {
                    rewrite_queue(&batch_path, &remaining)?;
                }
                Ok(count)
            }
            Ok(response) => Err(io::Error::other(format!(
                "telemetry upload failed with status {}",
                response.status()
            ))),
            Err(error) => Err(io::Error::other(format!(
                "telemetry upload failed: {error}"
            ))),
        }
    }

    fn ensure_first_run_consent(&mut self) -> io::Result<()> {
        if self.config.consent_state != ConsentState::Unknown {
            return Ok(());
        }
        if env::var("GENSEE_TELEMETRY_REMOTE")
            .ok()
            .is_some_and(|value| value == "0" || value.eq_ignore_ascii_case("false"))
        {
            self.config.remote_enabled = false;
            self.config.consent_state = ConsentState::Disabled;
            self.save_config()?;
            return Ok(());
        }

        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty");
        match tty {
            Ok(mut tty) => {
                writeln!(tty, "Gensee telemetry is enabled by default.")?;
                writeln!(tty, "{TELEMETRY_PRIVACY_NOTICE}")?;
                writeln!(
                    tty,
                    "Collected categories: lifecycle, policy outcomes, and tool/access stats."
                )?;
                writeln!(tty, "{TELEMETRY_SUPPORT_NOTICE}")?;
                write!(
                    tty,
                    "Press Enter to keep telemetry enabled, or type 'no' to disable remote upload: "
                )?;
                tty.flush()?;
                let mut reader = io::BufReader::new(tty.try_clone()?);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                if line.trim().eq_ignore_ascii_case("no") {
                    self.config.remote_enabled = false;
                    self.config.consent_state = ConsentState::Disabled;
                } else {
                    self.config.remote_enabled = true;
                    self.config.consent_state = ConsentState::Enabled;
                }
            }
            Err(_) => {
                self.config.remote_enabled = true;
                self.config.consent_state = ConsentState::Enabled;
            }
        }
        self.save_config()
    }

    fn status_json(&self) -> Value {
        json!({
            "schema_version": self.config.schema_version,
            "install_id": self.config.install_id,
            "collection_enabled": self.config.collection_enabled,
            "remote_enabled": self.config.remote_enabled,
            "consent_state": match self.config.consent_state {
                ConsentState::Unknown => "unknown",
                ConsentState::Enabled => "enabled",
                ConsentState::Disabled => "disabled",
            },
            "endpoint": self.config.endpoint,
            "batch_size": self.config.batch_size,
            "queue_path": self.queue_path(),
        })
    }
}

fn redact_telemetry_props(event_name: &str, mut props: Value) -> Value {
    let Some(props_object) = props.as_object_mut() else {
        return props;
    };

    match event_name {
        "policy_set_changed" => {
            if let Some(key) = props_object.get("key").and_then(|value| value.as_str()) {
                props_object.insert("key".to_string(), json!(telemetry_policy_key_bucket(key)));
            }
        }
        "policy_setup_completed" => {
            props_object.remove("path");
        }
        _ => {}
    }

    props
}

fn rewrite_queue(path: &Path, events: &[TelemetryEvent]) -> io::Result<()> {
    let mut output = String::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        output.push_str(&line);
        output.push('\n');
    }
    fs::write(path, output)
}

fn apply_env_overrides(config: &mut TelemetryConfig) {
    if let Ok(endpoint) = env::var("GENSEE_TELEMETRY_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            config.endpoint = endpoint;
        }
    }
    if let Ok(api_key) = env::var("GENSEE_TELEMETRY_API_KEY") {
        config.api_key = if api_key.trim().is_empty() {
            None
        } else {
            Some(api_key)
        };
    }
    if let Ok(remote) = env::var("GENSEE_TELEMETRY_REMOTE") {
        if remote == "0" || remote.eq_ignore_ascii_case("false") {
            config.remote_enabled = false;
            config.consent_state = ConsentState::Disabled;
        } else if remote == "1" || remote.eq_ignore_ascii_case("true") {
            config.remote_enabled = true;
            config.consent_state = ConsentState::Enabled;
        }
    }
    if let Ok(collection) = env::var("GENSEE_TELEMETRY_COLLECTION") {
        if collection == "0" || collection.eq_ignore_ascii_case("false") {
            config.collection_enabled = false;
        } else if collection == "1" || collection.eq_ignore_ascii_case("true") {
            config.collection_enabled = true;
        }
    }
}

fn telemetry_config_path(root: &Path) -> PathBuf {
    root.join("telemetry.json")
}

pub(crate) fn telemetry_bootstrap_for_command(command: &str) {
    if matches!(
        command,
        "hook" | "daemon" | "telemetry" | "help" | "--help" | "-h"
    ) {
        return;
    }
    let mut client = match TelemetryClient::load_default() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("gensee telemetry: {error}");
            return;
        }
    };
    if let Err(error) = client.ensure_first_run_consent() {
        eprintln!("gensee telemetry: {error}");
    }
    if let Err(error) = client.record_event(
        "app_started",
        json!({
            "command": command,
        }),
    ) {
        eprintln!("gensee telemetry: {error}");
    }
    if let Err(error) = client.record_event(
        "command_invoked",
        json!({
            "command": command,
        }),
    ) {
        eprintln!("gensee telemetry: {error}");
    }
    client.flush_in_background();
}

pub(crate) fn telemetry_record_policy_event(
    event: &AgentHookEvent,
    decision: &PolicyDecision,
    file_intents: &[FileIntent],
) {
    let client = match TelemetryClient::load_default() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("gensee telemetry: {error}");
            return;
        }
    };

    let decision_name = decision.action.hook_permission_decision();
    let tool_name = event.tool_name.as_deref().unwrap_or("unknown");
    let tool_category = telemetry_tool_category(tool_name);
    let command_category = event
        .tool_input_command
        .as_deref()
        .map(telemetry_command_category)
        .unwrap_or("none");
    let network_access_category = if event_has_network_egress(event) {
        "egress_attempt"
    } else {
        "none"
    };

    let file_categories = if file_intents.is_empty() {
        vec!["none".to_string()]
    } else {
        let mut values = BTreeMap::<String, bool>::new();
        for intent in file_intents {
            values.insert(intent.operation.clone(), true);
        }
        values.keys().cloned().collect::<Vec<_>>()
    };

    let _ = client.record_event(
        "policy_decision",
        json!({
            "provider": event.provider,
            "decision": decision_name,
            "session_id": event.session_id,
            "tool_use_id": event.tool_use_id,
            "tool_category": tool_category,
            "command_category": command_category,
            "network_access_category": network_access_category,
        }),
    );

    let _ = client.record_event(
        "tool_call",
        json!({
            "provider": event.provider,
            "tool_category": tool_category,
        }),
    );

    if decision
        .findings
        .iter()
        .any(|finding| finding.rule_id == "policy_unparsed_vscode_file_tool")
    {
        let _ = client.record_event(
            "hook_schema_drift",
            json!({
                "provider": event.provider,
                "hook_event_name": event.hook_event_name,
                "tool_category": tool_category,
                "rule_id": "policy_unparsed_vscode_file_tool",
            }),
        );
    }

    if command_category != "none" {
        let _ = client.record_event(
            "command_category",
            json!({
                "category": command_category,
            }),
        );
    }

    for category in &file_categories {
        let _ = client.record_event(
            "file_access_category",
            json!({
                "category": category,
            }),
        );
    }

    if network_access_category != "none" {
        let _ = client.record_event(
            "network_access_category",
            json!({
                "category": network_access_category,
            }),
        );
    }

    for finding in &decision.findings {
        let _ = client.record_event(
            "rule_outcome",
            json!({
                "rule_id": finding.rule_id,
                "decision": decision_name,
                "severity": finding.severity,
                "action": finding.action.alert_action(),
            }),
        );
    }

    // Hook PreToolUse/PermissionRequest must stay low-latency and fail-open on
    // telemetry transport issues; upload on non-hook paths instead.
}

pub(crate) fn telemetry_record_policy_change(kind: &str, props: Value) {
    telemetry_record_dashboard_event(kind, props);
}

pub(crate) fn telemetry_record_dashboard_event(kind: &str, props: Value) {
    let client = match TelemetryClient::load_default() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("gensee telemetry: {error}");
            return;
        }
    };
    let _ = client.record_event(kind, props);
    client.flush_in_background();
}

pub(crate) fn handle_telemetry(args: Vec<OsString>) -> io::Result<()> {
    let mut client = TelemetryClient::load_default()?;
    match args.first().and_then(|arg| arg.to_str()) {
        Some("status") | None => {
            println!("{}", serde_json::to_string_pretty(&client.status_json())?);
            println!("gensee telemetry: {TELEMETRY_PRIVACY_NOTICE} {TELEMETRY_SUPPORT_NOTICE}");
            Ok(())
        }
        Some("enable") => {
            client.config.remote_enabled = true;
            client.config.consent_state = ConsentState::Enabled;
            client.save_config()?;
            println!("gensee telemetry: remote upload enabled");
            println!("gensee telemetry: {TELEMETRY_PRIVACY_NOTICE} {TELEMETRY_SUPPORT_NOTICE}");
            Ok(())
        }
        Some("disable") => {
            client.config.remote_enabled = false;
            client.config.consent_state = ConsentState::Disabled;
            client.save_config()?;
            println!("gensee telemetry: remote upload disabled");
            Ok(())
        }
        Some("enable-collection") => {
            client.config.collection_enabled = true;
            client.save_config()?;
            println!("gensee telemetry: local collection enabled");
            Ok(())
        }
        Some("disable-collection") => {
            client.config.collection_enabled = false;
            client.save_config()?;
            println!("gensee telemetry: local collection disabled");
            Ok(())
        }
        Some("flush") => {
            let uploaded = client.flush_once()?;
            println!("gensee telemetry: uploaded {uploaded} event(s)");
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee telemetry [status|enable|disable|enable-collection|disable-collection|flush]",
        )),
    }
}

fn telemetry_tool_category(tool_name: &str) -> &'static str {
    if tool_name == "Bash" {
        "shell"
    } else if matches!(
        tool_name,
        "Read" | "Write" | "Edit" | "MultiEdit" | "apply_patch"
    ) {
        "filesystem"
    } else if tool_name == "WebFetch" {
        "network"
    } else if is_mcp_tool_name(tool_name) {
        "mcp"
    } else {
        "other"
    }
}

fn telemetry_command_category(command: &str) -> &'static str {
    let lower = command.to_ascii_lowercase();
    if command_has_network_tool(command) {
        "network"
    } else if lower.contains(" rm ")
        || lower.starts_with("rm ")
        || lower.contains(" chmod ")
        || lower.starts_with("chmod ")
        || lower.contains(" chown ")
        || lower.starts_with("chown ")
    {
        "destructive"
    } else if lower.contains(" cat ")
        || lower.starts_with("cat ")
        || lower.contains(" ls ")
        || lower.starts_with("ls ")
        || lower.contains(" find ")
        || lower.starts_with("find ")
    {
        "filesystem"
    } else {
        "other"
    }
}
