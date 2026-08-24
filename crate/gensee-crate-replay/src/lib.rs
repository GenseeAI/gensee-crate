use chrono::DateTime;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use gensee_crate_core::redact_value;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const REPLAY_SCHEMA_VERSION: u32 = 1;
const DEFAULT_MAX_OUT_OF_ORDER_MS: u64 = 60_000;
const DEFAULT_MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_BUFFERED_EVENTS: usize = 1_000_000;
const DEFAULT_MAX_ACTIVE_CORRELATIONS: usize = 10_000;
const DEFAULT_MAX_CORRELATION_MATCHES: usize = 1_000;
const HARD_MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const HARD_MAX_NORMALIZED_RECORD_BYTES: usize = HARD_MAX_RECORD_BYTES + 1024 * 1024;
const HARD_MAX_BUFFERED_EVENTS: usize = 10_000_000;
const HARD_MAX_SOURCES: usize = 1_024;
const HARD_MAX_CORRELATION_RULES: usize = 1_024;
const HARD_MAX_CORRELATION_STEPS: usize = 64;
const HARD_MAX_ACTIVE_CORRELATIONS: usize = 100_000;
const HARD_MAX_CORRELATION_MATCHES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayManifest {
    pub schema_version: u32,
    pub replay_id: String,
    #[serde(default = "default_max_out_of_order_ms")]
    pub max_out_of_order_ms: u64,
    #[serde(default = "default_max_record_bytes")]
    pub max_record_bytes: usize,
    #[serde(default = "default_max_buffered_events")]
    pub max_buffered_events: usize,
    pub sources: Vec<ReplaySource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySource {
    pub id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub format: SourceFormat,
    pub clock: ClockSpec,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub include_record: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    #[default]
    Jsonl,
    JsonlGzip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClockSpec {
    Numeric {
        pointers: Vec<String>,
        unit: TimestampUnit,
    },
    Rfc3339 {
        pointers: Vec<String>,
    },
    Sequence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampUnit {
    Seconds,
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayEvent {
    pub timestamp_ns: u64,
    pub source: String,
    pub source_record: u64,
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SequenceEvent {
    pub source: String,
    pub source_record: u64,
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCoverage {
    pub source: String,
    pub path: String,
    pub format: SourceFormat,
    pub clock_kind: String,
    pub input_sha256: String,
    pub input_bytes: u64,
    pub records_read: u64,
    pub events_emitted: u64,
    pub sequence_events: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub input_timestamp_regressions: u64,
    pub maximum_input_regression_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub replay_id: String,
    pub timeline_events: u64,
    pub sequence_events: u64,
    pub sources: Vec<SourceCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProvenance {
    pub schema_version: u32,
    pub replay_id: String,
    pub created_at_ms: u64,
    pub producer: String,
    pub manifest_sha256: String,
    pub max_out_of_order_ms: u64,
    pub payload_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub replay_id: String,
    pub artifacts: Vec<ArtifactDigest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReport {
    pub bundle: String,
    pub replay_id: String,
    pub timeline_events: u64,
    pub sequence_events: u64,
    pub bundle_manifest_sha256: String,
    pub signature: Option<SignatureReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureReport {
    pub algorithm: String,
    pub public_key_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub bundle: String,
    pub replay_id: String,
    pub artifacts_verified: usize,
    pub timeline_events: u64,
    pub sequence_events: u64,
    pub timeline_monotonic: bool,
    pub signature: Option<SignatureReport>,
    pub trusted_key_matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRules {
    pub schema_version: u32,
    #[serde(default = "default_max_active_correlations")]
    pub max_active: usize,
    #[serde(default = "default_max_correlation_matches")]
    pub max_matches_per_rule: usize,
    pub rules: Vec<CorrelationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRule {
    pub id: String,
    pub description: String,
    pub max_span_ms: u64,
    pub steps: Vec<CorrelationStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationStep {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub equals: BTreeMap<String, Value>,
    #[serde(default)]
    pub exists: Vec<String>,
    #[serde(default)]
    pub same_as_previous: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventReference {
    pub timestamp_ns: u64,
    pub source: String,
    pub source_record: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    pub events: Vec<EventReference>,
    pub span_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCorrelationReport {
    pub id: String,
    pub description: String,
    pub matches: Vec<CorrelationMatch>,
    pub active_candidates_dropped: u64,
    pub matches_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    pub schema_version: u32,
    pub replay_id: String,
    pub rules_sha256: String,
    pub timeline_events_scanned: u64,
    pub rules: Vec<RuleCorrelationReport>,
}

#[derive(Debug)]
struct HeapEvent(ReplayEvent);

impl PartialEq for HeapEvent {
    fn eq(&self, other: &Self) -> bool {
        event_key(&self.0) == event_key(&other.0)
    }
}

impl Eq for HeapEvent {}

impl PartialOrd for HeapEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        event_key(&other.0).cmp(&event_key(&self.0))
    }
}

#[derive(Debug)]
struct ActiveCorrelation {
    next_step: usize,
    started_at_ns: u64,
    events: Vec<EventReference>,
    last_fields: BTreeMap<String, Value>,
}

fn default_max_out_of_order_ms() -> u64 {
    DEFAULT_MAX_OUT_OF_ORDER_MS
}

fn default_max_record_bytes() -> usize {
    DEFAULT_MAX_RECORD_BYTES
}

fn default_max_buffered_events() -> usize {
    DEFAULT_MAX_BUFFERED_EVENTS
}

fn default_max_active_correlations() -> usize {
    DEFAULT_MAX_ACTIVE_CORRELATIONS
}

fn default_max_correlation_matches() -> usize {
    DEFAULT_MAX_CORRELATION_MATCHES
}

pub fn build_bundle(
    manifest_path: &Path,
    output: &Path,
    signing_key_path: Option<&Path>,
) -> io::Result<BuildReport> {
    let manifest_bytes = fs::read(manifest_path)?;
    let manifest: ReplayManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| invalid_data(format!("invalid replay manifest: {error}")))?;
    validate_replay_manifest(&manifest)?;
    if output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("replay output already exists: {}", output.display()),
        ));
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = parent.join(format!(
        ".gensee-replay-{}-{}",
        std::process::id(),
        now_ms()?
    ));
    fs::create_dir(&staging)?;
    let result = build_bundle_in_staging(
        &manifest,
        &manifest_bytes,
        manifest_path,
        &staging,
        signing_key_path,
    );
    match result {
        Ok(mut report) => {
            fs::rename(&staging, output)?;
            report.bundle = output.display().to_string();
            Ok(report)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

fn build_bundle_in_staging(
    manifest: &ReplayManifest,
    manifest_bytes: &[u8],
    manifest_path: &Path,
    staging: &Path,
    signing_key_path: Option<&Path>,
) -> io::Result<BuildReport> {
    let source_root = staging.join(".sources");
    fs::create_dir(&source_root)?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut coverage = Vec::with_capacity(manifest.sources.len());
    let sequence_path = staging.join("sequence.jsonl");
    let mut sequence_writer = BufWriter::new(File::create(&sequence_path)?);

    for source in &manifest.sources {
        let input = if source.path.is_absolute() {
            source.path.clone()
        } else {
            base.join(&source.path)
        };
        let source_output = source_root.join(format!("{}.jsonl", source.id));
        coverage.push(normalize_source(
            source,
            &input,
            &source_output,
            &mut sequence_writer,
            manifest.max_out_of_order_ms,
            manifest.max_record_bytes,
            manifest.max_buffered_events,
        )?);
    }
    sequence_writer.flush()?;

    let timeline_path = staging.join("timeline.jsonl");
    let timeline_events = merge_sources(&manifest.sources, &source_root, &timeline_path)?;
    let sequence_events = coverage.iter().map(|item| item.sequence_events).sum();
    let coverage_report = CoverageReport {
        schema_version: REPLAY_SCHEMA_VERSION,
        replay_id: manifest.replay_id.clone(),
        timeline_events,
        sequence_events,
        sources: coverage,
    };
    write_pretty_json(&staging.join("coverage.json"), &coverage_report)?;
    fs::write(staging.join("replay-manifest.json"), manifest_bytes)?;
    let provenance = ReplayProvenance {
        schema_version: REPLAY_SCHEMA_VERSION,
        replay_id: manifest.replay_id.clone(),
        created_at_ms: now_ms()?,
        producer: format!("gensee-crate-replay/{}", env!("CARGO_PKG_VERSION")),
        manifest_sha256: sha256_bytes(manifest_bytes),
        max_out_of_order_ms: manifest.max_out_of_order_ms,
        payload_policy: if manifest.sources.iter().any(|source| source.include_record) {
            "selected_fields_plus_redacted_records".to_string()
        } else {
            "selected_fields_only".to_string()
        },
    };
    write_pretty_json(&staging.join("provenance.json"), &provenance)?;
    fs::remove_dir_all(source_root)?;
    if sequence_events == 0 {
        fs::remove_file(&sequence_path)?;
    }

    let artifact_names = [
        "replay-manifest.json",
        "timeline.jsonl",
        "sequence.jsonl",
        "coverage.json",
        "provenance.json",
    ];
    let mut artifacts = Vec::new();
    for name in artifact_names {
        let path = staging.join(name);
        if path.exists() {
            artifacts.push(digest_file(name, &path)?);
        }
    }
    let bundle_manifest = BundleManifest {
        schema_version: REPLAY_SCHEMA_VERSION,
        replay_id: manifest.replay_id.clone(),
        artifacts,
    };
    let bundle_manifest_bytes = pretty_json_bytes(&bundle_manifest)?;
    fs::write(staging.join("bundle-manifest.json"), &bundle_manifest_bytes)?;
    let signature = signing_key_path
        .map(|key| sign_bundle_manifest(staging, &bundle_manifest_bytes, key))
        .transpose()?;

    Ok(BuildReport {
        bundle: staging.display().to_string(),
        replay_id: manifest.replay_id.clone(),
        timeline_events,
        sequence_events,
        bundle_manifest_sha256: sha256_bytes(&bundle_manifest_bytes),
        signature,
    })
}

pub fn verify_bundle(
    bundle: &Path,
    trusted_key_path: Option<&Path>,
    require_signature: bool,
) -> io::Result<VerifyReport> {
    let manifest_path = bundle.join("bundle-manifest.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| invalid_data(format!("invalid bundle manifest: {error}")))?;
    if manifest.schema_version != REPLAY_SCHEMA_VERSION {
        return Err(invalid_data("unsupported bundle manifest schema version"));
    }
    validate_bundle_artifacts(bundle, &manifest)?;
    for artifact in &manifest.artifacts {
        let relative = safe_relative_path(&artifact.path)?;
        let artifact_path = bundle.join(relative);
        ensure_regular_file(&artifact_path)?;
        let actual = digest_file(&artifact.path, &artifact_path)?;
        if actual.bytes != artifact.bytes || actual.sha256 != artifact.sha256 {
            return Err(invalid_data(format!(
                "replay artifact digest mismatch: {}",
                artifact.path
            )));
        }
    }

    let signature = verify_bundle_signature(bundle, &manifest_bytes, trusted_key_path)?;
    if (require_signature || trusted_key_path.is_some()) && signature.is_none() {
        return Err(invalid_data("replay bundle is not signed"));
    }
    let trusted_key_matched = trusted_key_path.is_some() && signature.is_some();
    let (timeline_events, timeline_monotonic) = verify_timeline(&bundle.join("timeline.jsonl"))?;
    let sequence_events = count_jsonl_if_present(&bundle.join("sequence.jsonl"))?;
    let coverage: CoverageReport = read_json(&bundle.join("coverage.json"))?;
    let replay_manifest_bytes = fs::read(bundle.join("replay-manifest.json"))?;
    let replay_manifest: ReplayManifest = serde_json::from_slice(&replay_manifest_bytes)
        .map_err(|error| invalid_data(format!("invalid replay manifest in bundle: {error}")))?;
    validate_replay_manifest(&replay_manifest)?;
    let provenance: ReplayProvenance = read_json(&bundle.join("provenance.json"))?;
    let expected_payload_policy = if replay_manifest
        .sources
        .iter()
        .any(|source| source.include_record)
    {
        "selected_fields_plus_redacted_records"
    } else {
        "selected_fields_only"
    };
    if coverage.schema_version != REPLAY_SCHEMA_VERSION
        || coverage.replay_id != manifest.replay_id
        || replay_manifest.replay_id != manifest.replay_id
        || provenance.replay_id != manifest.replay_id
        || provenance.schema_version != REPLAY_SCHEMA_VERSION
        || provenance.manifest_sha256 != sha256_bytes(&replay_manifest_bytes)
        || provenance.max_out_of_order_ms != replay_manifest.max_out_of_order_ms
        || provenance.payload_policy != expected_payload_policy
        || coverage.timeline_events != timeline_events
        || coverage.sequence_events != sequence_events
        || coverage
            .sources
            .iter()
            .map(|item| item.events_emitted)
            .sum::<u64>()
            != timeline_events
        || coverage
            .sources
            .iter()
            .map(|item| item.sequence_events)
            .sum::<u64>()
            != sequence_events
    {
        return Err(invalid_data(
            "replay manifest, provenance, or coverage accounting does not match bundle artifacts",
        ));
    }
    let manifest_sources = replay_manifest
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect::<Vec<_>>();
    let coverage_sources = coverage
        .sources
        .iter()
        .map(|source| source.source.as_str())
        .collect::<Vec<_>>();
    if manifest_sources != coverage_sources {
        return Err(invalid_data(
            "coverage source order does not match replay manifest",
        ));
    }

    Ok(VerifyReport {
        bundle: bundle.display().to_string(),
        replay_id: manifest.replay_id,
        artifacts_verified: manifest.artifacts.len(),
        timeline_events,
        sequence_events,
        timeline_monotonic,
        signature,
        trusted_key_matched,
    })
}

pub fn correlate_bundle(
    bundle: &Path,
    rules_path: &Path,
    output: &Path,
    trusted_key_path: Option<&Path>,
    require_signature: bool,
) -> io::Result<CorrelationReport> {
    verify_bundle(bundle, trusted_key_path, require_signature)?;
    let rules_bytes = fs::read(rules_path)?;
    let rules: CorrelationRules = serde_json::from_slice(&rules_bytes)
        .map_err(|error| invalid_data(format!("invalid correlation rules: {error}")))?;
    validate_correlation_rules(&rules)?;
    let bundle_manifest: BundleManifest = read_json(&bundle.join("bundle-manifest.json"))?;
    let mut states = rules
        .rules
        .iter()
        .map(|rule| {
            (
                rule,
                VecDeque::<ActiveCorrelation>::new(),
                Vec::new(),
                0_u64,
                false,
            )
        })
        .collect::<Vec<_>>();
    let mut reader = BufReader::new(File::open(bundle.join("timeline.jsonl"))?);
    let mut scanned = 0_u64;
    while let Some(event) = read_replay_event(&mut reader)? {
        scanned += 1;
        for (rule, active, matches, dropped, matches_truncated) in &mut states {
            let max_span_ns = rule.max_span_ms.saturating_mul(1_000_000);
            while active.front().is_some_and(|candidate| {
                event.timestamp_ns.saturating_sub(candidate.started_at_ns) > max_span_ns
            }) {
                active.pop_front();
            }

            let candidates = active.len();
            for _ in 0..candidates {
                let mut candidate = active.pop_front().expect("length checked");
                if event_matches(
                    &event,
                    &rule.steps[candidate.next_step],
                    Some(&candidate.last_fields),
                ) {
                    candidate.events.push(event_reference(&event));
                    candidate.last_fields.clone_from(&event.fields);
                    candidate.next_step += 1;
                    if candidate.next_step == rule.steps.len() {
                        if matches.len() < rules.max_matches_per_rule {
                            matches.push(CorrelationMatch {
                                span_ms: event.timestamp_ns.saturating_sub(candidate.started_at_ns)
                                    / 1_000_000,
                                events: candidate.events,
                            });
                        } else {
                            *matches_truncated = true;
                        }
                        continue;
                    }
                }
                active.push_back(candidate);
            }

            if event_matches(&event, &rule.steps[0], None) {
                if rule.steps.len() == 1 {
                    if matches.len() < rules.max_matches_per_rule {
                        matches.push(CorrelationMatch {
                            events: vec![event_reference(&event)],
                            span_ms: 0,
                        });
                    } else {
                        *matches_truncated = true;
                    }
                } else {
                    active.push_back(ActiveCorrelation {
                        next_step: 1,
                        started_at_ns: event.timestamp_ns,
                        events: vec![event_reference(&event)],
                        last_fields: event.fields.clone(),
                    });
                }
            }
            while active.len() > rules.max_active {
                active.pop_front();
                *dropped += 1;
            }
        }
    }

    let report = CorrelationReport {
        schema_version: REPLAY_SCHEMA_VERSION,
        replay_id: bundle_manifest.replay_id,
        rules_sha256: sha256_bytes(&rules_bytes),
        timeline_events_scanned: scanned,
        rules: states
            .into_iter()
            .map(
                |(rule, _, matches, active_candidates_dropped, matches_truncated)| {
                    RuleCorrelationReport {
                        id: rule.id.clone(),
                        description: rule.description.clone(),
                        matches,
                        active_candidates_dropped,
                        matches_truncated,
                    }
                },
            )
            .collect(),
    };
    write_pretty_json(output, &report)?;
    Ok(report)
}

fn validate_replay_manifest(manifest: &ReplayManifest) -> io::Result<()> {
    if manifest.schema_version != REPLAY_SCHEMA_VERSION {
        return Err(invalid_data("unsupported replay manifest schema version"));
    }
    validate_identifier(&manifest.replay_id, "replay_id")?;
    if manifest.sources.is_empty() || manifest.sources.len() > HARD_MAX_SOURCES {
        return Err(invalid_data(
            "replay manifest source count is outside the supported bound",
        ));
    }
    if manifest.max_record_bytes == 0 || manifest.max_record_bytes > HARD_MAX_RECORD_BYTES {
        return Err(invalid_data(
            "max_record_bytes is outside the supported bound",
        ));
    }
    if manifest.max_buffered_events == 0 || manifest.max_buffered_events > HARD_MAX_BUFFERED_EVENTS
    {
        return Err(invalid_data(
            "max_buffered_events is outside the supported bound",
        ));
    }
    let mut ids = BTreeMap::new();
    for source in &manifest.sources {
        validate_identifier(&source.id, "source id")?;
        if ids.insert(&source.id, ()).is_some() {
            return Err(invalid_data(format!(
                "duplicate replay source id: {}",
                source.id
            )));
        }
        match &source.clock {
            ClockSpec::Numeric { pointers, .. } | ClockSpec::Rfc3339 { pointers } => {
                if pointers.is_empty() || pointers.iter().any(|pointer| !pointer.starts_with('/')) {
                    return Err(invalid_data(format!(
                        "source {} clock pointers must be non-empty JSON pointers",
                        source.id
                    )));
                }
            }
            ClockSpec::Sequence => {}
        }
        if source
            .fields
            .values()
            .any(|pointer| !pointer.starts_with('/'))
        {
            return Err(invalid_data(format!(
                "source {} selected fields must use JSON pointers",
                source.id
            )));
        }
    }
    Ok(())
}

fn validate_correlation_rules(rules: &CorrelationRules) -> io::Result<()> {
    if rules.schema_version != REPLAY_SCHEMA_VERSION {
        return Err(invalid_data("unsupported correlation-rule schema version"));
    }
    if rules.rules.len() > HARD_MAX_CORRELATION_RULES
        || rules.max_active == 0
        || rules.max_active > HARD_MAX_ACTIVE_CORRELATIONS
        || rules.max_matches_per_rule == 0
        || rules.max_matches_per_rule > HARD_MAX_CORRELATION_MATCHES
    {
        return Err(invalid_data(
            "correlation limits are outside supported bounds",
        ));
    }
    for rule in &rules.rules {
        validate_identifier(&rule.id, "correlation rule id")?;
        if rule.steps.is_empty() || rule.steps.len() > HARD_MAX_CORRELATION_STEPS {
            return Err(invalid_data(format!(
                "correlation rule {} has no steps",
                rule.id
            )));
        }
        if !rule.steps[0].same_as_previous.is_empty() {
            return Err(invalid_data(format!(
                "correlation rule {} first step cannot use same_as_previous",
                rule.id
            )));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(invalid_data(format!(
            "{label} must contain only ASCII letters, digits, hyphens, or underscores"
        )));
    }
    Ok(())
}

fn normalize_source(
    source: &ReplaySource,
    input: &Path,
    output: &Path,
    sequence_writer: &mut BufWriter<File>,
    max_out_of_order_ms: u64,
    max_record_bytes: usize,
    max_buffered_events: usize,
) -> io::Result<SourceCoverage> {
    let input_digest = digest_file(&source.path.display().to_string(), input)?;
    let mut reader = open_source_reader(input, source.format)?;
    let mut writer = BufWriter::new(File::create(output)?);
    let mut line = Vec::new();
    let mut heap = BinaryHeap::new();
    let mut record_number = 0_u64;
    let mut events_emitted = 0_u64;
    let mut sequence_events = 0_u64;
    let mut max_seen = 0_u64;
    let mut last_input_timestamp = None;
    let mut last_emitted_timestamp = None;
    let mut first_timestamp = None;
    let mut last_timestamp = None;
    let mut regressions = 0_u64;
    let mut maximum_regression = 0_u64;
    let window_ns = max_out_of_order_ms.saturating_mul(1_000_000);

    loop {
        let bytes = read_bounded_line(&mut reader, &mut line, max_record_bytes)?;
        if bytes == 0 {
            break;
        }
        record_number += 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let mut record: Value = serde_json::from_slice(&line).map_err(|error| {
            invalid_data(format!(
                "source {} record {} is invalid JSON: {error}",
                source.id, record_number
            ))
        })?;
        let fields = select_and_redact_fields(&record, &source.fields);
        let included_record = if source.include_record {
            redact_value(&mut record);
            Some(record.clone())
        } else {
            None
        };
        match &source.clock {
            ClockSpec::Sequence => {
                write_jsonl(
                    sequence_writer,
                    &SequenceEvent {
                        source: source.id.clone(),
                        source_record: record_number,
                        fields,
                        record: included_record,
                    },
                )?;
                sequence_events += 1;
            }
            clock => {
                let timestamp_ns = extract_timestamp_ns(&record, clock).ok_or_else(|| {
                    invalid_data(format!(
                        "source {} record {} has no valid timestamp",
                        source.id, record_number
                    ))
                })?;
                if let Some(previous) = last_input_timestamp {
                    if timestamp_ns < previous {
                        regressions += 1;
                        maximum_regression = maximum_regression.max(previous - timestamp_ns);
                    }
                }
                last_input_timestamp = Some(timestamp_ns);
                max_seen = max_seen.max(timestamp_ns);
                if heap.len() >= max_buffered_events {
                    return Err(invalid_data(format!(
                        "source {} exceeded max_buffered_events within the reorder window",
                        source.id
                    )));
                }
                heap.push(HeapEvent(ReplayEvent {
                    timestamp_ns,
                    source: source.id.clone(),
                    source_record: record_number,
                    fields,
                    record: included_record,
                }));
                let watermark = max_seen.saturating_sub(window_ns);
                while heap
                    .peek()
                    .is_some_and(|item| item.0.timestamp_ns <= watermark)
                {
                    emit_ordered_event(
                        &mut writer,
                        heap.pop().expect("peeked").0,
                        &mut last_emitted_timestamp,
                        &mut first_timestamp,
                        &mut last_timestamp,
                    )?;
                    events_emitted += 1;
                }
            }
        }
    }
    while let Some(item) = heap.pop() {
        emit_ordered_event(
            &mut writer,
            item.0,
            &mut last_emitted_timestamp,
            &mut first_timestamp,
            &mut last_timestamp,
        )?;
        events_emitted += 1;
    }
    writer.flush()?;

    Ok(SourceCoverage {
        source: source.id.clone(),
        path: source.path.display().to_string(),
        format: source.format,
        clock_kind: match source.clock {
            ClockSpec::Numeric { .. } => "numeric".to_string(),
            ClockSpec::Rfc3339 { .. } => "rfc3339".to_string(),
            ClockSpec::Sequence => "sequence".to_string(),
        },
        input_sha256: input_digest.sha256,
        input_bytes: input_digest.bytes,
        records_read: record_number,
        events_emitted,
        sequence_events,
        first_timestamp_ns: first_timestamp,
        last_timestamp_ns: last_timestamp,
        input_timestamp_regressions: regressions,
        maximum_input_regression_ns: maximum_regression,
    })
}

fn emit_ordered_event(
    writer: &mut BufWriter<File>,
    event: ReplayEvent,
    last_emitted: &mut Option<u64>,
    first_timestamp: &mut Option<u64>,
    last_timestamp: &mut Option<u64>,
) -> io::Result<()> {
    if last_emitted.is_some_and(|last| event.timestamp_ns < last) {
        return Err(invalid_data(
            "source exceeded the configured bounded-reordering window",
        ));
    }
    first_timestamp.get_or_insert(event.timestamp_ns);
    *last_timestamp = Some(event.timestamp_ns);
    *last_emitted = Some(event.timestamp_ns);
    write_jsonl(writer, &event)
}

fn merge_sources(sources: &[ReplaySource], root: &Path, output: &Path) -> io::Result<u64> {
    let mut readers = Vec::with_capacity(sources.len());
    let mut current = Vec::with_capacity(sources.len());
    let mut heap = BinaryHeap::<std::cmp::Reverse<(u64, usize, u64)>>::new();
    for (index, source) in sources.iter().enumerate() {
        let mut reader = BufReader::new(File::open(root.join(format!("{}.jsonl", source.id)))?);
        let event = read_replay_event(&mut reader)?;
        if let Some(event) = &event {
            heap.push(std::cmp::Reverse((
                event.timestamp_ns,
                index,
                event.source_record,
            )));
        }
        readers.push(reader);
        current.push(event);
    }
    let mut writer = BufWriter::new(File::create(output)?);
    let mut count = 0_u64;
    let mut last_timestamp = None;
    while let Some(std::cmp::Reverse((_, index, _))) = heap.pop() {
        let event = current[index].take().expect("heap has current event");
        if last_timestamp.is_some_and(|last| event.timestamp_ns < last) {
            return Err(invalid_data("global replay merge is not monotonic"));
        }
        last_timestamp = Some(event.timestamp_ns);
        write_jsonl(&mut writer, &event)?;
        count += 1;
        let next = read_replay_event(&mut readers[index])?;
        if let Some(event) = &next {
            heap.push(std::cmp::Reverse((
                event.timestamp_ns,
                index,
                event.source_record,
            )));
        }
        current[index] = next;
    }
    writer.flush()?;
    Ok(count)
}

fn extract_timestamp_ns(record: &Value, clock: &ClockSpec) -> Option<u64> {
    match clock {
        ClockSpec::Numeric { pointers, unit } => pointers.iter().find_map(|pointer| {
            let value = record.pointer(pointer)?;
            let number = value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse::<u64>().ok())?;
            match unit {
                TimestampUnit::Seconds => number.checked_mul(1_000_000_000),
                TimestampUnit::Milliseconds => number.checked_mul(1_000_000),
                TimestampUnit::Microseconds => number.checked_mul(1_000),
                TimestampUnit::Nanoseconds => Some(number),
            }
        }),
        ClockSpec::Rfc3339 { pointers } => pointers.iter().find_map(|pointer| {
            let value = record.pointer(pointer)?.as_str()?;
            let parsed = DateTime::parse_from_rfc3339(value).ok()?;
            u64::try_from(parsed.timestamp_nanos_opt()?).ok()
        }),
        ClockSpec::Sequence => None,
    }
}

fn select_and_redact_fields(
    record: &Value,
    selectors: &BTreeMap<String, String>,
) -> BTreeMap<String, Value> {
    let selected = selectors
        .iter()
        .filter_map(|(name, pointer)| {
            record
                .pointer(pointer)
                .cloned()
                .map(|value| (name.clone(), value))
        })
        .collect::<serde_json::Map<_, _>>();
    let mut selected = Value::Object(selected);
    redact_value(&mut selected);
    selected
        .as_object()
        .expect("constructed as object")
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn event_matches(
    event: &ReplayEvent,
    step: &CorrelationStep,
    previous_fields: Option<&BTreeMap<String, Value>>,
) -> bool {
    if step
        .source
        .as_deref()
        .is_some_and(|source| source != event.source)
    {
        return false;
    }
    let ordinary_match = step
        .equals
        .iter()
        .all(|(field, expected)| event.fields.get(field) == Some(expected))
        && step
            .exists
            .iter()
            .all(|field| event.fields.contains_key(field));
    let linked_match = step.same_as_previous.iter().all(|field| {
        previous_fields
            .and_then(|previous| previous.get(field))
            .is_some_and(|previous| event.fields.get(field) == Some(previous))
    });
    ordinary_match && linked_match
}

fn event_reference(event: &ReplayEvent) -> EventReference {
    EventReference {
        timestamp_ns: event.timestamp_ns,
        source: event.source.clone(),
        source_record: event.source_record,
    }
}

fn open_source_reader(path: &Path, format: SourceFormat) -> io::Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    match format {
        SourceFormat::Jsonl => Ok(Box::new(BufReader::new(file))),
        SourceFormat::JsonlGzip => Ok(Box::new(BufReader::new(GzDecoder::new(file)))),
    }
}

fn read_replay_event(reader: &mut impl BufRead) -> io::Result<Option<ReplayEvent>> {
    let mut line = Vec::new();
    if read_bounded_line(reader, &mut line, HARD_MAX_NORMALIZED_RECORD_BYTES)? == 0 {
        return Ok(None);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|error| invalid_data(format!("invalid normalized replay event: {error}")))
}

fn verify_timeline(path: &Path) -> io::Result<(u64, bool)> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut count = 0_u64;
    let mut last = None;
    while let Some(event) = read_replay_event(&mut reader)? {
        if last.is_some_and(|timestamp| event.timestamp_ns < timestamp) {
            return Err(invalid_data("replay timeline is not monotonic"));
        }
        last = Some(event.timestamp_ns);
        count += 1;
    }
    Ok((count, true))
}

fn count_jsonl_if_present(path: &Path) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut count = 0_u64;
    let mut line = Vec::new();
    while read_bounded_line(&mut reader, &mut line, HARD_MAX_NORMALIZED_RECORD_BYTES)? != 0 {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        serde_json::from_slice::<SequenceEvent>(&line)
            .map_err(|error| invalid_data(format!("invalid sequence event: {error}")))?;
        count += 1;
    }
    Ok(count)
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    output: &mut Vec<u8>,
    maximum_bytes: usize,
) -> io::Result<usize> {
    output.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(output.len());
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if output.len().saturating_add(consumed) > maximum_bytes {
            return Err(invalid_data(format!(
                "JSONL record exceeds the {maximum_bytes}-byte limit"
            )));
        }
        output.extend_from_slice(&available[..consumed]);
        let finished = available[..consumed].ends_with(b"\n");
        reader.consume(consumed);
        if finished {
            return Ok(output.len());
        }
    }
}

fn sign_bundle_manifest(
    bundle: &Path,
    manifest_bytes: &[u8],
    key_path: &Path,
) -> io::Result<SignatureReport> {
    let signing_key = read_signing_key(key_path)?;
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(manifest_bytes);
    fs::write(
        bundle.join("public-key.hex"),
        format!("{}\n", hex::encode(verifying_key.as_bytes())),
    )?;
    fs::write(
        bundle.join("bundle-manifest.sig"),
        format!("{}\n", hex::encode(signature.to_bytes())),
    )?;
    Ok(SignatureReport {
        algorithm: "ed25519".to_string(),
        public_key_sha256: sha256_bytes(verifying_key.as_bytes()),
    })
}

fn verify_bundle_signature(
    bundle: &Path,
    manifest_bytes: &[u8],
    trusted_key_path: Option<&Path>,
) -> io::Result<Option<SignatureReport>> {
    let signature_path = bundle.join("bundle-manifest.sig");
    let public_key_path = bundle.join("public-key.hex");
    if !signature_path.exists() && !public_key_path.exists() {
        return Ok(None);
    }
    if !signature_path.exists() || !public_key_path.exists() {
        return Err(invalid_data("replay signature files are incomplete"));
    }
    let public_key = read_hex_array::<32>(&public_key_path, "Ed25519 public key")?;
    if let Some(trusted) = trusted_key_path {
        let trusted = read_hex_array::<32>(trusted, "trusted Ed25519 public key")?;
        if public_key != trusted {
            return Err(invalid_data("bundle public key does not match trusted key"));
        }
    }
    let signature = read_hex_array::<64>(&signature_path, "Ed25519 signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| invalid_data(format!("invalid Ed25519 public key: {error}")))?;
    verifying_key
        .verify(manifest_bytes, &Signature::from_bytes(&signature))
        .map_err(|error| invalid_data(format!("invalid replay signature: {error}")))?;
    Ok(Some(SignatureReport {
        algorithm: "ed25519".to_string(),
        public_key_sha256: sha256_bytes(&public_key),
    }))
}

fn read_hex_array<const N: usize>(path: &Path, label: &str) -> io::Result<[u8; N]> {
    let text = fs::read_to_string(path)?;
    let decoded = hex::decode(text.trim())
        .map_err(|error| invalid_data(format!("invalid {label}: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| invalid_data(format!("{label} must contain exactly {N} bytes")))
}

fn read_signing_key(path: &Path) -> io::Result<SigningKey> {
    let text = Zeroizing::new(fs::read_to_string(path)?);
    let decoded = Zeroizing::new(
        hex::decode(text.trim())
            .map_err(|error| invalid_data(format!("invalid Ed25519 signing key: {error}")))?,
    );
    let bytes = Zeroizing::new(
        <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| invalid_data("Ed25519 signing key must contain exactly 32 bytes"))?,
    );
    Ok(SigningKey::from_bytes(&bytes))
}

fn validate_bundle_artifacts(bundle: &Path, manifest: &BundleManifest) -> io::Result<()> {
    let mut paths = BTreeMap::new();
    for artifact in &manifest.artifacts {
        safe_relative_path(&artifact.path)?;
        if paths.insert(artifact.path.as_str(), ()).is_some() {
            return Err(invalid_data(format!(
                "duplicate bundle artifact: {}",
                artifact.path
            )));
        }
    }
    for required in [
        "replay-manifest.json",
        "timeline.jsonl",
        "coverage.json",
        "provenance.json",
    ] {
        if !paths.contains_key(required) {
            return Err(invalid_data(format!(
                "bundle manifest omits required artifact: {required}"
            )));
        }
    }
    let sequence_exists = bundle.join("sequence.jsonl").exists();
    if sequence_exists != paths.contains_key("sequence.jsonl") {
        return Err(invalid_data(
            "sequence artifact and bundle manifest disagree",
        ));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_data(format!(
            "replay artifact is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn digest_file(name: &str, path: &Path) -> io::Result<ArtifactDigest> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok(ArtifactDigest {
        path: name.to_string(),
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn safe_relative_path(value: &str) -> io::Result<PathBuf> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_data(format!(
            "unsafe bundle artifact path: {value}"
        )));
    }
    Ok(path.to_path_buf())
}

fn event_key(event: &ReplayEvent) -> (u64, &str, u64) {
    (event.timestamp_ns, &event.source, event.source_record)
}

fn write_jsonl(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| invalid_data(format!("could not serialize replay event: {error}")))?;
    writer.write_all(b"\n")
}

fn write_pretty_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    fs::write(path, pretty_json_bytes(value)?)
}

fn pretty_json_bytes(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| invalid_data(format!("could not serialize replay data: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid JSON in {}: {error}", path.display())))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|error| io::Error::other(format!("system clock is before Unix epoch: {error}")))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "gensee-replay-{name}-{}-{}",
            std::process::id(),
            now_ms().unwrap()
        ))
    }

    fn write(path: &Path, value: &str) {
        fs::write(path, value).unwrap();
    }

    fn manifest(source_path: &str) -> ReplayManifest {
        ReplayManifest {
            schema_version: REPLAY_SCHEMA_VERSION,
            replay_id: "unit_replay".to_string(),
            max_out_of_order_ms: 10,
            max_record_bytes: 4096,
            max_buffered_events: 100,
            sources: vec![ReplaySource {
                id: "falco".to_string(),
                path: PathBuf::from(source_path),
                format: SourceFormat::Jsonl,
                clock: ClockSpec::Numeric {
                    pointers: vec!["/output_fields/evt.time".to_string()],
                    unit: TimestampUnit::Nanoseconds,
                },
                fields: BTreeMap::from([
                    ("rule".to_string(), "/rule".to_string()),
                    ("pid".to_string(), "/output_fields/proc.pid".to_string()),
                ]),
                include_record: false,
            }],
        }
    }

    #[test]
    fn builds_verifies_and_correlates_a_signed_bundle() {
        let root = temp_root("signed");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("events.jsonl"),
            concat!(
                "{\"rule\":\"start\",\"output_fields\":{\"evt.time\":30000000,\"proc.pid\":7}}\n",
                "{\"rule\":\"start\",\"output_fields\":{\"evt.time\":10000000,\"proc.pid\":7}}\n",
                "{\"rule\":\"finish\",\"output_fields\":{\"evt.time\":20000000,\"proc.pid\":7}}\n"
            ),
        );
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &manifest("events.jsonl")).unwrap();
        let key_path = root.join("key.hex");
        write(&key_path, &format!("{}\n", "11".repeat(32)));
        let bundle = root.join("bundle");

        let built = build_bundle(&manifest_path, &bundle, Some(&key_path)).unwrap();
        assert_eq!(built.timeline_events, 3);
        assert!(built.signature.is_some());
        let verified = verify_bundle(&bundle, Some(&bundle.join("public-key.hex")), true).unwrap();
        assert_eq!(verified.timeline_events, 3);
        assert!(verified.timeline_monotonic);
        assert!(verified.trusted_key_matched);

        let rules = CorrelationRules {
            schema_version: REPLAY_SCHEMA_VERSION,
            max_active: 10,
            max_matches_per_rule: 10,
            rules: vec![CorrelationRule {
                id: "start_finish".to_string(),
                description: "start is followed by finish".to_string(),
                max_span_ms: 20,
                steps: vec![
                    CorrelationStep {
                        source: Some("falco".to_string()),
                        equals: BTreeMap::from([("rule".to_string(), Value::from("start"))]),
                        exists: vec!["pid".to_string()],
                        same_as_previous: Vec::new(),
                    },
                    CorrelationStep {
                        source: Some("falco".to_string()),
                        equals: BTreeMap::from([("rule".to_string(), Value::from("finish"))]),
                        exists: Vec::new(),
                        same_as_previous: vec!["pid".to_string()],
                    },
                ],
            }],
        };
        let rules_path = root.join("rules.json");
        write_pretty_json(&rules_path, &rules).unwrap();
        let report = correlate_bundle(
            &bundle,
            &rules_path,
            &root.join("correlations.json"),
            Some(&bundle.join("public-key.hex")),
            true,
        )
        .unwrap();
        assert_eq!(report.timeline_events_scanned, 3);
        assert_eq!(report.rules[0].matches.len(), 1);
        assert_eq!(report.rules[0].matches[0].span_ms, 10);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sequence_sources_are_accounted_separately() {
        let root = temp_root("sequence");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("events.jsonl"),
            "{\"kind\":\"tool\"}\n{\"kind\":\"model\"}\n",
        );
        let mut value = manifest("events.jsonl");
        value.sources[0].clock = ClockSpec::Sequence;
        value.sources[0].fields = BTreeMap::from([("kind".to_string(), "/kind".to_string())]);
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &value).unwrap();
        let bundle = root.join("bundle");
        let report = build_bundle(&manifest_path, &bundle, None).unwrap();
        assert_eq!(report.timeline_events, 0);
        assert_eq!(report.sequence_events, 2);
        let verified = verify_bundle(&bundle, None, false).unwrap();
        assert_eq!(verified.sequence_events, 2);
        assert!(verified.signature.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_gzip_jsonl_with_rfc3339_clocks() {
        let root = temp_root("gzip");
        fs::create_dir_all(&root).unwrap();
        let input = root.join("requests.jsonl.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            File::create(&input).unwrap(),
            flate2::Compression::default(),
        );
        encoder
            .write_all(b"{\"timestamp\":\"2024-04-05T19:34:38.250Z\",\"status\":200}\n")
            .unwrap();
        encoder.finish().unwrap();
        let value = ReplayManifest {
            schema_version: REPLAY_SCHEMA_VERSION,
            replay_id: "gzip_replay".to_string(),
            max_out_of_order_ms: 0,
            max_record_bytes: 4096,
            max_buffered_events: 100,
            sources: vec![ReplaySource {
                id: "http".to_string(),
                path: PathBuf::from("requests.jsonl.gz"),
                format: SourceFormat::JsonlGzip,
                clock: ClockSpec::Rfc3339 {
                    pointers: vec!["/timestamp".to_string()],
                },
                fields: BTreeMap::from([("status".to_string(), "/status".to_string())]),
                include_record: false,
            }],
        };
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &value).unwrap();
        let bundle = root.join("bundle");
        let built = build_bundle(&manifest_path, &bundle, None).unwrap();
        assert_eq!(built.timeline_events, 1);
        let event: ReplayEvent = serde_json::from_str(
            fs::read_to_string(bundle.join("timeline.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(event.timestamp_ns, 1_712_345_678_250_000_000);
        assert_eq!(event.fields["status"], 200);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_reorder_fails_when_an_event_arrives_too_late() {
        let root = temp_root("late");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("events.jsonl"),
            concat!(
                "{\"output_fields\":{\"evt.time\":100000000}}\n",
                "{\"output_fields\":{\"evt.time\":200000000}}\n",
                "{\"output_fields\":{\"evt.time\":1000000}}\n"
            ),
        );
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &manifest("events.jsonl")).unwrap();
        let error = build_bundle(&manifest_path, &root.join("bundle"), None).unwrap_err();
        assert!(error.to_string().contains("bounded-reordering window"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_detects_timeline_tampering() {
        let root = temp_root("tamper");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("events.jsonl"),
            "{\"output_fields\":{\"evt.time\":1000000}}\n",
        );
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &manifest("events.jsonl")).unwrap();
        let bundle = root.join("bundle");
        build_bundle(&manifest_path, &bundle, None).unwrap();
        write(&bundle.join("timeline.jsonl"), "{}\n");
        assert!(verify_bundle(&bundle, None, false).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn included_records_use_the_redaction_floor() {
        let root = temp_root("redact");
        fs::create_dir_all(&root).unwrap();
        write(
            &root.join("events.jsonl"),
            "{\"api_key\":\"secret-value\",\"output_fields\":{\"evt.time\":1000000}}\n",
        );
        let mut value = manifest("events.jsonl");
        value.sources[0].include_record = true;
        let manifest_path = root.join("manifest.json");
        write_pretty_json(&manifest_path, &value).unwrap();
        let bundle = root.join("bundle");
        build_bundle(&manifest_path, &bundle, None).unwrap();
        let line = fs::read_to_string(bundle.join("timeline.jsonl")).unwrap();
        assert!(!line.contains("secret-value"));
        assert!(line.contains("<redacted>"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_artifact_paths_are_rejected() {
        assert!(safe_relative_path("../outside").is_err());
        assert!(safe_relative_path("/absolute").is_err());
        assert!(safe_relative_path("timeline.jsonl").is_ok());
    }
}
