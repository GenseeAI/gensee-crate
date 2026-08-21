//! Provider-neutral capability requests for authority-expanding operations.
//!
//! A request describes *what* an operation needs and where its effects land.
//! It deliberately does not name a package manager, agent, or isolation
//! runtime. Enforcement layers can therefore map the same request to a local
//! sandbox, an ephemeral tclone cell, or a brokered external transaction.

use serde::{Deserialize, Serialize};

pub const CAPABILITY_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const EFFECT_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FilesystemRead,
    FilesystemWrite,
    FilesystemMetadata,
    DestructiveFilesystem,
    NetworkEgress,
    NetworkListen,
    SecretUse,
    IdentityUse,
    WorkloadIdentity,
    CloudIam,
    Syscall,
    LinuxCapability,
    ProcessExecution,
    PrivilegedExecution,
    UntrustedCodeExecution,
    ExternalApplication,
    DatabaseAccess,
    IrreversibleEffect,
    OutputPromotion,
    ExternalMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectScope {
    ReadOnly,
    ReversibleLocal,
    IrreversibleLocal,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBoundary {
    Source,
    IsolatedCell,
    BrokeredCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationKind {
    Read,
    Create,
    Write,
    Rename,
    Delete,
    Metadata,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOperationScope {
    pub path: String,
    pub operation: FileOperationKind,
    /// Required to distinguish a new file from a new directory. Older
    /// producers omit this field; a missing kind on `create` remains a file
    /// for schema-v1 compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_kind: Option<FileEntryKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDestinationScope {
    pub destination: String,
    pub protocol: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretIdentityScope {
    /// A broker-side reference. It must never contain secret material.
    pub handle: String,
    pub identity: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudIamScope {
    pub provider: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assume_role: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelScope {
    #[serde(default)]
    pub syscalls: Vec<String>,
    #[serde(default)]
    pub linux_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalApplicationScope {
    pub application: String,
    pub target: String,
    pub actions: Vec<String>,
    pub irreversible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseScope {
    pub service: String,
    pub database: String,
    pub roles: Vec<String>,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPromotionScope {
    pub path: String,
    pub destination: String,
    pub transactional: bool,
}

/// Requested resource selectors. Empty lists mean that no resource has been
/// granted yet; they never mean "all resources". A lease issuer must resolve
/// these selectors before execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Compatibility selectors for schema-v1 producers. New producers should
    /// also populate the typed scopes below.
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub network_hosts: Vec<String>,
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default)]
    pub external_targets: Vec<String>,
    #[serde(default)]
    pub file_operations: Vec<FileOperationScope>,
    #[serde(default)]
    pub network_destinations: Vec<NetworkDestinationScope>,
    #[serde(default)]
    pub secret_identities: Vec<SecretIdentityScope>,
    #[serde(default)]
    pub cloud_iam: Vec<CloudIamScope>,
    #[serde(default)]
    pub kernel: KernelScope,
    #[serde(default)]
    pub external_applications: Vec<ExternalApplicationScope>,
    #[serde(default)]
    pub databases: Vec<DatabaseScope>,
    #[serde(default)]
    pub output_promotions: Vec<OutputPromotionScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub schema_version: u32,
    pub operation_class: String,
    pub effect_scope: EffectScope,
    pub execution_boundary: ExecutionBoundary,
    pub capabilities: Vec<Capability>,
    pub scope: CapabilityScope,
    /// Upper bound for a lease. The enforcement boundary must reject expired
    /// leases; this is not merely a cleanup hint.
    pub lease_ttl_seconds: u64,
    /// The source environment must not perform this operation when true.
    pub source_must_not_execute: bool,
    /// Outputs must be inspected and explicitly promoted instead of sharing a
    /// writable workspace with the source environment.
    pub inspect_before_commit: bool,
}

/// Whether an enforcement boundary can account for a class of effects. An
/// empty effect list is trustworthy only when its coverage is `complete` or
/// the capability was made `not_applicable` by an enforced denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryCoverage {
    Complete,
    Partial,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectTelemetryCoverage {
    pub filesystem_reads: TelemetryCoverage,
    pub filesystem_writes: TelemetryCoverage,
    pub network_connections: TelemetryCoverage,
    pub external_requests: TelemetryCoverage,
    pub secret_accesses: TelemetryCoverage,
    pub process_tree: TelemetryCoverage,
}

/// Mount-level disclosure for filesystem-read telemetry. Partial coverage is
/// informative and machine-readable; it is not itself an effect violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemReadCoverage {
    pub covered_mounts: Vec<String>,
    pub uncovered_mounts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChangeEffect {
    pub path: String,
    pub change: FileChangeKind,
    pub entry_kind: FileEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_mode: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectionEffect {
    pub protocol: String,
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub broker_lease_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRequestEffect {
    pub gateway: String,
    pub target: String,
    pub action: String,
    pub request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_token_id: Option<String>,
}

/// Records a broker handle and its purpose, never secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAccessEffect {
    pub broker: String,
    pub handle_id: String,
    pub identity: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEffect {
    pub executable: String,
    pub argv_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub started_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionOutput {
    pub path: String,
    pub change: FileChangeKind,
    pub entry_kind: FileEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionReceipt {
    pub promotion_id: String,
    pub source_run_id: String,
    pub paths: Vec<String>,
    pub promoted_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectViolation {
    pub kind: String,
    pub resource: String,
    pub detail: String,
    pub observed_at_ms: u64,
}

/// A telemetry-backed account of a privileged operation. Promotion policy
/// consumes this record; it must never rely on an agent's success claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectManifest {
    pub schema_version: u32,
    pub operation_id: String,
    pub source_run_id: String,
    pub cell_id: String,
    pub requested_capabilities: Vec<Capability>,
    pub capabilities_used: Vec<Capability>,
    pub files_read: Vec<String>,
    pub files_changed: Vec<FileChangeEffect>,
    pub network_connections: Vec<NetworkConnectionEffect>,
    pub external_requests: Vec<ExternalRequestEffect>,
    pub secrets_accessed: Vec<SecretAccessEffect>,
    pub processes_started: Vec<ProcessEffect>,
    pub outputs_proposed_for_promotion: Vec<PromotionOutput>,
    #[serde(default)]
    pub promotions: Vec<PromotionReceipt>,
    pub violations: Vec<EffectViolation>,
    pub telemetry_coverage: EffectTelemetryCoverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_read_coverage: Option<FilesystemReadCoverage>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

impl CapabilityRequest {
    pub fn isolated(
        operation_class: impl Into<String>,
        effect_scope: EffectScope,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
            operation_class: operation_class.into(),
            effect_scope,
            execution_boundary: ExecutionBoundary::IsolatedCell,
            capabilities,
            scope: CapabilityScope::default(),
            lease_ttl_seconds: 240,
            source_must_not_execute: true,
            inspect_before_commit: true,
        }
    }

    pub fn brokered(operation_class: impl Into<String>, capabilities: Vec<Capability>) -> Self {
        Self {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
            operation_class: operation_class.into(),
            effect_scope: EffectScope::External,
            execution_boundary: ExecutionBoundary::BrokeredCommit,
            capabilities,
            scope: CapabilityScope::default(),
            lease_ttl_seconds: 240,
            source_must_not_execute: true,
            inspect_before_commit: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_request_has_stable_wire_names() {
        let request = CapabilityRequest::isolated(
            "untrusted_execution",
            EffectScope::ReversibleLocal,
            vec![
                Capability::NetworkEgress,
                Capability::UntrustedCodeExecution,
            ],
        );
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["execution_boundary"], "isolated_cell");
        assert_eq!(value["capabilities"][0], "network_egress");
        assert_eq!(value["source_must_not_execute"], true);
        assert_eq!(value["inspect_before_commit"], true);
        assert_eq!(value["scope"]["network_hosts"], serde_json::json!([]));
        assert_eq!(value["lease_ttl_seconds"], 240);
    }

    #[test]
    fn legacy_capability_scope_defaults_new_privilege_dimensions_to_empty() {
        let scope: CapabilityScope = serde_json::from_value(serde_json::json!({
            "read_paths": ["src"],
            "write_paths": [],
            "network_hosts": [],
            "identities": [],
            "external_targets": []
        }))
        .unwrap();

        assert_eq!(scope.read_paths, vec!["src"]);
        assert!(scope.file_operations.is_empty());
        assert!(scope.network_destinations.is_empty());
        assert!(scope.secret_identities.is_empty());
        assert!(scope.cloud_iam.is_empty());
        assert!(scope.kernel.syscalls.is_empty());
        assert!(scope.external_applications.is_empty());
        assert!(scope.databases.is_empty());
        assert!(scope.output_promotions.is_empty());
    }
}
