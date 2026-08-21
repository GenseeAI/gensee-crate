//! Provider-neutral capability requests for authority-expanding operations.
//!
//! A request describes *what* an operation needs and where its effects land.
//! It deliberately does not name a package manager, agent, or isolation
//! runtime. Enforcement layers can therefore map the same request to a local
//! sandbox, an ephemeral tclone cell, or a brokered external transaction.

use serde::{Deserialize, Serialize};

pub const CAPABILITY_REQUEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FilesystemRead,
    FilesystemWrite,
    DestructiveFilesystem,
    NetworkEgress,
    IdentityUse,
    ProcessExecution,
    PrivilegedExecution,
    UntrustedCodeExecution,
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

/// Requested resource selectors. Empty lists mean that no resource has been
/// granted yet; they never mean "all resources". A lease issuer must resolve
/// these selectors before execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub network_hosts: Vec<String>,
    pub identities: Vec<String>,
    pub external_targets: Vec<String>,
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
}
