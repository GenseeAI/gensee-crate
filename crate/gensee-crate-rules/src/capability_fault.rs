//! Provider-neutral observations emitted when an operation crosses an enforced
//! capability boundary. A fault describes the effect that reached the
//! boundary; it never chooses an executor or grants itself authority.

use crate::capability::{
    Capability, CapabilityRequest, CloudIamScope, DatabaseScope, EffectScope,
    ExternalApplicationScope, FileOperationKind, FileOperationScope, KernelScope,
    NetworkDestinationScope, OutputPromotionScope, SecretIdentityScope,
    CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use crate::capability_policy::CapabilityExecutor;
use serde::{Deserialize, Serialize};

pub const CAPABILITY_FAULT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityFaultSubject {
    LocalProcess { pid: u32, start_time_ticks: u64 },
    NetworkPeer { source_address: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundaryEffectObservation {
    NetworkConnect {
        destination: String,
        protocol: String,
        port: u16,
    },
    FileOperation {
        operation: FileOperationScope,
    },
    Kernel {
        #[serde(default)]
        syscalls: Vec<String>,
        #[serde(default)]
        linux_capabilities: Vec<String>,
    },
    SecretIdentity {
        scope: SecretIdentityScope,
    },
    CloudIam {
        scope: CloudIamScope,
    },
    ExternalApplication {
        scope: ExternalApplicationScope,
    },
    Database {
        scope: DatabaseScope,
    },
    OutputPromotion {
        scope: OutputPromotionScope,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFault {
    pub schema_version: u32,
    pub fault_id: String,
    pub operation_id: String,
    pub source_run_id: String,
    pub subject: CapabilityFaultSubject,
    pub effect: BoundaryEffectObservation,
    pub requested_ttl_seconds: u64,
    /// The receiver replaces this with its own clock before making a lease
    /// decision. The producer timestamp remains useful only as raw evidence.
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityFaultAction {
    ContinueAlreadyAuthorized,
    RetryAfterLease,
    Delegate,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFaultResolution {
    pub fault_id: String,
    pub action: CapabilityFaultAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<CapabilityExecutor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    pub retry_allowed: bool,
    pub reason_codes: Vec<String>,
}

impl CapabilityFault {
    pub fn validation_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.schema_version != CAPABILITY_FAULT_SCHEMA_VERSION {
            reasons.push("unsupported_fault_schema".to_string());
        }
        for (name, value) in [
            ("fault", self.fault_id.as_str()),
            ("operation", self.operation_id.as_str()),
            ("source_run", self.source_run_id.as_str()),
        ] {
            if !bounded_token(value) {
                reasons.push(format!("invalid_{name}_id"));
            }
        }
        if self.requested_ttl_seconds == 0 || self.requested_ttl_seconds > 15 * 60 {
            reasons.push("fault_ttl_out_of_bounds".to_string());
        }
        match &self.subject {
            CapabilityFaultSubject::LocalProcess {
                pid,
                start_time_ticks,
            } if *pid == 0 || *start_time_ticks == 0 => {
                reasons.push("invalid_local_process_identity".to_string());
            }
            CapabilityFaultSubject::NetworkPeer { source_address }
                if source_address.parse::<std::net::IpAddr>().is_err() =>
            {
                reasons.push("invalid_network_peer_identity".to_string());
            }
            _ => {}
        }
        match &self.effect {
            BoundaryEffectObservation::NetworkConnect {
                destination,
                protocol,
                port,
            } => {
                if destination.parse::<std::net::IpAddr>().is_err()
                    || !matches!(protocol.to_ascii_lowercase().as_str(), "tcp" | "udp")
                    || *port == 0
                {
                    reasons.push("invalid_network_connect_effect".to_string());
                }
            }
            BoundaryEffectObservation::FileOperation { operation }
                if operation.path.trim().is_empty() =>
            {
                reasons.push("invalid_file_effect".to_string());
            }
            BoundaryEffectObservation::Kernel {
                syscalls,
                linux_capabilities,
            } if syscalls.is_empty() && linux_capabilities.is_empty() => {
                reasons.push("empty_kernel_effect".to_string());
            }
            _ => {}
        }
        reasons
    }

    pub fn capability_request(&self) -> CapabilityRequest {
        let (operation_class, effect_scope, capabilities, scope) = match &self.effect {
            BoundaryEffectObservation::NetworkConnect {
                destination,
                protocol,
                port,
            } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.network_destinations.push(NetworkDestinationScope {
                    destination: destination.clone(),
                    protocol: protocol.to_ascii_lowercase(),
                    ports: vec![*port],
                });
                (
                    "boundary_network_connect",
                    EffectScope::ReversibleLocal,
                    vec![Capability::NetworkEgress],
                    scope,
                )
            }
            BoundaryEffectObservation::FileOperation { operation } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.file_operations.push(operation.clone());
                let capabilities = match operation.operation {
                    FileOperationKind::Read | FileOperationKind::Execute => {
                        vec![Capability::FilesystemRead]
                    }
                    FileOperationKind::Metadata => vec![Capability::FilesystemMetadata],
                    FileOperationKind::Delete => vec![
                        Capability::FilesystemWrite,
                        Capability::DestructiveFilesystem,
                    ],
                    FileOperationKind::Create
                    | FileOperationKind::Write
                    | FileOperationKind::Rename => vec![Capability::FilesystemWrite],
                };
                (
                    "boundary_file_operation",
                    if operation.operation == FileOperationKind::Delete {
                        EffectScope::IrreversibleLocal
                    } else {
                        EffectScope::ReversibleLocal
                    },
                    capabilities,
                    scope,
                )
            }
            BoundaryEffectObservation::Kernel {
                syscalls,
                linux_capabilities,
            } => {
                let scope = crate::capability::CapabilityScope {
                    kernel: KernelScope {
                        syscalls: syscalls.clone(),
                        linux_capabilities: linux_capabilities.clone(),
                    },
                    ..crate::capability::CapabilityScope::default()
                };
                let mut capabilities = Vec::new();
                if !syscalls.is_empty() {
                    capabilities.push(Capability::Syscall);
                }
                if !linux_capabilities.is_empty() {
                    capabilities.push(Capability::LinuxCapability);
                }
                (
                    "boundary_kernel",
                    EffectScope::ReversibleLocal,
                    capabilities,
                    scope,
                )
            }
            BoundaryEffectObservation::SecretIdentity { scope: observed } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.secret_identities.push(observed.clone());
                (
                    "boundary_secret_identity",
                    EffectScope::ReversibleLocal,
                    vec![Capability::SecretUse, Capability::IdentityUse],
                    scope,
                )
            }
            BoundaryEffectObservation::CloudIam { scope: observed } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.cloud_iam.push(observed.clone());
                (
                    "boundary_cloud_iam",
                    EffectScope::External,
                    vec![Capability::CloudIam, Capability::ExternalMutation],
                    scope,
                )
            }
            BoundaryEffectObservation::ExternalApplication { scope: observed } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.external_applications.push(observed.clone());
                let mut capabilities = vec![Capability::ExternalApplication];
                if observed.irreversible {
                    capabilities
                        .extend([Capability::ExternalMutation, Capability::IrreversibleEffect]);
                }
                (
                    "boundary_external_application",
                    EffectScope::External,
                    capabilities,
                    scope,
                )
            }
            BoundaryEffectObservation::Database { scope: observed } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.databases.push(observed.clone());
                (
                    "boundary_database",
                    EffectScope::External,
                    vec![Capability::DatabaseAccess],
                    scope,
                )
            }
            BoundaryEffectObservation::OutputPromotion { scope: observed } => {
                let mut scope = crate::capability::CapabilityScope::default();
                scope.output_promotions.push(observed.clone());
                (
                    "boundary_output_promotion",
                    EffectScope::IrreversibleLocal,
                    vec![Capability::OutputPromotion],
                    scope,
                )
            }
        };
        CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
            operation_class: operation_class.to_string(),
            effect_scope,
            capabilities,
            scope,
            lease_ttl_seconds: self.requested_ttl_seconds,
        }
    }
}

fn bounded_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network_fault() -> CapabilityFault {
        CapabilityFault {
            schema_version: CAPABILITY_FAULT_SCHEMA_VERSION,
            fault_id: "fault_1".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            subject: CapabilityFaultSubject::LocalProcess {
                pid: 42,
                start_time_ticks: 9001,
            },
            effect: BoundaryEffectObservation::NetworkConnect {
                destination: "203.0.113.8".to_string(),
                protocol: "tcp".to_string(),
                port: 443,
            },
            requested_ttl_seconds: 15,
            observed_at_ms: 1,
        }
    }

    #[test]
    fn network_fault_becomes_a_scoped_request_without_an_executor() {
        let fault = network_fault();
        assert!(fault.validation_reasons().is_empty());
        let request = fault.capability_request();
        assert_eq!(request.capabilities, vec![Capability::NetworkEgress]);
        assert_eq!(request.scope.network_destinations[0].ports, vec![443]);
    }

    #[test]
    fn network_fault_requires_exact_resolved_authority_and_process_identity() {
        let mut fault = network_fault();
        fault.effect = BoundaryEffectObservation::NetworkConnect {
            destination: "example.com".to_string(),
            protocol: "tcp".to_string(),
            port: 443,
        };
        fault.subject = CapabilityFaultSubject::LocalProcess {
            pid: 0,
            start_time_ticks: 0,
        };
        let reasons = fault.validation_reasons();
        assert!(reasons.contains(&"invalid_network_connect_effect".to_string()));
        assert!(reasons.contains(&"invalid_local_process_identity".to_string()));
    }
}
