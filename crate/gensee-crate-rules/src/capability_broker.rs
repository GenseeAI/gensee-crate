//! Public, secret-free protocol types for capability brokers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BROKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerResourceKind {
    /// An opaque, mediator-bound credential for a downstream service. The
    /// credential material itself never crosses the broker boundary.
    ServiceCredential,
    /// Retained wire variants keep protocol-v1 cleanup requests byte-compatible
    /// with adapters registered before service credentials were generalized.
    #[doc(hidden)]
    #[serde(rename = "repository_token")]
    LegacyServiceCredentialV1A,
    #[doc(hidden)]
    #[serde(rename = "api_token")]
    LegacyServiceCredentialV1B,
    WorkloadIdentity,
    MtlsCertificate,
    FilesystemHandle,
    NetworkLease,
    DatabaseRole,
    ExternalActionCommitToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLeaseRequest {
    pub protocol_version: u32,
    pub operation_id: String,
    pub source_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<String>,
    pub resource_kind: BrokerResourceKind,
    pub adapter_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub ttl_seconds: u64,
    #[serde(default)]
    pub constraints: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerLeaseStatus {
    Active,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerGatewayEffectKind {
    /// A request performed by a service mediator on behalf of the operation.
    ServiceRequest,
    #[doc(hidden)]
    #[serde(rename = "repository_request")]
    LegacyServiceRequestV1A,
    #[doc(hidden)]
    #[serde(rename = "api_request")]
    LegacyServiceRequestV1B,
    IdentityExchange,
    MtlsConnection,
    SecretAccess,
    NetworkConnection,
    DatabaseRequest,
    BrowserAction,
    CloudAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerGatewayEffect {
    pub kind: BrokerGatewayEffectKind,
    pub occurred_at_ms: u64,
    pub target: String,
    pub action: String,
    pub request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_handle_id: Option<String>,
}

/// Delivery always names a mediator or an opaque handle. Credential bytes,
/// private keys, and broad identities are not valid public lease fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrokerDelivery {
    Gateway {
        gateway_endpoint: String,
        provider_handle: String,
    },
    FilesystemHandle {
        handle_id: String,
    },
    NetworkLease {
        network_lease_id: String,
    },
    CommitToken {
        commit_token_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerLease {
    pub protocol_version: u32,
    pub lease_id: String,
    pub operation_id: String,
    pub source_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<String>,
    pub resource_kind: BrokerResourceKind,
    pub adapter_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub constraints: Value,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: BrokerLeaseStatus,
    pub delivery: BrokerDelivery,
    #[serde(default)]
    pub public_metadata: Value,
    #[serde(default)]
    pub gateway_effects: Vec<BrokerGatewayEffect>,
    #[serde(default)]
    pub effect_telemetry_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at_ms: Option<u64>,
}

/// Exact claims authorized by a human-approved external-action commit. The
/// signature and one-use state are stored by the trusted host broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionCommitClaims {
    pub protocol_version: u32,
    pub token_id: String,
    pub lease_id: String,
    pub operation_id: String,
    pub source_run_id: String,
    pub gateway: String,
    pub target: String,
    pub action: String,
    pub request_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExternalActionCommitToken {
    pub claims: ExternalActionCommitClaims,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAdapterRequest {
    pub protocol_version: u32,
    pub action: String,
    pub lease: BrokerLeaseRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAdapterResponse {
    pub protocol_version: u32,
    pub provider_handle: String,
    pub gateway_endpoint: String,
    #[serde(default)]
    pub public_metadata: Value,
    #[serde(default)]
    pub effects: Vec<BrokerGatewayEffect>,
    pub effect_telemetry_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_lease_has_no_field_for_credential_material() {
        let lease = BrokerLease {
            protocol_version: BROKER_PROTOCOL_VERSION,
            lease_id: "lease_1".to_string(),
            operation_id: "op_1".to_string(),
            source_run_id: "run_1".to_string(),
            cell_id: Some("cell_1".to_string()),
            resource_kind: BrokerResourceKind::ServiceCredential,
            adapter_id: "records-broker".to_string(),
            audience: "records.example.test".to_string(),
            scopes: vec!["records:read".to_string()],
            constraints: Value::Null,
            issued_at_ms: 1,
            expires_at_ms: 2,
            status: BrokerLeaseStatus::Active,
            delivery: BrokerDelivery::Gateway {
                gateway_endpoint: "unix:///run/gensee/records.sock".to_string(),
                provider_handle: "opaque_1".to_string(),
            },
            public_metadata: Value::Null,
            gateway_effects: Vec::new(),
            effect_telemetry_complete: false,
            revoked_at_ms: None,
            consumed_at_ms: None,
        };
        let value = serde_json::to_value(lease).unwrap();
        let text = serde_json::to_string(&value).unwrap();

        assert!(!text.contains("\"credential\":"));
        assert!(!text.contains("credential_material"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("access_token"));
    }

    #[test]
    fn adapter_response_rejects_unknown_secret_fields() {
        let result = serde_json::from_value::<BrokerAdapterResponse>(serde_json::json!({
            "protocol_version": 1,
            "provider_handle": "opaque_1",
            "gateway_endpoint": "unix:///run/gensee/records.sock",
            "public_metadata": {},
            "effects": [],
            "effect_telemetry_complete": false,
            "access_token": "must-not-cross-boundary"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn legacy_service_credential_names_round_trip_for_cleanup_only() {
        let legacy_resource_kinds = [
            (
                "repository_token",
                BrokerResourceKind::LegacyServiceCredentialV1A,
            ),
            ("api_token", BrokerResourceKind::LegacyServiceCredentialV1B),
        ];
        for (wire_name, expected) in legacy_resource_kinds {
            let kind: BrokerResourceKind =
                serde_json::from_str(&format!("\"{wire_name}\"")).unwrap();
            assert_eq!(kind, expected);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{wire_name}\"")
            );
        }
        assert_eq!(
            serde_json::to_string(&BrokerResourceKind::ServiceCredential).unwrap(),
            "\"service_credential\""
        );

        let legacy_effect_kinds = [
            (
                "repository_request",
                BrokerGatewayEffectKind::LegacyServiceRequestV1A,
            ),
            (
                "api_request",
                BrokerGatewayEffectKind::LegacyServiceRequestV1B,
            ),
        ];
        for (wire_name, expected) in legacy_effect_kinds {
            let kind: BrokerGatewayEffectKind =
                serde_json::from_str(&format!("\"{wire_name}\"")).unwrap();
            assert_eq!(kind, expected);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{wire_name}\"")
            );
        }
        assert_eq!(
            serde_json::to_string(&BrokerGatewayEffectKind::ServiceRequest).unwrap(),
            "\"service_request\""
        );
    }
}
