//! Public, secret-free protocol types for capability brokers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BROKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerResourceKind {
    RepositoryToken,
    ApiToken,
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
    /// Caller-generated stable id for one issuance intent. Reusing it with
    /// different canonical request content is rejected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
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
    Preparing,
    Activating,
    Publishing,
    Active,
    Revoking,
    Consumed,
    Revoked,
    Expired,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerProviderStatus {
    Absent,
    Active,
    Revoked,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerGatewayEffectKind {
    RepositoryRequest,
    ApiRequest,
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
    /// Stable across retries and crash recovery. Adapters must use this key to
    /// make `mint` and `revoke` idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_handle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAdapterResponse {
    pub protocol_version: u32,
    /// Required for `status`. Legacy mint/revoke adapters may omit this; the
    /// broker interprets successful legacy responses according to the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<BrokerProviderStatus>,
    #[serde(default)]
    pub provider_handle: String,
    #[serde(default)]
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
            resource_kind: BrokerResourceKind::RepositoryToken,
            adapter_id: "repo-broker".to_string(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["repository:one:read".to_string()],
            constraints: Value::Null,
            issued_at_ms: 1,
            expires_at_ms: 2,
            status: BrokerLeaseStatus::Active,
            delivery: BrokerDelivery::Gateway {
                gateway_endpoint: "unix:///run/gensee/repo.sock".to_string(),
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

        assert!(!text.contains("credential"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("access_token"));
    }

    #[test]
    fn adapter_response_rejects_unknown_secret_fields() {
        let result = serde_json::from_value::<BrokerAdapterResponse>(serde_json::json!({
            "protocol_version": 1,
            "provider_handle": "opaque_1",
            "gateway_endpoint": "unix:///run/gensee/repo.sock",
            "public_metadata": {},
            "effects": [],
            "effect_telemetry_complete": false,
            "access_token": "must-not-cross-boundary"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_protocol_additions_deserialize_legacy_adapter_messages() {
        let request: BrokerAdapterRequest = serde_json::from_value(serde_json::json!({
            "protocol_version": 1,
            "action": "mint",
            "lease": {
                "protocol_version": 1,
                "operation_id": "op_1",
                "source_run_id": "run_1",
                "resource_kind": "repository_token",
                "adapter_id": "repo-broker",
                "audience": "repo.example.test",
                "scopes": ["repository:one:read"],
                "ttl_seconds": 60
            }
        }))
        .unwrap();
        assert_eq!(request.idempotency_key, None);
        assert_eq!(request.lease_id, None);
        assert!(request.lease.request_id.is_empty());
        let serialized = serde_json::to_value(&request).unwrap();
        assert!(serialized.get("idempotency_key").is_none());
        assert!(serialized.get("lease_id").is_none());
        assert!(serialized["lease"].get("request_id").is_none());

        let response: BrokerAdapterResponse = serde_json::from_value(serde_json::json!({
            "protocol_version": 1,
            "provider_handle": "opaque_1",
            "gateway_endpoint": "unix:///run/gensee/repo.sock",
            "effect_telemetry_complete": false
        }))
        .unwrap();
        assert_eq!(response.provider_status, None);
    }
}
