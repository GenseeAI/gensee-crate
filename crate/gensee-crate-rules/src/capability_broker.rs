//! Public, secret-free protocol types for capability brokers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Component, Path};

pub const BROKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerResourceKind {
    ExternalServiceAuthority,
    #[doc(hidden)]
    #[serde(rename = "repository_token")]
    LegacyExternalServiceAuthorityV1,
    ApiToken,
    WorkloadIdentity,
    MtlsCertificate,
    FilesystemHandle,
    NetworkLease,
    DatabaseRole,
    ExternalActionCommitToken,
    CredentialUse,
    HttpApiCall,
    BrowserSession,
    DatabaseTransaction,
    MessageDelivery,
    CiJobInvocation,
    SecretRead,
    FilesystemMutation,
    CloudControlAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerCapabilityScope {
    CredentialUse {
        handle: String,
        audience: String,
        actions: Vec<String>,
    },
    HttpApiCall {
        origin: String,
        methods: Vec<String>,
        path_prefixes: Vec<String>,
        max_request_bytes: u64,
        max_response_bytes: u64,
    },
    BrowserSession {
        origin: String,
        session_profile: String,
        actions: Vec<String>,
    },
    DatabaseTransaction {
        service: String,
        database: String,
        actions: Vec<String>,
        read_only: bool,
    },
    MessageDelivery {
        channel: String,
        destinations: Vec<String>,
        actions: Vec<String>,
    },
    CiJobInvocation {
        runner: String,
        workflow: String,
        source_ref: String,
        inputs_digest: String,
    },
    SecretRead {
        handle: String,
        purpose: String,
    },
    FilesystemMutation {
        root: String,
        operations: Vec<String>,
        path_prefixes: Vec<String>,
    },
    CloudControlAction {
        provider: String,
        resource: String,
        actions: Vec<String>,
    },
}

impl BrokerCapabilityScope {
    pub fn resource_kind(&self) -> BrokerResourceKind {
        match self {
            Self::CredentialUse { .. } => BrokerResourceKind::CredentialUse,
            Self::HttpApiCall { .. } => BrokerResourceKind::HttpApiCall,
            Self::BrowserSession { .. } => BrokerResourceKind::BrowserSession,
            Self::DatabaseTransaction { .. } => BrokerResourceKind::DatabaseTransaction,
            Self::MessageDelivery { .. } => BrokerResourceKind::MessageDelivery,
            Self::CiJobInvocation { .. } => BrokerResourceKind::CiJobInvocation,
            Self::SecretRead { .. } => BrokerResourceKind::SecretRead,
            Self::FilesystemMutation { .. } => BrokerResourceKind::FilesystemMutation,
            Self::CloudControlAction { .. } => BrokerResourceKind::CloudControlAction,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::CredentialUse {
                handle,
                audience,
                actions,
            } => {
                exact_token(handle, "credential handle")?;
                exact_target(audience, "credential audience")?;
                exact_actions(actions, "credential actions")
            }
            Self::HttpApiCall {
                origin,
                methods,
                path_prefixes,
                max_request_bytes,
                max_response_bytes,
            } => {
                exact_origin(origin, "HTTP origin")?;
                if methods.is_empty()
                    || methods.len() > 16
                    || methods.iter().any(|method| {
                        method.is_empty()
                            || method.len() > 16
                            || !method.bytes().all(|byte| byte.is_ascii_uppercase())
                    })
                {
                    return Err("HTTP methods must be bounded explicit uppercase values".into());
                }
                exact_paths(path_prefixes, "HTTP path prefixes")?;
                if *max_request_bytes == 0
                    || *max_response_bytes == 0
                    || *max_request_bytes > 1024 * 1024 * 1024
                    || *max_response_bytes > 1024 * 1024 * 1024
                {
                    return Err("HTTP byte budgets are invalid".into());
                }
                Ok(())
            }
            Self::BrowserSession {
                origin,
                session_profile,
                actions,
            } => {
                exact_origin(origin, "browser origin")?;
                exact_token(session_profile, "browser session profile")?;
                exact_actions(actions, "browser actions")
            }
            Self::DatabaseTransaction {
                service,
                database,
                actions,
                ..
            } => {
                exact_token(service, "database service")?;
                exact_token(database, "database name")?;
                exact_actions(actions, "database actions")
            }
            Self::MessageDelivery {
                channel,
                destinations,
                actions,
            } => {
                exact_token(channel, "message channel")?;
                exact_targets(destinations, "message destinations")?;
                exact_actions(actions, "message actions")
            }
            Self::CiJobInvocation {
                runner,
                workflow,
                source_ref,
                inputs_digest,
            } => {
                exact_token(runner, "CI runner")?;
                exact_target(workflow, "CI workflow")?;
                exact_target(source_ref, "CI source ref")?;
                sha256(inputs_digest, "CI inputs digest")
            }
            Self::SecretRead { handle, purpose } => {
                exact_token(handle, "secret handle")?;
                exact_token(purpose, "secret purpose")
            }
            Self::FilesystemMutation {
                root,
                operations,
                path_prefixes,
            } => {
                let path = Path::new(root);
                if !path.is_absolute()
                    || root.contains("//")
                    || path
                        .components()
                        .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
                {
                    return Err("filesystem root must be an absolute normalized path".into());
                }
                exact_actions(operations, "filesystem operations")?;
                exact_paths(path_prefixes, "filesystem path prefixes")
            }
            Self::CloudControlAction {
                provider,
                resource,
                actions,
            } => {
                exact_token(provider, "cloud provider")?;
                exact_target(resource, "cloud resource")?;
                exact_actions(actions, "cloud actions")
            }
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_scope: Option<BrokerCapabilityScope>,
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
    ExternalServiceRequest,
    #[doc(hidden)]
    #[serde(rename = "repository_request")]
    LegacyExternalServiceRequestV1,
    ApiRequest,
    IdentityExchange,
    MtlsConnection,
    SecretAccess,
    NetworkConnection,
    DatabaseRequest,
    BrowserAction,
    CloudAction,
    MessageDelivery,
    CiJobInvocation,
    FilesystemMutation,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_scope: Option<BrokerCapabilityScope>,
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

fn exact_actions(values: &[String], label: &str) -> Result<(), String> {
    if values.is_empty() || values.len() > 128 {
        return Err(format!("{label} must be a nonempty bounded list"));
    }
    for value in values {
        exact_token(value, label)?;
    }
    if values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
    {
        return Err(format!("{label} contains duplicates"));
    }
    Ok(())
}

fn exact_paths(values: &[String], label: &str) -> Result<(), String> {
    exact_targets(values, label)?;
    if values.iter().any(|value| !value.starts_with('/')) {
        return Err(format!("{label} must begin with /"));
    }
    Ok(())
}

fn exact_targets(values: &[String], label: &str) -> Result<(), String> {
    if values.is_empty() || values.len() > 128 {
        return Err(format!("{label} must be a nonempty bounded list"));
    }
    for value in values {
        exact_target(value, label)?;
    }
    if values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
    {
        return Err(format!("{label} contains duplicates"));
    }
    Ok(())
}

fn exact_target(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 2048
        || value.contains('*')
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} must be exact, bounded, and non-wildcard"));
    }
    Ok(())
}

fn exact_origin(value: &str, label: &str) -> Result<(), String> {
    let parsed = url::Url::parse(value).map_err(|_| format!("{label} is not a valid URL"))?;
    let scheme_allowed = parsed.scheme() == "https"
        || (parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "::1")));
    if !scheme_allowed
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(format!(
            "{label} must be an exact HTTPS or loopback HTTP origin"
        ));
    }
    Ok(())
}

fn exact_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(format!("{label} must be a bounded ASCII token"));
    }
    Ok(())
}

fn sha256(value: &str, label: &str) -> Result<(), String> {
    if !value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err(format!("{label} must be a SHA-256 digest"));
    }
    Ok(())
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
            resource_kind: BrokerResourceKind::ExternalServiceAuthority,
            typed_scope: None,
            adapter_id: "repo-broker".to_string(),
            audience: "repo.example.test".to_string(),
            scopes: vec!["service:one:read".to_string()],
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
                "resource_kind": "external_service_authority",
                "adapter_id": "repo-broker",
                "audience": "repo.example.test",
                "scopes": ["service:one:read"],
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

    #[test]
    fn retained_service_authority_keeps_its_v1_cleanup_discriminator() {
        let kind: BrokerResourceKind = serde_json::from_str("\"repository_token\"").unwrap();
        assert_eq!(kind, BrokerResourceKind::LegacyExternalServiceAuthorityV1);
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            "\"repository_token\""
        );

        let effect: BrokerGatewayEffectKind =
            serde_json::from_str("\"repository_request\"").unwrap();
        assert_eq!(
            effect,
            BrokerGatewayEffectKind::LegacyExternalServiceRequestV1
        );
        assert_eq!(
            serde_json::to_string(&effect).unwrap(),
            "\"repository_request\""
        );
    }

    #[test]
    fn typed_provider_scopes_are_exact_and_non_wildcard() {
        let valid = BrokerCapabilityScope::HttpApiCall {
            origin: "https://api.example.test".into(),
            methods: vec!["GET".into(), "POST".into()],
            path_prefixes: vec!["/v1/records".into()],
            max_request_bytes: 4096,
            max_response_bytes: 1024 * 1024,
        };
        assert_eq!(valid.resource_kind(), BrokerResourceKind::HttpApiCall);
        assert!(valid.validate().is_ok());

        for invalid in [
            BrokerCapabilityScope::HttpApiCall {
                origin: "https://api.example.test/path".into(),
                methods: vec!["GET".into()],
                path_prefixes: vec!["/v1".into()],
                max_request_bytes: 1,
                max_response_bytes: 1,
            },
            BrokerCapabilityScope::HttpApiCall {
                origin: "https://api.example.test".into(),
                methods: vec!["GET".into()],
                path_prefixes: vec!["/*".into()],
                max_request_bytes: 1,
                max_response_bytes: 1,
            },
            BrokerCapabilityScope::HttpApiCall {
                origin: "http://198.51.100.8".into(),
                methods: vec!["GET".into()],
                path_prefixes: vec!["/v1".into()],
                max_request_bytes: 1,
                max_response_bytes: 1,
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }
}
