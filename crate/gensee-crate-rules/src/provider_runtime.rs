//! Provider-neutral action invocation bound to an active capability lease.

use crate::capability_broker::{
    BrokerCapabilityScope, BrokerGatewayEffectKind, BrokerResourceKind,
};
use serde::{Deserialize, Serialize};

pub const PROVIDER_INVOCATION_SCHEMA_VERSION: u32 = 1;

/// Root-controlled executable registration for one operational provider.
///
/// The provider implementation is intentionally outside the Gensee core. The
/// runtime pins this complete configuration and supplies only an invocation
/// already attenuated to an active lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntimeConfig {
    pub adapter_id: String,
    pub resource_kind: BrokerResourceKind,
    pub executable: String,
    pub executable_sha256: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_directory: String,
    pub max_runtime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvocation {
    pub schema_version: u32,
    pub invocation_id: String,
    pub operation_id: String,
    pub lease_id: String,
    pub request_digest: String,
    pub operation: ProviderOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderOperation {
    CredentialUse {
        audience: String,
        action: String,
    },
    HttpApiCall {
        origin: String,
        method: String,
        path: String,
        request_bytes: u64,
    },
    BrowserSession {
        origin: String,
        session_profile: String,
        action: String,
    },
    DatabaseTransaction {
        service: String,
        database: String,
        action: String,
        read_only: bool,
    },
    MessageDelivery {
        channel: String,
        destination: String,
        action: String,
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
        operation: String,
        path: String,
    },
    CloudControlAction {
        provider: String,
        resource: String,
        action: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDecision {
    Completed,
    Denied,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdapterResult {
    pub schema_version: u32,
    pub invocation_id: String,
    pub decision: ProviderDecision,
    pub effect_kind: BrokerGatewayEffectKind,
    pub target: String,
    pub action: String,
    pub request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    pub occurred_at_ms: u64,
}

/// Host-authenticated evidence that a particular provider implementation
/// handled one exact invocation under one exact lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDispatchReceipt {
    pub schema_version: u32,
    pub invocation: ProviderInvocation,
    pub lease_digest: String,
    pub adapter_id: String,
    pub adapter_executable_digest: String,
    pub result: ProviderAdapterResult,
    pub host_signature: String,
}

impl ProviderInvocation {
    pub fn validate_against(&self, scope: &BrokerCapabilityScope) -> Result<(), String> {
        if self.schema_version != PROVIDER_INVOCATION_SCHEMA_VERSION
            || !token(&self.invocation_id)
            || !token(&self.operation_id)
            || !token(&self.lease_id)
            || !sha256(&self.request_digest)
        {
            return Err("provider invocation identity is malformed".into());
        }
        let allowed = match (&self.operation, scope) {
            (
                ProviderOperation::CredentialUse { audience, action },
                BrokerCapabilityScope::CredentialUse {
                    audience: a,
                    actions,
                    ..
                },
            ) => audience == a && actions.contains(action),
            (
                ProviderOperation::HttpApiCall {
                    origin,
                    method,
                    path,
                    request_bytes,
                },
                BrokerCapabilityScope::HttpApiCall {
                    origin: a,
                    methods,
                    path_prefixes,
                    max_request_bytes,
                    ..
                },
            ) => {
                origin == a
                    && methods.contains(method)
                    && *request_bytes <= *max_request_bytes
                    && path_prefixes.iter().any(|prefix| {
                        path == prefix
                            || (path.starts_with(prefix)
                                && (prefix.ends_with('/')
                                    || path.as_bytes().get(prefix.len()) == Some(&b'/')))
                    })
            }
            (
                ProviderOperation::BrowserSession {
                    origin,
                    session_profile,
                    action,
                },
                BrokerCapabilityScope::BrowserSession {
                    origin: a,
                    session_profile: p,
                    actions,
                },
            ) => origin == a && session_profile == p && actions.contains(action),
            (
                ProviderOperation::DatabaseTransaction {
                    service,
                    database,
                    action,
                    read_only,
                },
                BrokerCapabilityScope::DatabaseTransaction {
                    service: s,
                    database: d,
                    actions,
                    read_only: ro,
                },
            ) => service == s && database == d && actions.contains(action) && (!*ro || *read_only),
            (
                ProviderOperation::MessageDelivery {
                    channel,
                    destination,
                    action,
                },
                BrokerCapabilityScope::MessageDelivery {
                    channel: c,
                    destinations,
                    actions,
                },
            ) => channel == c && destinations.contains(destination) && actions.contains(action),
            (
                ProviderOperation::CiJobInvocation {
                    runner,
                    workflow,
                    source_ref,
                    inputs_digest,
                },
                BrokerCapabilityScope::CiJobInvocation {
                    runner: r,
                    workflow: w,
                    source_ref: s,
                    inputs_digest: i,
                },
            ) => runner == r && workflow == w && source_ref == s && inputs_digest == i,
            (
                ProviderOperation::SecretRead { handle, purpose },
                BrokerCapabilityScope::SecretRead {
                    handle: h,
                    purpose: p,
                },
            ) => handle == h && purpose == p,
            (
                ProviderOperation::FilesystemMutation {
                    root,
                    operation,
                    path,
                },
                BrokerCapabilityScope::FilesystemMutation {
                    root: r,
                    operations,
                    path_prefixes,
                },
            ) => {
                root == r
                    && operations.contains(operation)
                    && path_prefixes.iter().any(|prefix| {
                        path == prefix
                            || (path.starts_with(prefix)
                                && (prefix.ends_with('/')
                                    || path.as_bytes().get(prefix.len()) == Some(&b'/')))
                    })
            }
            (
                ProviderOperation::CloudControlAction {
                    provider,
                    resource,
                    action,
                },
                BrokerCapabilityScope::CloudControlAction {
                    provider: p,
                    resource: r,
                    actions,
                },
            ) => provider == p && resource == r && actions.contains(action),
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err("provider operation exceeds the active typed scope".into())
        }
    }

    pub fn resource_kind(&self) -> BrokerResourceKind {
        match self.operation {
            ProviderOperation::CredentialUse { .. } => BrokerResourceKind::CredentialUse,
            ProviderOperation::HttpApiCall { .. } => BrokerResourceKind::HttpApiCall,
            ProviderOperation::BrowserSession { .. } => BrokerResourceKind::BrowserSession,
            ProviderOperation::DatabaseTransaction { .. } => {
                BrokerResourceKind::DatabaseTransaction
            }
            ProviderOperation::MessageDelivery { .. } => BrokerResourceKind::MessageDelivery,
            ProviderOperation::CiJobInvocation { .. } => BrokerResourceKind::CiJobInvocation,
            ProviderOperation::SecretRead { .. } => BrokerResourceKind::SecretRead,
            ProviderOperation::FilesystemMutation { .. } => BrokerResourceKind::FilesystemMutation,
            ProviderOperation::CloudControlAction { .. } => BrokerResourceKind::CloudControlAction,
        }
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}
fn sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributor_provider_config_fixture_matches_public_protocol() {
        let config: ProviderRuntimeConfig = serde_json::from_str(include_str!(
            "../../../integrations/boundary/extensions/capability-provider-config.json"
        ))
        .unwrap();
        assert_eq!(config.adapter_id, "analytics_database_v1");
        assert_eq!(
            config.resource_kind,
            BrokerResourceKind::DatabaseTransaction
        );
    }

    #[test]
    fn every_provider_operation_is_scope_checked() {
        let cases = vec![
            (
                BrokerCapabilityScope::CredentialUse {
                    handle: "cred".into(),
                    audience: "api".into(),
                    actions: vec!["sign".into()],
                },
                ProviderOperation::CredentialUse {
                    audience: "api".into(),
                    action: "sign".into(),
                },
            ),
            (
                BrokerCapabilityScope::HttpApiCall {
                    origin: "https://api.example".into(),
                    methods: vec!["POST".into()],
                    path_prefixes: vec!["/v1".into()],
                    max_request_bytes: 100,
                    max_response_bytes: 100,
                },
                ProviderOperation::HttpApiCall {
                    origin: "https://api.example".into(),
                    method: "POST".into(),
                    path: "/v1/items".into(),
                    request_bytes: 50,
                },
            ),
            (
                BrokerCapabilityScope::BrowserSession {
                    origin: "https://site.example".into(),
                    session_profile: "clean".into(),
                    actions: vec!["navigate".into()],
                },
                ProviderOperation::BrowserSession {
                    origin: "https://site.example".into(),
                    session_profile: "clean".into(),
                    action: "navigate".into(),
                },
            ),
            (
                BrokerCapabilityScope::DatabaseTransaction {
                    service: "primary".into(),
                    database: "app".into(),
                    actions: vec!["select".into()],
                    read_only: true,
                },
                ProviderOperation::DatabaseTransaction {
                    service: "primary".into(),
                    database: "app".into(),
                    action: "select".into(),
                    read_only: true,
                },
            ),
            (
                BrokerCapabilityScope::MessageDelivery {
                    channel: "mail".into(),
                    destinations: vec!["ops@example.test".into()],
                    actions: vec!["send".into()],
                },
                ProviderOperation::MessageDelivery {
                    channel: "mail".into(),
                    destination: "ops@example.test".into(),
                    action: "send".into(),
                },
            ),
            (
                BrokerCapabilityScope::CiJobInvocation {
                    runner: "ci".into(),
                    workflow: "verify".into(),
                    source_ref: "refs/heads/main".into(),
                    inputs_digest: format!("sha256:{}", "22".repeat(32)),
                },
                ProviderOperation::CiJobInvocation {
                    runner: "ci".into(),
                    workflow: "verify".into(),
                    source_ref: "refs/heads/main".into(),
                    inputs_digest: format!("sha256:{}", "22".repeat(32)),
                },
            ),
            (
                BrokerCapabilityScope::SecretRead {
                    handle: "secret".into(),
                    purpose: "signing".into(),
                },
                ProviderOperation::SecretRead {
                    handle: "secret".into(),
                    purpose: "signing".into(),
                },
            ),
            (
                BrokerCapabilityScope::FilesystemMutation {
                    root: "/workspace".into(),
                    operations: vec!["write".into()],
                    path_prefixes: vec!["/out".into()],
                },
                ProviderOperation::FilesystemMutation {
                    root: "/workspace".into(),
                    operation: "write".into(),
                    path: "/out/result".into(),
                },
            ),
            (
                BrokerCapabilityScope::CloudControlAction {
                    provider: "cloud".into(),
                    resource: "project/a".into(),
                    actions: vec!["read".into()],
                },
                ProviderOperation::CloudControlAction {
                    provider: "cloud".into(),
                    resource: "project/a".into(),
                    action: "read".into(),
                },
            ),
        ];
        for (scope, operation) in cases {
            let request = ProviderInvocation {
                schema_version: 1,
                invocation_id: "invoke_1".into(),
                operation_id: "op_1".into(),
                lease_id: "lease_1".into(),
                request_digest: format!("sha256:{}", "11".repeat(32)),
                operation,
            };
            assert!(request.validate_against(&scope).is_ok(), "{scope:?}");
        }
    }
}
