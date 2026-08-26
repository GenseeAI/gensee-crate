//! Authenticated, attenuating operation identity for service-to-service hops.

use crate::capability_broker::BrokerResourceKind;
use crate::contract_catalog::{ApprovedOperationService, ContractCatalog};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION_CONTEXT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContextClaims {
    pub schema_version: u32,
    pub token_id: String,
    pub operation_id: String,
    pub generation: u64,
    pub issuer_service: String,
    pub audience_service: String,
    pub catalog_digest: String,
    pub contract_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_context_digest: Option<String>,
    #[serde(default)]
    pub grants: Vec<ContextGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextGrant {
    pub grant_id: String,
    pub resource_kind: BrokerResourceKind,
    pub scope_digest: String,
    pub lease_generation: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContextSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperationContext {
    pub claims: OperationContextClaims,
    pub signature: OperationContextSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContextChain {
    pub contexts: Vec<SignedOperationContext>,
}

pub const OPERATION_TRANSPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_OPERATION_TRANSPORT_TTL_MS: u64 = 15 * 60 * 1_000;

/// Transport-neutral authenticated request envelope. HTTP, RPC, task queue,
/// and local-socket middleware can carry the same object after independently
/// deriving `peer_service` from mTLS or local peer credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTransportClaims {
    pub schema_version: u32,
    pub envelope_id: String,
    pub context_digest: String,
    pub sender_service: String,
    pub recipient_service: String,
    pub payload_digest: String,
    pub content_type: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperationTransport {
    pub claims: OperationTransportClaims,
    pub payload_hex: String,
    pub signature_hex: String,
}

impl OperationTransportClaims {
    pub fn validate_for_context(
        &self,
        tail: &OperationContextClaims,
        context_digest: &str,
        peer_service: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        if self.schema_version != OPERATION_TRANSPORT_SCHEMA_VERSION
            || !token(&self.envelope_id)
            || !token(&self.sender_service)
            || !token(&self.recipient_service)
            || !token(&self.content_type)
            || !token(&self.nonce)
            || !sha256(&self.context_digest)
            || !sha256(&self.payload_digest)
            || self.context_digest != context_digest
            || self.sender_service != tail.issuer_service
            || self.recipient_service != tail.audience_service
            || peer_service != self.sender_service
            || self.issued_at_ms < tail.issued_at_ms
            || self.issued_at_ms >= self.expires_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_OPERATION_TRANSPORT_TTL_MS
            || self.expires_at_ms > tail.expires_at_ms
            || now_ms >= self.expires_at_ms
        {
            return Err(
                "operation transport is not bound to context and authenticated peer".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownstreamEffectClaims {
    pub schema_version: u32,
    pub effect_id: String,
    pub operation_id: String,
    pub context_digest: String,
    pub service_id: String,
    pub effect_kind: String,
    pub effect_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_effect_digest: Option<String>,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDownstreamEffect {
    pub claims: DownstreamEffectClaims,
    pub signature: OperationContextSignature,
}

impl OperationContextClaims {
    pub fn validate_root<'a>(
        &self,
        catalog: &'a ContractCatalog,
        now_ms: u64,
    ) -> Result<&'a ApprovedOperationService, String> {
        self.validate_shape(now_ms)?;
        if self.generation != 0 || self.parent_context_digest.is_some() {
            return Err("root operation context must have generation zero and no parent".into());
        }
        let issuer = approved_service(catalog, &self.issuer_service)?;
        if !issuer.can_initiate {
            return Err("context issuer is not approved to initiate operations".into());
        }
        validate_audience(issuer, &self.audience_service)?;
        Ok(issuer)
    }

    pub fn validate_child<'a>(
        &self,
        parent: &OperationContextClaims,
        parent_digest: &str,
        catalog: &'a ContractCatalog,
        now_ms: u64,
    ) -> Result<&'a ApprovedOperationService, String> {
        self.validate_shape(now_ms)?;
        if self.parent_context_digest.as_deref() != Some(parent_digest)
            || self.generation != parent.generation.saturating_add(1)
            || self.operation_id != parent.operation_id
            || self.catalog_digest != parent.catalog_digest
            || self.contract_digest != parent.contract_digest
            || self.issuer_service != parent.audience_service
            || self.issued_at_ms < parent.issued_at_ms
            || self.expires_at_ms > parent.expires_at_ms
        {
            return Err("child context does not preserve the parent operation chain".into());
        }
        let issuer = approved_service(catalog, &self.issuer_service)?;
        validate_audience(issuer, &self.audience_service)?;
        validate_attenuation(&parent.grants, &self.grants)?;
        Ok(issuer)
    }

    fn validate_shape(&self, now_ms: u64) -> Result<(), String> {
        if self.schema_version != OPERATION_CONTEXT_SCHEMA_VERSION
            || !token(&self.token_id)
            || !token(&self.operation_id)
            || !token(&self.issuer_service)
            || !token(&self.audience_service)
            || !sha256(&self.catalog_digest)
            || !sha256(&self.contract_digest)
            || self.issued_at_ms >= self.expires_at_ms
            || now_ms >= self.expires_at_ms
            || self.grants.len() > 256
        {
            return Err("operation context is malformed, expired, or oversized".into());
        }
        if self
            .parent_context_digest
            .as_deref()
            .is_some_and(|digest| !sha256(digest))
        {
            return Err("parent context digest is invalid".into());
        }
        let mut grant_ids = BTreeSet::new();
        for grant in &self.grants {
            if !grant_ids.insert(grant.grant_id.as_str())
                || !token(&grant.grant_id)
                || !sha256(&grant.scope_digest)
                || grant.expires_at_ms > self.expires_at_ms
            {
                return Err("operation context grant is malformed or duplicated".into());
            }
        }
        Ok(())
    }
}

impl DownstreamEffectClaims {
    pub fn validate_for_context(
        &self,
        context: &OperationContextClaims,
        context_digest: &str,
    ) -> Result<(), String> {
        if self.schema_version != OPERATION_CONTEXT_SCHEMA_VERSION
            || !token(&self.effect_id)
            || self.operation_id != context.operation_id
            || self.context_digest != context_digest
            || self.service_id != context.audience_service
            || !token(&self.effect_kind)
            || !sha256(&self.effect_digest)
            || self
                .previous_effect_digest
                .as_deref()
                .is_some_and(|digest| !sha256(digest))
            || self.occurred_at_ms < context.issued_at_ms
            || self.occurred_at_ms > context.expires_at_ms
        {
            return Err("downstream effect is not bound to the operation context".into());
        }
        Ok(())
    }
}

fn approved_service<'a>(
    catalog: &'a ContractCatalog,
    service_id: &str,
) -> Result<&'a ApprovedOperationService, String> {
    catalog
        .operation_services
        .iter()
        .find(|service| service.service_id == service_id)
        .ok_or_else(|| "operation context service is not catalog-approved".to_string())
}

fn validate_audience(issuer: &ApprovedOperationService, audience: &str) -> Result<(), String> {
    if !issuer
        .allowed_audiences
        .iter()
        .any(|allowed| allowed == audience)
    {
        return Err("operation context audience is not approved for the issuer".into());
    }
    Ok(())
}

fn validate_attenuation(parent: &[ContextGrant], child: &[ContextGrant]) -> Result<(), String> {
    let parent = parent
        .iter()
        .map(|grant| (grant.grant_id.as_str(), grant))
        .collect::<BTreeMap<_, _>>();
    for grant in child {
        let inherited = parent
            .get(grant.grant_id.as_str())
            .ok_or_else(|| "child context introduced a new grant".to_string())?;
        if grant.resource_kind != inherited.resource_kind
            || grant.scope_digest != inherited.scope_digest
            || grant.lease_generation != inherited.lease_generation
            || grant.expires_at_ms > inherited.expires_at_ms
        {
            return Err("child context widened or replaced a parent grant".into());
        }
    }
    Ok(())
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: &str) -> ContextGrant {
        ContextGrant {
            grant_id: id.into(),
            resource_kind: BrokerResourceKind::HttpApiCall,
            scope_digest: format!("sha256:{}", "11".repeat(32)),
            lease_generation: 7,
            expires_at_ms: 900,
        }
    }

    #[test]
    fn attenuation_allows_subset_but_not_new_authority() {
        let parent = vec![grant("grant_a"), grant("grant_b")];
        assert!(validate_attenuation(&parent, &[grant("grant_a")]).is_ok());
        assert!(validate_attenuation(&parent, &[grant("grant_c")]).is_err());
        let mut widened = grant("grant_a");
        widened.scope_digest = format!("sha256:{}", "22".repeat(32));
        assert!(validate_attenuation(&parent, &[widened]).is_err());
    }

    #[test]
    fn transport_requires_the_authenticated_sender_and_exact_context() {
        let tail = OperationContextClaims {
            schema_version: OPERATION_CONTEXT_SCHEMA_VERSION,
            token_id: "context".into(),
            operation_id: "operation".into(),
            generation: 1,
            issuer_service: "gateway".into(),
            audience_service: "worker".into(),
            catalog_digest: format!("sha256:{}", "11".repeat(32)),
            contract_digest: format!("sha256:{}", "22".repeat(32)),
            parent_context_digest: Some(format!("sha256:{}", "33".repeat(32))),
            issued_at_ms: 100,
            expires_at_ms: 900,
            grants: Vec::new(),
        };
        let claims = OperationTransportClaims {
            schema_version: OPERATION_TRANSPORT_SCHEMA_VERSION,
            envelope_id: "envelope".into(),
            context_digest: format!("sha256:{}", "44".repeat(32)),
            sender_service: "gateway".into(),
            recipient_service: "worker".into(),
            payload_digest: format!("sha256:{}", "55".repeat(32)),
            content_type: "application_json".into(),
            nonce: "nonce".into(),
            issued_at_ms: 110,
            expires_at_ms: 800,
        };
        assert!(claims
            .validate_for_context(&tail, &claims.context_digest, "gateway", 200)
            .is_ok());
        assert!(claims
            .validate_for_context(&tail, &claims.context_digest, "attacker", 200)
            .is_err());

        let mut long_tail = tail;
        long_tail.expires_at_ms = MAX_OPERATION_TRANSPORT_TTL_MS + 10_000;
        let mut long_lived = claims;
        long_lived.expires_at_ms = long_lived.issued_at_ms + MAX_OPERATION_TRANSPORT_TTL_MS + 1;
        assert!(long_lived
            .validate_for_context(&long_tail, &long_lived.context_digest, "gateway", 200)
            .is_err());
    }
}
