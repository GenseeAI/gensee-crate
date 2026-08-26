//! Generic semantic-verifier request and signed receipt schemas.

use crate::operation_contract::StructuralProductType;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SEMANTIC_VERIFIER_SCHEMA_VERSION: u32 = 1;

/// Root-controlled executable registration for a domain-specific verifier.
/// The signed organization catalog pins the digest of this complete value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedVerifierConfig {
    pub verifier_id: String,
    pub policy_version: String,
    pub executable: String,
    pub executable_sha256: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_directory: String,
    pub max_runtime_seconds: u64,
}

/// Bounded stdout protocol emitted by an isolated verifier implementation.
/// Gensee adds request, product, policy, identity, and isolation bindings before
/// signing the final receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierProgramResult {
    pub verdict: SemanticVerdict,
    pub reason_codes: Vec<String>,
    pub validation_effect_manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub nonce: String,
    pub operation_id: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub product_type: StructuralProductType,
    pub product_digest: String,
    pub verifier_profile: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVerdict {
    Accept,
    Reject,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReceiptClaims {
    pub schema_version: u32,
    pub receipt_id: String,
    pub request_digest: String,
    pub nonce: String,
    pub operation_id: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub product_type: StructuralProductType,
    pub product_digest: String,
    pub verifier_profile: String,
    pub verifier_id: String,
    pub policy_version: String,
    pub verdict: SemanticVerdict,
    pub reason_codes: Vec<String>,
    pub validation_effect_manifest_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<VerifierIsolationClaims>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierIsolationClaims {
    pub profile: String,
    pub executable_digest: String,
    pub runtime_config_digest: String,
    pub network_denied: bool,
    pub process_creation_denied: bool,
    pub filesystem_mutation_denied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReceiptSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedVerifierReceipt {
    pub claims: VerifierReceiptClaims,
    pub signature: VerifierReceiptSignature,
}

impl VerifierRequest {
    pub fn validate(&self, now_ms: u64) -> Result<(), String> {
        if self.schema_version != SEMANTIC_VERIFIER_SCHEMA_VERSION
            || !token(&self.request_id)
            || !token(&self.nonce)
            || !token(&self.operation_id)
            || !token(&self.contract_id)
            || !sha256(&self.contract_digest)
            || !sha256(&self.product_digest)
            || !token(&self.verifier_profile)
            || self.issued_at_ms >= self.expires_at_ms
            || now_ms >= self.expires_at_ms
        {
            return Err("semantic-verifier request is malformed or expired".into());
        }
        Ok(())
    }
}

impl VerifierReceiptClaims {
    pub fn validate_for_request(
        &self,
        request: &VerifierRequest,
        request_digest: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        request.validate(now_ms)?;
        if self.schema_version != SEMANTIC_VERIFIER_SCHEMA_VERSION
            || !token(&self.receipt_id)
            || self.request_digest != request_digest
            || self.nonce != request.nonce
            || self.operation_id != request.operation_id
            || self.contract_id != request.contract_id
            || self.contract_digest != request.contract_digest
            || self.product_type != request.product_type
            || self.product_digest != request.product_digest
            || self.verifier_profile != request.verifier_profile
            || !token(&self.verifier_id)
            || !token(&self.policy_version)
            || !sha256(&self.validation_effect_manifest_digest)
            || self.isolation.as_ref().is_some_and(|isolation| {
                !token(&isolation.profile)
                    || !sha256(&isolation.executable_digest)
                    || !sha256(&isolation.runtime_config_digest)
                    || !isolation.network_denied
                    || !isolation.process_creation_denied
                    || !isolation.filesystem_mutation_denied
            })
            || self.issued_at_ms < request.issued_at_ms
            || self.issued_at_ms >= self.expires_at_ms
            || self.expires_at_ms > request.expires_at_ms
            || now_ms >= self.expires_at_ms
            || self.reason_codes.is_empty()
            || self.reason_codes.len() > 128
        {
            return Err("semantic-verifier receipt is not bound to the exact request".into());
        }
        let mut reasons = BTreeSet::new();
        if self
            .reason_codes
            .iter()
            .any(|reason| !token(reason) || !reasons.insert(reason.as_str()))
        {
            return Err("semantic-verifier reason codes are malformed or duplicated".into());
        }
        Ok(())
    }
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

    #[test]
    fn contributor_verifier_fixtures_match_public_protocols() {
        let config: IsolatedVerifierConfig = serde_json::from_str(include_str!(
            "../../../integrations/boundary/extensions/semantic-verifier-config.json"
        ))
        .unwrap();
        let result: VerifierProgramResult = serde_json::from_str(include_str!(
            "../../../integrations/boundary/extensions/semantic-verifier-result.json"
        ))
        .unwrap();
        assert_eq!(config.verifier_id, "structured_result_policy");
        assert_eq!(result.verdict, SemanticVerdict::Accept);
    }

    fn request() -> VerifierRequest {
        VerifierRequest {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            request_id: "verify_one".into(),
            nonce: "nonce_one".into(),
            operation_id: "operation_one".into(),
            contract_id: "contract_one".into(),
            contract_digest: format!("sha256:{}", "11".repeat(32)),
            product_type: StructuralProductType::DirectoryTree,
            product_digest: format!("sha256:{}", "22".repeat(32)),
            verifier_profile: "content_policy".into(),
            issued_at_ms: 100,
            expires_at_ms: 900,
        }
    }

    #[test]
    fn receipt_is_bound_to_exact_product_and_request() {
        let request = request();
        let mut receipt = VerifierReceiptClaims {
            schema_version: SEMANTIC_VERIFIER_SCHEMA_VERSION,
            receipt_id: "receipt_one".into(),
            request_digest: format!("sha256:{}", "33".repeat(32)),
            nonce: request.nonce.clone(),
            operation_id: request.operation_id.clone(),
            contract_id: request.contract_id.clone(),
            contract_digest: request.contract_digest.clone(),
            product_type: request.product_type,
            product_digest: request.product_digest.clone(),
            verifier_profile: request.verifier_profile.clone(),
            verifier_id: "verifier_one".into(),
            policy_version: "policy_v4".into(),
            verdict: SemanticVerdict::Accept,
            reason_codes: vec!["validated".into()],
            validation_effect_manifest_digest: format!("sha256:{}", "44".repeat(32)),
            isolation: None,
            issued_at_ms: 110,
            expires_at_ms: 800,
        };
        assert!(receipt
            .validate_for_request(&request, &receipt.request_digest.clone(), 200)
            .is_ok());
        receipt.product_digest = format!("sha256:{}", "55".repeat(32));
        assert!(receipt
            .validate_for_request(&request, &receipt.request_digest.clone(), 200)
            .is_err());
    }
}
