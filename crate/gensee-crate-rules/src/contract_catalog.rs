//! Organization-approved catalogs of operation contracts.
//!
//! A workload never chooses a contract identifier or capability envelope.
//! Catalog selectors bind an OS-observed caller to an operation class, and a
//! separately authenticated intent analyzer may only nominate that class.

use crate::operation_contract::OperationContract;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONTRACT_CATALOG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractCatalog {
    pub schema_version: u32,
    pub catalog_id: String,
    pub organization_id: String,
    pub version: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub contracts: Vec<ApprovedContract>,
    pub selectors: Vec<ContractSelector>,
    pub intent_analyzers: Vec<ApprovedIntentAnalyzer>,
    pub fallback: FallbackPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedContract {
    pub contract: OperationContract,
    pub owner: ContractOwner,
    pub approval: ContractApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractOwner {
    pub application_id: String,
    pub owning_team: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractApproval {
    pub approval_id: String,
    pub approved_by: String,
    pub approved_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSelector {
    pub selector_id: String,
    pub caller: CallerSelector,
    pub operation_class: String,
    pub contract_id: String,
}

/// Exact caller facts observed by the trusted boundary process. At least one
/// field must be set. Matching is conjunctive; wildcards are intentionally not
/// part of schema v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedIntentAnalyzer {
    pub analyzer_id: String,
    pub public_key_hex: String,
    pub model_identity: String,
    pub minimum_confidence_bps: u16,
    pub allowed_operation_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackPolicy {
    pub on_ambiguous_intent: AmbiguousIntentAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_default_contract_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguousIntentAction {
    Deny,
    RequireApproval,
    UseSafeDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContractCatalog {
    pub catalog: ContractCatalog,
    pub signature: CatalogSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAudit {
    pub catalog_id: String,
    pub version: u64,
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ContractCatalog {
    pub fn audit(&self, platform: &str, now_ms: u64) -> CatalogAudit {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        if self.schema_version != CONTRACT_CATALOG_SCHEMA_VERSION {
            errors.push(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, CONTRACT_CATALOG_SCHEMA_VERSION
            ));
        }
        for (label, value) in [
            ("catalog_id", self.catalog_id.as_str()),
            ("organization_id", self.organization_id.as_str()),
        ] {
            if !bounded_token(value) {
                errors.push(format!("{label} must be a bounded ASCII token"));
            }
        }
        if self.version == 0 {
            errors.push("catalog version must be nonzero".to_string());
        }
        if self.issued_at_ms >= self.expires_at_ms {
            errors.push("catalog expiry must be after issuance".to_string());
        } else if now_ms >= self.expires_at_ms {
            errors.push("catalog is expired".to_string());
        }
        if self.contracts.is_empty() {
            errors.push("catalog must contain at least one approved contract".to_string());
        }

        let mut contract_ids = BTreeSet::new();
        for approved in &self.contracts {
            let id = approved.contract.contract_id.as_str();
            if !contract_ids.insert(id) {
                errors.push(format!("duplicate contract_id {id}"));
            }
            let audit = approved.contract.audit_for_platform(platform);
            errors.extend(
                audit
                    .errors
                    .into_iter()
                    .map(|error| format!("contract {id}: {error}")),
            );
            warnings.extend(
                audit
                    .warnings
                    .into_iter()
                    .map(|warning| format!("contract {id}: {warning}")),
            );
            for (label, value) in [
                ("application_id", approved.owner.application_id.as_str()),
                ("owning_team", approved.owner.owning_team.as_str()),
                ("approval_id", approved.approval.approval_id.as_str()),
                ("approved_by", approved.approval.approved_by.as_str()),
            ] {
                if !bounded_token(value) {
                    errors.push(format!("contract {id} {label} is invalid"));
                }
            }
            if approved.approval.approved_at_ms >= approved.approval.expires_at_ms
                || approved.approval.expires_at_ms > self.expires_at_ms
                || now_ms >= approved.approval.expires_at_ms
            {
                errors.push(format!(
                    "contract {id} approval is expired or out of bounds"
                ));
            }
        }

        let mut selector_ids = BTreeSet::new();
        let mut selector_keys = BTreeSet::new();
        for selector in &self.selectors {
            if !bounded_token(&selector.selector_id)
                || !selector.caller.valid()
                || !bounded_token(&selector.operation_class)
            {
                errors.push(format!("selector {} is invalid", selector.selector_id));
            }
            if !selector_ids.insert(selector.selector_id.as_str()) {
                errors.push(format!("duplicate selector_id {}", selector.selector_id));
            }
            if !contract_ids.contains(selector.contract_id.as_str()) {
                errors.push(format!(
                    "selector {} references unknown contract {}",
                    selector.selector_id, selector.contract_id
                ));
            } else if self
                .contracts
                .iter()
                .find(|item| item.contract.contract_id == selector.contract_id)
                .is_some_and(|item| item.contract.operation_class != selector.operation_class)
            {
                errors.push(format!(
                    "selector {} operation class does not match contract",
                    selector.selector_id
                ));
            }
            let key = serde_json::to_string(&(selector.caller.clone(), &selector.operation_class))
                .unwrap_or_default();
            if !selector_keys.insert(key) {
                errors.push(format!(
                    "multiple contracts match selector caller/class for {}",
                    selector.selector_id
                ));
            }
        }

        let mut analyzer_ids = BTreeSet::new();
        for analyzer in &self.intent_analyzers {
            if !bounded_token(&analyzer.analyzer_id)
                || !bounded_token(&analyzer.model_identity)
                || analyzer.minimum_confidence_bps > 10_000
                || !valid_hex(&analyzer.public_key_hex, 32)
                || analyzer.allowed_operation_classes.is_empty()
                || analyzer
                    .allowed_operation_classes
                    .iter()
                    .any(|class| !bounded_token(class))
            {
                errors.push(format!(
                    "intent analyzer {} is invalid",
                    analyzer.analyzer_id
                ));
            }
            if !analyzer_ids.insert(analyzer.analyzer_id.as_str()) {
                errors.push(format!("duplicate analyzer_id {}", analyzer.analyzer_id));
            }
        }

        match self.fallback.on_ambiguous_intent {
            AmbiguousIntentAction::UseSafeDefault => {
                match self.fallback.safe_default_contract_id.as_deref() {
                    Some(id) if contract_ids.contains(id) => {}
                    _ => errors.push(
                        "use_safe_default requires a catalog-approved safe_default_contract_id"
                            .to_string(),
                    ),
                }
            }
            _ if self.fallback.safe_default_contract_id.is_some() => warnings.push(
                "safe_default_contract_id is unused unless ambiguity action is use_safe_default"
                    .to_string(),
            ),
            _ => {}
        }

        CatalogAudit {
            catalog_id: self.catalog_id.clone(),
            version: self.version,
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    pub fn contract(&self, id: &str) -> Option<&ApprovedContract> {
        self.contracts
            .iter()
            .find(|item| item.contract.contract_id == id)
    }
}

impl CallerSelector {
    fn valid(&self) -> bool {
        (self.uid.is_some() || self.executable_sha256.is_some() || self.service_identity.is_some())
            && self.executable_sha256.as_deref().is_none_or(valid_sha256)
            && self.service_identity.as_deref().is_none_or(bounded_token)
    }
}

fn bounded_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value != "."
        && value != ".."
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| valid_hex(hex, 32))
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_contract::{
        ContractCapabilities, ExecutionContract, OPERATION_CONTRACT_SCHEMA_VERSION,
    };

    fn catalog() -> ContractCatalog {
        let contract = OperationContract {
            schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
            contract_id: "offline_transform_v1".into(),
            operation_class: "document_transform".into(),
            execution: ExecutionContract::default(),
            capabilities: ContractCapabilities::default(),
            product: None,
        };
        ContractCatalog {
            schema_version: CONTRACT_CATALOG_SCHEMA_VERSION,
            catalog_id: "production_v1".into(),
            organization_id: "example_org".into(),
            version: 1,
            issued_at_ms: 10,
            expires_at_ms: 1_000,
            contracts: vec![ApprovedContract {
                contract,
                owner: ContractOwner {
                    application_id: "editor".into(),
                    owning_team: "product_security".into(),
                },
                approval: ContractApproval {
                    approval_id: "review_42".into(),
                    approved_by: "security_board".into(),
                    approved_at_ms: 10,
                    expires_at_ms: 900,
                },
            }],
            selectors: vec![ContractSelector {
                selector_id: "editor_transform".into(),
                caller: CallerSelector {
                    uid: Some(1000),
                    executable_sha256: None,
                    service_identity: Some("editor_service".into()),
                },
                operation_class: "document_transform".into(),
                contract_id: "offline_transform_v1".into(),
            }],
            intent_analyzers: vec![ApprovedIntentAnalyzer {
                analyzer_id: "trajectory_analyzer".into(),
                public_key_hex: "11".repeat(32),
                model_identity: "intent_model_v3".into(),
                minimum_confidence_bps: 8_000,
                allowed_operation_classes: vec!["document_transform".into()],
            }],
            fallback: FallbackPolicy {
                on_ambiguous_intent: AmbiguousIntentAction::Deny,
                safe_default_contract_id: None,
            },
        }
    }

    #[test]
    fn approved_catalog_is_valid() {
        let audit = catalog().audit("linux", 100);
        assert!(audit.valid, "{:?}", audit.errors);
    }

    #[test]
    fn duplicate_selector_cannot_hide_more_permissive_contract() {
        let mut candidate = catalog();
        candidate.selectors.push(candidate.selectors[0].clone());
        candidate.selectors[1].selector_id = "shadow".into();
        let audit = candidate.audit("linux", 100);
        assert!(!audit.valid);
        assert!(audit
            .errors
            .iter()
            .any(|error| error.contains("multiple contracts")));
    }

    #[test]
    fn default_must_reference_approved_contract() {
        let mut candidate = catalog();
        candidate.fallback.on_ambiguous_intent = AmbiguousIntentAction::UseSafeDefault;
        candidate.fallback.safe_default_contract_id = Some("caller_chosen".into());
        assert!(!candidate.audit("linux", 100).valid);
    }
}
