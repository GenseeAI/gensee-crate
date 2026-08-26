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
    #[serde(default)]
    pub operation_services: Vec<ApprovedOperationService>,
    #[serde(default)]
    pub semantic_verifiers: Vec<ApprovedSemanticVerifier>,
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
pub struct ApprovedOperationService {
    pub service_id: String,
    pub public_key_hex: String,
    pub can_initiate: bool,
    pub allowed_audiences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedSemanticVerifier {
    pub verifier_id: String,
    pub public_key_hex: String,
    pub profiles: Vec<String>,
    pub policy_versions: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_isolation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolated_runtime_config_digest: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
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

pub const INTENT_OBSERVATION_SCHEMA_VERSION: u32 = 1;
pub const INTENT_INFERENCE_SCHEMA_VERSION: u32 = 1;
pub const INTENT_MODEL_SCHEMA_VERSION: u32 = 1;

/// Facts presented to an approved probabilistic analyzer. Runtime caller and
/// command facts are re-derived by the admission process before execution;
/// evidence references allow a long-horizon analyzer to use authenticated
/// earlier effects without making the authorization core model-specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentObservation {
    pub schema_version: u32,
    pub observation_id: String,
    pub observed_at_ms: u64,
    pub caller: ObservedCaller,
    pub command_digest: String,
    #[serde(default)]
    pub command_features: Vec<String>,
    #[serde(default)]
    pub trajectory: Vec<TrajectoryEvidence>,
    pub history_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCaller {
    pub uid: u32,
    pub executable_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrajectoryEvidence {
    pub evidence_id: String,
    pub kind: String,
    pub digest: String,
    pub trust_domain: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    /// Bounded, non-secret behavioral labels produced by trusted telemetry
    /// normalization. The analyzer consumes labels, never raw transcript text.
    #[serde(default)]
    pub features: Vec<String>,
}

/// A portable scored-feature analyzer. Organizations can replace this with a
/// learned service, but this built-in model makes intent discovery runnable
/// without placing authorization policy in the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentAnalysisModel {
    pub schema_version: u32,
    pub analyzer_id: String,
    pub model_identity: String,
    pub classes: Vec<IntentClassModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentClassModel {
    pub operation_class: String,
    /// Base score in milli-units. Scores are converted to normalized
    /// probabilities only after all bounded feature weights are applied.
    pub intercept: i32,
    #[serde(default)]
    pub weights: std::collections::BTreeMap<String, i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentInference {
    pub schema_version: u32,
    pub inference_id: String,
    pub analyzer_id: String,
    pub model_identity: String,
    pub observation_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub candidates: Vec<IntentCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentCandidate {
    pub operation_class: String,
    pub confidence_bps: u16,
    pub rationale_code: String,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIntentInference {
    pub inference: IntentInference,
    pub signature: InferenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractResolutionSource {
    ProbabilisticInference,
    ApprovedSafeDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractResolution {
    pub catalog_id: String,
    pub catalog_version: u64,
    pub observation_id: String,
    pub inference_id: String,
    pub analyzer_id: String,
    pub selected_operation_class: String,
    pub selected_contract_id: String,
    pub confidence_bps: u16,
    pub source: ContractResolutionSource,
    pub ambiguity_reason: Option<String>,
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
        } else if now_ms < self.issued_at_ms {
            errors.push("catalog is not valid yet".to_string());
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
            if approved.approval.approved_at_ms < self.issued_at_ms
                || approved.approval.approved_at_ms >= approved.approval.expires_at_ms
                || approved.approval.expires_at_ms > self.expires_at_ms
                || now_ms < approved.approval.approved_at_ms
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

        let mut service_ids = BTreeSet::new();
        for service in &self.operation_services {
            if !bounded_token(&service.service_id)
                || !valid_hex(&service.public_key_hex, 32)
                || service.allowed_audiences.is_empty()
                || service
                    .allowed_audiences
                    .iter()
                    .any(|audience| !bounded_token(audience))
            {
                errors.push(format!(
                    "operation service {} is invalid",
                    service.service_id
                ));
            }
            if !service_ids.insert(service.service_id.as_str()) {
                errors.push(format!(
                    "duplicate operation service {}",
                    service.service_id
                ));
            }
        }

        let mut verifier_ids = BTreeSet::new();
        for verifier in &self.semantic_verifiers {
            if !bounded_token(&verifier.verifier_id)
                || !valid_hex(&verifier.public_key_hex, 32)
                || verifier.profiles.is_empty()
                || verifier.policy_versions.is_empty()
                || verifier.profiles.iter().any(|value| !bounded_token(value))
                || verifier
                    .policy_versions
                    .iter()
                    .any(|value| !bounded_token(value))
                || (verifier.require_isolation
                    && verifier
                        .isolated_runtime_config_digest
                        .as_deref()
                        .is_none_or(|digest| !valid_sha256(digest)))
                || (!verifier.require_isolation
                    && verifier.isolated_runtime_config_digest.is_some())
            {
                errors.push(format!(
                    "semantic verifier {} is invalid",
                    verifier.verifier_id
                ));
            }
            if !verifier_ids.insert(verifier.verifier_id.as_str()) {
                errors.push(format!(
                    "duplicate semantic verifier {}",
                    verifier.verifier_id
                ));
            }
        }
        for service in &self.operation_services {
            for audience in &service.allowed_audiences {
                if !service_ids.contains(audience.as_str()) {
                    errors.push(format!(
                        "operation service {} references unknown audience {}",
                        service.service_id, audience
                    ));
                }
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

    /// Resolve one verified inference. The inference contains no contract ID
    /// and therefore cannot widen authority; selection always passes through
    /// an exact caller/class selector in this signed catalog.
    pub fn resolve_intent(
        &self,
        observation: &IntentObservation,
        inference: &IntentInference,
        now_ms: u64,
    ) -> Result<ContractResolution, String> {
        observation.validate()?;
        inference.validate(observation, now_ms)?;
        let analyzer = self
            .intent_analyzers
            .iter()
            .find(|item| item.analyzer_id == inference.analyzer_id)
            .ok_or_else(|| "intent inference uses an unapproved analyzer".to_string())?;
        if analyzer.model_identity != inference.model_identity {
            return Err("intent inference model identity is not catalog-approved".to_string());
        }

        let mut ranked = inference.candidates.iter().collect::<Vec<_>>();
        ranked.sort_by_key(|candidate| std::cmp::Reverse(candidate.confidence_bps));
        let best = ranked
            .first()
            .ok_or_else(|| "intent inference has no candidates".to_string())?;
        let tied = ranked
            .get(1)
            .is_some_and(|candidate| candidate.confidence_bps == best.confidence_bps);
        let permitted_class = analyzer
            .allowed_operation_classes
            .iter()
            .any(|class| class == &best.operation_class);
        let confident = best.confidence_bps >= analyzer.minimum_confidence_bps;

        if !tied && permitted_class && confident {
            let selected = self.select_for_caller(&observation.caller, &best.operation_class)?;
            return Ok(ContractResolution {
                catalog_id: self.catalog_id.clone(),
                catalog_version: self.version,
                observation_id: observation.observation_id.clone(),
                inference_id: inference.inference_id.clone(),
                analyzer_id: inference.analyzer_id.clone(),
                selected_operation_class: best.operation_class.clone(),
                selected_contract_id: selected.contract_id.clone(),
                confidence_bps: best.confidence_bps,
                source: ContractResolutionSource::ProbabilisticInference,
                ambiguity_reason: None,
            });
        }

        let reason = if tied {
            "highest-confidence operation classes are tied"
        } else if !permitted_class {
            "highest-confidence operation class is outside analyzer scope"
        } else {
            "highest-confidence operation class is below the catalog threshold"
        };
        match self.fallback.on_ambiguous_intent {
            AmbiguousIntentAction::Deny => Err(format!("ambiguous intent denied: {reason}")),
            AmbiguousIntentAction::RequireApproval => Err(format!(
                "ambiguous intent requires explicit operator approval: {reason}"
            )),
            AmbiguousIntentAction::UseSafeDefault => {
                let contract_id = self
                    .fallback
                    .safe_default_contract_id
                    .as_deref()
                    .ok_or_else(|| "safe-default contract is missing".to_string())?;
                let approved = self
                    .contract(contract_id)
                    .ok_or_else(|| "safe-default contract is not approved".to_string())?;
                let selected = self
                    .select_for_caller(&observation.caller, &approved.contract.operation_class)?;
                if selected.contract_id != contract_id {
                    return Err(
                        "safe-default contract is not selected for the observed caller".to_string(),
                    );
                }
                Ok(ContractResolution {
                    catalog_id: self.catalog_id.clone(),
                    catalog_version: self.version,
                    observation_id: observation.observation_id.clone(),
                    inference_id: inference.inference_id.clone(),
                    analyzer_id: inference.analyzer_id.clone(),
                    selected_operation_class: approved.contract.operation_class.clone(),
                    selected_contract_id: contract_id.to_string(),
                    confidence_bps: best.confidence_bps,
                    source: ContractResolutionSource::ApprovedSafeDefault,
                    ambiguity_reason: Some(reason.to_string()),
                })
            }
        }
    }

    fn select_for_caller(
        &self,
        caller: &ObservedCaller,
        operation_class: &str,
    ) -> Result<&ContractSelector, String> {
        let mut matches = self.selectors.iter().filter(|selector| {
            selector.operation_class == operation_class && selector.caller.matches(caller)
        });
        let selected = matches.next().ok_or_else(|| {
            "no approved contract matches the observed caller and class".to_string()
        })?;
        if matches.next().is_some() {
            return Err(
                "multiple approved contracts match the observed caller and class".to_string(),
            );
        }
        Ok(selected)
    }
}

impl CallerSelector {
    fn valid(&self) -> bool {
        (self.uid.is_some() || self.executable_sha256.is_some() || self.service_identity.is_some())
            && self.executable_sha256.as_deref().is_none_or(valid_sha256)
            && self.service_identity.as_deref().is_none_or(bounded_token)
    }

    fn matches(&self, caller: &ObservedCaller) -> bool {
        self.uid.is_none_or(|uid| uid == caller.uid)
            && self
                .executable_sha256
                .as_deref()
                .is_none_or(|digest| digest == caller.executable_sha256)
            && self
                .service_identity
                .as_deref()
                .is_none_or(|identity| caller.service_identity.as_deref() == Some(identity))
    }
}

impl IntentObservation {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != INTENT_OBSERVATION_SCHEMA_VERSION
            || !bounded_token(&self.observation_id)
            || !valid_sha256(&self.command_digest)
            || !valid_sha256(&self.caller.executable_sha256)
            || self
                .caller
                .service_identity
                .as_deref()
                .is_some_and(|value| !bounded_token(value))
            || self.command_features.len() > 128
            || self
                .command_features
                .iter()
                .any(|value| !bounded_token(value))
            || self.trajectory.len() > 1024
        {
            return Err("intent observation is malformed or exceeds schema limits".to_string());
        }
        let mut ids = BTreeSet::new();
        for evidence in &self.trajectory {
            if !ids.insert(evidence.evidence_id.as_str())
                || !bounded_token(&evidence.evidence_id)
                || !bounded_token(&evidence.kind)
                || !bounded_token(&evidence.trust_domain)
                || !valid_sha256(&evidence.digest)
                || evidence.started_at_ms > evidence.finished_at_ms
                || evidence.finished_at_ms > self.observed_at_ms
                || evidence.features.len() > 128
                || evidence
                    .features
                    .iter()
                    .any(|feature| !bounded_token(feature))
            {
                return Err("trajectory evidence is malformed or duplicated".to_string());
            }
        }
        Ok(())
    }
}

impl IntentInference {
    pub fn validate(&self, observation: &IntentObservation, now_ms: u64) -> Result<(), String> {
        if self.schema_version != INTENT_INFERENCE_SCHEMA_VERSION
            || !bounded_token(&self.inference_id)
            || !bounded_token(&self.analyzer_id)
            || !bounded_token(&self.model_identity)
            || !valid_sha256(&self.observation_digest)
            || self.issued_at_ms >= self.expires_at_ms
            || now_ms >= self.expires_at_ms
            || self.candidates.is_empty()
            || self.candidates.len() > 64
        {
            return Err("intent inference is malformed, expired, or empty".to_string());
        }
        let evidence_ids = observation
            .trajectory
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut classes = BTreeSet::new();
        for candidate in &self.candidates {
            if !classes.insert(candidate.operation_class.as_str())
                || !bounded_token(&candidate.operation_class)
                || !bounded_token(&candidate.rationale_code)
                || candidate.confidence_bps > 10_000
                || candidate.evidence_ids.len() > 128
                || candidate
                    .evidence_ids
                    .iter()
                    .any(|id| !evidence_ids.contains(id.as_str()))
            {
                return Err("intent candidate is malformed or duplicated".to_string());
            }
        }
        Ok(())
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
            operation_services: Vec::new(),
            semantic_verifiers: Vec::new(),
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

    #[test]
    fn future_catalog_or_approval_cannot_authorize_early() {
        let mut candidate = catalog();
        candidate.issued_at_ms = 200;
        candidate.contracts[0].approval.approved_at_ms = 200;
        let audit = candidate.audit("linux", 100);
        assert!(!audit.valid);
        assert!(audit
            .errors
            .iter()
            .any(|error| error.contains("not valid yet")));

        let mut candidate = catalog();
        candidate.contracts[0].approval.approved_at_ms = 200;
        let audit = candidate.audit("linux", 100);
        assert!(!audit.valid);
        assert!(audit
            .errors
            .iter()
            .any(|error| error.contains("approval is expired or out of bounds")));
    }

    #[test]
    fn isolated_verifier_requires_catalog_pinned_runtime_config() {
        let mut candidate = catalog();
        candidate.semantic_verifiers.push(ApprovedSemanticVerifier {
            verifier_id: "content_verifier".into(),
            public_key_hex: "33".repeat(32),
            profiles: vec!["content_policy".into()],
            policy_versions: vec!["policy_v1".into()],
            require_isolation: true,
            isolated_runtime_config_digest: None,
        });
        assert!(!candidate.audit("linux", 100).valid);
        candidate.semantic_verifiers[0].isolated_runtime_config_digest =
            Some(format!("sha256:{}", "44".repeat(32)));
        assert!(candidate.audit("linux", 100).valid);
    }

    fn observation() -> IntentObservation {
        IntentObservation {
            schema_version: INTENT_OBSERVATION_SCHEMA_VERSION,
            observation_id: "obs_1".into(),
            observed_at_ms: 100,
            caller: ObservedCaller {
                uid: 1000,
                executable_sha256: format!("sha256:{}", "22".repeat(32)),
                service_identity: Some("editor_service".into()),
            },
            command_digest: format!("sha256:{}", "33".repeat(32)),
            command_features: vec!["writes_structured_output".into()],
            trajectory: vec![TrajectoryEvidence {
                evidence_id: "prior_effects".into(),
                kind: "effect_manifest".into(),
                digest: format!("sha256:{}", "44".repeat(32)),
                trust_domain: "host_observer".into(),
                started_at_ms: 1,
                finished_at_ms: 90,
                features: vec!["prior_network_effect".into()],
            }],
            history_complete: true,
        }
    }

    fn inference(confidence_bps: u16) -> IntentInference {
        IntentInference {
            schema_version: INTENT_INFERENCE_SCHEMA_VERSION,
            inference_id: "infer_1".into(),
            analyzer_id: "trajectory_analyzer".into(),
            model_identity: "intent_model_v3".into(),
            observation_digest: format!("sha256:{}", "55".repeat(32)),
            issued_at_ms: 100,
            expires_at_ms: 500,
            candidates: vec![IntentCandidate {
                operation_class: "document_transform".into(),
                confidence_bps,
                rationale_code: "trajectory_match".into(),
                evidence_ids: vec!["prior_effects".into()],
            }],
        }
    }

    #[test]
    fn inference_selects_class_not_contract() {
        let resolution = catalog()
            .resolve_intent(&observation(), &inference(9_000), 200)
            .unwrap();
        assert_eq!(resolution.selected_contract_id, "offline_transform_v1");
        assert_eq!(
            resolution.source,
            ContractResolutionSource::ProbabilisticInference
        );
    }

    #[test]
    fn low_confidence_cannot_widen_authority() {
        let error = catalog()
            .resolve_intent(&observation(), &inference(7_999), 200)
            .unwrap_err();
        assert!(error.contains("ambiguous intent denied"));
    }
}
