//! Generic admission contracts for operation-bound execution.
//!
//! Contracts describe authority and product shape without recognizing an
//! application, package manager, browser, or attack signature. The runtime
//! binds each admitted instance to an OS-observed execution subject and an
//! effect boundary before the command starts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Component, Path};

pub const OPERATION_CONTRACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContract {
    pub schema_version: u32,
    pub contract_id: String,
    pub operation_class: String,
    #[serde(default)]
    pub execution: ExecutionContract,
    #[serde(default)]
    pub capabilities: ContractCapabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<ProductContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContract {
    #[serde(default = "default_max_runtime_seconds")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_true")]
    pub require_os_execution_binding: bool,
}

impl Default for ExecutionContract {
    fn default() -> Self {
        Self {
            max_runtime_seconds: default_max_runtime_seconds(),
            require_os_execution_binding: true,
        }
    }
}

fn default_max_runtime_seconds() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractCapabilities {
    #[serde(default)]
    pub network: ContractNetworkCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractNetworkCapability {
    #[serde(default)]
    pub mode: ContractNetworkMode,
    #[serde(default)]
    pub allowed_endpoints: Vec<ContractNetworkEndpoint>,
}

impl Default for ContractNetworkCapability {
    fn default() -> Self {
        Self {
            mode: ContractNetworkMode::DenyAll,
            allowed_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractNetworkMode {
    #[default]
    DenyAll,
    AllowExact,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractNetworkEndpoint {
    /// A resolved IP address, never a hostname. Resolution belongs in a
    /// trusted protocol mediator so enforcement cannot be bypassed by DNS.
    pub destination: String,
    pub protocol: ContractNetworkProtocol,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractNetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductContract {
    pub kind: StructuralProductType,
    /// Relative path inside the staged workspace. The producer never chooses
    /// the trusted destination.
    pub path: String,
    #[serde(default = "default_max_product_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_max_product_entries")]
    pub max_entries: u64,
    #[serde(default = "default_true")]
    pub reject_symlinks: bool,
    #[serde(default = "default_true")]
    pub reject_special_files: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_verifier_profile: Option<String>,
}

fn default_max_product_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_max_product_entries() -> u64 {
    10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralProductType {
    Blob,
    BlobSet,
    DirectoryTree,
    WorkspacePatch,
    StructuredResult,
    EnvironmentSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractAudit {
    pub contract_id: String,
    pub valid: bool,
    pub enforceable_on_platform: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Host-produced evidence for one concrete admitted contract instance. The
/// schema separates structural product facts from semantic-verifier claims so
/// a consumer cannot mistake a hash for a malware verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRunManifest {
    pub schema_version: u32,
    pub operation_id: String,
    pub source_run_id: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub command_digest: String,
    pub admission: OperationAdmissionEvidence,
    pub operation_record: String,
    pub original_workspace: String,
    pub staged_workspace: String,
    pub enforcement: OperationEnforcementEvidence,
    pub process: OperationProcessEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<StructuralProductEvidence>,
    pub promotion: OperationPromotionEvidence,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_signature: Option<OperationManifestSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationManifestSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAdmissionEvidence {
    pub catalog_id: String,
    pub catalog_version: u64,
    pub catalog_digest: String,
    pub observation_digest: String,
    pub inference_digest: String,
    pub analyzer_id: String,
    pub selected_operation_class: String,
    pub confidence_bps: u16,
    pub resolution_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ambiguity_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEnforcementEvidence {
    pub os_execution_binding_established: bool,
    pub execution_subject_kind: String,
    pub network_mode: ContractNetworkMode,
    pub network_boundary: String,
    pub network_effect_coverage: String,
    #[serde(default)]
    pub allowed_network_effects: Vec<OperationNetworkEffect>,
    #[serde(default)]
    pub denied_network_effects: Vec<OperationNetworkEffect>,
    #[serde(default)]
    pub collection_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationNetworkEffect {
    pub destination: String,
    pub protocol: String,
    pub ports: Vec<u16>,
    pub packets: u64,
    pub bytes: u64,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProcessEvidence {
    pub root_pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_start_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub process_group_drained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralProductEvidence {
    pub kind: StructuralProductType,
    pub path: String,
    pub digest: String,
    pub entries: u64,
    pub bytes: u64,
    pub structurally_valid: bool,
    /// `not_claimed` or `receipt_required:<profile>` in schema v1. It is never
    /// inferred from structural facts.
    pub semantic_status: String,
    #[serde(default)]
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPromotionEvidence {
    pub performed: bool,
    pub structurally_eligible: bool,
    pub semantically_verified: bool,
    pub reason: String,
}

impl OperationContract {
    pub fn audit_for_platform(&self, platform: &str) -> ContractAudit {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        if self.schema_version != OPERATION_CONTRACT_SCHEMA_VERSION {
            errors.push(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, OPERATION_CONTRACT_SCHEMA_VERSION
            ));
        }
        if !bounded_token(&self.contract_id) {
            errors.push("contract_id must be a bounded ASCII token".to_string());
        }
        if !bounded_token(&self.operation_class) {
            errors.push("operation_class must be a bounded ASCII token".to_string());
        }
        if !(1..=86_400).contains(&self.execution.max_runtime_seconds) {
            errors.push("execution.max_runtime_seconds must be between 1 and 86400".to_string());
        }
        if !self.execution.require_os_execution_binding {
            errors.push(
                "v1 contracts must require an OS execution-subject binding; audit-only attribution is not an enforcement contract"
                    .to_string(),
            );
        }
        self.audit_network(&mut errors);
        if let Some(product) = &self.product {
            audit_product(product, &mut errors, &mut warnings);
        }

        let platform_supported = matches!(platform, "linux" | "macos");
        if !platform_supported {
            warnings.push(format!(
                "OS-bound execution enforcement is not implemented on platform {platform}"
            ));
        }
        if platform == "macos" && self.capabilities.network.mode == ContractNetworkMode::AllowExact
        {
            warnings.push(
                "exact endpoint network envelopes require Linux cgroup/nftables; macOS v1 supports deny_all only"
                    .to_string(),
            );
        }
        let valid = errors.is_empty();
        let enforceable_on_platform = valid
            && platform_supported
            && !(platform == "macos"
                && self.capabilities.network.mode == ContractNetworkMode::AllowExact);
        ContractAudit {
            contract_id: self.contract_id.clone(),
            valid,
            enforceable_on_platform,
            errors,
            warnings,
        }
    }

    fn audit_network(&self, errors: &mut Vec<String>) {
        let network = &self.capabilities.network;
        if network.mode == ContractNetworkMode::DenyAll && !network.allowed_endpoints.is_empty() {
            errors.push("deny_all network mode cannot contain allowed_endpoints".to_string());
        }
        if network.mode == ContractNetworkMode::AllowExact && network.allowed_endpoints.is_empty() {
            errors.push("allow_exact network mode requires at least one endpoint".to_string());
        }
        let mut unique = BTreeSet::new();
        for endpoint in &network.allowed_endpoints {
            match endpoint.destination.parse::<IpAddr>() {
                Ok(address) if restricted_raw_destination(address) => errors.push(format!(
                    "network endpoint {} is local, private, metadata-adjacent, or otherwise ineligible for raw authority; use a trusted mediator",
                    endpoint.destination
                )),
                Ok(_) => {}
                Err(_) => errors.push(format!(
                    "network endpoint {} must be an exact resolved IP address",
                    endpoint.destination
                )),
            }
            if endpoint.ports.is_empty() || endpoint.ports.contains(&0) {
                errors.push(format!(
                    "network endpoint {} requires nonzero ports",
                    endpoint.destination
                ));
            }
            if !unique.insert(endpoint.clone()) {
                errors.push(format!(
                    "duplicate network endpoint {}",
                    endpoint.destination
                ));
            }
        }
    }
}

fn audit_product(product: &ProductContract, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    if !safe_relative_path(&product.path) {
        errors.push("product.path must contain only normal relative path components".to_string());
    }
    if product.max_bytes == 0 || product.max_entries == 0 {
        errors.push("product byte and entry budgets must be nonzero".to_string());
    }
    if product.max_bytes > 16 * 1024 * 1024 * 1024 {
        errors.push("product.max_bytes exceeds the 16 GiB contract ceiling".to_string());
    }
    if product.max_entries > 1_000_000 {
        errors.push("product.max_entries exceeds the 1,000,000 entry ceiling".to_string());
    }
    if !product.reject_symlinks || !product.reject_special_files {
        errors.push(
            "v1 product contracts must reject symlinks and special filesystem objects".to_string(),
        );
    }
    if let Some(profile) = product.semantic_verifier_profile.as_deref() {
        if !bounded_token(profile) {
            errors.push("semantic_verifier_profile must be a bounded ASCII token".to_string());
        } else {
            warnings.push(format!(
                "semantic verifier profile {profile} requires a separately authenticated verifier receipt; the structural core does not infer semantic safety"
            ));
        }
    } else {
        warnings.push(
            "product has structural verification only; it must not be represented as semantically safe"
                .to_string(),
        );
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

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && !value.starts_with("./")
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains('\\')
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn restricted_raw_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> OperationContract {
        OperationContract {
            schema_version: OPERATION_CONTRACT_SCHEMA_VERSION,
            contract_id: "offline-transform-v1".to_string(),
            operation_class: "document_transform".to_string(),
            execution: ExecutionContract::default(),
            capabilities: ContractCapabilities::default(),
            product: Some(ProductContract {
                kind: StructuralProductType::StructuredResult,
                path: "out/result.json".to_string(),
                max_bytes: 1024,
                max_entries: 1,
                reject_symlinks: true,
                reject_special_files: true,
                semantic_verifier_profile: None,
            }),
        }
    }

    #[test]
    fn generic_contract_is_valid_and_honest_about_semantics() {
        let audit = contract().audit_for_platform("linux");
        assert!(audit.valid);
        assert!(audit.enforceable_on_platform);
        assert!(audit
            .warnings
            .iter()
            .any(|warning| warning.contains("structural verification only")));
    }

    #[test]
    fn product_paths_reject_traversal_and_aliases() {
        for path in ["../out", "out/../escape", "/tmp/out", "./out", "out//file"] {
            let mut candidate = contract();
            candidate.product.as_mut().unwrap().path = path.to_string();
            assert!(!candidate.audit_for_platform("linux").valid, "{path}");
        }
    }

    #[test]
    fn exact_network_scope_is_ip_and_port_bound() {
        let mut candidate = contract();
        candidate.capabilities.network = ContractNetworkCapability {
            mode: ContractNetworkMode::AllowExact,
            allowed_endpoints: vec![ContractNetworkEndpoint {
                destination: "example.com".to_string(),
                protocol: ContractNetworkProtocol::Tcp,
                ports: vec![443],
            }],
        };
        assert!(!candidate.audit_for_platform("linux").valid);
        candidate.capabilities.network.allowed_endpoints[0].destination = "93.184.216.34".into();
        assert!(candidate.audit_for_platform("linux").valid);
        assert!(
            !candidate
                .audit_for_platform("macos")
                .enforceable_on_platform
        );
        candidate.capabilities.network.allowed_endpoints[0].destination = "127.0.0.1".into();
        assert!(!candidate.audit_for_platform("linux").valid);
    }

    #[test]
    fn v1_rejects_weak_identity_and_unsafe_product_switches() {
        let mut candidate = contract();
        candidate.execution.require_os_execution_binding = false;
        assert!(!candidate.audit_for_platform("linux").valid);
        candidate.execution.require_os_execution_binding = true;
        candidate.product.as_mut().unwrap().reject_symlinks = false;
        assert!(!candidate.audit_for_platform("linux").valid);
    }
}
