//! Generic authority-closure and transactional-promotion evidence.

use crate::capability_broker::BrokerLeaseStatus;
use serde::{Deserialize, Serialize};

pub const TRANSACTIONAL_PROMOTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityLifecycleHead {
    pub lease_id: String,
    pub status: BrokerLeaseStatus,
    pub lifecycle_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityClosureClaims {
    pub schema_version: u32,
    pub proof_id: String,
    pub operation_id: String,
    pub source_run_id: String,
    pub checked_at_ms: u64,
    pub lifecycle_heads: Vec<AuthorityLifecycleHead>,
    pub active_lease_ids: Vec<String>,
    pub unresolved_lease_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityClosure {
    pub claims: AuthorityClosureClaims,
    pub host_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionJournalState {
    Prepared,
    Switching,
    Complete,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionJournalClaims {
    pub schema_version: u32,
    pub promotion_id: String,
    pub operation_id: String,
    pub contract_digest: String,
    pub product_digest: String,
    pub verifier_receipt_digest: String,
    pub authority_closure_digest: String,
    pub destination_root: String,
    pub active_pointer: String,
    pub new_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_target: Option<String>,
    pub state: PromotionJournalState,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPromotionJournal {
    pub claims: PromotionJournalClaims,
    pub host_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionalPromotionReceipt {
    pub schema_version: u32,
    pub promotion_id: String,
    pub operation_id: String,
    pub product_digest: String,
    pub verifier_receipt_digest: String,
    pub authority_closure_digest: String,
    pub active_target: String,
    pub promoted_at_ms: u64,
    pub host_signature: String,
}
