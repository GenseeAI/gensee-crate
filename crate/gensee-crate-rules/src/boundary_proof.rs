//! Independently signed proof bundle for the generic boundary conformance run.

use serde::{Deserialize, Serialize};

pub const BOUNDARY_PROOF_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryProofArtifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryProofClaims {
    pub schema_version: u32,
    pub proof_id: String,
    pub operation_id: String,
    pub created_at_ms: u64,
    pub os_execution_binding_established: bool,
    pub allowed_packets: u64,
    pub denied_packets: u64,
    pub execution_subject_drained: bool,
    pub product_digest: String,
    pub active_target: String,
    pub artifacts: Vec<BoundaryProofArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBoundaryProof {
    pub claims: BoundaryProofClaims,
    pub algorithm: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}
