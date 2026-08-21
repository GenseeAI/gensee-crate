use super::TcloneRunRecord;
use crate::operation_supervisor::{
    OperationCapabilityEnvelope, OperationCgroupState, OperationState, OperationSupervisor,
};
use crate::*;
use gensee_crate_rules::capability::{
    Capability, CapabilityRequest, CapabilityScope, EffectScope, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use gensee_crate_rules::capability_policy::{
    ApprovalRequirement, CapabilityDecision, CapabilityExecutor, CapabilityPolicyDecision,
    CapabilityPolicyEngine, MediationBoundary, PolicyEvaluationContext,
};

pub(crate) const TCLONE_CAPABILITY_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
const TCLONE_AUTHORITY_ROOT_ENV: &str = "GENSEE_TCLONE_AUTHORITY_ROOT";
const DEFAULT_TCLONE_AUTHORITY_ROOT: &str = "/var/lib/gensee-boundary";

pub(crate) fn tclone_authority_root() -> io::Result<PathBuf> {
    let root = env::var_os(TCLONE_AUTHORITY_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TCLONE_AUTHORITY_ROOT));
    validate_tclone_authority_root(&root)?;
    Ok(root)
}

#[cfg(target_os = "linux")]
fn validate_tclone_authority_root(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability-supervised Tclone requires root",
        ));
    }
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Tclone authority root must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tclone authority root must be a root-owned mode-0700 directory",
        ));
    }
    for ancestor in root.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Tclone authority root ancestry must be root-controlled",
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_tclone_authority_root(_root: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "capability-supervised Tclone requires Linux",
    ))
}

/// Host-authored evidence that a live clone was admitted only as a
/// same-authority continuation. A copy is exposed to the container for
/// attribution, but enforcement always reloads the host operation record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TcloneCapabilityLifecycle {
    pub schema_version: u32,
    pub operation_id: String,
    pub parent_operation_id: String,
    pub policy_decision: CapabilityDecision,
    pub inherited_capabilities: Vec<Capability>,
    pub authority_delta: Vec<Capability>,
    pub authority_expansion_allowed: bool,
    /// Long-lived Tclone currently inherits process memory and container
    /// configuration. This remains false until that inherited authority can be
    /// measured and rebound by the confinement backend.
    pub inherited_ambient_authority_attested: bool,
    pub created_at_ms: u64,
}

pub(crate) struct TcloneOperationGuard {
    supervisor: Option<OperationSupervisor>,
}

impl TcloneOperationGuard {
    pub(crate) fn prepare_source(
        state_root: &Path,
        operation_id: &str,
        run_id: &str,
    ) -> io::Result<Self> {
        validate_tclone_authority_root(state_root)?;
        let supervisor = OperationSupervisor::prepare_at(
            state_root,
            operation_id,
            run_id,
            "tclone_source",
            OperationCapabilityEnvelope {
                capabilities: vec![Capability::ProcessExecution],
                ..OperationCapabilityEnvelope::default()
            },
            None,
        )?;
        Ok(Self {
            supervisor: Some(supervisor),
        })
    }

    pub(crate) fn prepare_fork(
        state_root: &Path,
        operation_id: &str,
        run_id: &str,
        inherited_capabilities: Vec<Capability>,
    ) -> io::Result<Self> {
        validate_tclone_authority_root(state_root)?;
        let supervisor = OperationSupervisor::prepare_at(
            state_root,
            operation_id,
            run_id,
            "tclone_live_fork",
            OperationCapabilityEnvelope {
                capabilities: inherited_capabilities,
                ..OperationCapabilityEnvelope::default()
            },
            None,
        )?;
        Ok(Self {
            supervisor: Some(supervisor),
        })
    }

    pub(crate) fn activate(&mut self, root_pid: u32) -> io::Result<()> {
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or_else(|| io::Error::other("tclone operation guard is no longer active"))?;
        supervisor.activate(root_pid)?;
        if !supervisor
            .envelope_snapshot()?
            .active_mediators
            .contains(&MediationBoundary::ProcessCgroup)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Tclone operation could not establish its mandatory process/cgroup boundary",
            ));
        }
        Ok(())
    }

    pub(crate) fn envelope_snapshot(&mut self) -> io::Result<OperationCapabilityEnvelope> {
        self.supervisor
            .as_mut()
            .ok_or_else(|| io::Error::other("tclone operation guard is no longer active"))?
            .envelope_snapshot()
    }

    pub(crate) fn leave_running(mut self) {
        self.supervisor.take();
    }
}

impl Drop for TcloneOperationGuard {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.as_mut() {
            let _ = supervisor.finish(Some(1), false);
        }
    }
}

pub(crate) fn open_tclone_operation(record: &TcloneRunRecord) -> io::Result<OperationSupervisor> {
    let operation_id = record.operation_id.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "tclone run {} predates capability lifecycle supervision; launch a fresh source before using live capability forks",
                record.run_id
            ),
        )
    })?;
    let state_root = record.operation_state_root.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tclone run has no trusted operation state root",
        )
    })?;
    let state_root = Path::new(state_root);
    validate_tclone_authority_root(state_root)?;
    OperationSupervisor::open_at(state_root, operation_id, &record.run_id)
}

pub(crate) fn attest_parent_for_live_fork(
    record: &TcloneRunRecord,
    expected_root_pid: u32,
) -> io::Result<(String, OperationCapabilityEnvelope)> {
    let mut operation = open_tclone_operation(record)?;
    let attestation = operation.attestation()?;
    if attestation.state != OperationState::Running
        || attestation.cgroup_state != OperationCgroupState::Attached
        || attestation.root_pid != Some(expected_root_pid)
        || attestation.root_start_time_ticks.is_none()
        || !attestation.root_identity_active
        || attestation.boundary_effect_count != 0
        || !attestation.violations.is_empty()
        || !attestation.envelope.leases.is_empty()
        || !attestation
            .envelope
            .active_mediators
            .contains(&MediationBoundary::ProcessCgroup)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork parent is not a clean same-authority operation",
        ));
    }
    Ok((attestation.operation_id, attestation.envelope))
}

pub(crate) fn plan_same_authority_live_fork(
    parent_operation_id: &str,
    child_operation_id: &str,
    parent_envelope: &OperationCapabilityEnvelope,
    now_ms: u64,
) -> io::Result<TcloneCapabilityLifecycle> {
    if !parent_envelope
        .capabilities
        .contains(&Capability::ProcessExecution)
        || !parent_envelope
            .active_mediators
            .contains(&MediationBoundary::ProcessCgroup)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live Tclone fork requires an active parent process/cgroup boundary",
        ));
    }
    let request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION,
        operation_class: "live_runtime_continuation".to_string(),
        effect_scope: EffectScope::ReversibleLocal,
        capabilities: vec![Capability::ProcessExecution],
        scope: CapabilityScope::default(),
        lease_ttl_seconds: 5 * 60,
    };
    let decision = CapabilityPolicyEngine::default().evaluate(
        &request,
        &PolicyEvaluationContext {
            active_mediators: parent_envelope.active_mediators.clone(),
            attachable_mediators: Vec::new(),
            locally_authorized_capabilities: parent_envelope.capabilities.clone(),
            locally_leaseable_capabilities: Vec::new(),
            trusted_mediator_available: false,
            fresh_cell_available: false,
            live_fork_available: true,
            approval_staging_available: false,
            effect_brokerable: false,
            requires_staged_effects: false,
            effects_inseparable_from_runtime: true,
        },
    );
    let authority_delta = request
        .capabilities
        .iter()
        .copied()
        .filter(|capability| !parent_envelope.capabilities.contains(capability))
        .collect::<Vec<_>>();
    if decision.decision != CapabilityPolicyDecision::Plan
        || decision.executor != Some(CapabilityExecutor::LiveFork)
        || decision.approval != ApprovalRequirement::None
        || !authority_delta.is_empty()
        || !decision.lease_delta.capabilities.is_empty()
        || !decision.lease_delta.mediators.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "live Tclone fork cannot be admitted without authority expansion: {}",
                decision.reason_codes.join(", ")
            ),
        ));
    }
    Ok(TcloneCapabilityLifecycle {
        schema_version: TCLONE_CAPABILITY_LIFECYCLE_SCHEMA_VERSION,
        operation_id: child_operation_id.to_string(),
        parent_operation_id: parent_operation_id.to_string(),
        policy_decision: decision,
        inherited_capabilities: parent_envelope.capabilities.clone(),
        authority_delta,
        authority_expansion_allowed: false,
        inherited_ambient_authority_attested: false,
        created_at_ms: now_ms,
    })
}

pub(crate) fn attest_live_fork_for_promotion(
    record: &TcloneRunRecord,
    parent: &TcloneRunRecord,
    expected_root_pid: u32,
    expected_parent_root_pid: u32,
) -> io::Result<()> {
    let lifecycle = record.capability_lifecycle.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork promotion requires capability lifecycle evidence",
        )
    })?;
    if lifecycle.schema_version != TCLONE_CAPABILITY_LIFECYCLE_SCHEMA_VERSION
        || lifecycle.operation_id != record.operation_id.as_deref().unwrap_or_default()
        || lifecycle.parent_operation_id != parent.operation_id.as_deref().unwrap_or_default()
        || lifecycle.policy_decision.decision != CapabilityPolicyDecision::Plan
        || lifecycle.policy_decision.executor != Some(CapabilityExecutor::LiveFork)
        || lifecycle.authority_expansion_allowed
        || !lifecycle.authority_delta.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork capability lifecycle evidence is invalid or expands authority",
        ));
    }
    let mut parent_operation = open_tclone_operation(parent)?;
    let parent_attestation = parent_operation.attestation()?;
    if parent_attestation.state != OperationState::Running
        || parent_attestation.cgroup_state != OperationCgroupState::Attached
        || parent_attestation.root_pid != Some(expected_parent_root_pid)
        || parent_attestation.root_start_time_ticks.is_none()
        || !parent_attestation.root_identity_active
        || parent_attestation.boundary_effect_count != 0
        || !parent_attestation.violations.is_empty()
        || !parent_attestation.envelope.leases.is_empty()
        || parent_attestation.envelope.capabilities != lifecycle.inherited_capabilities
        || !parent_attestation
            .envelope
            .active_mediators
            .contains(&MediationBoundary::ProcessCgroup)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork parent operation is no longer an active supervised source",
        ));
    }
    let mut operation = open_tclone_operation(record)?;
    let attestation = operation.attestation()?;
    if attestation.operation_id != lifecycle.operation_id
        || attestation.source_run_id != record.run_id
        || attestation.state != OperationState::Running
        || attestation.cgroup_state != OperationCgroupState::Attached
        || attestation.root_pid != Some(expected_root_pid)
        || attestation.root_start_time_ticks.is_none()
        || !attestation.root_identity_active
        || attestation.boundary_effect_count != 0
        || !attestation.violations.is_empty()
        || attestation.envelope.capabilities != lifecycle.inherited_capabilities
        || !attestation
            .envelope
            .active_mediators
            .contains(&MediationBoundary::ProcessCgroup)
        || !attestation.envelope.leases.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork operation attestation is incomplete, violated, or contains additional leases",
        ));
    }
    let recomputed = plan_same_authority_live_fork(
        &parent_attestation.operation_id,
        &attestation.operation_id,
        &attestation.envelope,
        lifecycle.created_at_ms,
    )?;
    if recomputed != *lifecycle {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "live fork policy evidence does not match the trusted operation state",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_envelope() -> OperationCapabilityEnvelope {
        OperationCapabilityEnvelope {
            capabilities: vec![Capability::ProcessExecution],
            active_mediators: vec![MediationBoundary::ProcessCgroup],
            ..OperationCapabilityEnvelope::default()
        }
    }

    #[test]
    fn live_fork_plan_has_no_authority_delta_and_cannot_expand_authority() {
        let lifecycle =
            plan_same_authority_live_fork("op_parent", "op_child", &parent_envelope(), 42).unwrap();
        assert_eq!(
            lifecycle.policy_decision.executor,
            Some(CapabilityExecutor::LiveFork)
        );
        assert!(lifecycle.authority_delta.is_empty());
        assert!(lifecycle
            .policy_decision
            .lease_delta
            .capabilities
            .is_empty());
        assert!(!lifecycle.authority_expansion_allowed);
        assert!(!lifecycle.inherited_ambient_authority_attested);
    }

    #[test]
    fn live_fork_plan_fails_without_parent_cgroup_boundary() {
        let mut envelope = parent_envelope();
        envelope.active_mediators.clear();
        assert!(plan_same_authority_live_fork("op_parent", "op_child", &envelope, 42).is_err());
    }
}
