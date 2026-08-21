//! Deterministic policy decisions for requested privilege deltas.
//!
//! This module does not execute commands or mint credentials. It decides
//! which boundary must own an operation and fails closed when a typed scope or
//! mandatory mediator is missing.

use crate::capability::{
    Capability, CapabilityRequest, EffectScope, ExecutionBoundary, FileOperationKind,
    CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediationBoundary {
    ProcessCgroup,
    FilesystemBoundary,
    NetworkBoundary,
    SecretBroker,
    WorkloadIdentityBroker,
    KernelBoundary,
    CloudApiGateway,
    ExternalApiGateway,
    BrowserAutomationGateway,
    DatabaseProxy,
    OutputPromotionTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPolicyDecision {
    AllowLocally,
    DelegateToIsolatedCell,
    StageForApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDecision {
    pub decision: CapabilityPolicyDecision,
    pub reason_codes: Vec<String>,
    pub required_mediators: Vec<MediationBoundary>,
    pub missing_mediators: Vec<MediationBoundary>,
}

/// Runtime facts supplied by the trusted orchestrator. Listing a mediator here
/// means its enforcement boundary is active for this operation, not merely
/// installed on the host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationContext {
    #[serde(default)]
    pub active_mediators: Vec<MediationBoundary>,
    #[serde(default)]
    pub locally_authorized_capabilities: Vec<Capability>,
    pub isolated_cell_available: bool,
    pub approval_staging_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPolicyEngine {
    pub max_lease_ttl_seconds: u64,
    pub denied_syscalls: Vec<String>,
    pub denied_linux_capabilities: Vec<String>,
}

impl Default for CapabilityPolicyEngine {
    fn default() -> Self {
        Self {
            max_lease_ttl_seconds: 15 * 60,
            denied_syscalls: vec![
                "delete_module".to_string(),
                "init_module".to_string(),
                "kexec_file_load".to_string(),
                "kexec_load".to_string(),
                "reboot".to_string(),
            ],
            denied_linux_capabilities: vec![
                "CAP_SYS_BOOT".to_string(),
                "CAP_SYS_MODULE".to_string(),
            ],
        }
    }
}

impl CapabilityPolicyEngine {
    pub fn evaluate(
        &self,
        request: &CapabilityRequest,
        context: &PolicyEvaluationContext,
    ) -> CapabilityDecision {
        let mut reasons = self.validation_reasons(request);
        reasons.extend(self.hard_deny_reasons(request));
        let required_mediators = required_mediators(request);
        let active = context
            .active_mediators
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let missing_mediators = required_mediators
            .iter()
            .copied()
            .filter(|boundary| !active.contains(boundary))
            .collect::<Vec<_>>();
        if !missing_mediators.is_empty() {
            reasons.push("mandatory_mediator_missing".to_string());
        }
        if !reasons.is_empty() {
            reasons.sort();
            reasons.dedup();
            return CapabilityDecision {
                decision: CapabilityPolicyDecision::Deny,
                reason_codes: reasons,
                required_mediators,
                missing_mediators,
            };
        }

        if requires_approval(request) {
            let (decision, reason) = if context.approval_staging_available {
                (
                    CapabilityPolicyDecision::StageForApproval,
                    "irreversible_or_external_effect_requires_approval",
                )
            } else {
                (
                    CapabilityPolicyDecision::Deny,
                    "approval_staging_unavailable",
                )
            };
            return CapabilityDecision {
                decision,
                reason_codes: vec![reason.to_string()],
                required_mediators,
                missing_mediators,
            };
        }

        let requires_cell = request.execution_boundary == ExecutionBoundary::IsolatedCell
            || request.source_must_not_execute
            || request.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::PrivilegedExecution | Capability::UntrustedCodeExecution
                )
            });
        if requires_cell {
            let (decision, reason) = if context.isolated_cell_available {
                (
                    CapabilityPolicyDecision::DelegateToIsolatedCell,
                    "source_authority_is_insufficient",
                )
            } else {
                (CapabilityPolicyDecision::Deny, "isolated_cell_unavailable")
            };
            return CapabilityDecision {
                decision,
                reason_codes: vec![reason.to_string()],
                required_mediators,
                missing_mediators,
            };
        }

        let locally_authorized = request
            .capabilities
            .iter()
            .all(|capability| context.locally_authorized_capabilities.contains(capability));
        let (decision, reason) = if locally_authorized {
            (
                CapabilityPolicyDecision::AllowLocally,
                "within_local_capability_envelope",
            )
        } else if context.isolated_cell_available {
            (
                CapabilityPolicyDecision::DelegateToIsolatedCell,
                "local_capability_envelope_exceeded",
            )
        } else {
            (
                CapabilityPolicyDecision::Deny,
                "local_capability_envelope_exceeded_and_no_cell_available",
            )
        };
        CapabilityDecision {
            decision,
            reason_codes: vec![reason.to_string()],
            required_mediators,
            missing_mediators,
        }
    }

    fn validation_reasons(&self, request: &CapabilityRequest) -> Vec<String> {
        let mut reasons = Vec::new();
        if request.schema_version != CAPABILITY_REQUEST_SCHEMA_VERSION {
            reasons.push("unsupported_request_schema".to_string());
        }
        if request.operation_class.trim().is_empty() {
            reasons.push("operation_class_missing".to_string());
        }
        if request.capabilities.is_empty() {
            reasons.push("capabilities_missing".to_string());
        }
        if request.lease_ttl_seconds == 0 || request.lease_ttl_seconds > self.max_lease_ttl_seconds
        {
            reasons.push("lease_ttl_out_of_policy".to_string());
        }
        for capability in &request.capabilities {
            if !request_has_scope_for(request, *capability) {
                reasons.push(format!(
                    "unresolved_scope:{}",
                    capability_wire_name(*capability)
                ));
            }
        }
        reasons.extend(scope_validation_reasons(request));
        if request.inspect_before_commit
            && request.scope.output_promotions.is_empty()
            && request.scope.write_paths.is_empty()
            && request.scope.file_operations.iter().all(|operation| {
                matches!(
                    operation.operation,
                    FileOperationKind::Read | FileOperationKind::Execute
                )
            })
            && request.effect_scope != EffectScope::ReadOnly
        {
            reasons.push("promotion_scope_missing".to_string());
        }
        if request.execution_boundary == ExecutionBoundary::BrokeredCommit
            && request.effect_scope != EffectScope::External
        {
            reasons.push("brokered_commit_requires_external_effect_scope".to_string());
        }
        reasons
    }

    fn hard_deny_reasons(&self, request: &CapabilityRequest) -> Vec<String> {
        let mut reasons = Vec::new();
        for syscall in &request.scope.kernel.syscalls {
            if self
                .denied_syscalls
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(syscall))
            {
                reasons.push(format!("syscall_denied:{syscall}"));
            }
        }
        for capability in &request.scope.kernel.linux_capabilities {
            if self
                .denied_linux_capabilities
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(capability))
            {
                reasons.push(format!("linux_capability_denied:{capability}"));
            }
        }
        if request.scope.network_destinations.iter().any(|network| {
            network.destination == "*"
                || network.destination == "0.0.0.0/0"
                || network.destination == "::/0"
                || network.protocol.trim().is_empty()
        }) {
            reasons.push("unbounded_network_scope".to_string());
        }
        if request.scope.secret_identities.iter().any(|secret| {
            secret.handle.trim().is_empty() || looks_like_secret_material(&secret.handle)
        }) {
            reasons.push("invalid_secret_broker_handle".to_string());
        }
        reasons
    }
}

fn request_has_scope_for(request: &CapabilityRequest, capability: Capability) -> bool {
    let scope = &request.scope;
    match capability {
        Capability::FilesystemRead => {
            !scope.read_paths.is_empty()
                || scope.file_operations.iter().any(|operation| {
                    matches!(
                        operation.operation,
                        FileOperationKind::Read | FileOperationKind::Execute
                    )
                })
        }
        Capability::FilesystemWrite => {
            !scope.write_paths.is_empty()
                || scope.file_operations.iter().any(|operation| {
                    matches!(
                        operation.operation,
                        FileOperationKind::Create
                            | FileOperationKind::Write
                            | FileOperationKind::Rename
                            | FileOperationKind::Delete
                            | FileOperationKind::Metadata
                    )
                })
        }
        Capability::FilesystemMetadata => scope
            .file_operations
            .iter()
            .any(|operation| operation.operation == FileOperationKind::Metadata),
        Capability::DestructiveFilesystem => scope
            .file_operations
            .iter()
            .any(|operation| operation.operation == FileOperationKind::Delete),
        Capability::NetworkEgress | Capability::NetworkListen => {
            !scope.network_hosts.is_empty() || !scope.network_destinations.is_empty()
        }
        Capability::SecretUse => !scope.secret_identities.is_empty(),
        Capability::IdentityUse => {
            !scope.identities.is_empty() || !scope.secret_identities.is_empty()
        }
        Capability::WorkloadIdentity => {
            !scope.secret_identities.is_empty()
                || scope
                    .cloud_iam
                    .iter()
                    .any(|cloud| cloud.assume_role.is_some())
        }
        Capability::CloudIam => !scope.cloud_iam.is_empty(),
        Capability::Syscall => !scope.kernel.syscalls.is_empty(),
        Capability::LinuxCapability => !scope.kernel.linux_capabilities.is_empty(),
        Capability::ExternalApplication => !scope.external_applications.is_empty(),
        Capability::DatabaseAccess => !scope.databases.is_empty(),
        Capability::IrreversibleEffect => {
            !scope.external_targets.is_empty()
                || scope
                    .external_applications
                    .iter()
                    .any(|application| application.irreversible)
        }
        Capability::OutputPromotion => !scope.output_promotions.is_empty(),
        Capability::ExternalMutation => {
            !scope.external_targets.is_empty()
                || !scope.external_applications.is_empty()
                || !scope.cloud_iam.is_empty()
                || !scope.databases.is_empty()
        }
        Capability::ProcessExecution
        | Capability::PrivilegedExecution
        | Capability::UntrustedCodeExecution => true,
    }
}

fn required_mediators(request: &CapabilityRequest) -> Vec<MediationBoundary> {
    let mut required = BTreeSet::new();
    for capability in &request.capabilities {
        match capability {
            Capability::FilesystemRead
            | Capability::FilesystemWrite
            | Capability::FilesystemMetadata
            | Capability::DestructiveFilesystem => {
                required.insert(MediationBoundary::FilesystemBoundary);
            }
            Capability::NetworkEgress | Capability::NetworkListen => {
                required.insert(MediationBoundary::NetworkBoundary);
            }
            Capability::SecretUse => {
                required.insert(MediationBoundary::SecretBroker);
            }
            Capability::IdentityUse | Capability::WorkloadIdentity => {
                required.insert(MediationBoundary::WorkloadIdentityBroker);
            }
            Capability::CloudIam => {
                required.insert(MediationBoundary::CloudApiGateway);
                required.insert(MediationBoundary::WorkloadIdentityBroker);
            }
            Capability::Syscall | Capability::LinuxCapability | Capability::PrivilegedExecution => {
                required.insert(MediationBoundary::KernelBoundary);
            }
            Capability::ProcessExecution | Capability::UntrustedCodeExecution => {
                required.insert(MediationBoundary::ProcessCgroup);
            }
            Capability::ExternalApplication => {
                if request
                    .scope
                    .external_applications
                    .iter()
                    .any(|application| application.application.eq_ignore_ascii_case("browser"))
                {
                    required.insert(MediationBoundary::BrowserAutomationGateway);
                } else {
                    required.insert(MediationBoundary::ExternalApiGateway);
                }
            }
            Capability::DatabaseAccess => {
                required.insert(MediationBoundary::DatabaseProxy);
            }
            Capability::OutputPromotion => {
                required.insert(MediationBoundary::OutputPromotionTransaction);
            }
            Capability::ExternalMutation | Capability::IrreversibleEffect => {
                if request.scope.external_applications.is_empty()
                    && request.scope.cloud_iam.is_empty()
                    && request.scope.databases.is_empty()
                {
                    required.insert(MediationBoundary::ExternalApiGateway);
                }
            }
        }
    }
    required.into_iter().collect()
}

fn scope_validation_reasons(request: &CapabilityRequest) -> Vec<String> {
    let scope = &request.scope;
    let mut reasons = Vec::new();
    if scope
        .read_paths
        .iter()
        .chain(&scope.write_paths)
        .any(|path| !is_safe_relative_selector(path))
        || scope
            .file_operations
            .iter()
            .any(|operation| !is_safe_relative_selector(&operation.path))
    {
        reasons.push("invalid_filesystem_scope".to_string());
    }
    if scope.network_destinations.iter().any(|network| {
        network.destination.trim().is_empty()
            || network.protocol.trim().is_empty()
            || (network.ports.is_empty()
                && !matches!(
                    network.protocol.to_ascii_lowercase().as_str(),
                    "unix" | "icmp"
                ))
    }) {
        reasons.push("invalid_network_scope".to_string());
    }
    if scope.secret_identities.iter().any(|secret| {
        secret.handle.trim().is_empty()
            || secret.identity.trim().is_empty()
            || secret.purpose.trim().is_empty()
    }) {
        reasons.push("invalid_secret_identity_scope".to_string());
    }
    if scope.cloud_iam.iter().any(|cloud| {
        cloud.provider.trim().is_empty()
            || cloud.resource.trim().is_empty()
            || cloud.resource == "*"
            || cloud.actions.is_empty()
            || cloud
                .actions
                .iter()
                .any(|action| action.trim().is_empty() || action == "*")
    }) {
        reasons.push("invalid_cloud_iam_scope".to_string());
    }
    if scope
        .kernel
        .syscalls
        .iter()
        .chain(&scope.kernel.linux_capabilities)
        .any(|value| value.trim().is_empty() || value == "*")
    {
        reasons.push("invalid_kernel_scope".to_string());
    }
    if scope.external_applications.iter().any(|application| {
        application.application.trim().is_empty()
            || application.target.trim().is_empty()
            || application.target == "*"
            || application.actions.is_empty()
            || application
                .actions
                .iter()
                .any(|action| action.trim().is_empty() || action == "*")
    }) {
        reasons.push("invalid_external_application_scope".to_string());
    }
    if scope.databases.iter().any(|database| {
        database.service.trim().is_empty()
            || database.database.trim().is_empty()
            || database.database == "*"
            || database.roles.is_empty()
            || database.actions.is_empty()
            || database
                .roles
                .iter()
                .chain(&database.actions)
                .any(|value| value.trim().is_empty() || value == "*")
    }) {
        reasons.push("invalid_database_scope".to_string());
    }
    if scope.output_promotions.iter().any(|promotion| {
        !is_safe_relative_selector(&promotion.path)
            || promotion.destination.trim().is_empty()
            || !promotion.transactional
    }) {
        reasons.push("invalid_output_promotion_scope".to_string());
    }
    reasons
}

fn is_safe_relative_selector(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(1) == Some(&b':')
    {
        return false;
    }
    value
        .split(['/', '\\'])
        .all(|component| !component.is_empty() && component != "..")
}

fn requires_approval(request: &CapabilityRequest) -> bool {
    let irreversible_local_is_contained = request.effect_scope == EffectScope::IrreversibleLocal
        && request.execution_boundary == ExecutionBoundary::IsolatedCell
        && request.source_must_not_execute
        && request.inspect_before_commit;
    request.execution_boundary == ExecutionBoundary::BrokeredCommit
        || request.effect_scope == EffectScope::External
        || (request.effect_scope == EffectScope::IrreversibleLocal
            && !irreversible_local_is_contained)
        || request.capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::ExternalMutation
                    | Capability::IrreversibleEffect
                    | Capability::OutputPromotion
            )
        })
        || request
            .scope
            .external_applications
            .iter()
            .any(|application| application.irreversible)
}

fn capability_wire_name(capability: Capability) -> String {
    serde_json::to_value(capability)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn looks_like_secret_material(handle: &str) -> bool {
    let value = handle.trim();
    value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("github_pat_")
        || value.contains("BEGIN PRIVATE KEY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        CloudIamScope, DatabaseScope, ExternalApplicationScope, FileOperationScope,
        NetworkDestinationScope, OutputPromotionScope, SecretIdentityScope,
    };

    fn context(mediators: Vec<MediationBoundary>) -> PolicyEvaluationContext {
        PolicyEvaluationContext {
            active_mediators: mediators,
            locally_authorized_capabilities: Vec::new(),
            isolated_cell_available: true,
            approval_staging_available: true,
        }
    }

    #[test]
    fn read_only_scoped_operation_can_be_allowed_locally() {
        let mut request = CapabilityRequest::isolated(
            "read_source",
            EffectScope::ReadOnly,
            vec![Capability::FilesystemRead, Capability::ProcessExecution],
        );
        request.execution_boundary = ExecutionBoundary::Source;
        request.source_must_not_execute = false;
        request.inspect_before_commit = false;
        request.scope.read_paths = vec!["src".to_string()];
        let mut context = context(vec![
            MediationBoundary::FilesystemBoundary,
            MediationBoundary::ProcessCgroup,
        ]);
        context.locally_authorized_capabilities = request.capabilities.clone();

        let decision = CapabilityPolicyEngine::default().evaluate(&request, &context);

        assert_eq!(decision.decision, CapabilityPolicyDecision::AllowLocally);
    }

    #[test]
    fn untrusted_operation_delegates_to_a_cell() {
        let mut request = CapabilityRequest::isolated(
            "build_untrusted_source",
            EffectScope::ReversibleLocal,
            vec![
                Capability::FilesystemRead,
                Capability::FilesystemWrite,
                Capability::ProcessExecution,
                Capability::UntrustedCodeExecution,
            ],
        );
        request.scope.read_paths = vec!["Cargo.toml".to_string()];
        request.scope.write_paths = vec!["target-metadata".to_string()];
        let decision = CapabilityPolicyEngine::default().evaluate(
            &request,
            &context(vec![
                MediationBoundary::FilesystemBoundary,
                MediationBoundary::ProcessCgroup,
            ]),
        );

        assert_eq!(
            decision.decision,
            CapabilityPolicyDecision::DelegateToIsolatedCell
        );
    }

    #[test]
    fn contained_irreversible_local_effect_delegates_without_approval_staging() {
        let mut request = CapabilityRequest::isolated(
            "destructive_workspace_mutation",
            EffectScope::IrreversibleLocal,
            vec![
                Capability::FilesystemWrite,
                Capability::DestructiveFilesystem,
                Capability::ProcessExecution,
            ],
        );
        request.scope.file_operations = vec![FileOperationScope {
            path: "target/cache".to_string(),
            operation: FileOperationKind::Delete,
            entry_kind: None,
        }];
        let mut evaluation_context = context(vec![
            MediationBoundary::FilesystemBoundary,
            MediationBoundary::ProcessCgroup,
        ]);
        evaluation_context.approval_staging_available = false;

        let decision = CapabilityPolicyEngine::default().evaluate(&request, &evaluation_context);

        assert_eq!(
            decision.decision,
            CapabilityPolicyDecision::DelegateToIsolatedCell
        );
        assert_eq!(
            decision.reason_codes,
            vec!["source_authority_is_insufficient"]
        );
    }

    #[test]
    fn uncontained_irreversible_local_effect_still_requires_approval() {
        let mut request = CapabilityRequest::isolated(
            "destructive_workspace_mutation",
            EffectScope::IrreversibleLocal,
            vec![
                Capability::FilesystemWrite,
                Capability::DestructiveFilesystem,
                Capability::ProcessExecution,
            ],
        );
        request.execution_boundary = ExecutionBoundary::Source;
        request.source_must_not_execute = false;
        request.inspect_before_commit = false;
        request.scope.file_operations = vec![FileOperationScope {
            path: "target/cache".to_string(),
            operation: FileOperationKind::Delete,
            entry_kind: None,
        }];

        let decision = CapabilityPolicyEngine::default().evaluate(
            &request,
            &context(vec![
                MediationBoundary::FilesystemBoundary,
                MediationBoundary::ProcessCgroup,
            ]),
        );

        assert_eq!(
            decision.decision,
            CapabilityPolicyDecision::StageForApproval
        );
    }

    #[test]
    fn external_database_mutation_stages_for_approval() {
        let mut request = CapabilityRequest::brokered(
            "apply_migration",
            vec![Capability::DatabaseAccess, Capability::ExternalMutation],
        );
        request.scope.databases = vec![DatabaseScope {
            service: "postgres".to_string(),
            database: "production".to_string(),
            roles: vec!["migration".to_string()],
            actions: vec!["alter_schema".to_string()],
        }];
        request.scope.external_targets = vec!["postgres/production".to_string()];
        request.scope.output_promotions = vec![OutputPromotionScope {
            path: "migration.sql".to_string(),
            destination: "postgres/production".to_string(),
            transactional: true,
        }];
        let decision = CapabilityPolicyEngine::default().evaluate(
            &request,
            &context(vec![
                MediationBoundary::DatabaseProxy,
                MediationBoundary::ExternalApiGateway,
            ]),
        );

        assert_eq!(
            decision.decision,
            CapabilityPolicyDecision::StageForApproval
        );
    }

    #[test]
    fn missing_mandatory_network_boundary_denies() {
        let mut request = CapabilityRequest::isolated(
            "download_artifact",
            EffectScope::ReversibleLocal,
            vec![Capability::NetworkEgress, Capability::ProcessExecution],
        );
        request.scope.network_destinations = vec![NetworkDestinationScope {
            destination: "packages.example.test".to_string(),
            protocol: "https".to_string(),
            ports: vec![443],
        }];
        let decision = CapabilityPolicyEngine::default()
            .evaluate(&request, &context(vec![MediationBoundary::ProcessCgroup]));

        assert_eq!(decision.decision, CapabilityPolicyDecision::Deny);
        assert_eq!(
            decision.missing_mediators,
            vec![MediationBoundary::NetworkBoundary]
        );
    }

    #[test]
    fn secret_material_cannot_be_used_as_a_broker_handle() {
        let mut request = CapabilityRequest::isolated(
            "call_repository",
            EffectScope::ReadOnly,
            vec![Capability::SecretUse, Capability::ProcessExecution],
        );
        request.scope.secret_identities = vec![SecretIdentityScope {
            handle: "sk-secret-value".to_string(),
            identity: "repository-reader".to_string(),
            purpose: "read metadata".to_string(),
        }];
        let decision = CapabilityPolicyEngine::default().evaluate(
            &request,
            &context(vec![
                MediationBoundary::SecretBroker,
                MediationBoundary::ProcessCgroup,
            ]),
        );

        assert_eq!(decision.decision, CapabilityPolicyDecision::Deny);
        assert!(decision
            .reason_codes
            .contains(&"invalid_secret_broker_handle".to_string()));
    }

    #[test]
    fn dangerous_kernel_authority_is_denied_even_with_mediation() {
        let mut request = CapabilityRequest::isolated(
            "load_kernel_module",
            EffectScope::IrreversibleLocal,
            vec![Capability::Syscall, Capability::LinuxCapability],
        );
        request.scope.kernel.syscalls = vec!["init_module".to_string()];
        request.scope.kernel.linux_capabilities = vec!["CAP_SYS_MODULE".to_string()];
        let decision = CapabilityPolicyEngine::default()
            .evaluate(&request, &context(vec![MediationBoundary::KernelBoundary]));

        assert_eq!(decision.decision, CapabilityPolicyDecision::Deny);
        assert!(decision
            .reason_codes
            .iter()
            .any(|reason| reason.starts_with("syscall_denied:")));
    }

    #[test]
    fn nontransactional_output_promotion_is_denied() {
        let mut request =
            CapabilityRequest::brokered("promote_build_output", vec![Capability::OutputPromotion]);
        request.scope.output_promotions = vec![OutputPromotionScope {
            path: "dist/app".to_string(),
            destination: "release".to_string(),
            transactional: false,
        }];
        let decision = CapabilityPolicyEngine::default().evaluate(
            &request,
            &context(vec![MediationBoundary::OutputPromotionTransaction]),
        );

        assert_eq!(decision.decision, CapabilityPolicyDecision::Deny);
        assert!(decision
            .reason_codes
            .contains(&"invalid_output_promotion_scope".to_string()));
    }

    #[test]
    fn browser_cloud_and_identity_scopes_require_every_gateway() {
        let mut request = CapabilityRequest::brokered(
            "publish_cloud_console_change",
            vec![
                Capability::CloudIam,
                Capability::ExternalApplication,
                Capability::WorkloadIdentity,
                Capability::ExternalMutation,
            ],
        );
        request.scope.cloud_iam = vec![CloudIamScope {
            provider: "example-cloud".to_string(),
            resource: "project/one".to_string(),
            actions: vec!["deploy".to_string()],
            assume_role: Some("deployer".to_string()),
        }];
        request.scope.external_applications = vec![ExternalApplicationScope {
            application: "browser".to_string(),
            target: "cloud-console".to_string(),
            actions: vec!["deploy".to_string()],
            irreversible: true,
        }];
        request.scope.external_targets = vec!["project/one".to_string()];
        let decision = CapabilityPolicyEngine::default()
            .evaluate(&request, &context(vec![MediationBoundary::CloudApiGateway]));

        assert_eq!(decision.decision, CapabilityPolicyDecision::Deny);
        assert!(decision
            .missing_mediators
            .contains(&MediationBoundary::BrowserAutomationGateway));
        assert!(decision
            .missing_mediators
            .contains(&MediationBoundary::WorkloadIdentityBroker));
        assert!(!decision
            .missing_mediators
            .contains(&MediationBoundary::ExternalApiGateway));
    }
}
