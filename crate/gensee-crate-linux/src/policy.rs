use crate::capabilities::{LinuxCapabilityReport, LinuxSpeculationBackend};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxPolicy {
    pub mode: LinuxEnforcementMode,
    pub sensitive_paths: Vec<SensitivePathRule>,
    pub network: LinuxNetworkPolicy,
    pub seccomp_enabled: bool,
    pub dangerous_syscalls: DangerousSyscallPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxEnforcementMode {
    Monitor,
    Warn,
    Enforce,
    Isolate,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SensitivePathRule {
    pub pattern: String,
    pub access: SensitivePathAccess,
    pub action: LinuxPolicyAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SensitivePathAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxPolicyAction {
    Observe,
    Warn,
    Deny,
    Ask,
    Speculate,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkPolicy {
    pub mode: LinuxNetworkMode,
    pub allowed_hosts: Vec<String>,
    pub denied_hosts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxNetworkMode {
    Off,
    Monitor,
    DenyAll,
    AllowListed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DangerousSyscallPolicy {
    pub deny_mount_namespace_changes: bool,
    pub deny_ptrace: bool,
    pub deny_bpf: bool,
    pub deny_kernel_module_loading: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxEnforcementPlan {
    pub mode: LinuxEnforcementMode,
    pub components: Vec<LinuxEnforcementComponent>,
    pub speculation: LinuxSpeculationAvailability,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxSpeculationAvailability {
    pub requested: bool,
    pub available: bool,
    pub selected_backend: Option<LinuxSpeculationBackend>,
    pub available_backends: Vec<LinuxSpeculationBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxEnforcementComponent {
    AgentWrapper,
    CgroupAttribution,
    EbpfTelemetry,
    FanotifyFilePermissions,
    AppArmorProfile,
    SeccompProfile,
    NftablesNetworkPolicy,
    LandlockSandbox,
    SpeculativeExecution,
}

impl Default for LinuxPolicy {
    fn default() -> Self {
        Self {
            mode: LinuxEnforcementMode::Monitor,
            sensitive_paths: default_sensitive_paths(),
            network: LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Off,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
            },
            seccomp_enabled: false,
            dangerous_syscalls: DangerousSyscallPolicy {
                deny_mount_namespace_changes: true,
                deny_ptrace: true,
                deny_bpf: true,
                deny_kernel_module_loading: true,
            },
        }
    }
}

impl LinuxPolicy {
    pub fn plan(&self, capabilities: &LinuxCapabilityReport) -> LinuxEnforcementPlan {
        let mut components = vec![
            LinuxEnforcementComponent::AgentWrapper,
            LinuxEnforcementComponent::CgroupAttribution,
        ];
        let mut warnings = Vec::new();

        if capabilities.supports_bpf_telemetry() {
            components.push(LinuxEnforcementComponent::EbpfTelemetry);
        } else {
            warnings.push("eBPF telemetry requires root and mounted bpffs".to_string());
        }

        if self.mode_requires_enforcement() && !self.sensitive_paths.is_empty() {
            if capabilities.supports_dynamic_file_enforcement() {
                components.push(LinuxEnforcementComponent::FanotifyFilePermissions);
            } else {
                warnings.push("dynamic file enforcement requires fanotify and root".to_string());
            }
        }

        if self.mode_requires_enforcement() && capabilities.apparmor_enabled {
            components.push(LinuxEnforcementComponent::AppArmorProfile);
        }

        if self.seccomp_enabled && capabilities.seccomp_filter_available {
            components.push(LinuxEnforcementComponent::SeccompProfile);
        } else if self.seccomp_enabled {
            warnings.push("seccomp profiles are not available on this kernel".to_string());
        }

        if matches!(
            self.network.mode,
            LinuxNetworkMode::DenyAll | LinuxNetworkMode::AllowListed
        ) || !self.network.denied_hosts.is_empty()
        {
            if capabilities.supports_cgroup_network_controls() {
                components.push(LinuxEnforcementComponent::NftablesNetworkPolicy);
            } else {
                warnings.push(
                    "network enforcement needs cgroup v2, nftables, and root; falling back to telemetry/proxy"
                        .to_string(),
                );
            }
        }

        if self.mode == LinuxEnforcementMode::Isolate && capabilities.landlock_available {
            components.push(LinuxEnforcementComponent::LandlockSandbox);
        }

        let speculation = self.speculation_availability(capabilities);
        if speculation.requested {
            if speculation.available {
                components.push(LinuxEnforcementComponent::SpeculativeExecution);
            } else {
                warnings.push(
                    "speculation was requested, but no speculative execution backend is available"
                        .to_string(),
                );
            }
        }

        LinuxEnforcementPlan {
            mode: self.mode,
            components,
            speculation,
            warnings,
        }
    }

    fn mode_requires_enforcement(&self) -> bool {
        matches!(
            self.mode,
            LinuxEnforcementMode::Enforce | LinuxEnforcementMode::Isolate
        )
    }

    fn speculation_availability(
        &self,
        capabilities: &LinuxCapabilityReport,
    ) -> LinuxSpeculationAvailability {
        let requested = self
            .sensitive_paths
            .iter()
            .any(|rule| rule.action == LinuxPolicyAction::Speculate);
        let selected_backend = requested
            .then(|| select_speculation_backend(&capabilities.speculation_backends))
            .flatten();

        LinuxSpeculationAvailability {
            requested,
            available: selected_backend.is_some(),
            selected_backend,
            available_backends: capabilities.speculation_backends.clone(),
        }
    }
}

fn select_speculation_backend(
    backends: &[LinuxSpeculationBackend],
) -> Option<LinuxSpeculationBackend> {
    [
        LinuxSpeculationBackend::Tclone,
        LinuxSpeculationBackend::BtrfsSnapshot,
        LinuxSpeculationBackend::OverlayFs,
        LinuxSpeculationBackend::FileStaging,
    ]
    .into_iter()
    .find(|backend| backends.contains(backend))
}

fn default_sensitive_paths() -> Vec<SensitivePathRule> {
    [
        "~/.ssh/**",
        "~/.aws/**",
        "~/.config/gcloud/**",
        "**/.env",
        "**/.env.*",
    ]
    .into_iter()
    .map(|pattern| SensitivePathRule {
        pattern: pattern.to_string(),
        access: SensitivePathAccess::ReadWrite,
        action: LinuxPolicyAction::Ask,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities_with(backends: Vec<LinuxSpeculationBackend>) -> LinuxCapabilityReport {
        LinuxCapabilityReport {
            apparmor_enabled: false,
            selinux_enabled: false,
            landlock_available: false,
            bpf_fs_mounted: false,
            bpf_lsm_enabled: false,
            cgroup_v2_mounted: false,
            fanotify_available: false,
            seccomp_filter_available: true,
            nft_available: false,
            running_as_root: false,
            speculation_backends: backends,
        }
    }

    #[test]
    fn plan_does_not_request_speculation_by_default() {
        let plan = LinuxPolicy::default().plan(&capabilities_with(vec![
            LinuxSpeculationBackend::FileStaging,
        ]));

        assert!(!plan.speculation.requested);
        assert!(!plan.speculation.available);
        assert_eq!(plan.speculation.selected_backend, None);
        assert!(!plan
            .components
            .contains(&LinuxEnforcementComponent::SpeculativeExecution));
    }

    #[test]
    fn plan_selects_best_available_speculation_backend_when_requested() {
        let mut policy = LinuxPolicy::default();
        policy.sensitive_paths[0].action = LinuxPolicyAction::Speculate;

        let plan = policy.plan(&capabilities_with(vec![
            LinuxSpeculationBackend::FileStaging,
            LinuxSpeculationBackend::BtrfsSnapshot,
        ]));

        assert!(plan.speculation.requested);
        assert!(plan.speculation.available);
        assert_eq!(
            plan.speculation.selected_backend,
            Some(LinuxSpeculationBackend::BtrfsSnapshot)
        );
        assert!(plan
            .components
            .contains(&LinuxEnforcementComponent::SpeculativeExecution));
    }

    #[test]
    fn plan_warns_when_speculation_is_requested_without_backend() {
        let mut policy = LinuxPolicy::default();
        policy.sensitive_paths[0].action = LinuxPolicyAction::Speculate;

        let plan = policy.plan(&capabilities_with(Vec::new()));

        assert!(plan.speculation.requested);
        assert!(!plan.speculation.available);
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("no speculative execution backend is available")));
    }
}
