use crate::capabilities::{LinuxCapabilityReport, LinuxSpeculationBackend};
use crate::policy::{LinuxEnforcementMode, LinuxPolicy, LinuxPolicyAction, SensitivePathAccess};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxEnforcementRequest {
    pub operation: LinuxAccessOperation,
    pub path: Option<String>,
    pub network_dest: Option<String>,
    pub syscall: Option<String>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxAccessOperation {
    FileRead,
    FileWrite,
    FileDelete,
    NetworkConnect,
    DangerousSyscall,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxEnforcementDecision {
    pub verdict: LinuxEnforcementVerdict,
    pub requested_action: LinuxPolicyAction,
    pub matched_rule: Option<String>,
    pub speculation_backend: Option<LinuxSpeculationBackend>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxEnforcementVerdict {
    Allow,
    Warn,
    Ask,
    Deny,
    Speculate,
}

impl LinuxPolicy {
    pub fn evaluate_access(
        &self,
        request: &LinuxEnforcementRequest,
        capabilities: &LinuxCapabilityReport,
    ) -> LinuxEnforcementDecision {
        let matched_rule = self.match_sensitive_path_rule(request);
        let requested_action = matched_rule
            .as_ref()
            .map(|rule| rule.action)
            .unwrap_or(LinuxPolicyAction::Observe);
        let speculation_backend = if requested_action == LinuxPolicyAction::Speculate {
            self.plan(capabilities).speculation.selected_backend
        } else {
            None
        };

        let verdict = match self.mode {
            LinuxEnforcementMode::Monitor => LinuxEnforcementVerdict::Allow,
            LinuxEnforcementMode::Warn => match requested_action {
                LinuxPolicyAction::Observe => LinuxEnforcementVerdict::Allow,
                _ => LinuxEnforcementVerdict::Warn,
            },
            LinuxEnforcementMode::Enforce | LinuxEnforcementMode::Isolate => {
                enforce_requested_action(requested_action, speculation_backend)
            }
        };

        LinuxEnforcementDecision {
            verdict,
            requested_action,
            matched_rule: matched_rule.map(|rule| rule.pattern.clone()),
            speculation_backend,
            reason: decision_reason(request, requested_action, verdict, speculation_backend),
        }
    }

    fn match_sensitive_path_rule(
        &self,
        request: &LinuxEnforcementRequest,
    ) -> Option<&crate::policy::SensitivePathRule> {
        let path = request.path.as_deref()?;
        self.sensitive_paths.iter().find(|rule| {
            access_matches(rule.access, request.operation) && path_matches(&rule.pattern, path)
        })
    }
}

fn enforce_requested_action(
    action: LinuxPolicyAction,
    speculation_backend: Option<LinuxSpeculationBackend>,
) -> LinuxEnforcementVerdict {
    match action {
        LinuxPolicyAction::Observe => LinuxEnforcementVerdict::Allow,
        LinuxPolicyAction::Warn => LinuxEnforcementVerdict::Warn,
        LinuxPolicyAction::Ask => LinuxEnforcementVerdict::Ask,
        LinuxPolicyAction::Deny => LinuxEnforcementVerdict::Deny,
        LinuxPolicyAction::Speculate => {
            if speculation_backend.is_some() {
                LinuxEnforcementVerdict::Speculate
            } else {
                LinuxEnforcementVerdict::Deny
            }
        }
    }
}

fn access_matches(access: SensitivePathAccess, operation: LinuxAccessOperation) -> bool {
    match operation {
        LinuxAccessOperation::FileRead => {
            matches!(
                access,
                SensitivePathAccess::Read | SensitivePathAccess::ReadWrite
            )
        }
        LinuxAccessOperation::FileWrite | LinuxAccessOperation::FileDelete => {
            matches!(
                access,
                SensitivePathAccess::Write | SensitivePathAccess::ReadWrite
            )
        }
        LinuxAccessOperation::NetworkConnect | LinuxAccessOperation::DangerousSyscall => false,
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let expanded = expand_home(pattern);
    if expanded == path {
        return true;
    }
    if let Some(prefix) = expanded.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = expanded.strip_prefix("**/") {
        return path == suffix || path.ends_with(&format!("/{suffix}"));
    }
    false
}

fn expand_home(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    pattern.to_string()
}

fn decision_reason(
    request: &LinuxEnforcementRequest,
    action: LinuxPolicyAction,
    verdict: LinuxEnforcementVerdict,
    speculation_backend: Option<LinuxSpeculationBackend>,
) -> String {
    match (action, verdict, speculation_backend) {
        (LinuxPolicyAction::Speculate, LinuxEnforcementVerdict::Speculate, Some(backend)) => {
            format!("matched speculative policy; using {backend:?}")
        }
        (LinuxPolicyAction::Speculate, LinuxEnforcementVerdict::Deny, None) => {
            "matched speculative policy, but no speculation backend is available".to_string()
        }
        _ => format!(
            "{:?} {:?} evaluated as {:?}",
            request.operation, request.path, verdict
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        DangerousSyscallPolicy, LinuxNetworkMode, LinuxNetworkPolicy, SensitivePathRule,
    };

    fn capabilities(backends: Vec<LinuxSpeculationBackend>) -> LinuxCapabilityReport {
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

    fn policy(mode: LinuxEnforcementMode, action: LinuxPolicyAction) -> LinuxPolicy {
        LinuxPolicy {
            mode,
            sensitive_paths: vec![SensitivePathRule {
                pattern: "/tmp/secret/**".to_string(),
                access: SensitivePathAccess::ReadWrite,
                action,
            }],
            network: LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
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

    fn request(path: &str) -> LinuxEnforcementRequest {
        LinuxEnforcementRequest {
            operation: LinuxAccessOperation::FileWrite,
            path: Some(path.to_string()),
            network_dest: None,
            syscall: None,
            pid: None,
            process_name: None,
            command_line: None,
        }
    }

    #[test]
    fn monitor_mode_allows_but_preserves_requested_action() {
        let decision = policy(LinuxEnforcementMode::Monitor, LinuxPolicyAction::Deny)
            .evaluate_access(&request("/tmp/secret/token"), &capabilities(Vec::new()));

        assert_eq!(decision.verdict, LinuxEnforcementVerdict::Allow);
        assert_eq!(decision.requested_action, LinuxPolicyAction::Deny);
    }

    #[test]
    fn enforce_mode_denies_speculation_without_backend() {
        let decision = policy(LinuxEnforcementMode::Enforce, LinuxPolicyAction::Speculate)
            .evaluate_access(&request("/tmp/secret/token"), &capabilities(Vec::new()));

        assert_eq!(decision.verdict, LinuxEnforcementVerdict::Deny);
        assert_eq!(decision.speculation_backend, None);
    }

    #[test]
    fn enforce_mode_speculates_with_backend() {
        let decision = policy(LinuxEnforcementMode::Enforce, LinuxPolicyAction::Speculate)
            .evaluate_access(
                &request("/tmp/secret/token"),
                &capabilities(vec![LinuxSpeculationBackend::FileStaging]),
            );

        assert_eq!(decision.verdict, LinuxEnforcementVerdict::Speculate);
        assert_eq!(
            decision.speculation_backend,
            Some(LinuxSpeculationBackend::FileStaging)
        );
    }
}
