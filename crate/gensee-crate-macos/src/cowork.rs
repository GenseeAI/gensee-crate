use crate::{EndpointSecurityEvent, EndpointSecurityProcess};
use gensee_crate_core::ExecutionOrigin;
use serde::{Deserialize, Serialize};

pub const ANTHROPIC_TEAM_ID: &str = "Q6L2SF6YDW";
pub const CLAUDE_DESKTOP_SIGNING_ID: &str = "com.anthropic.claudefordesktop";
pub const CLAUDE_CODE_SIGNING_ID: &str = "com.anthropic.claude-code";
pub const APPLE_VIRTUAL_MACHINE_SIGNING_ID: &str = "com.apple.Virtualization.VirtualMachine";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoworkSessionMode {
    Local,
    Cloud,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoworkToolSurface {
    Host,
    Shell,
    #[default]
    Unknown,
}

/// Optional evidence supplied by the local Cowork audit adapter. Endpoint
/// Security alone cannot distinguish a local native tool from a cloud session
/// using Claude Desktop as a bridge, so absence of this context must not be
/// interpreted as local execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoworkEventContext {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_mode: CoworkSessionMode,
    #[serde(default)]
    pub tool_surface: CoworkToolSurface,
    #[serde(default)]
    pub tool_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoworkVisibility {
    pub execution_origin: ExecutionOrigin,
    pub confidence: f64,
    pub matched_by: &'static str,
    pub visibility_limit: Option<&'static str>,
}

pub fn classify_cowork_event(event: &EndpointSecurityEvent) -> CoworkVisibility {
    let context = event.cowork.as_ref();

    if context.is_some_and(|context| context.session_mode == CoworkSessionMode::Cloud) {
        return CoworkVisibility {
            execution_origin: ExecutionOrigin::CloudMediated,
            confidence: 1.0,
            matched_by: "cowork_session_mode",
            visibility_limit: Some("cloud execution is outside endpoint visibility"),
        };
    }

    if is_cowork_virtual_machine_process(&event.actor)
        || context.is_some_and(|context| context.tool_surface == CoworkToolSurface::Shell)
    {
        return CoworkVisibility {
            execution_origin: ExecutionOrigin::VmMediated,
            confidence: if is_cowork_virtual_machine_process(&event.actor) {
                1.0
            } else {
                0.9
            },
            matched_by: if is_cowork_virtual_machine_process(&event.actor) {
                "apple_virtualization_signing_identity"
            } else {
                "cowork_shell_tool"
            },
            visibility_limit: Some("guest command and process lineage are not endpoint-visible"),
        };
    }

    if context.is_some_and(|context| {
        context.session_mode == CoworkSessionMode::Local
            && context.tool_surface == CoworkToolSurface::Host
    }) && is_anthropic_host_process(&event.actor)
    {
        return CoworkVisibility {
            execution_origin: ExecutionOrigin::HostNative,
            confidence: 1.0,
            matched_by: "local_cowork_host_tool_and_signing_identity",
            visibility_limit: None,
        };
    }

    CoworkVisibility {
        execution_origin: ExecutionOrigin::Unattributed,
        confidence: 0.0,
        matched_by: "insufficient_endpoint_evidence",
        visibility_limit: Some(
            "session mode or tool surface is required to attribute this Cowork event",
        ),
    }
}

pub fn is_anthropic_host_process(process: &EndpointSecurityProcess) -> bool {
    process.team_id.as_deref() == Some(ANTHROPIC_TEAM_ID)
        && matches!(
            process.signing_id.as_deref(),
            Some(CLAUDE_DESKTOP_SIGNING_ID | CLAUDE_CODE_SIGNING_ID)
        )
}

pub fn is_cowork_virtual_machine_process(process: &EndpointSecurityProcess) -> bool {
    process.signing_id.as_deref() == Some(APPLE_VIRTUAL_MACHINE_SIGNING_ID)
        || process.executable_path.as_deref().is_some_and(|path| {
            path.ends_with("/com.apple.Virtualization.VirtualMachine") && process.platform_binary
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EndpointSecurityAttribution, EndpointSecurityDecision};

    fn event(actor: EndpointSecurityProcess) -> EndpointSecurityEvent {
        EndpointSecurityEvent {
            schema_version: 1,
            event_id: "event-1".to_string(),
            boot_id: "boot-1".to_string(),
            observed_at_ms: 1,
            event_type: "write".to_string(),
            action: "notify".to_string(),
            message_version: 1,
            seq_num: None,
            global_seq_num: None,
            dropped_events: 0,
            actor,
            target: None,
            file: None,
            destination: None,
            cwd: None,
            script: None,
            arguments: Vec::new(),
            open_flags: None,
            exit_status: None,
            modified: None,
            attribution: EndpointSecurityAttribution::default(),
            decision: EndpointSecurityDecision::default(),
            cowork: None,
        }
    }

    fn anthropic_actor() -> EndpointSecurityProcess {
        EndpointSecurityProcess {
            pid: 42,
            signing_id: Some(CLAUDE_CODE_SIGNING_ID.to_string()),
            team_id: Some(ANTHROPIC_TEAM_ID.to_string()),
            ..EndpointSecurityProcess::default()
        }
    }

    #[test]
    fn host_tool_requires_local_session_evidence() {
        let mut event = event(anthropic_actor());
        assert_eq!(
            classify_cowork_event(&event).execution_origin,
            ExecutionOrigin::Unattributed
        );
        event.cowork = Some(CoworkEventContext {
            session_mode: CoworkSessionMode::Local,
            tool_surface: CoworkToolSurface::Host,
            ..CoworkEventContext::default()
        });
        assert_eq!(
            classify_cowork_event(&event).execution_origin,
            ExecutionOrigin::HostNative
        );
    }

    #[test]
    fn shell_is_vm_mediated_and_preserves_the_visibility_limit() {
        let mut event = event(anthropic_actor());
        event.cowork = Some(CoworkEventContext {
            session_mode: CoworkSessionMode::Local,
            tool_surface: CoworkToolSurface::Shell,
            tool_name: Some("mcp__workspace__bash".to_string()),
            ..CoworkEventContext::default()
        });
        let visibility = classify_cowork_event(&event);
        assert_eq!(visibility.execution_origin, ExecutionOrigin::VmMediated);
        assert!(visibility
            .visibility_limit
            .unwrap()
            .contains("guest command"));
    }

    #[test]
    fn explicit_cloud_mode_wins_over_the_host_bridge_process() {
        let mut event = event(anthropic_actor());
        event.cowork = Some(CoworkEventContext {
            session_mode: CoworkSessionMode::Cloud,
            tool_surface: CoworkToolSurface::Host,
            ..CoworkEventContext::default()
        });
        assert_eq!(
            classify_cowork_event(&event).execution_origin,
            ExecutionOrigin::CloudMediated
        );
    }

    #[test]
    fn apple_virtualization_process_is_vm_mediated() {
        let event = event(EndpointSecurityProcess {
            pid: 9,
            signing_id: Some(APPLE_VIRTUAL_MACHINE_SIGNING_ID.to_string()),
            platform_binary: true,
            ..EndpointSecurityProcess::default()
        });
        assert_eq!(
            classify_cowork_event(&event).execution_origin,
            ExecutionOrigin::VmMediated
        );
    }
}
