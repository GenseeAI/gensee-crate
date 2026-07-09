use crate::*;

pub(crate) fn list_runs() -> io::Result<()> {
    let store = EventStore::default_local()?;
    let sessions = compact_sessions(store.list_sessions()?);

    if sessions.is_empty() {
        println!("No runs found.");
        return Ok(());
    }

    for session in sessions {
        println!(
            "{} | {} | root_pid={} | {} | {}",
            session.session_id,
            session.agent_binary,
            session.root_pid,
            session.cwd,
            if session.is_active() {
                "active"
            } else {
                "ended"
            },
        );
    }

    Ok(())
}

pub(crate) fn show_timeline(args: Vec<OsString>) -> io::Result<()> {
    let filter = TimelineFilter::parse(&args)?;
    let store = EventStore::default_local()?;
    let mut sessions = compact_sessions(store.list_sessions()?);
    let hooks = store.list_hook_events()?;
    let observations = store.list_process_observations()?;
    let file_intents = store.list_file_intents()?;
    let mut system_events = store.list_system_events()?;
    let mut workspace_effects = store.list_workspace_effects()?;
    let mut alerts = store.list_alerts()?;
    let mut user_prompts = compact_user_prompts(&hooks);
    let mut assistant_responses = compact_assistant_responses(&hooks);
    let mut tool_calls = compact_tool_calls(
        &hooks,
        &observations,
        &file_intents,
        &system_events,
        &workspace_effects,
        &alerts,
    );

    filter.apply(TimelineCollections {
        sessions: &mut sessions,
        user_prompts: &mut user_prompts,
        assistant_responses: &mut assistant_responses,
        tool_calls: &mut tool_calls,
        system_events: &mut system_events,
        workspace_effects: &mut workspace_effects,
        alerts: &mut alerts,
    });
    let agent_refusals = derive_agent_refusals(&user_prompts, &assistant_responses);

    if sessions.is_empty()
        && user_prompts.is_empty()
        && assistant_responses.is_empty()
        && agent_refusals.is_empty()
        && tool_calls.is_empty()
        && system_events.is_empty()
        && workspace_effects.is_empty()
        && alerts.is_empty()
    {
        println!("No sessions, hook events, alerts, workspace effects, or Layer 1 system events found for this filter.");
        return Ok(());
    }

    for session in sessions {
        println!("Run {}", session.session_id);
        println!("  agent: {}", session.agent_binary);
        println!("  root_pid: {}", session.root_pid);
        println!("  cwd: {}", session.cwd);
        if let Some(mode) = &session.mode {
            println!("  mode: {mode}");
        }
        if let Some(workspace_mode) = &session.workspace_mode {
            println!("  workspace_mode: {workspace_mode}");
        }
        if let Some(staged_workspace) = &session.staged_workspace {
            println!("  staged_workspace: {staged_workspace}");
        }
        if let Some(sandbox_profile) = &session.sandbox_profile {
            println!("  sandbox_profile: {sandbox_profile}");
        }
        if let Some(repo_path) = &session.repo_path {
            println!("  repo: {repo_path}");
        }
        println!(
            "  status: {}",
            if session.is_active() {
                "active"
            } else {
                "ended"
            }
        );

        match ProcessTree::from_root_pid(session.root_pid) {
            Ok(tree) => {
                let descendants = tree.descendants();
                if descendants.is_empty() {
                    println!("  descendants: none currently visible");
                } else {
                    println!("  descendants:");
                    for node in descendants {
                        println!(
                            "    pid={} ppid={} confidence={:.2} {}",
                            node.pid,
                            node.ppid,
                            tree.attribution_confidence(node.pid),
                            node.binary
                        );
                    }
                }
            }
            Err(error) => {
                println!("  process tree: unavailable ({error})");
            }
        }
    }

    if !workspace_effects.is_empty() {
        println!("Workspace effects");
        for effect in workspace_effects.iter().rev().take(40).rev() {
            println!(
                "  {} | session={} | {} | confidence={} | {}",
                effect.observed_at_ms,
                effect.session_id.as_deref().unwrap_or("unknown"),
                effect.effect_type,
                effect.confidence,
                effect.path,
            );
        }
    }

    if !alerts.is_empty() {
        println!("Policy alerts");
        let display_alerts = dedupe_policy_alerts(&alerts);
        for alert in display_alerts.iter().rev().take(40).rev() {
            println!(
                "  {} | severity={} | action={} | rule={} | request={}{} | {}",
                alert.created_at,
                alert.severity,
                alert.action,
                alert.rule_id,
                alert
                    .request_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                alert
                    .path
                    .as_deref()
                    .map(|path| format!(" | path={path}"))
                    .unwrap_or_default(),
                alert.message,
            );
        }
    }

    if !user_prompts.is_empty() {
        println!("Agent user prompts");
        for prompt in user_prompts {
            println!(
                "  session={} | observed_at={}{}",
                prompt.session_id.as_deref().unwrap_or("unknown"),
                prompt.observed_at_ms,
                prompt
                    .prompt
                    .as_deref()
                    .map(|value| format!(" | prompt={}", one_line(value)))
                    .unwrap_or_default(),
            );
            if let Some(cwd) = prompt.cwd.as_deref() {
                println!("    cwd: {cwd}");
            }
            if let Some(transcript_path) = prompt.transcript_path.as_deref() {
                println!("    transcript: {transcript_path}");
            }
            if prompt.permission_mode.is_some() || prompt.effort_level.is_some() {
                println!(
                    "    agent: permission_mode={} effort={}",
                    prompt.permission_mode.as_deref().unwrap_or("unknown"),
                    prompt.effort_level.as_deref().unwrap_or("unknown"),
                );
            }
        }
    }

    if !assistant_responses.is_empty() {
        println!("Agent assistant responses");
        for response in assistant_responses {
            println!(
                "  session={} | observed_at={}{}",
                response.session_id.as_deref().unwrap_or("unknown"),
                response.observed_at_ms,
                response
                    .message
                    .as_deref()
                    .map(|value| format!(" | response={}", one_line(value)))
                    .unwrap_or_default(),
            );
            if let Some(cwd) = response.cwd.as_deref() {
                println!("    cwd: {cwd}");
            }
            if let Some(transcript_path) = response.transcript_path.as_deref() {
                println!("    transcript: {transcript_path}");
            }
            if response.permission_mode.is_some() || response.effort_level.is_some() {
                println!(
                    "    agent: permission_mode={} effort={}",
                    response.permission_mode.as_deref().unwrap_or("unknown"),
                    response.effort_level.as_deref().unwrap_or("unknown"),
                );
            }
        }
    }

    if !agent_refusals.is_empty() {
        println!("Agent refused requests");
        for refusal in &agent_refusals {
            println!(
                "  session={} | observed_at={} | action=deny | reason={}",
                refusal.session_id.as_deref().unwrap_or("unknown"),
                refusal.observed_at_ms,
                refusal.reason,
            );
            if let Some(prompt) = refusal.prompt.as_deref() {
                println!("    prompt: {}", one_line(prompt));
            }
            if let Some(response) = refusal.response.as_deref() {
                println!("    response: {}", one_line(response));
            }
            if let Some(cwd) = refusal.cwd.as_deref() {
                println!("    cwd: {cwd}");
            }
        }
    }

    if !tool_calls.is_empty() {
        println!("Agent tool calls");
        for call in tool_calls {
            println!(
                "  session={} | tool_use={} | tool={} | status={}{}",
                call.session_id.as_deref().unwrap_or("unknown"),
                call.tool_use_id.as_deref().unwrap_or("unknown"),
                call.tool_name.as_deref().unwrap_or("unknown"),
                call.status(),
                call.duration_ms
                    .map(|duration| format!(" | duration={}ms", duration))
                    .unwrap_or_default(),
            );
            if let Some(cwd) = call.cwd.as_deref() {
                println!("    cwd: {cwd}");
            }
            if let Some(command) = call.command.as_deref() {
                println!("    command: {command}");
            }
            if let Some(description) = call.description.as_deref() {
                println!("    description: {description}");
            }
            if call.permission_mode.is_some() || call.effort_level.is_some() {
                println!(
                    "    agent: permission_mode={} effort={}",
                    call.permission_mode.as_deref().unwrap_or("unknown"),
                    call.effort_level.as_deref().unwrap_or("unknown"),
                );
            }
            if let Some(stdout) = call.stdout.as_deref() {
                println!("    stdout: {}", one_line(stdout));
            }
            if let Some(stderr) = call.stderr.as_deref().filter(|value| !value.is_empty()) {
                println!("    stderr: {}", one_line(stderr));
            }
            if let Some(interrupted) = call.interrupted {
                println!("    interrupted: {interrupted}");
            }
            if !call.policy_alerts.is_empty() {
                println!("    policy:");
                for alert in dedupe_policy_alerts(&call.policy_alerts) {
                    println!(
                        "      action={} severity={} rule={}{} | {}",
                        alert.action,
                        alert.severity,
                        alert.rule_id,
                        alert
                            .path
                            .as_deref()
                            .map(|path| format!(" path={path}"))
                            .unwrap_or_default(),
                        alert.message,
                    );
                }
            }
            if call.shows_process_correlation() {
                println!("    process correlation:");
                let has_real_processes = call.processes.iter().any(|process| process.pid != 0);
                for process in call.processes.iter().take(TIMELINE_PROCESS_DISPLAY_LIMIT) {
                    if process.pid == 0 && !has_real_processes {
                        println!(
                            "      source={} confidence={} {}",
                            process.provider,
                            correlation_confidence(process),
                            one_line(&process.command)
                        );
                    } else if process.pid != 0 {
                        println!(
                            "      source={} confidence={} pid={} ppid={} {}",
                            process.provider,
                            correlation_confidence(process),
                            process.pid,
                            process.ppid,
                            one_line(&process.command)
                        );
                    }
                }
                if call.processes.len() > TIMELINE_PROCESS_DISPLAY_LIMIT {
                    println!(
                        "      ... {} more process observations omitted",
                        call.processes.len() - TIMELINE_PROCESS_DISPLAY_LIMIT
                    );
                }
            }
            if !call.file_intents.is_empty() {
                println!("    file intents:");
                for intent in &call.file_intents {
                    println!(
                        "      source={} confidence={} op={} sensitive={} path={}",
                        intent.provider,
                        intent.confidence,
                        intent.operation,
                        intent.sensitive,
                        intent.path,
                    );
                }
            }
            if !call.system_events.is_empty() {
                println!("    system events:");
                for event in &call.system_events {
                    println!(
                        "      source={} kind={} type={} pid={} ppid={} process={} path={} network={} command={}",
                        event.source,
                        event.event_kind,
                        event.event_type,
                        option_u32_display(event.pid),
                        option_u32_display(event.ppid),
                        event.process_name.as_deref().unwrap_or("unknown"),
                        event.file_path.as_deref().unwrap_or("-"),
                        system_event_network_dest(event).unwrap_or_else(|| "-".to_string()),
                        one_line(event.command_line.as_deref().unwrap_or("-")),
                    );
                }
            }
            if !call.workspace_effects.is_empty() {
                println!("    file effects:");
                for effect in &call.workspace_effects {
                    println!(
                        "      source={} confidence={} op={} path={}",
                        effect.source, effect.confidence, effect.effect_type, effect.path,
                    );
                }
            }
        }
    }

    if filter.shows_standalone_system_events() && !system_events.is_empty() {
        println!("Layer 1 system events");
        for event in system_events.iter().rev().take(20).rev() {
            println!(
                "  {} | source={} | kind={} | type={} | pid={} | process={} | path={} | network={} | command={}",
                event.observed_at_ms,
                event.source,
                event.event_kind,
                event.event_type,
                option_u32_display(event.pid),
                event.process_name.as_deref().unwrap_or("unknown"),
                event.file_path.as_deref().unwrap_or("-"),
                system_event_network_dest(event).unwrap_or_else(|| "-".to_string()),
                one_line(event.command_line.as_deref().unwrap_or("-")),
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) enum TimelineFilter {
    All,
    Latest,
    Session(String),
    Path(String),
}

struct TimelineCollections<'a> {
    sessions: &'a mut Vec<AgentSession>,
    user_prompts: &'a mut Vec<AgentUserPrompt>,
    assistant_responses: &'a mut Vec<AgentAssistantResponse>,
    tool_calls: &'a mut Vec<AgentToolCall>,
    system_events: &'a mut Vec<SystemEvent>,
    workspace_effects: &'a mut Vec<WorkspaceEffect>,
    alerts: &'a mut Vec<AlertRecord>,
}

impl TimelineFilter {
    pub(crate) fn parse(args: &[OsString]) -> io::Result<Self> {
        if args.is_empty() {
            return Ok(Self::All);
        }

        match args.first().and_then(|arg| arg.to_str()) {
            Some("--latest") => Ok(Self::Latest),
            Some("--session") => Ok(Self::Session(required_arg_value(args, "--session")?)),
            Some("--path") => Ok(Self::Path(required_arg_value(args, "--path")?)),
            Some("--help") | Some("-h") => {
                print_usage();
                Ok(Self::All)
            }
            Some(other) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown timeline option: {other}"),
            )),
            None => Ok(Self::All),
        }
    }

    fn apply(&self, collections: TimelineCollections<'_>) {
        match self {
            Self::All => {}
            Self::Latest => {
                let Some(session_id) = latest_agent_session_id(
                    collections.user_prompts,
                    collections.assistant_responses,
                    collections.tool_calls,
                ) else {
                    return;
                };
                keep_prompt_session(collections.user_prompts, &session_id);
                keep_response_session(collections.assistant_responses, &session_id);
                keep_session(collections.tool_calls, &session_id);
                collections.sessions.clear();
                keep_system_event_session(collections.system_events, &session_id);
                collections
                    .workspace_effects
                    .retain(|effect| effect.session_id.as_deref() == Some(session_id.as_str()));
                keep_alert_sessions(collections.alerts, &session_id);
            }
            Self::Session(session_id) => {
                keep_prompt_session(collections.user_prompts, session_id);
                keep_response_session(collections.assistant_responses, session_id);
                keep_session(collections.tool_calls, session_id);
                collections
                    .sessions
                    .retain(|session| session.session_id == *session_id);
                keep_system_event_session(collections.system_events, session_id);
                collections
                    .workspace_effects
                    .retain(|effect| effect.session_id.as_deref() == Some(session_id.as_str()));
                keep_alert_sessions(collections.alerts, session_id);
            }
            Self::Path(path) => {
                collections.sessions.clear();
                collections
                    .user_prompts
                    .retain(|prompt| user_prompt_matches_path(prompt, path));
                collections
                    .assistant_responses
                    .retain(|response| assistant_response_matches_path(response, path));
                collections
                    .tool_calls
                    .retain(|call| tool_call_matches_path(call, path));
                collections
                    .system_events
                    .retain(|event| system_event_matches_path(event, path));
                collections
                    .workspace_effects
                    .retain(|effect| effect.path.contains(path));
                collections
                    .alerts
                    .retain(|alert| alert_matches_path(alert, path));
            }
        }
    }

    fn shows_standalone_system_events(&self) -> bool {
        matches!(self, Self::All | Self::Path(_))
    }
}

pub(crate) fn latest_agent_session_id(
    user_prompts: &[AgentUserPrompt],
    assistant_responses: &[AgentAssistantResponse],
    tool_calls: &[AgentToolCall],
) -> Option<String> {
    let latest_prompt = user_prompts
        .iter()
        .filter_map(|prompt| Some((prompt.observed_at_ms, prompt.session_id.clone()?)));
    let latest_response = assistant_responses
        .iter()
        .filter_map(|response| Some((response.observed_at_ms, response.session_id.clone()?)));
    let latest_tool = tool_calls
        .iter()
        .filter_map(|call| Some((call.last_observed_at_ms()?, call.session_id.clone()?)));

    latest_prompt
        .chain(latest_response)
        .chain(latest_tool)
        .max_by_key(|(observed_at_ms, _)| *observed_at_ms)
        .map(|(_, session_id)| session_id)
}

pub(crate) fn keep_prompt_session(user_prompts: &mut Vec<AgentUserPrompt>, session_id: &str) {
    user_prompts.retain(|prompt| prompt.session_id.as_deref() == Some(session_id));
}

pub(crate) fn keep_response_session(
    assistant_responses: &mut Vec<AgentAssistantResponse>,
    session_id: &str,
) {
    assistant_responses.retain(|response| response.session_id.as_deref() == Some(session_id));
}

pub(crate) fn keep_session(tool_calls: &mut Vec<AgentToolCall>, session_id: &str) {
    tool_calls.retain(|call| call.session_id.as_deref() == Some(session_id));
}

pub(crate) fn keep_alert_sessions(alerts: &mut Vec<AlertRecord>, session_id: &str) {
    alerts.retain(|alert| alert.session_id.as_deref() == Some(session_id));
}

pub(crate) fn keep_system_event_session(system_events: &mut Vec<SystemEvent>, session_id: &str) {
    system_events.retain(|event| system_event_session_id(event).as_deref() == Some(session_id));
}

pub(crate) fn user_prompt_matches_path(prompt: &AgentUserPrompt, path: &str) -> bool {
    prompt
        .cwd
        .as_deref()
        .is_some_and(|value| value.contains(path))
        || prompt
            .transcript_path
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || prompt
            .prompt
            .as_deref()
            .is_some_and(|value| value.contains(path))
}

pub(crate) fn assistant_response_matches_path(
    response: &AgentAssistantResponse,
    path: &str,
) -> bool {
    response
        .cwd
        .as_deref()
        .is_some_and(|value| value.contains(path))
        || response
            .transcript_path
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || response
            .message
            .as_deref()
            .is_some_and(|value| value.contains(path))
}

pub(crate) fn tool_call_matches_path(call: &AgentToolCall, path: &str) -> bool {
    call.cwd
        .as_deref()
        .is_some_and(|value| value.contains(path))
        || call
            .command
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || call
            .stdout
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || call
            .file_intents
            .iter()
            .any(|intent| intent.path.contains(path) || intent.source_command.contains(path))
        || call
            .system_events
            .iter()
            .any(|event| system_event_matches_path(event, path))
        || call
            .workspace_effects
            .iter()
            .any(|effect| effect.path.contains(path) || effect.workspace.contains(path))
}

pub(crate) fn system_event_matches_path(event: &SystemEvent, path: &str) -> bool {
    event
        .file_path
        .as_deref()
        .is_some_and(|value| value.contains(path))
        || event
            .executable_path
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || event
            .command_line
            .as_deref()
            .is_some_and(|value| value.contains(path))
        || event.raw_json.contains(path)
}

pub(crate) fn system_event_session_id(event: &SystemEvent) -> Option<String> {
    serde_json::from_str::<Value>(&event.raw_json)
        .ok()?
        .get("session_id")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn system_event_network_dest(event: &SystemEvent) -> Option<String> {
    serde_json::from_str::<Value>(&event.raw_json)
        .ok()?
        .get("network_dest")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn alert_matches_path(alert: &AlertRecord, path: &str) -> bool {
    alert
        .path
        .as_deref()
        .is_some_and(|value| value.contains(path))
        || alert.message.contains(path)
        || alert
            .evidence
            .as_deref()
            .is_some_and(|value| value.contains(path))
}

pub(crate) fn alert_tool_use_id(alert: &AlertRecord) -> Option<String> {
    let value = serde_json::from_str::<Value>(alert.evidence.as_deref()?).ok()?;
    value
        .get("tool_use_id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub(crate) fn compact_sessions(mut records: Vec<AgentSession>) -> Vec<AgentSession> {
    records.sort_by_key(|session| session.started_at_ms);
    let mut compacted: Vec<AgentSession> = Vec::new();

    for record in records {
        if let Some(existing) = compacted
            .iter_mut()
            .find(|session| session.session_id == record.session_id)
        {
            if record.ended_at_ms.is_some() {
                *existing = record;
            }
        } else {
            compacted.push(record);
        }
    }

    compacted
}

#[derive(Debug, Clone)]
pub(crate) struct AgentUserPrompt {
    pub(crate) session_id: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) transcript_path: Option<String>,
    pub(crate) prompt: Option<String>,
    pub(crate) permission_mode: Option<String>,
    pub(crate) effort_level: Option<String>,
    pub(crate) observed_at_ms: u64,
}

impl AgentUserPrompt {
    fn from_hook(hook: &AgentHookEvent) -> Self {
        Self {
            session_id: hook.session_id.clone(),
            cwd: hook.cwd.clone(),
            transcript_path: hook.transcript_path.clone(),
            prompt: user_prompt_from_hook(hook),
            permission_mode: hook.permission_mode.clone(),
            effort_level: hook.effort_level.clone(),
            observed_at_ms: hook.observed_at_ms,
        }
    }
}

pub(crate) fn compact_user_prompts(records: &[AgentHookEvent]) -> Vec<AgentUserPrompt> {
    let mut prompts = records
        .iter()
        .filter(|hook| hook.hook_event_name.as_deref() == Some("UserPromptSubmit"))
        .map(AgentUserPrompt::from_hook)
        .collect::<Vec<_>>();
    prompts.sort_by_key(|prompt| prompt.observed_at_ms);
    prompts
}

pub(crate) fn user_prompt_from_hook(hook: &AgentHookEvent) -> Option<String> {
    let value = serde_json::from_str::<Value>(&hook.raw_json).ok()?;
    top_level_str(&value, &["prompt", "user_prompt", "message"])
}

#[derive(Debug, Clone)]
pub(crate) struct AgentAssistantResponse {
    pub(crate) session_id: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) transcript_path: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) permission_mode: Option<String>,
    pub(crate) effort_level: Option<String>,
    pub(crate) observed_at_ms: u64,
}

impl AgentAssistantResponse {
    fn from_hook(hook: &AgentHookEvent) -> Self {
        Self {
            session_id: hook.session_id.clone(),
            cwd: hook.cwd.clone(),
            transcript_path: hook.transcript_path.clone(),
            message: assistant_response_from_hook(hook),
            permission_mode: hook.permission_mode.clone(),
            effort_level: hook.effort_level.clone(),
            observed_at_ms: hook.observed_at_ms,
        }
    }
}

pub(crate) fn compact_assistant_responses(
    records: &[AgentHookEvent],
) -> Vec<AgentAssistantResponse> {
    let mut responses = records
        .iter()
        .filter(|hook| hook.hook_event_name.as_deref() == Some("Stop"))
        .map(AgentAssistantResponse::from_hook)
        .collect::<Vec<_>>();
    responses.sort_by_key(|response| response.observed_at_ms);
    responses
}

pub(crate) fn assistant_response_from_hook(hook: &AgentHookEvent) -> Option<String> {
    let value = serde_json::from_str::<Value>(&hook.raw_json).ok()?;
    top_level_str(&value, &["last_assistant_message"])
}

#[derive(Debug, Clone)]
pub(crate) struct AgentRefusal {
    pub(crate) session_id: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) observed_at_ms: u64,
    pub(crate) prompt: Option<String>,
    pub(crate) response: Option<String>,
    pub(crate) reason: String,
}

pub(crate) fn derive_agent_refusals(
    prompts: &[AgentUserPrompt],
    responses: &[AgentAssistantResponse],
) -> Vec<AgentRefusal> {
    let unsafe_prompts = prompts
        .iter()
        .filter(|prompt| {
            prompt
                .prompt
                .as_deref()
                .is_some_and(looks_unsafe_destructive_prompt)
        })
        .collect::<Vec<_>>();
    if unsafe_prompts.is_empty() {
        return Vec::new();
    }

    responses
        .iter()
        .filter(|response| {
            response
                .message
                .as_deref()
                .is_some_and(looks_like_agent_refusal)
        })
        .filter_map(|response| {
            let prompt = unsafe_prompts
                .iter()
                .filter(|prompt| {
                    prompt.session_id == response.session_id
                        && prompt.observed_at_ms <= response.observed_at_ms
                })
                .max_by_key(|prompt| prompt.observed_at_ms)?;
            Some(AgentRefusal {
                session_id: response.session_id.clone(),
                cwd: response.cwd.clone().or_else(|| prompt.cwd.clone()),
                observed_at_ms: response.observed_at_ms,
                prompt: prompt.prompt.clone(),
                response: response.message.clone(),
                reason: "agent_refusal_destructive_request".to_string(),
            })
        })
        .collect()
}

pub(crate) fn looks_unsafe_destructive_prompt(prompt: &str) -> bool {
    let lower = prompt.to_ascii_lowercase();
    (lower.contains("rm -rf") || lower.contains("rm -fr"))
        && (lower.contains("~/") || lower.contains("$home") || lower.contains(" /"))
        || lower.contains("delete my home directory")
        || lower.contains("delete the home directory")
        || lower.contains("delete everything")
}

pub(crate) fn looks_like_agent_refusal(response: &str) -> bool {
    let lower = response.to_ascii_lowercase();
    lower.contains("i can't run")
        || lower.contains("i can’t run")
        || lower.contains("i cannot run")
        || lower.contains("i won’t run")
        || lower.contains("i won't run")
        || lower.contains("would destructively delete")
}

#[derive(Debug, Clone)]
pub(crate) struct AgentToolCall {
    pub(crate) session_id: Option<String>,
    pub(crate) tool_use_id: Option<String>,
    pub(crate) tool_name: Option<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) transcript_path: Option<String>,
    pub(crate) pre_observed_at_ms: Option<u64>,
    pub(crate) post_observed_at_ms: Option<u64>,
    pub(crate) command: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) stdout: Option<String>,
    pub(crate) stderr: Option<String>,
    pub(crate) interrupted: Option<bool>,
    pub(crate) duration_ms: Option<u64>,
    pub(crate) permission_mode: Option<String>,
    pub(crate) effort_level: Option<String>,
    pub(crate) processes: Vec<ProcessObservation>,
    pub(crate) file_intents: Vec<FileIntent>,
    pub(crate) policy_alerts: Vec<AlertRecord>,
    pub(crate) system_events: Vec<SystemEvent>,
    pub(crate) workspace_effects: Vec<WorkspaceEffect>,
}

impl AgentToolCall {
    fn from_hook(hook: &AgentHookEvent) -> Self {
        let mut call = Self {
            session_id: hook.session_id.clone(),
            tool_use_id: hook.tool_use_id.clone(),
            tool_name: hook.tool_name.clone(),
            cwd: hook.cwd.clone(),
            transcript_path: hook.transcript_path.clone(),
            pre_observed_at_ms: None,
            post_observed_at_ms: None,
            command: hook.tool_input_command.clone(),
            description: hook.tool_input_description.clone(),
            stdout: hook.tool_response_stdout.clone(),
            stderr: hook.tool_response_stderr.clone(),
            interrupted: hook.tool_response_interrupted,
            duration_ms: hook.duration_ms,
            permission_mode: hook.permission_mode.clone(),
            effort_level: hook.effort_level.clone(),
            processes: Vec::new(),
            file_intents: Vec::new(),
            policy_alerts: Vec::new(),
            system_events: Vec::new(),
            workspace_effects: Vec::new(),
        };
        call.mark_observed(hook);
        call
    }

    fn merge_hook(&mut self, hook: &AgentHookEvent) {
        fill_missing(&mut self.session_id, &hook.session_id);
        fill_missing(&mut self.tool_use_id, &hook.tool_use_id);
        fill_missing(&mut self.tool_name, &hook.tool_name);
        fill_missing(&mut self.cwd, &hook.cwd);
        fill_missing(&mut self.transcript_path, &hook.transcript_path);
        fill_missing(&mut self.command, &hook.tool_input_command);
        fill_missing(&mut self.description, &hook.tool_input_description);
        fill_missing(&mut self.stdout, &hook.tool_response_stdout);
        fill_missing(&mut self.stderr, &hook.tool_response_stderr);
        fill_missing(&mut self.permission_mode, &hook.permission_mode);
        fill_missing(&mut self.effort_level, &hook.effort_level);

        if self.interrupted.is_none() {
            self.interrupted = hook.tool_response_interrupted;
        }
        if self.duration_ms.is_none() {
            self.duration_ms = hook.duration_ms;
        }

        self.mark_observed(hook);
    }

    fn mark_observed(&mut self, hook: &AgentHookEvent) {
        match hook.hook_event_name.as_deref() {
            Some("PreToolUse") => self.pre_observed_at_ms = Some(hook.observed_at_ms),
            Some("PostToolUse") => self.post_observed_at_ms = Some(hook.observed_at_ms),
            _ => {}
        }
    }

    pub(crate) fn status(&self) -> &'static str {
        if self.has_policy_action("block") {
            return "blocked";
        }
        if self.has_policy_action("ask") {
            return "ask";
        }
        match (self.pre_observed_at_ms, self.post_observed_at_ms) {
            (Some(_), Some(_)) => "completed",
            (Some(_), None) => "started",
            (None, Some(_)) => "completed-no-pre",
            (None, None) => "observed",
        }
    }

    fn has_policy_action(&self, action: &str) -> bool {
        self.policy_alerts
            .iter()
            .any(|alert| alert.action == action)
    }

    pub(crate) fn shows_process_correlation(&self) -> bool {
        !self.processes.is_empty()
            && !self.has_policy_action("block")
            && !self.has_policy_action("ask")
    }

    fn last_observed_at_ms(&self) -> Option<u64> {
        self.post_observed_at_ms.or(self.pre_observed_at_ms)
    }
}

pub(crate) fn compact_tool_calls(
    records: &[AgentHookEvent],
    observations: &[ProcessObservation],
    file_intents: &[FileIntent],
    system_events: &[SystemEvent],
    workspace_effects: &[WorkspaceEffect],
    alerts: &[AlertRecord],
) -> Vec<AgentToolCall> {
    let mut hooks = records.to_vec();
    hooks.sort_by_key(|event| event.observed_at_ms);
    let mut calls: Vec<AgentToolCall> = Vec::new();

    for hook in &hooks {
        if !is_tool_use_hook(hook) {
            continue;
        }
        if let Some(existing) = calls.iter_mut().find(|call| same_tool_call(call, hook)) {
            existing.merge_hook(hook);
        } else {
            calls.push(AgentToolCall::from_hook(hook));
        }
    }

    for observation in observations {
        if let Some(call) = calls
            .iter_mut()
            .find(|call| same_observed_tool_call(call, observation))
        {
            if !call
                .processes
                .iter()
                .any(|existing| existing.pid == observation.pid)
            {
                call.processes.push(observation.clone());
            }
        }
    }

    for call in &mut calls {
        call.processes.sort_by_key(|process| process.observed_at_ms);
    }

    for intent in file_intents {
        if let Some(call) = calls
            .iter_mut()
            .find(|call| same_file_intent_tool_call(call, intent))
        {
            if !call.file_intents.iter().any(|existing| {
                existing.operation == intent.operation
                    && existing.path == intent.path
                    && existing.source_command == intent.source_command
            }) {
                call.file_intents.push(intent.clone());
            }
        }
    }

    for call in &mut calls {
        call.file_intents
            .sort_by_key(|intent| intent.observed_at_ms);
    }

    for alert in alerts {
        let Some(tool_use_id) = alert_tool_use_id(alert) else {
            continue;
        };
        if let Some(call) = calls.iter_mut().find(|call| {
            call.session_id == alert.session_id
                && call.tool_use_id.as_deref() == Some(tool_use_id.as_str())
        }) {
            call.policy_alerts.push(alert.clone());
        }
    }

    for call in &mut calls {
        call.policy_alerts
            .sort_by_key(|alert| (alert.created_at, alert.alert_id));
        call.policy_alerts = dedupe_policy_alerts(&call.policy_alerts);
    }

    for event in system_events {
        if let Some(call) = calls
            .iter_mut()
            .find(|call| same_system_event_tool_call(call, event))
        {
            if !call.system_events.iter().any(|existing| {
                existing.observed_at_ms == event.observed_at_ms
                    && existing.event_type == event.event_type
                    && existing.pid == event.pid
                    && existing.file_path == event.file_path
            }) {
                call.system_events.push(event.clone());
            }
        }
    }

    for call in &mut calls {
        call.system_events.sort_by_key(|event| event.observed_at_ms);
    }

    for effect in workspace_effects {
        if let Some(index) = best_workspace_effect_tool_call_index(&calls, effect) {
            let call = &mut calls[index];
            if !call.workspace_effects.iter().any(|existing| {
                existing.observed_at_ms == effect.observed_at_ms
                    && existing.effect_type == effect.effect_type
                    && existing.path == effect.path
            }) {
                call.workspace_effects.push(effect.clone());
            }
        }
    }

    for call in &mut calls {
        call.workspace_effects
            .sort_by_key(|effect| effect.observed_at_ms);
    }

    calls
}

fn dedupe_policy_alerts(alerts: &[AlertRecord]) -> Vec<AlertRecord> {
    let mut deduped = Vec::new();
    for alert in alerts {
        let tool_use_id = alert_tool_use_id(alert);
        if deduped.iter().any(|existing: &AlertRecord| {
            existing.session_id == alert.session_id
                && alert_tool_use_id(existing) == tool_use_id
                && existing.request_id == alert.request_id
                && existing.action == alert.action
                && existing.severity == alert.severity
                && existing.rule_id == alert.rule_id
                && existing.path == alert.path
                && existing.message == alert.message
        }) {
            continue;
        }
        deduped.push(alert.clone());
    }
    deduped
}

pub(crate) fn is_tool_use_hook(hook: &AgentHookEvent) -> bool {
    matches!(
        hook.hook_event_name.as_deref(),
        Some("PreToolUse") | Some("PostToolUse")
    ) || hook.tool_use_id.is_some()
        || hook.tool_name.is_some()
}

pub(crate) fn same_tool_call(call: &AgentToolCall, hook: &AgentHookEvent) -> bool {
    call.session_id == hook.session_id
        && call.tool_use_id.is_some()
        && call.tool_use_id == hook.tool_use_id
}

pub(crate) fn same_observed_tool_call(
    call: &AgentToolCall,
    observation: &ProcessObservation,
) -> bool {
    call.session_id == observation.session_id
        && call.tool_use_id.is_some()
        && call.tool_use_id == observation.tool_use_id
        && observed_inside_tool_window(call, observation)
}

pub(crate) fn same_file_intent_tool_call(call: &AgentToolCall, intent: &FileIntent) -> bool {
    call.session_id == intent.session_id
        && call.tool_use_id.is_some()
        && call.tool_use_id == intent.tool_use_id
}

pub(crate) fn same_system_event_tool_call(call: &AgentToolCall, event: &SystemEvent) -> bool {
    observed_at_inside_tool_window(call, event.observed_at_ms)
}

pub(crate) fn same_workspace_effect_tool_call(
    call: &AgentToolCall,
    effect: &WorkspaceEffect,
) -> bool {
    observed_at_inside_tool_window(call, effect.observed_at_ms)
}

pub(crate) fn best_workspace_effect_tool_call_index(
    calls: &[AgentToolCall],
    effect: &WorkspaceEffect,
) -> Option<usize> {
    calls
        .iter()
        .enumerate()
        .filter(|(_, call)| same_workspace_effect_tool_call(call, effect))
        .min_by_key(|(_, call)| workspace_effect_correlation_score(call, effect))
        .map(|(index, _)| index)
}

pub(crate) fn workspace_effect_correlation_score(
    call: &AgentToolCall,
    effect: &WorkspaceEffect,
) -> (u8, u64) {
    let completeness = match (call.pre_observed_at_ms, call.post_observed_at_ms) {
        (Some(_), Some(_)) => 0,
        (None, Some(_)) => 1,
        (Some(_), None) => 2,
        (None, None) => 3,
    };
    let distance = call
        .last_observed_at_ms()
        .map(|observed_at_ms| observed_at_ms.abs_diff(effect.observed_at_ms))
        .unwrap_or(u64::MAX);

    (completeness, distance)
}

pub(crate) fn observed_inside_tool_window(
    call: &AgentToolCall,
    observation: &ProcessObservation,
) -> bool {
    observed_at_inside_tool_window(call, observation.observed_at_ms)
}

pub(crate) fn observed_at_inside_tool_window(call: &AgentToolCall, observed_at_ms: u64) -> bool {
    let Some((start, end)) = tool_window_bounds(call) else {
        return false;
    };
    observed_at_ms >= start && observed_at_ms <= end
}

pub(crate) fn tool_window_bounds(call: &AgentToolCall) -> Option<(u64, u64)> {
    match (call.pre_observed_at_ms, call.post_observed_at_ms) {
        (Some(pre), Some(post)) => Some((
            pre.saturating_sub(TOOL_WINDOW_TOLERANCE_MS),
            post.saturating_add(TOOL_WINDOW_TOLERANCE_MS),
        )),
        (Some(pre), None) => Some((
            pre.saturating_sub(TOOL_WINDOW_TOLERANCE_MS),
            pre.saturating_add(STARTED_TOOL_WINDOW_MS),
        )),
        (None, Some(post)) => {
            let start = call
                .duration_ms
                .map(|duration| {
                    post.saturating_sub(duration.saturating_add(TOOL_WINDOW_TOLERANCE_MS))
                })
                .unwrap_or_else(|| post.saturating_sub(TOOL_WINDOW_TOLERANCE_MS));
            Some((start, post.saturating_add(TOOL_WINDOW_TOLERANCE_MS)))
        }
        (None, None) => None,
    }
}

pub(crate) fn correlation_confidence(process: &ProcessObservation) -> &'static str {
    if process.pid == 0 {
        return "none";
    }

    match process.provider.as_str() {
        "process-sampler" => "medium",
        _ => "unknown",
    }
}

pub(crate) fn system_event_from_eslogger_line(line: &str, observed_at_ms: u64) -> SystemEvent {
    let Ok(mut value) = serde_json::from_str::<Value>(line) else {
        // Not valid JSON: keep only a redacted raw copy. Structured fields are
        // unavailable, but nothing secret-bearing is persisted.
        let redacted = redact_text(line);
        return SystemEvent {
            source: "macos-eslogger".to_string(),
            event_type: "unknown".to_string(),
            event_kind: "unknown".to_string(),
            observed_at_ms,
            pid: None,
            ppid: None,
            process_name: None,
            executable_path: None,
            file_path: None,
            command_line: None,
            // Keep DB CHECK(json_valid(args)) compatible even for malformed lines.
            raw_json: serde_json::to_string(&redacted).unwrap_or_else(|_| "\"\"".to_string()),
        };
    };

    // Redact before any field is read or persisted.
    redact_value(&mut value);

    let event_type = detect_eslogger_event_type(&value, line);
    let event_kind = classify_system_event_kind(&event_type);
    let executable_path = find_first_str(&value, &["executable_path", "exec_path", "path"]);
    let command_line = find_first_str(&value, &["command_line", "command", "args"]);
    let file_path = detect_file_path(&value, executable_path.as_deref(), &event_type);

    SystemEvent {
        source: "macos-eslogger".to_string(),
        event_type,
        event_kind,
        observed_at_ms,
        pid: find_first_u32(&value, &["pid", "process_id", "audit_token_pid"]),
        ppid: find_first_u32(&value, &["ppid", "parent_pid"]),
        process_name: find_first_str(&value, &["process_name", "name", "comm", "signing_id"]),
        executable_path,
        file_path,
        command_line,
        raw_json: serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Find the first JSON value (depth-first) whose key matches one of `keys`,
/// honoring the priority order of `keys`.
pub(crate) fn find_first<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| find_by_key(value, key))
}

pub(crate) fn find_by_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|child| find_by_key(child, key))),
        Value::Array(items) => items.iter().find_map(|item| find_by_key(item, key)),
        _ => None,
    }
}

pub(crate) fn find_first_str(value: &Value, keys: &[&str]) -> Option<String> {
    find_first(value, keys).and_then(value_as_string)
}

pub(crate) fn top_level_str(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(value_as_string))
}

pub(crate) fn find_first_u32(value: &Value, keys: &[&str]) -> Option<u32> {
    find_first(value, keys).and_then(value_as_u32)
}

pub(crate) fn value_as_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

pub(crate) fn value_as_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

pub(crate) fn v_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(value_as_string)
}

pub(crate) fn v_nested_str(value: &Value, parent: &str, key: &str) -> Option<String> {
    value
        .get(parent)
        .and_then(|child| child.get(key))
        .and_then(value_as_string)
}

pub(crate) fn detect_eslogger_event_type(value: &Value, line: &str) -> String {
    if let Some(found) = find_first_str(value, &["event_type", "eventType", "type"]) {
        return found.to_ascii_lowercase();
    }

    for event_type in [
        "exec",
        "fork",
        "exit",
        "create",
        "write",
        "rename",
        "unlink",
        "close",
        "truncate",
        "clone",
        "copyfile",
        "exchangedata",
        "setextattr",
        "deleteextattr",
        "setmode",
        "setowner",
        "setflags",
        "setacl",
        "open",
        "lookup",
        "access",
        "stat",
        "getattrlist",
        "readlink",
        "readdir",
        "getextattr",
        "listextattr",
        "fsgetpath",
    ] {
        if line.contains(&format!("\"{event_type}\"")) || line.contains(&format!("_{event_type}\""))
        {
            return event_type.to_string();
        }
    }

    "unknown".to_string()
}

pub(crate) fn classify_system_event_kind(event_type: &str) -> String {
    match event_type {
        "exec" | "fork" | "exit" => "process".to_string(),
        "open" | "lookup" | "access" | "stat" | "getattrlist" | "readlink" | "readdir"
        | "getextattr" | "listextattr" | "fsgetpath" => "file_open".to_string(),
        "create" | "write" | "rename" | "unlink" | "close" | "truncate" | "clone" | "copyfile"
        | "exchangedata" | "setextattr" | "deleteextattr" | "setmode" | "setowner" | "setflags"
        | "setacl" => "file_mutation".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(crate) fn detect_file_path(
    value: &Value,
    executable_path: Option<&str>,
    event_type: &str,
) -> Option<String> {
    let path = find_first_str(
        value,
        &[
            "target_path",
            "file_path",
            "destination_path",
            "source_path",
            "new_path",
            "old_path",
            "path",
        ],
    )?;

    if Some(path.as_str()) == executable_path && event_type == "exec" {
        None
    } else {
        Some(path)
    }
}

pub(crate) fn start_process_sampler(event: &AgentHookEvent) -> io::Result<()> {
    let Some(session_id) = event.session_id.as_deref() else {
        return Ok(());
    };
    let Some(tool_use_id) = event.tool_use_id.as_deref() else {
        return Ok(());
    };

    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("observe-tool-window")
        .arg("--session-id")
        .arg(session_id)
        .arg("--tool-use-id")
        .arg(tool_use_id)
        .arg("--duration-ms")
        .arg(PROCESS_SAMPLE_WINDOW_MS.to_string())
        .arg("--interval-ms")
        .arg(PROCESS_SAMPLE_INTERVAL_MS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(cwd) = event.cwd.as_deref() {
        command.current_dir(cwd);
    }

    command.spawn()?;
    Ok(())
}

pub(crate) fn observe_tool_window(args: Vec<OsString>) -> io::Result<()> {
    let session_id = required_arg_value(&args, "--session-id")?;
    let tool_use_id = required_arg_value(&args, "--tool-use-id")?;
    let duration_ms = optional_arg_u64(&args, "--duration-ms").unwrap_or(PROCESS_SAMPLE_WINDOW_MS);
    let interval_ms =
        optional_arg_u64(&args, "--interval-ms").unwrap_or(PROCESS_SAMPLE_INTERVAL_MS);

    if let Err(error) = sample_process_window(&session_id, &tool_use_id, duration_ms, interval_ms) {
        EventStore::default_local()?.append_process_observation(&ProcessObservation {
            provider: "process-sampler-error".to_string(),
            session_id: Some(session_id),
            tool_use_id: Some(tool_use_id),
            observed_at_ms: unix_millis()?,
            pid: 0,
            ppid: 0,
            binary: "gensee".to_string(),
            command: format!("process sampler unavailable: {error}"),
        })?;
    }

    Ok(())
}

pub(crate) fn sample_process_window(
    session_id: &str,
    tool_use_id: &str,
    duration_ms: u64,
    interval_ms: u64,
) -> io::Result<()> {
    let store = EventStore::default_local()?;
    let baseline = snapshot_process_table()?
        .into_iter()
        .map(|process| process.pid)
        .collect::<HashSet<_>>();
    let mut seen = baseline.clone();
    let sampler_pid = std::process::id();
    let started_at_ms = unix_millis()?;

    while unix_millis()?.saturating_sub(started_at_ms) < duration_ms {
        thread::sleep(Duration::from_millis(interval_ms));
        let observed_at_ms = unix_millis()?;

        for process in snapshot_process_table()? {
            if baseline.contains(&process.pid)
                || is_sampler_noise(&process, sampler_pid)
                || !seen.insert(process.pid)
            {
                continue;
            }

            store.append_process_observation(&ProcessObservation {
                provider: "process-sampler".to_string(),
                session_id: Some(session_id.to_string()),
                tool_use_id: Some(tool_use_id.to_string()),
                observed_at_ms,
                pid: process.pid,
                ppid: process.ppid,
                binary: process.binary,
                command: process.command,
            })?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessSnapshot {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) binary: String,
    pub(crate) command: String,
}

pub(crate) fn snapshot_process_table() -> io::Result<Vec<ProcessSnapshot>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,comm=,command="])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other("failed to snapshot process table with ps"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(ppid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(binary) = parts.next() else {
            continue;
        };
        let command = parts.collect::<Vec<_>>().join(" ");

        processes.push(ProcessSnapshot {
            pid,
            ppid,
            binary: binary.to_string(),
            command: if command.is_empty() {
                binary.to_string()
            } else {
                command
            },
        });
    }

    Ok(processes)
}

pub(crate) fn is_sampler_noise(process: &ProcessSnapshot, sampler_pid: u32) -> bool {
    // This sampler is intentionally conservative about noisy self-observations.
    // It may hide an agent-run `ps` or Spotlight work triggered by an agent, but
    // avoids presenting helper processes as evidence that the agent spawned them.
    process.pid == sampler_pid
        || process.ppid == sampler_pid
        || matches!(process.binary.as_str(), "ps" | "(ps)")
        || process.command == "(ps)"
        || process
            .command
            .contains("ps -axo pid=,ppid=,comm=,command=")
        || process.command.contains(" observe-tool-window ")
        || process.command.ends_with(" observe-tool-window")
        || process.binary.ends_with("/gensee")
        || process.binary == "gensee"
        || process.binary.ends_with("/mdworker_shared")
        || process.binary == "mdworker_shared"
}
