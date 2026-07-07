use crate::*;

/// URL-bearing text to scan: the shell command, plus explicit url/uri/endpoint
/// fields of native tools. Deliberately excludes free-form content fields (e.g.
/// `Write`) so writing a document that mentions a URL is not blocked.
pub(crate) fn url_candidate_texts(event: &AgentHookEvent) -> Vec<String> {
    let mut texts = Vec::new();
    if let Some(command) = event
        .tool_input_command
        .as_deref()
        .filter(|command| command_has_network_tool(command))
    {
        texts.push(command.to_string());
    }
    if let Ok(value) = serde_json::from_str::<Value>(&event.raw_json) {
        if let Some(input) = value.get("tool_input") {
            for key in ["url", "uri", "endpoint"] {
                if let Some(text) = input.get(key).and_then(Value::as_str) {
                    texts.push(text.to_string());
                }
            }
            if event.tool_name.as_deref().is_some_and(is_mcp_tool_name) {
                texts.extend(explicit_string_fields(input, &["url", "uri", "endpoint"]));
                texts.extend(
                    mcp_command_texts(input)
                        .into_iter()
                        .filter(|command| command_has_network_tool(command)),
                );
            }
        }
    }
    texts.sort();
    texts.dedup();
    texts
}

pub(crate) fn command_has_network_tool(command: &str) -> bool {
    // Bash pseudo-device redirects open a socket without any named tool.
    if command.contains("/dev/tcp/") || command.contains("/dev/udp/") {
        return true;
    }
    command
        .split([';', '|', '&', '\n'])
        .any(segment_invokes_network_tool)
}

/// Whether one shell segment invokes a network-capable tool. Split out from
/// [`command_has_network_tool`] so `git` can be matched by *subcommand* (only
/// `clone`/`fetch`/`pull`/`push`/… touch the network) rather than treating every
/// `git status`/`git add` as egress, which would over-trigger the shared
/// egress gates.
fn segment_invokes_network_tool(segment: &str) -> bool {
    let Some(program) = segment
        .split_whitespace()
        .find(|token| !is_env_assignment_token(token))
    else {
        return false;
    };
    let name = command_basename(program);
    // Interpreters are matched by prefix so version-suffixed binaries
    // (python3.12, node20, …) are covered consistently with
    // `is_python_interpreter` — otherwise `python3.12 -c <net>` bypasses
    // the URL-rule and egress triggers gated on this check.
    if is_python_interpreter(name) || name.starts_with("node") || name.starts_with("ruby") {
        return true;
    }
    if name == "git" {
        return git_segment_is_network(segment);
    }
    matches!(
        name,
        "curl"
            | "wget"
            | "wget2"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "telnet"
            | "ssh"
            | "scp"
            | "sftp"
            | "rsync"
            | "ftp"
            | "tftp"
            | "lynx"
            | "links"
            | "aria2c"
            | "http"
            | "https"
            | "httpie"
            | "xh"
            | "curlie"
            | "perl"
            | "php"
    )
}

/// Whether a `git` invocation performs network egress, by inspecting its
/// subcommand. Skips leading env assignments and global options (`-c k=v`,
/// `-C <dir>` take a value) to find the real subcommand, so `git -C /repo push`
/// is recognized while `git commit -m fetch` is not.
fn git_segment_is_network(segment: &str) -> bool {
    const NETWORK_SUBCOMMANDS: &[&str] = &[
        "clone",
        "fetch",
        "pull",
        "push",
        "remote",
        "ls-remote",
        "fetch-pack",
        "send-pack",
    ];
    let mut tokens = segment
        .split_whitespace()
        .filter(|token| !is_env_assignment_token(token));
    // Consume the program token (`git` / `/usr/bin/git`).
    let _ = tokens.next();
    let mut expect_value = false;
    for token in tokens {
        if expect_value {
            expect_value = false;
            continue;
        }
        if token == "-C" || token == "-c" {
            expect_value = true;
            continue;
        }
        if token.starts_with('-') {
            continue;
        }
        return NETWORK_SUBCOMMANDS.contains(&token);
    }
    false
}

/// Whether a tool call performs network egress — either a Bash command that
/// invokes a network tool or a raw `/dev/tcp` socket, or a native tool with an
/// explicit `url`/`uri`/`endpoint` field (e.g. `WebFetch`). Shared by the
/// memory and sensitive-read egress triggers so a non-Bash network tool call is
/// not a bypass.
pub(crate) fn event_has_network_egress(event: &AgentHookEvent) -> bool {
    if event
        .tool_input_command
        .as_deref()
        .is_some_and(command_has_network_tool)
    {
        return true;
    }
    if let Ok(value) = serde_json::from_str::<Value>(&event.raw_json) {
        if let Some(input) = value.get("tool_input") {
            if event.tool_name.as_deref().is_some_and(is_mcp_tool_name) {
                return explicit_string_fields(input, &["url", "uri", "endpoint"])
                    .iter()
                    .any(|text| text_has_network_url(text))
                    || mcp_command_texts(input)
                        .iter()
                        .any(|command| command_has_network_tool(command));
            }
            return ["url", "uri", "endpoint"].iter().any(|key| {
                input
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(text_has_network_url)
            });
        }
    }
    false
}

pub(crate) fn is_mcp_tool_name(tool_name: &str) -> bool {
    tool_name.starts_with("mcp__")
}

pub(crate) fn mcp_command_texts(input: &Value) -> Vec<String> {
    let mut commands = explicit_string_fields(
        input,
        &["command", "cmd", "shell_command", "script", "bash"],
    );
    commands.sort();
    commands.dedup();
    commands
}

fn explicit_string_fields(value: &Value, keys: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    collect_explicit_string_fields(value, None, keys, &mut values);
    values
}

fn collect_explicit_string_fields(
    value: &Value,
    key: Option<&str>,
    keys: &[&str],
    values: &mut Vec<String>,
) {
    match value {
        Value::String(text) => {
            if key.is_some_and(|key| {
                let lower = key.to_ascii_lowercase();
                keys.iter().any(|wanted| lower == *wanted)
            }) {
                values.push(text.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_explicit_string_fields(item, key, keys, values);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                collect_explicit_string_fields(value, Some(key), keys, values);
            }
        }
        _ => {}
    }
}

pub(crate) fn text_has_network_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(idx) = rest.find("://") {
        let scheme = rest[..idx]
            .rsplit(|c: char| !is_url_scheme_char(c))
            .next()
            .unwrap_or("");
        let after = &rest[idx + 3..];
        let end = url_authority_end(after);
        let authority = &after[..end];
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if is_network_url_scheme(scheme) && !host.is_empty() {
            return true;
        }
        rest = &after[end..];
    }
    false
}

pub(crate) fn is_url_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

pub(crate) fn is_network_url_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "http" | "https" | "ws" | "wss" | "ftp" | "tftp" | "sftp" | "ssh" | "telnet" | "rsync"
    )
}

pub(crate) fn url_authority_end(after: &str) -> usize {
    after.find(url_authority_end_char).unwrap_or(after.len())
}

pub(crate) fn url_authority_end_char(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '/' | '?' | '#' | '"' | '\'' | '`' | '\\' | ')' | '<' | '>'
        )
}

pub(crate) fn command_basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

pub(crate) fn is_env_assignment_token(token: &str) -> bool {
    match token.find('=') {
        Some(eq) if eq > 0 => token[..eq]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// Parse an agent hook payload, redact secrets, and project it into an
/// `AgentHookEvent`. All structured fields are read from the *redacted* JSON, so
/// nothing secret-bearing is persisted or fed into downstream intent parsing.
pub(crate) fn build_hook_event(payload: &str, provider: &str) -> io::Result<AgentHookEvent> {
    let observed_at_ms = unix_millis()?;

    let Some(value) = serde_json::from_str::<Value>(payload)
        .ok()
        .map(|mut value| {
            redact_value(&mut value);
            value
        })
    else {
        // Unparseable payload: keep only a redacted raw copy, no structured fields.
        return Ok(AgentHookEvent {
            provider: provider.to_string(),
            session_id: env::var("AGENT_SHIELD_SESSION_ID").ok(),
            hook_event_name: None,
            cwd: current_dir_string(),
            transcript_path: None,
            tool_name: None,
            tool_use_id: None,
            tool_input_command: None,
            tool_input_description: None,
            tool_response_stdout: None,
            tool_response_stderr: None,
            tool_response_interrupted: None,
            duration_ms: None,
            permission_mode: None,
            effort_level: None,
            observed_at_ms,
            raw_json: redact_text(payload),
        });
    };

    if provider == PROVIDER_ANTIGRAVITY {
        return build_antigravity_hook_event(value, observed_at_ms);
    }

    let hook_event_name = v_str(&value, "hook_event_name");
    let top_level_permission_command = hook_event_name
        .as_deref()
        .filter(|name| *name == "PermissionRequest")
        .and_then(|_| v_str(&value, "command"));
    let tool_input_command =
        v_nested_str(&value, "tool_input", "command").or(top_level_permission_command);
    let tool_name = v_str(&value, "tool_name").or_else(|| {
        if hook_event_name.as_deref() == Some("PermissionRequest") && tool_input_command.is_some() {
            Some("Bash".to_string())
        } else {
            None
        }
    });

    Ok(AgentHookEvent {
        provider: provider.to_string(),
        session_id: v_str(&value, "session_id")
            .or_else(|| env::var("AGENT_SHIELD_SESSION_ID").ok()),
        hook_event_name,
        cwd: v_str(&value, "cwd").or_else(current_dir_string),
        transcript_path: v_str(&value, "transcript_path"),
        tool_name,
        tool_use_id: v_str(&value, "tool_use_id"),
        tool_input_command,
        tool_input_description: v_nested_str(&value, "tool_input", "description"),
        tool_response_stdout: v_nested_str(&value, "tool_response", "stdout"),
        tool_response_stderr: v_nested_str(&value, "tool_response", "stderr"),
        tool_response_interrupted: value
            .get("tool_response")
            .and_then(|response| response.get("interrupted"))
            .and_then(Value::as_bool),
        duration_ms: find_first(&value, &["duration_ms"]).and_then(Value::as_u64),
        permission_mode: v_str(&value, "permission_mode"),
        effort_level: find_first_str(&value, &["level"]),
        observed_at_ms,
        raw_json: serde_json::to_string(&value).map_err(io::Error::other)?,
    })
}

fn build_antigravity_hook_event(value: Value, observed_at_ms: u64) -> io::Result<AgentHookEvent> {
    let hook_event_name = antigravity_event_name(&value);
    let tool_call = value.get("toolCall");
    let tool_name = tool_call
        .and_then(|tool_call| tool_call.get("name"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let tool_input = tool_call.and_then(|tool_call| tool_call.get("args"));
    let tool_input_command = tool_input
        .and_then(|input| {
            input
                .get("CommandLine")
                .or_else(|| input.get("command"))
                .or_else(|| input.get("commandLine"))
        })
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let cwd = tool_input
        .and_then(|input| input.get("Cwd").or_else(|| input.get("cwd")))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("workspacePaths")
                .and_then(Value::as_array)
                .and_then(|paths| paths.first())
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(current_dir_string);

    Ok(AgentHookEvent {
        provider: PROVIDER_ANTIGRAVITY.to_string(),
        session_id: v_str(&value, "conversationId")
            .or_else(|| v_str(&value, "session_id"))
            .or_else(|| env::var("AGENT_SHIELD_SESSION_ID").ok()),
        hook_event_name,
        cwd,
        transcript_path: v_str(&value, "transcriptPath"),
        tool_name,
        tool_use_id: value
            .get("stepIdx")
            .and_then(Value::as_u64)
            .map(|idx| idx.to_string()),
        tool_input_command,
        tool_input_description: tool_input
            .and_then(|input| {
                input
                    .get("Description")
                    .or_else(|| input.get("description"))
                    .or_else(|| input.get("Instruction"))
            })
            .and_then(Value::as_str)
            .map(ToString::to_string),
        tool_response_stdout: None,
        tool_response_stderr: value
            .get("error")
            .and_then(Value::as_str)
            .filter(|error| !error.is_empty())
            .map(ToString::to_string),
        tool_response_interrupted: None,
        duration_ms: None,
        permission_mode: None,
        effort_level: None,
        observed_at_ms,
        raw_json: serde_json::to_string(&value).map_err(io::Error::other)?,
    })
}

fn antigravity_event_name(value: &Value) -> Option<String> {
    if value.get("toolCall").is_some() {
        return Some("PreToolUse".to_string());
    }
    if value.get("stepIdx").is_some() || value.get("error").is_some() {
        return Some("PostToolUse".to_string());
    }
    if value.get("invocationNum").is_some() {
        return Some("PreInvocation".to_string());
    }
    if value.get("executionNum").is_some() || value.get("terminationReason").is_some() {
        return Some("Stop".to_string());
    }
    v_str(value, "hook_event_name")
}

pub(crate) fn file_intents_from_hook(
    event: &AgentHookEvent,
    original_command: Option<&str>,
) -> Vec<FileIntent> {
    if !matches!(event.tool_name.as_deref(), Some("Bash" | "run_command")) {
        return Vec::new();
    }

    // Parse the original command for accuracy; store the redacted form.
    let Some(command) = original_command else {
        return Vec::new();
    };
    let source_command = event
        .tool_input_command
        .clone()
        .unwrap_or_else(|| redact_text(command));

    let cwd = event.cwd.as_deref().unwrap_or(".");
    parse_bash_file_intents(command, cwd)
        .into_iter()
        .map(|(operation, path)| {
            let sensitive = Policy::global().classify_path(&path).is_some();
            FileIntent {
                provider: "bash-command-parser".to_string(),
                session_id: event.session_id.clone(),
                tool_use_id: event.tool_use_id.clone(),
                observed_at_ms: event.observed_at_ms,
                operation,
                path,
                source_command: source_command.clone(),
                sensitive,
                confidence: "low".to_string(),
            }
        })
        .collect()
}

/// Extract the un-redacted Bash command directly from a hook payload, used only
/// to drive intent parsing (never persisted).
pub(crate) fn original_bash_command(payload: &str) -> Option<String> {
    let value: Value = serde_json::from_str(payload).ok()?;
    if let Some(command) = value
        .get("toolCall")
        .and_then(|tool_call| tool_call.get("args"))
        .and_then(|args| {
            args.get("CommandLine")
                .or_else(|| args.get("command"))
                .or_else(|| args.get("commandLine"))
        })
        .and_then(Value::as_str)
    {
        return Some(command.to_string());
    }
    if v_str(&value, "tool_name").as_deref() == Some("Bash") {
        return v_nested_str(&value, "tool_input", "command");
    }
    if v_str(&value, "hook_event_name").as_deref() == Some("PermissionRequest") {
        return v_str(&value, "command");
    }
    None
}

pub(crate) fn parse_bash_file_intents(command: &str, cwd: &str) -> Vec<(String, String)> {
    let mut intents = Vec::new();
    let command = strip_heredoc_bodies(command);

    for segment in split_shell_segments(&command) {
        let tokens = shell_words(&segment);
        if tokens.is_empty() {
            continue;
        }

        collect_redirection_intents(&tokens, cwd, &mut intents);

        // Skip leading `VAR=value` environment assignments so the real program
        // is recognized (e.g. `AWS_PROFILE=x cat ~/.aws/credentials`).
        let command_tokens = strip_leading_env_assignments(&tokens);
        let Some(program) = command_tokens.first().map(String::as_str) else {
            continue;
        };
        let args = &command_tokens[1..];
        match program {
            "cat" | "less" | "more" | "head" | "tail" | "open" => {
                for path in command_paths(args) {
                    push_file_intent(&mut intents, "read", &path, cwd);
                }
            }
            "rm" | "unlink" => {
                for path in command_paths(args) {
                    push_file_intent(&mut intents, "delete", &path, cwd);
                }
            }
            "mv" => {
                let paths = command_paths(args);
                if let Some(path) = paths.first() {
                    push_file_intent(&mut intents, "rename", path, cwd);
                }
                if let Some(path) = paths.last().filter(|_| paths.len() > 1) {
                    push_file_intent(&mut intents, "create", path, cwd);
                }
            }
            "cp" => {
                let paths = command_paths(args);
                if paths.len() > 1 {
                    let destination = paths.last().expect("paths has at least two entries");
                    let destination_is_dir = is_directory_like_copy_dest(destination);
                    for source in &paths[..paths.len() - 1] {
                        push_file_intent(&mut intents, "copy_source", source, cwd);
                        if destination_is_dir {
                            if let Some(path) = copy_destination_file_path(source, destination) {
                                push_file_intent(&mut intents, "copy_dest", &path, cwd);
                            }
                        }
                    }
                    if !destination_is_dir {
                        push_file_intent(&mut intents, "copy_dest", destination, cwd);
                    }
                }
            }
            "touch" | "mkdir" => {
                for path in command_paths(args) {
                    push_file_intent(&mut intents, "create", &path, cwd);
                }
            }
            "chmod" | "chown" | "chgrp" => {
                for path in command_paths_after_leading_value(args) {
                    push_file_intent(&mut intents, "metadata", &path, cwd);
                }
            }
            "tee" => {
                for path in command_paths(args) {
                    push_file_intent(&mut intents, "write", &path, cwd);
                }
            }
            "sed" => {
                // `sed -i[SUFFIX] ... FILE` edits FILE in place (a write); plain
                // `sed` only streams to stdout. The first non-option operand is
                // the script expression; the rest are the in-place targets.
                if args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
                    let operands: Vec<&str> = args
                        .iter()
                        .map(String::as_str)
                        .filter(|a| !a.starts_with('-'))
                        .collect();
                    for path in operands.iter().skip(1) {
                        push_file_intent(&mut intents, "write", path, cwd);
                    }
                }
            }
            "grep" | "egrep" | "fgrep" | "rg" => {
                // The first operand is the PATTERN (unless `-e/-f` supplied it);
                // the rest are files/dirs the tool reads. `grep root /etc/passwd`
                // and `grep -r key ~/.ssh` both read protected paths that the
                // per-file rule never saw before. Over-inclusion is safe:
                // classify_path only blocks actual secret paths.
                for path in grep_read_paths(args) {
                    push_file_intent(&mut intents, "read", &path, cwd);
                }
            }
            "tar" => {
                // A `tar` *create* reads every input path (recursively for
                // directories). Emit reads for all operands; the archive operand
                // (e.g. `loot.tgz`, `-`) classifies as nothing and is ignored.
                if tar_is_create(args) {
                    for path in command_paths(args) {
                        push_file_intent(&mut intents, "read", &path, cwd);
                    }
                }
            }
            "find" => {
                // `find <roots> ... -exec <reader> ...` reads the files under
                // <roots>. Only treat it as a read when the exec/predicate
                // actually reads content, so a plain `find -name` listing does
                // not over-trigger.
                if find_reads_content(args) {
                    for path in find_roots(args) {
                        push_file_intent(&mut intents, "read", &path, cwd);
                    }
                }
            }
            p if is_python_interpreter(p) => {
                parse_python_intents(args, cwd, &mut intents);
            }
            _ => {}
        }
    }

    dedupe_file_intents(intents)
}

/// File/dir operands a grep-family command reads. The first non-flag operand is
/// the PATTERN unless a `-e/-f/--regexp/--file` flag supplied it; remaining
/// operands are read targets. Short flags that take a value (`-m/-A/-B/-C/-d`)
/// consume the next token so it is not mistaken for a path.
fn grep_read_paths(args: &[String]) -> Vec<String> {
    let mut pattern_from_flag = false;
    let mut operands: Vec<String> = Vec::new();
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        match arg.as_str() {
            "-e" | "-f" | "--regexp" | "--file" => {
                pattern_from_flag = true;
                skip_value = true;
                continue;
            }
            "-m" | "-A" | "-B" | "-C" | "-d" | "--max-count" | "--context" | "--before-context"
            | "--after-context" => {
                skip_value = true;
                continue;
            }
            _ => {}
        }
        if arg.starts_with('-') || is_shell_control_token(arg) {
            continue;
        }
        operands.push(arg.clone());
    }
    if pattern_from_flag {
        operands
    } else {
        operands.into_iter().skip(1).collect()
    }
}

/// Whether a grep-family invocation recurses into directories (`-r`, `-R`,
/// `--recursive`, or a bundled short flag containing `r`/`R`).
fn grep_is_recursive(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--recursive"
            || arg == "--dereference-recursive"
            || (arg.starts_with('-')
                && !arg.starts_with("--")
                && (arg.contains('r') || arg.contains('R')))
    })
}

/// Recursive-search roots for a grep/rg invocation. A recursive search with no
/// explicit path operand defaults to the current directory (`.`), so return `.`
/// in that case — the caller resolves it against the event's cwd, catching
/// `rg AKIA` / `grep -r AKIA` launched from a broad scope like `$HOME`.
fn recursive_search_roots(args: &[String]) -> Vec<String> {
    let paths = grep_read_paths(args);
    if paths.is_empty() {
        vec![".".to_string()]
    } else {
        paths
    }
}

/// Whether a `tar` invocation creates an archive (and therefore reads its
/// inputs), via `--create`, `-c`, or a leading mode bundle containing `c`.
fn tar_is_create(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--create")
        || args.first().is_some_and(|first| {
            let body = first.strip_prefix('-').unwrap_or(first);
            !body.is_empty()
                && body.chars().all(|c| "cxtrudAvjJzZfwphPkmWO".contains(c))
                && body.contains('c')
        })
        || args
            .iter()
            .any(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c'))
}

/// Reader programs whose invocation (incl. as a `find -exec` target) reads file
/// contents.
fn is_content_reader(program: &str) -> bool {
    let name = command_basename(program);
    is_python_interpreter(name)
        || matches!(
            name,
            "cat"
                | "less"
                | "more"
                | "head"
                | "tail"
                | "grep"
                | "egrep"
                | "fgrep"
                | "rg"
                | "cp"
                | "scp"
                | "rsync"
                | "tar"
                | "dd"
                | "xxd"
                | "od"
                | "strings"
                | "base64"
                | "openssl"
                | "gzip"
                | "bzip2"
                | "sh"
                | "bash"
        )
}

/// Whether a `find` invocation reads file contents — via `-exec`/`-execdir`
/// running a reader program, or content predicates like `-fprintf`.
fn find_reads_content(args: &[String]) -> bool {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-exec" || arg == "-execdir" {
            if let Some(program) = iter.peek() {
                if is_content_reader(program) {
                    return true;
                }
            }
        }
    }
    false
}

/// Leading path roots of a `find` command (operands before the first predicate,
/// which begins with `-`). Defaults to `.` when none are given.
fn find_roots(args: &[String]) -> Vec<String> {
    let roots: Vec<String> = args
        .iter()
        .take_while(|arg| !arg.starts_with('-'))
        .filter(|arg| !is_shell_control_token(arg))
        .cloned()
        .collect();
    if roots.is_empty() {
        vec![".".to_string()]
    } else {
        roots
    }
}

/// Raw root tokens of a *recursive* read sweep (recursive grep, tar-create,
/// content-reading find, `cp -r`, `rsync -r/-a`). Returned un-normalized so the
/// broad-scope check can recognize `~` / `$HOME` literals. Used only to flag a
/// recursive sweep rooted at a broad scope (home/system) where the per-path
/// secret rule cannot see the individual files it would traverse.
pub(crate) fn recursive_sweep_roots(command: &str) -> Vec<String> {
    let mut roots = Vec::new();
    let command = strip_heredoc_bodies(command);
    for segment in split_shell_segments(&command) {
        let tokens = shell_words(&segment);
        let command_tokens = strip_leading_env_assignments(&tokens);
        let Some(program) = command_tokens.first().map(String::as_str) else {
            continue;
        };
        let args = &command_tokens[1..];
        match command_basename(program) {
            "grep" | "egrep" | "fgrep" if grep_is_recursive(args) => {
                roots.extend(recursive_search_roots(args));
            }
            // ripgrep recurses into directory operands by default (no -r needed),
            // so every rg search path is a recursive sweep root.
            "rg" => {
                roots.extend(recursive_search_roots(args));
            }
            "tar" if tar_is_create(args) => {
                roots.extend(command_paths(args));
            }
            "find" if find_reads_content(args) => {
                roots.extend(find_roots(args));
            }
            "cp" | "rsync"
                if args.iter().any(|a| {
                    a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('r') || a.contains('a'))
                }) || args.iter().any(|a| a == "--recursive" || a == "--archive") =>
            {
                let paths = command_paths(args);
                // Sources are everything but the final destination.
                if paths.len() > 1 {
                    roots.extend(paths[..paths.len() - 1].iter().cloned());
                }
            }
            _ => {}
        }
    }
    roots
}

/// A Python interpreter invocation (`python`, `python3`, `python3.12`, …),
/// possibly path-qualified (`/usr/bin/python3`).
pub(crate) fn is_python_interpreter(program: &str) -> bool {
    command_basename(program).starts_with("python")
}

/// Extract file/exec intents hidden inside a Python invocation — `python -c
/// "<code>"` (inline) or `python <script.py>` (the script is read and scanned).
/// The intents flow through the SAME sensitive-path / memory / command rules
/// that gate bash, so `open('/etc/passwd')` is blocked, `open('MEMORY.md','a')`
/// hits the memory-write rule, and `open('data.csv')` is an unremarkable read.
/// Deliberately an evadable best-effort floor (no eval/obfuscation handling).
pub(crate) fn parse_python_intents(
    args: &[String],
    cwd: &str,
    intents: &mut Vec<(String, String)>,
) {
    let code = if let Some(idx) = args.iter().position(|a| a == "-c") {
        args.get(idx + 1).cloned()
    } else {
        // First non-flag operand is the script path; read and scan its content.
        args.iter()
            .find(|a| !a.starts_with('-'))
            .and_then(|script| {
                let path = normalize_intent_path(script, cwd);
                read_small_artifact_content(&path)
                    .ok()
                    .flatten()
                    .map(|snap| snap.content)
            })
    };
    let Some(code) = code else {
        return;
    };
    scan_python_code(&code, cwd, intents);
}

/// Max import depth followed from the entry script, and the global budget of
/// local module files read across the whole scan. Bounds the work on the
/// synchronous PreToolUse path.
const PY_IMPORT_MAX_DEPTH: usize = 3;
const PY_IMPORT_MAX_FILES: usize = 20;

fn scan_python_code(code: &str, cwd: &str, intents: &mut Vec<(String, String)>) {
    let mut visited = HashSet::new();
    scan_python_code_inner(code, cwd, intents, 0, &mut visited);
}

/// Scan one Python source for file/exec intents, then follow `import` /
/// `from … import …` into **local** module files (resolved relative to `cwd`)
/// and scan those too. Closes the encapsulated-read gap where
/// `open('~/.ssh/id_rsa')` or an exfil `subprocess` lives one import away —
/// e.g. `from scripts.validator import EnvValidator`. Bounded by depth, a global
/// visited-file budget, and on-disk existence (stdlib/site-packages do not
/// resolve relative to `cwd`, so they are never read).
fn scan_python_code_inner(
    code: &str,
    cwd: &str,
    intents: &mut Vec<(String, String)>,
    depth: usize,
    visited: &mut HashSet<String>,
) {
    // Resolve simple `IDENT = "literal"` bindings so `open(MEMORY_FILE, "w")`
    // (path held in a variable) is gated, not just `open("MEMORY.md", "w")`.
    let vars = python_string_vars(code);
    // open(<path>[, <mode>]) — write/create if the mode contains w/a/x/+, else read.
    let mut rest = code;
    while let Some(pos) = rest.find("open(") {
        let after = &rest[pos + "open(".len()..];
        let call = &after[..after.find(')').unwrap_or(after.len())];
        let (path_expr, mode_expr) = match call.split_once(',') {
            Some((p, m)) => (p, m),
            None => (call, ""),
        };
        if let Some(path) = resolve_python_str(path_expr, &vars) {
            let mode = resolve_python_str(mode_expr, &vars).unwrap_or_default();
            let op = if mode.contains(['w', 'a', 'x', '+']) {
                "write"
            } else {
                "read"
            };
            push_file_intent(intents, op, &path, cwd);
        }
        rest = after;
    }
    // Deletes (path may be a literal or a resolved variable).
    for marker in ["os.remove(", "os.unlink(", "os.rmdir(", "shutil.rmtree("] {
        let mut rest = code;
        while let Some(pos) = rest.find(marker) {
            let after = &rest[pos + marker.len()..];
            let arg = &after[..after.find(')').unwrap_or(after.len())];
            if let Some(path) = resolve_python_str(arg, &vars) {
                push_file_intent(intents, "delete", &path, cwd);
            }
            rest = after;
        }
    }
    // Nested shell execution — recurse into the inner command string so its own
    // intents (rm, curl, cat …) are gated. The extracted substring is strictly
    // shorter, so the mutual recursion with parse_bash_file_intents terminates.
    for marker in [
        "os.system(",
        "os.popen(",
        "subprocess.run(",
        "subprocess.call(",
        "subprocess.Popen(",
        "subprocess.check_output(",
    ] {
        for inner in scan_first_quoted(code, marker) {
            intents.extend(parse_bash_file_intents(&inner, cwd));
        }
    }

    // Follow local imports so an intent hidden in an imported module is gated.
    if depth >= PY_IMPORT_MAX_DEPTH {
        return;
    }
    for spec in python_import_specs(code) {
        if visited.len() >= PY_IMPORT_MAX_FILES {
            break;
        }
        let Some(path) = resolve_local_module(&spec, cwd) else {
            continue;
        };
        if !visited.insert(path.clone()) {
            continue;
        }
        if let Ok(Some(snapshot)) = read_small_artifact_content(&path) {
            // open()/relative paths inside the module resolve against the
            // process cwd in Python, so keep the original `cwd` for recursion.
            scan_python_code_inner(&snapshot.content, cwd, intents, depth + 1, visited);
        }
    }
}

/// Dotted module specs referenced by `import …` / `from … import …` lines,
/// expanded so a `from pkg import sub` submodule is resolvable as `pkg.sub`.
/// Leading dots (relative imports) are stripped to anchor resolution at `cwd`.
fn python_import_specs(code: &str) -> Vec<String> {
    let mut specs = Vec::new();
    for line in code.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("from ") {
            if let Some((module, names)) = rest.split_once(" import ") {
                let package = module.trim().trim_start_matches('.').to_string();
                if !package.is_empty() {
                    specs.push(package.clone());
                }
                let names = names.trim().trim_start_matches('(').trim_end_matches(')');
                for name in names.split(',') {
                    let Some(name) = name.split_whitespace().next() else {
                        continue;
                    };
                    if name.is_empty() || name == "*" {
                        continue;
                    }
                    specs.push(if package.is_empty() {
                        name.to_string()
                    } else {
                        format!("{package}.{name}")
                    });
                }
            }
        } else if let Some(rest) = line.strip_prefix("import ") {
            for part in rest.split(',') {
                if let Some(module) = part.split_whitespace().next() {
                    let module = module.trim_start_matches('.');
                    if !module.is_empty() {
                        specs.push(module.to_string());
                    }
                }
            }
        }
    }
    specs
}

/// Resolve a dotted module spec to an existing local file under `cwd`
/// (`a/b.py` or `a/b/__init__.py`). Returns `None` for modules that do not
/// exist on disk relative to `cwd` — i.e. stdlib/site-packages — so they are
/// never followed.
fn resolve_local_module(spec: &str, cwd: &str) -> Option<String> {
    let relative = spec.replace('.', "/");
    if relative.is_empty() {
        return None;
    }
    for candidate in [format!("{relative}.py"), format!("{relative}/__init__.py")] {
        let path = normalize_intent_path(&candidate, cwd);
        if Path::new(&path).is_file() {
            return Some(path);
        }
    }
    None
}

/// All first-string-literal arguments immediately following each `marker`.
fn scan_first_quoted(code: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(pos) = rest.find(marker) {
        let after = &rest[pos + marker.len()..];
        if let Some((literal, _)) = first_quoted(after) {
            out.push(literal);
        }
        rest = after;
    }
    out
}

/// If `s` (after optional whitespace) begins with a `'`/`"` string literal,
/// return (literal, remainder-after-closing-quote). Returns None for a
/// non-literal first argument (e.g. `open(var)`), so dynamic paths don't
/// produce bogus intents.
fn first_quoted(s: &str) -> Option<(String, &str)> {
    let trimmed = s.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after_quote = &trimmed[quote.len_utf8()..];
    let end = after_quote.find(quote)?;
    Some((
        after_quote[..end].to_string(),
        &after_quote[end + quote.len_utf8()..],
    ))
}

/// Module-level `IDENT = "literal"` string bindings, so a path/mode held in a
/// variable can be resolved. Skips comparisons/augmented assignments.
fn python_string_vars(code: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for line in code.lines() {
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let name = lhs.trim();
        if name.is_empty()
            || rhs.starts_with('=')
            || lhs
                .trim_end()
                .ends_with(['!', '<', '>', '+', '-', '*', '/', '%'])
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        if let Some((literal, _)) = first_quoted(rhs) {
            vars.insert(name.to_string(), literal);
        }
    }
    vars
}

/// Resolve a Python argument expression to a string: a literal, or a simple
/// identifier bound to a string literal earlier in the module.
fn resolve_python_str(expr: &str, vars: &HashMap<String, String>) -> Option<String> {
    if let Some((literal, _)) = first_quoted(expr) {
        return Some(literal);
    }
    let ident: String = expr
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        None
    } else {
        vars.get(&ident).cloned()
    }
}

pub(crate) fn split_shell_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            current.push(character);
            escaped = true;
            continue;
        }
        if character == '\'' || character == '"' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            current.push(character);
            continue;
        }
        if quote.is_none() && matches!(character, ';' | '|' | '&') {
            if !current.trim().is_empty() {
                segments.push(current.trim().to_string());
            }
            current.clear();
            continue;
        }
        current.push(character);
    }

    if !current.trim().is_empty() {
        segments.push(current.trim().to_string());
    }

    segments
}

pub(crate) fn strip_heredoc_bodies(command: &str) -> String {
    let mut output = Vec::new();
    let mut pending_delimiters: Vec<String> = Vec::new();
    let mut lines = command.lines();

    while let Some(line) = lines.next() {
        output.push(line.to_string());
        pending_delimiters.extend(heredoc_delimiters(line));

        while let Some(delimiter) = pending_delimiters.first() {
            let Some(body_line) = lines.next() else {
                pending_delimiters.clear();
                break;
            };
            if body_line.trim() == delimiter {
                pending_delimiters.remove(0);
                if pending_delimiters.is_empty() {
                    break;
                }
            }
        }
    }

    output.join("\n")
}

fn heredoc_delimiters(line: &str) -> Vec<String> {
    let tokens = shell_words(line);
    let mut delimiters = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "<<" {
            if let Some(delimiter) = tokens
                .get(index + 1)
                .and_then(|value| heredoc_delimiter(value))
            {
                delimiters.push(delimiter);
            }
            index += 2;
            continue;
        }
        if let Some(raw) = token.strip_prefix("<<") {
            if let Some(delimiter) = heredoc_delimiter(raw) {
                delimiters.push(delimiter);
            }
        }
        index += 1;
    }
    delimiters
}

fn heredoc_delimiter(raw: &str) -> Option<String> {
    let delimiter = raw.strip_prefix('-').unwrap_or(raw);
    (!delimiter.is_empty()).then(|| delimiter.to_string())
}

pub(crate) fn shell_words(segment: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for character in segment.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == '\'' || character == '"' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if quote.is_none() && character.is_whitespace() {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
            continue;
        }
        if quote.is_none() && matches!(character, '<' | '>') {
            // Start or extend a redirection operator. Flush a preceding word
            // (e.g. `echo` in `echo>f`), but keep consecutive operator chars
            // (`>>`, `<<`) together as a single token.
            if !current.is_empty() && !is_redirection_operator(&current) {
                words.push(current.clone());
                current.clear();
            }
            current.push(character);
            continue;
        }
        // A normal char ends any in-progress redirection operator token.
        if is_redirection_operator(&current) {
            words.push(current.clone());
            current.clear();
        }
        current.push(character);
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
}

pub(crate) fn is_redirection_operator(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|character| matches!(character, '<' | '>'))
}

pub(crate) fn collect_redirection_intents(
    tokens: &[String],
    cwd: &str,
    intents: &mut Vec<(String, String)>,
) {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if matches!(token, ">" | ">>" | "1>" | "1>>" | "2>" | "2>>") {
            if let Some(path) = tokens.get(index + 1) {
                push_file_intent(intents, "write", path, cwd);
            }
            index += 2;
            continue;
        }
        if let Some(path) = token.strip_prefix(">>").or_else(|| token.strip_prefix('>')) {
            if !path.is_empty() {
                push_file_intent(intents, "write", path, cwd);
            }
        }
        index += 1;
    }
}

pub(crate) fn strip_leading_env_assignments(tokens: &[String]) -> &[String] {
    let mut start = 0;
    while start < tokens.len() && is_env_assignment(&tokens[start]) {
        start += 1;
    }
    &tokens[start..]
}

pub(crate) fn is_env_assignment(token: &str) -> bool {
    match token.find('=') {
        Some(eq) if eq > 0 => token[..eq]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        _ => false,
    }
}

pub(crate) fn command_paths(tokens: &[String]) -> Vec<String> {
    command_path_tokens(tokens)
        .filter(|token| !token.starts_with('-') && !is_shell_control_token(token))
        .cloned()
        .collect()
}

pub(crate) fn is_directory_like_copy_dest(path: &str) -> bool {
    path == "." || path == ".." || path.ends_with('/')
}

pub(crate) fn copy_destination_file_path(source: &str, destination: &str) -> Option<String> {
    let name = source
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())?;
    if destination == "." {
        return Some(name.to_string());
    }
    if destination == ".." {
        return Some(format!("../{name}"));
    }
    Some(format!("{}/{name}", destination.trim_end_matches('/')))
}

pub(crate) fn command_paths_after_leading_value(tokens: &[String]) -> Vec<String> {
    let mut seen_value = false;
    let mut paths = Vec::new();

    for token in command_path_tokens(tokens) {
        if token.starts_with('-') {
            continue;
        }
        if !seen_value {
            seen_value = true;
            continue;
        }
        if !is_shell_control_token(token) {
            paths.push(token.clone());
        }
    }

    paths
}

pub(crate) fn command_path_tokens(tokens: &[String]) -> impl Iterator<Item = &String> {
    tokens
        .iter()
        .scan(false, |skip_next, token| {
            if *skip_next {
                *skip_next = false;
                return Some(None);
            }
            if redirection_operator_requires_path(token) {
                *skip_next = true;
                return Some(None);
            }
            if is_compact_redirection(token) {
                return Some(None);
            }
            Some(Some(token))
        })
        .flatten()
}

pub(crate) fn redirection_operator_requires_path(token: &str) -> bool {
    matches!(token, ">" | ">>" | "<" | "<<" | "1>" | "1>>" | "2>" | "2>>")
}

pub(crate) fn is_compact_redirection(token: &str) -> bool {
    [">>", ">", "<<", "<", "1>>", "1>", "2>>", "2>"]
        .iter()
        .any(|operator| token.starts_with(operator) && token.len() > operator.len())
}

pub(crate) fn is_shell_control_token(token: &str) -> bool {
    redirection_operator_requires_path(token)
}

pub(crate) fn push_file_intent(
    intents: &mut Vec<(String, String)>,
    operation: &str,
    raw_path: &str,
    cwd: &str,
) {
    if raw_path.is_empty()
        || (raw_path.starts_with('$')
            && !raw_path.starts_with("$HOME")
            && !raw_path.starts_with("${HOME}"))
    {
        return;
    }

    intents.push((operation.to_string(), normalize_intent_path(raw_path, cwd)));
}

pub(crate) fn normalize_intent_path(raw_path: &str, cwd: &str) -> String {
    normalize_agent_path(raw_path, cwd)
}

pub(crate) fn dedupe_file_intents(intents: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut deduped = Vec::new();
    for intent in intents {
        if !deduped.contains(&intent) {
            deduped.push(intent);
        }
    }
    deduped
}

pub(crate) fn fill_missing(target: &mut Option<String>, candidate: &Option<String>) {
    if target.is_none() {
        *target = candidate.clone();
    }
}
