pub(crate) use gensee_crate_attribution::process_tree::ProcessTree;
pub(crate) use gensee_crate_core::is_vscode_file_tool_name;
pub(crate) use gensee_crate_core::{
    extract_apply_patch_input, normalize_agent_path, parse_apply_patch_changes,
    parse_mcp_file_intents, parse_vscode_file_intents, redact_text, redact_value, AgentHookEvent,
    AgentSession, FileIntent, ProcessObservation, SystemEvent, WorkspaceEffect,
};
pub(crate) use gensee_crate_rules::policy::{self, Policy};
pub(crate) use gensee_crate_store::{
    daemon_socket_path, default_root, AlertRecord, ArtifactObservationInput, ArtifactRiskTagInput,
    ArtifactRiskTagRecord, EventStore, PolicyAlert,
};
pub(crate) use serde_json::{json, Value};
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use std::collections::{BTreeMap, HashMap, HashSet};
pub(crate) use std::env;
pub(crate) use std::ffi::OsString;
#[cfg(target_os = "macos")]
pub(crate) use std::ffi::{c_char, c_void, CStr, CString};
pub(crate) use std::fs;
pub(crate) use std::io::{self, BufRead, Read, Write};
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::process::{Command, Stdio};
pub(crate) use std::sync::mpsc;
pub(crate) use std::thread;
pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const PROCESS_SAMPLE_WINDOW_MS: u64 = 15_000;
pub(crate) const PROCESS_SAMPLE_INTERVAL_MS: u64 = 25;
pub(crate) const STARTED_TOOL_WINDOW_MS: u64 = 15_000;
pub(crate) const TOOL_WINDOW_TOLERANCE_MS: u64 = 250;
pub(crate) const PREEXEC_CONTENT_READ_LIMIT_BYTES: u64 = 64 * 1024;
pub(crate) const ARTIFACT_CONTENT_READ_TIMEOUT_MS: u64 = 150;
pub(crate) const ARTIFACT_FACT_RECENT_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;
pub(crate) const TIMELINE_PROCESS_DISPLAY_LIMIT: usize = 20;
pub(crate) const PROVIDER_CLAUDE_CODE: &str = "claude-code";
pub(crate) const PROVIDER_CODEX: &str = "codex";
pub(crate) const PROVIDER_ANTIGRAVITY: &str = "antigravity";
pub(crate) const PROVIDER_VSCODE: &str = "vscode";
pub(crate) const PROVIDER_CURSOR: &str = "cursor";

pub(crate) fn is_supported_provider(provider: &str) -> bool {
    matches!(
        provider,
        PROVIDER_CLAUDE_CODE
            | PROVIDER_CODEX
            | PROVIDER_ANTIGRAVITY
            | PROVIDER_VSCODE
            | PROVIDER_CURSOR
    )
}

mod policy_eval;
pub(crate) use policy_eval::*;
mod preexec;
pub(crate) use preexec::*;
mod command_parse;
pub(crate) use command_parse::*;
mod resource_governance;
pub(crate) use resource_governance::*;
mod run;
pub(crate) use run::*;
mod tclone;
pub(crate) use tclone::*;
mod watch;
pub(crate) use watch::*;
mod timeline;
pub(crate) use timeline::*;
mod daemon;
pub(crate) use daemon::*;
mod telemetry;
pub(crate) use telemetry::*;

#[cfg(feature = "bench")]
mod bench;

#[cfg(test)]
mod tests;

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("gensee: {error}");
        std::process::exit(1);
    }
}

pub(crate) fn run_cli() -> io::Result<()> {
    let mut args = env::args_os().skip(1).collect::<Vec<_>>();
    let command = args
        .first()
        .and_then(|arg| arg.to_str())
        .map(ToString::to_string);
    if let Some(command_name) = command
        .as_deref()
        .filter(|name| should_bootstrap_telemetry_for_command(name))
    {
        telemetry_bootstrap_for_command(command_name);
    }
    if proxy_tclone_host_control_if_needed(&args)? {
        return Ok(());
    }

    match command.as_deref() {
        Some("__linux-exec") => {
            args.remove(0);
            linux_exec_wrapper(args)
        }
        Some("run") => {
            args.remove(0);
            if args.first().and_then(|arg| arg.to_str()) == Some("list") {
                args.remove(0);
                return list_runs();
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("fork") {
                args.remove(0);
                return tclone_fork(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("shell") {
                args.remove(0);
                return tclone_shell(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("attach") {
                args.remove(0);
                return tclone_attach(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("send") {
                args.remove(0);
                return tclone_send(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("exec") {
                args.remove(0);
                return tclone_run_exec(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("diff") {
                args.remove(0);
                return tclone_diff(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("merge") {
                args.remove(0);
                return tclone_merge(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("switch") {
                args.remove(0);
                return tclone_switch(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("keep") {
                args.remove(0);
                return tclone_keep(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("delete") {
                args.remove(0);
                return tclone_delete(args);
            }
            if args.first().and_then(|arg| arg.to_str()) == Some("discard") {
                args.remove(0);
                return discard_run(args);
            }
            run_agent(RunConfig::parse(args)?)
        }
        Some("fork") => {
            args.remove(0);
            tclone_fork(args)
        }
        Some("watch") => {
            args.remove(0);
            watch_workspace(WatchConfig::parse(args)?)
        }
        Some("debug") => {
            args.remove(0);
            handle_debug(args)
        }
        Some("session") => {
            args.remove(0);
            match args.first().and_then(|arg| arg.to_str()) {
                Some("list") => list_runs(),
                _ => {
                    print_usage();
                    Ok(())
                }
            }
        }
        Some("timeline") => {
            args.remove(0);
            show_timeline(args)
        }
        Some("hook") => {
            args.remove(0);
            handle_hook(args)
        }
        Some("setup") => {
            args.remove(0);
            handle_setup(args)
        }
        Some("daemon") => {
            args.remove(0);
            run_daemon()
        }
        Some("verify-log") => {
            args.remove(0);
            verify_log()
        }
        Some("policy") => {
            args.remove(0);
            handle_policy(args)
        }
        Some("linux") => {
            args.remove(0);
            handle_linux(args)
        }
        Some(command) if is_linux_top_level_command(command) => {
            args.remove(0);
            handle_linux_top_level(command, args)
        }
        Some("feedback") => {
            args.remove(0);
            handle_feedback(args)
        }
        Some("gateway-alert") => {
            args.remove(0);
            handle_gateway_alert(args)
        }
        Some("dashboard-state") => {
            args.remove(0);
            dashboard_state()
        }
        Some("telemetry") => {
            args.remove(0);
            handle_telemetry(args)
        }
        Some("ingest") => {
            args.remove(0);
            handle_ingest(args)
        }
        Some("observe-tool-window") => {
            args.remove(0);
            observe_tool_window(args)
        }
        #[cfg(feature = "bench")]
        Some("bench") => {
            args.remove(0);
            bench::run_bench(args)
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command: {other}"),
        )),
    }
}

fn should_bootstrap_telemetry_for_command(command: &str) -> bool {
    command != "linux"
        && command != "debug"
        && command != "__linux-exec"
        && !is_linux_top_level_command(command)
}

fn is_linux_top_level_command(command: &str) -> bool {
    matches!(command, "status")
}

fn handle_linux_top_level(command: &str, args: Vec<OsString>) -> io::Result<()> {
    if std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "gensee {command} is currently supported on Linux, not {}",
                std::env::consts::OS
            ),
        ));
    }

    let mut linux_args = Vec::with_capacity(args.len() + 1);
    linux_args.push(OsString::from(command));
    linux_args.extend(args);
    handle_linux(linux_args)
}

fn handle_debug(args: Vec<OsString>) -> io::Result<()> {
    let subcommand = args
        .iter()
        .filter_map(|arg| arg.to_str())
        .find(|arg| !arg.starts_with('-'))
        .unwrap_or("--help");
    match subcommand {
        "plan" | "fanotify-plan" | "fanotify-once" | "seccomp-profile" | "network-plan"
        | "network-apply" => handle_linux(args),
        "--help" | "-h" => {
            println!(
                "usage: gensee debug [plan|fanotify-plan|fanotify-once|seccomp-profile|network-plan|network-apply] [--json]\n       gensee debug network-plan --session-id <id> [--pid <pid>] [--allow <ip-or-cidr>]... [--deny <ip-or-cidr>]... [--json]\n       sudo gensee debug network-apply --session-id <id> --pid <pid> [--allow <ip-or-cidr>]... [--deny <ip-or-cidr>]..."
            );
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown debug command: {other}"),
        )),
    }
}

pub(crate) fn handle_linux(args: Vec<OsString>) -> io::Result<()> {
    let json_output = has_arg(&args, "--json");
    let subcommand = args
        .iter()
        .filter_map(|arg| arg.to_str())
        .find(|arg| !arg.starts_with('-'))
        .unwrap_or("status");
    if !matches!(subcommand, "--help" | "-h") && std::env::consts::OS != "linux" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "gensee {subcommand} is currently supported on Linux, not {}",
                std::env::consts::OS
            ),
        ));
    }

    match subcommand {
        "status" => {
            let report = gensee_crate_linux::LinuxCapabilityReport::detect();
            if json_output {
                print_json(&report)
            } else {
                println!("Linux capability status");
                print_bool("AppArmor enabled", report.apparmor_enabled);
                print_bool("SELinux enabled", report.selinux_enabled);
                print_bool("Landlock available", report.landlock_available);
                print_bool("bpffs mounted", report.bpf_fs_mounted);
                print_bool("BPF LSM enabled", report.bpf_lsm_enabled);
                print_bool("cgroup v2 mounted", report.cgroup_v2_mounted);
                print_bool("fanotify available", report.fanotify_available);
                print_bool("seccomp filter available", report.seccomp_filter_available);
                print_bool("nft available", report.nft_available);
                print_bool("running as root", report.running_as_root);
                println!("speculation backends:");
                if report.speculation_backends.is_empty() {
                    println!("  - none");
                } else {
                    for backend in report.speculation_backends {
                        println!("  - {backend:?}");
                    }
                }
                Ok(())
            }
        }
        "plan" => {
            let capabilities = gensee_crate_linux::LinuxCapabilityReport::detect();
            let policy = linux_policy_from_policy_document(Policy::global().document());
            let plan = policy.plan(&capabilities);
            if json_output {
                print_json(&plan)
            } else {
                println!("Linux enforcement plan");
                println!("mode: {:?}", plan.mode);
                println!("components:");
                for component in plan.components {
                    println!("  - {component:?}");
                }
                if !plan.warnings.is_empty() {
                    println!("warnings:");
                    for warning in plan.warnings {
                        println!("  - {warning}");
                    }
                }
                println!("speculation:");
                println!("  requested: {}", plan.speculation.requested);
                println!("  available: {}", plan.speculation.available);
                match plan.speculation.selected_backend {
                    Some(backend) => println!("  selected backend: {backend:?}"),
                    None => println!("  selected backend: none"),
                }
                println!("  available backends:");
                if plan.speculation.available_backends.is_empty() {
                    println!("    - none");
                } else {
                    for backend in plan.speculation.available_backends {
                        println!("    - {backend:?}");
                    }
                }
                Ok(())
            }
        }
        "monitor" => {
            let pid = linux_arg_value(&args, "--pid")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "usage: gensee monitor --pid <pid> [--session-id <id>] [--json]",
                    )
                })?
                .parse::<u32>()
                .map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid --pid: {err}"))
                })?;
            let session_id =
                linux_arg_value(&args, "--session-id").unwrap_or_else(|| format!("linux-{pid}"));
            let session = gensee_crate_linux::LinuxSessionTarget::from_pid(session_id, pid)?;
            let mut monitor = gensee_crate_linux::LinuxAuditMonitor::with_config(
                gensee_crate_linux::LinuxMonitorConfig {
                    session: Some(session),
                    enable_exec_events: true,
                    enable_file_events: false,
                    enable_network_events: false,
                },
            );
            let events = monitor.poll_events()?;
            if json_output {
                print_json(&events)
            } else {
                println!("Linux process monitor events");
                for event in events {
                    println!(
                        "pid={} ppid={} process={} command={}",
                        option_u32_display(event.pid),
                        option_u32_display(event.ppid),
                        event.process_name.as_deref().unwrap_or("unknown"),
                        event.command_line.as_deref().unwrap_or("")
                    );
                }
                Ok(())
            }
        }
        "fanotify-plan" => {
            let policy = linux_fanotify_policy_from_policy_document(Policy::global().document());
            let plan = gensee_crate_linux::plan_fanotify_marks(&policy);
            if json_output {
                print_json(&plan)
            } else {
                println!("Linux fanotify mark plan");
                println!("marks:");
                for mark in plan.marks {
                    println!(
                        "  - {}{}",
                        mark.path,
                        if mark.include_children { "/**" } else { "" }
                    );
                }
                if !plan.warnings.is_empty() {
                    println!("warnings:");
                    for warning in plan.warnings {
                        println!("  - {warning}");
                    }
                }
                Ok(())
            }
        }
        "fanotify-once" => {
            let policy = linux_fanotify_policy_from_policy_document(Policy::global().document());
            let mut enforcer = gensee_crate_linux::LinuxFanotifyEnforcer::new(
                gensee_crate_linux::LinuxFanotifyConfig::new(policy),
            )?;
            let status = enforcer.status();
            let events = enforcer.handle_events_once()?;
            if json_output {
                print_json(&json!({
                    "status": status,
                    "events": events,
                }))
            } else {
                println!("Linux fanotify enforcement");
                println!("enforcing: {}", status.enforcing);
                println!("marked paths:");
                for path in status.marked_paths {
                    println!("  - {path}");
                }
                if !status.warnings.is_empty() {
                    println!("warnings:");
                    for warning in status.warnings {
                        println!("  - {warning}");
                    }
                }
                println!("events handled: {}", events.len());
                Ok(())
            }
        }
        "seccomp-profile" => {
            let profile = gensee_crate_linux::LinuxSeccompProfile::from_policy(
                &linux_dangerous_syscall_policy(&Policy::global().document().linux.seccomp),
            );
            if json_output {
                print_json(&profile)
            } else {
                println!("Linux seccomp launcher profile");
                println!("default action: {:?}", profile.default_action);
                println!("denied syscalls:");
                for syscall in profile.denied_syscalls {
                    println!(
                        "  - {} [{:?}] - {}",
                        syscall.name, syscall.group, syscall.reason
                    );
                }
                Ok(())
            }
        }
        "exec-seccomp" => linux_exec_seccomp(args),
        "network-plan" => {
            let config = linux_network_config(&args)?;
            let plan = gensee_crate_linux::plan_nftables_policy(&config);
            if json_output {
                print_json(&plan)
            } else {
                print_linux_network_plan(&plan);
                Ok(())
            }
        }
        "network-apply" => {
            let config = linux_network_config(&args)?;
            let plan = gensee_crate_linux::plan_nftables_policy(&config);
            gensee_crate_linux::validate_nftables_plan_for_apply(&plan.nftables)?;
            if let Some(pid) = config.root_pid {
                let attached = gensee_crate_linux::attach_process_tree_to_cgroup(
                    pid,
                    Path::new(&config.cgroup_path),
                )
                .map_err(linux_network_debug_privilege_error("attach process tree to cgroup"))?;
                println!(
                    "gensee: attached {} process(es) to {}",
                    attached.len(),
                    config.cgroup_path
                );
            }
            gensee_crate_linux::apply_nftables_script(&plan.nftables.script)
                .map_err(linux_network_debug_privilege_error("apply nftables policy"))?;
            if json_output {
                print_json(&plan)
            } else {
                print_linux_network_plan(&plan);
                Ok(())
            }
        }
        "--help" | "-h" => {
            println!("usage: gensee status [--json]\n       gensee watch --pid <pid> [--session-id <id>] [--linux-fanotify] [--duration-seconds <seconds>] [--interval-ms <ms>]\n       gensee debug [plan|fanotify-plan|fanotify-once|seccomp-profile|network-plan|network-apply] [--json]\n\ncompatibility alias: gensee linux ...");
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: gensee status|plan|monitor|fanotify-plan|fanotify-once|seccomp-profile|network-plan|network-apply [--json] (unknown: {other})"),
        )),
    }
}

fn linux_network_debug_privilege_error(
    operation: &'static str,
) -> impl FnOnce(io::Error) -> io::Error {
    move |error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                error.kind(),
                format!(
                    "Linux network debug apply could not {operation}: {error}. cgroup/nftables enforcement requires root; retry with sudo",
                ),
            )
        } else {
            error
        }
    }
}

fn linux_network_config(
    args: &[OsString],
) -> io::Result<gensee_crate_linux::LinuxNetworkEnforcementConfig> {
    let session_id = linux_arg_value(args, "--session-id").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee network-plan --session-id <id> [--pid <pid>] [--allow <ip-or-cidr>]... [--deny <ip-or-cidr>]... [--deny-all]",
        )
    })?;
    let policy_doc = Policy::global().document();
    let allowed_overrides = linux_arg_values(args, "--allow");
    let denied_overrides = linux_arg_values(args, "--deny");
    let has_allowed_overrides = !allowed_overrides.is_empty();
    let allowed_hosts = if has_allowed_overrides {
        allowed_overrides
    } else {
        policy_doc.linux.network.allow.clone()
    };
    let denied_hosts = if denied_overrides.is_empty() {
        policy_doc.linux.network.deny.clone()
    } else {
        denied_overrides
    };
    let mode =
        if has_allowed_overrides && !has_arg(args, "--deny-all") && !has_arg(args, "--monitor") {
            gensee_crate_linux::LinuxNetworkMode::AllowListed
        } else if has_arg(args, "--monitor") {
            gensee_crate_linux::LinuxNetworkMode::Monitor
        } else if has_arg(args, "--deny-all") {
            gensee_crate_linux::LinuxNetworkMode::DenyAll
        } else {
            linux_network_mode_from_policy(policy_doc.linux.network.mode)
        };
    let mode = crate::run::linux_effective_network_mode(mode, !denied_hosts.is_empty());
    if mode == gensee_crate_linux::LinuxNetworkMode::AllowListed && allowed_hosts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux network allowlist mode requires policy linux.network.allow or --allow-net",
        ));
    }
    let root_pid = linux_arg_value(args, "--pid")
        .map(|value| {
            value.parse::<u32>().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid --pid: {err}"))
            })
        })
        .transpose()?;
    let mut config = gensee_crate_linux::LinuxNetworkEnforcementConfig::new(
        session_id,
        gensee_crate_linux::LinuxNetworkPolicy {
            mode,
            allowed_hosts,
            denied_hosts,
        },
    );
    config.root_pid = root_pid;
    if let Some(cgroup_path) = linux_arg_value(args, "--cgroup-path") {
        config.cgroup_path = cgroup_path;
    }
    Ok(config)
}

fn print_linux_network_plan(plan: &gensee_crate_linux::LinuxNetworkEnforcementPlan) {
    println!("Linux cgroup/nftables network plan");
    println!("cgroup: {}", plan.cgroup.cgroup_path);
    if let Some(pid) = plan.cgroup.root_pid {
        println!("root pid: {pid}");
        println!("processes: {}", plan.cgroup.process_ids.len());
    }
    println!("table: {}", plan.nftables.table_name);
    println!("chain: {}", plan.nftables.chain_name);
    println!("mode: {:?}", plan.nftables.mode);
    println!("allowed destinations:");
    if plan.nftables.destinations.is_empty() {
        println!("  - none");
    } else {
        for destination in &plan.nftables.destinations {
            println!("  - {} [{:?}]", destination.value, destination.family);
        }
    }
    println!("denied destinations:");
    if plan.nftables.denied_destinations.is_empty() {
        println!("  - none");
    } else {
        for destination in &plan.nftables.denied_destinations {
            println!("  - {} [{:?}]", destination.value, destination.family);
        }
    }
    if !plan.warnings.is_empty() {
        println!("warnings:");
        for warning in &plan.warnings {
            println!("  - {warning}");
        }
    }
    println!("nftables script:\n{}", plan.nftables.script);
}

fn linux_exec_seccomp(args: Vec<OsString>) -> io::Result<()> {
    let command_args = linux_args_after_double_dash(&args).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee linux exec-seccomp -- <agent> [args...]",
        )
    })?;
    let (program, program_args) = command_args.split_first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee linux exec-seccomp -- <agent> [args...]",
        )
    })?;
    let profile = gensee_crate_linux::LinuxSeccompProfile::from_policy(
        &linux_dangerous_syscall_policy(&Policy::global().document().linux.seccomp),
    );
    linux_spawn_seccomp(program, program_args, profile)
}

fn linux_exec_wrapper(args: Vec<OsString>) -> io::Result<()> {
    let command_args = linux_args_after_double_dash(&args).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee __linux-exec [--cgroup-path <path>] [--seccomp-profile-json <json>] -- <agent> [args...]",
        )
    })?;
    let (program, program_args) = command_args.split_first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee __linux-exec [--cgroup-path <path>] [--seccomp-profile-json <json>] -- <agent> [args...]",
        )
    })?;
    let cgroup_path = linux_arg_value(&args, "--cgroup-path");
    let seccomp_profile = linux_arg_value(&args, "--seccomp-profile-json")
        .map(|value| {
            serde_json::from_str::<gensee_crate_linux::LinuxSeccompProfile>(&value).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid --seccomp-profile-json: {err}"),
                )
            })
        })
        .transpose()?;
    linux_exec_agent(
        program,
        program_args,
        cgroup_path.as_deref(),
        seccomp_profile,
    )
}

fn linux_args_after_double_dash(args: &[OsString]) -> Option<Vec<OsString>> {
    args.iter()
        .position(|arg| arg.to_str() == Some("--"))
        .map(|index| args[index + 1..].to_vec())
}

#[cfg(target_os = "linux")]
fn linux_spawn_seccomp(
    program: &OsString,
    program_args: &[OsString],
    profile: gensee_crate_linux::LinuxSeccompProfile,
) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command.args(program_args);
    unsafe {
        command.pre_exec(move || gensee_crate_linux::install_seccomp_filter(&profile));
    }
    let status = command.status()?;
    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(1),
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_spawn_seccomp(
    _program: &OsString,
    _program_args: &[OsString],
    _profile: gensee_crate_linux::LinuxSeccompProfile,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seccomp launcher profiles are only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn linux_exec_agent(
    program: &OsString,
    program_args: &[OsString],
    cgroup_path: Option<&str>,
    seccomp_profile: Option<gensee_crate_linux::LinuxSeccompProfile>,
) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    if let Some(cgroup_path) = cgroup_path {
        gensee_crate_linux::attach_current_process_to_cgroup(Path::new(cgroup_path))?;
    }
    if let Some(profile) = seccomp_profile.as_ref() {
        gensee_crate_linux::install_seccomp_filter(profile)?;
    }

    let error = Command::new(program).args(program_args).exec();
    Err(error)
}

#[cfg(not(target_os = "linux"))]
fn linux_exec_agent(
    _program: &OsString,
    _program_args: &[OsString],
    _cgroup_path: Option<&str>,
    _seccomp_profile: Option<gensee_crate_linux::LinuxSeccompProfile>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux run wrappers are only available on Linux",
    ))
}

fn linux_arg_value(args: &[OsString], name: &str) -> Option<String> {
    args.windows(2).find_map(|window| {
        if window[0].to_str() == Some(name) {
            window[1].to_str().map(ToString::to_string)
        } else {
            None
        }
    })
}

fn linux_arg_values(args: &[OsString], name: &str) -> Vec<String> {
    args.windows(2)
        .filter_map(|window| {
            if window[0].to_str() == Some(name) {
                window[1].to_str().map(ToString::to_string)
            } else {
                None
            }
        })
        .collect()
}

fn print_json<T: serde::Serialize>(value: &T) -> io::Result<()> {
    let serialized = serde_json::to_string_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    println!("{serialized}");
    Ok(())
}

fn print_bool(label: &str, value: bool) {
    println!("{label}: {}", if value { "yes" } else { "no" });
}

pub(crate) fn handle_hook(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("claude-code") => handle_agent_hook(PROVIDER_CLAUDE_CODE),
        Some("codex") => handle_agent_hook(PROVIDER_CODEX),
        Some("antigravity") => handle_agent_hook(PROVIDER_ANTIGRAVITY),
        Some("vscode") => handle_agent_hook(PROVIDER_VSCODE),
        Some("cursor") => handle_agent_hook(PROVIDER_CURSOR),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee hook <claude-code|codex|antigravity|vscode|cursor>",
        )),
    }
}

pub(crate) fn handle_setup(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("claude-code") => setup_claude_code(args[1..].to_vec()),
        Some("codex") => setup_codex(args[1..].to_vec()),
        Some("antigravity") => setup_antigravity(args[1..].to_vec()),
        Some("vscode") => setup_vscode(args[1..].to_vec()),
        Some("cursor") => setup_cursor(args[1..].to_vec()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee setup <claude-code|codex|antigravity|vscode|cursor> [--gensee-home <path>] [--settings <path>|--hooks <path>] [--bin <path>]",
        )),
    }
}

fn setup_claude_code(args: Vec<OsString>) -> io::Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let mut settings_path = home.join(".claude").join("settings.json");
    let mut gensee_home = env::var_os("GENSEE_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_root()?);
    let mut bin_path = env::current_exe()?;
    let mut gateway = ClaudeCodeGatewaySettings::default();

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "setup: non-UTF8 argument")
        })?;
        match arg {
            "--yes" => {
                index += 1;
            }
            "--gensee-home" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --gensee-home requires a path",
                    )
                })?;
                gensee_home = PathBuf::from(value);
                index += 2;
            }
            "--settings" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --settings requires a path",
                    )
                })?;
                settings_path = PathBuf::from(value);
                index += 2;
            }
            "--bin" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "setup: --bin requires a path")
                })?;
                bin_path = PathBuf::from(value);
                index += 2;
            }
            "--anthropic-base-url" | "--gateway-url" => {
                gateway.base_url = Some(required_next_arg(&args, index, arg)?);
                index += 2;
            }
            "--anthropic-auth-token" | "--gateway-auth-token" => {
                gateway.auth_token = Some(required_next_arg(&args, index, arg)?);
                index += 2;
            }
            "--anthropic-api-key" | "--gateway-api-key" => {
                gateway.api_key = Some(required_next_arg(&args, index, arg)?);
                index += 2;
            }
            "--anthropic-custom-headers" => {
                gateway.custom_headers = Some(required_next_arg(&args, index, arg)?);
                index += 2;
            }
            "--api-key-helper" => {
                gateway.api_key_helper = Some(required_next_arg(&args, index, arg)?);
                index += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: gensee setup claude-code [--gensee-home <path>] [--settings <path>] [--bin <path>] [--anthropic-base-url <url>] [--anthropic-auth-token <token>|--anthropic-api-key <key>|--api-key-helper <command>]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("setup: unknown argument `{arg}`"),
                ));
            }
        }
    }
    gateway.validate()?;

    gensee_home = absolutize_for_hook(&gensee_home)?;
    bin_path = absolutize_for_hook(&bin_path)?;
    let command = claude_code_hook_command(&gensee_home, &bin_path);
    let hooks_disabled = write_claude_code_settings(&settings_path, &command, &gateway)?;

    println!(
        "gensee setup: configured Claude Code hooks in {}",
        settings_path.display()
    );
    if !gateway.is_empty() {
        println!("gensee setup: configured Claude Code gateway routing.");
    }
    if let Some(warning) = claude_code_disabled_hooks_warning(hooks_disabled) {
        eprintln!("{warning}");
    }
    println!("gensee setup: hook command: {command}");
    println!("gensee setup: fully restart Claude Code before testing enforcement.");
    Ok(())
}

const CLAUDE_CODE_DISABLED_HOOKS_WARNING: &str = "gensee setup: warning: Claude Code disableAllHooks is true; Gensee hooks are installed but will not run until it is set to false.";

fn claude_code_disabled_hooks_warning(hooks_disabled: bool) -> Option<&'static str> {
    hooks_disabled.then_some(CLAUDE_CODE_DISABLED_HOOKS_WARNING)
}

fn setup_codex(args: Vec<OsString>) -> io::Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let mut hooks_path = home.join(".codex").join("hooks.json");
    let mut gensee_home = env::var_os("GENSEE_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_root()?);
    let mut bin_path = env::current_exe()?;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "setup: non-UTF8 argument")
        })?;
        match arg {
            "--yes" => {
                index += 1;
            }
            "--gensee-home" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --gensee-home requires a path",
                    )
                })?;
                gensee_home = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --hooks requires a path",
                    )
                })?;
                hooks_path = PathBuf::from(value);
                index += 2;
            }
            "--bin" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "setup: --bin requires a path")
                })?;
                bin_path = PathBuf::from(value);
                index += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: gensee setup codex [--gensee-home <path>] [--hooks <path>] [--bin <path>]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("setup: unknown argument `{arg}`"),
                ));
            }
        }
    }

    gensee_home = absolutize_for_hook(&gensee_home)?;
    bin_path = absolutize_for_hook(&bin_path)?;
    let command = codex_hook_command(&gensee_home, &bin_path);
    write_codex_hook_settings(&hooks_path, &command)?;

    println!(
        "gensee setup: configured Codex hooks in {}",
        hooks_path.display()
    );
    println!("gensee setup: hook command: {command}");
    println!("gensee setup: open /hooks in Codex to review and trust this hook command.");
    println!("gensee setup: re-trust the hook whenever the command or binary path changes.");
    Ok(())
}

fn setup_antigravity(args: Vec<OsString>) -> io::Result<()> {
    let mut hooks_path = default_antigravity_hooks_path()?;
    let mut gensee_home = env::var_os("GENSEE_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_root()?);
    let mut bin_path = env::current_exe()?;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "setup: non-UTF8 argument")
        })?;
        match arg {
            "--yes" => {
                index += 1;
            }
            "--gensee-home" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --gensee-home requires a path",
                    )
                })?;
                gensee_home = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --hooks requires a path",
                    )
                })?;
                hooks_path = PathBuf::from(value);
                index += 2;
            }
            "--bin" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "setup: --bin requires a path")
                })?;
                bin_path = PathBuf::from(value);
                index += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: gensee setup antigravity [--gensee-home <path>] [--hooks <path>] [--bin <path>]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("setup: unknown argument `{arg}`"),
                ));
            }
        }
    }

    gensee_home = absolutize_for_hook(&gensee_home)?;
    bin_path = absolutize_for_hook(&bin_path)?;
    let command = antigravity_hook_command(&gensee_home, &bin_path);
    write_antigravity_hook_settings(&hooks_path, &command)?;

    println!(
        "gensee setup: configured Antigravity hooks in {}",
        hooks_path.display()
    );
    println!("gensee setup: hook command: {command}");
    println!("gensee setup: restart Antigravity before testing enforcement.");
    Ok(())
}

fn default_antigravity_hooks_path() -> io::Result<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(home.join(".gemini").join("config").join("hooks.json"))
}

fn default_vscode_hooks_path() -> io::Result<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    // VS Code loads all *.json files from ~/.copilot/hooks/; use a dedicated
    // gensee.json so unrelated hook files in that directory are not touched.
    Ok(home.join(".copilot").join("hooks").join("gensee.json"))
}

fn setup_vscode(args: Vec<OsString>) -> io::Result<()> {
    let mut hooks_path = default_vscode_hooks_path()?;
    let mut gensee_home = env::var_os("GENSEE_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_root()?);
    let mut bin_path = env::current_exe()?;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "setup: non-UTF8 argument")
        })?;
        match arg {
            "--yes" => {
                index += 1;
            }
            "--gensee-home" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --gensee-home requires a path",
                    )
                })?;
                gensee_home = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --hooks requires a path",
                    )
                })?;
                hooks_path = PathBuf::from(value);
                index += 2;
            }
            "--bin" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "setup: --bin requires a path")
                })?;
                bin_path = PathBuf::from(value);
                index += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: gensee setup vscode [--gensee-home <path>] [--hooks <path>] [--bin <path>]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("setup: unknown argument `{arg}`"),
                ));
            }
        }
    }

    gensee_home = absolutize_for_hook(&gensee_home)?;
    bin_path = absolutize_for_hook(&bin_path)?;
    let command = vscode_hook_command(&gensee_home, &bin_path);
    write_vscode_hook_settings(&hooks_path, &command)?;

    println!(
        "gensee setup: configured VS Code hooks in {}",
        hooks_path.display()
    );
    println!("gensee setup: hook command: {command}");
    println!("gensee setup: VS Code reloads hook files automatically on save.");
    Ok(())
}

fn write_vscode_hook_settings(hooks_path: &Path, command: &str) -> io::Result<()> {
    let (existing_contents, mut root) = read_json_config(hooks_path)?;
    apply_vscode_hook_settings(&mut root, command)?;
    write_json_config_if_changed(hooks_path, existing_contents.as_deref(), &root, "hooks")?;
    Ok(())
}

pub(crate) fn apply_vscode_hook_settings(root: &mut Value, command: &str) -> io::Result<()> {
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "VS Code hooks must be a JSON object",
        )
    })?;
    let hooks = root_object
        .entry("hooks".to_string())
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VS Code hooks field must be a JSON object",
        ));
    }
    let hooks_object = hooks.as_object_mut().expect("hooks is an object");
    // VS Code hooks use a flat entry format: each hook is directly
    // { "type": "command", "command": "..." } without the nested matcher/hooks
    // arrays used by Claude Code.  VS Code also reads Claude Code's nested
    // format, but the flat form is the idiomatic VS Code style.
    let hook_entry = json!({
        "type": "command",
        "command": command,
        "timeout": 30
    });
    for event_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"] {
        merge_flat_hook_event(
            hooks_object,
            event_name,
            PROVIDER_VSCODE,
            hook_entry.clone(),
            "VS Code",
        )?;
    }
    Ok(())
}

fn vscode_hook_command(gensee_home: &Path, bin_path: &Path) -> String {
    format!(
        "GENSEE_HOME={} {} hook vscode",
        shell_quote(&gensee_home.display().to_string()),
        shell_quote(&bin_path.display().to_string())
    )
}

fn setup_cursor(args: Vec<OsString>) -> io::Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let mut hooks_path = home.join(".cursor").join("hooks.json");
    let mut gensee_home = env::var_os("GENSEE_HOME")
        .map(PathBuf::from)
        .unwrap_or(default_root()?);
    let mut bin_path = env::current_exe()?;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "setup: non-UTF8 argument")
        })?;
        match arg {
            "--yes" => {
                index += 1;
            }
            "--gensee-home" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --gensee-home requires a path",
                    )
                })?;
                gensee_home = PathBuf::from(value);
                index += 2;
            }
            "--hooks" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "setup: --hooks requires a path",
                    )
                })?;
                hooks_path = PathBuf::from(value);
                index += 2;
            }
            "--bin" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "setup: --bin requires a path")
                })?;
                bin_path = PathBuf::from(value);
                index += 2;
            }
            "--help" | "-h" => {
                println!(
                    "usage: gensee setup cursor [--gensee-home <path>] [--hooks <path>] [--bin <path>]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("setup: unknown argument `{arg}`"),
                ));
            }
        }
    }

    gensee_home = absolutize_for_hook(&gensee_home)?;
    bin_path = absolutize_for_hook(&bin_path)?;
    let command = cursor_hook_command(&gensee_home, &bin_path);
    write_cursor_hook_settings(&hooks_path, &command)?;

    println!(
        "gensee setup: configured Cursor hooks in {}",
        hooks_path.display()
    );
    println!("gensee setup: hook command: {command}");
    println!("gensee setup: fully restart Cursor before testing enforcement.");
    Ok(())
}

fn write_cursor_hook_settings(hooks_path: &Path, command: &str) -> io::Result<bool> {
    let (existing_contents, mut root) = read_json_config(hooks_path)?;
    apply_cursor_hook_settings(&mut root, command)?;
    write_json_config_if_changed(hooks_path, existing_contents.as_deref(), &root, "hooks")
}

fn write_file_atomically(
    path: &Path,
    contents: &[u8],
    new_file_mode: Option<u32>,
) -> io::Result<()> {
    // Renaming a temporary file over a symlink replaces the link itself. Resolve
    // an existing symlink first so dotfile-managed configurations keep the link
    // and receive the atomic update at their real target.
    let write_path = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::canonicalize(path).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "cannot resolve symlinked config {}: {err}; ensure the symlink target exists or fix/remove the link, then rerun setup",
                        path.display()
                    ),
                )
            })?
        }
        Ok(_) => path.to_path_buf(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => path.to_path_buf(),
        Err(err) => return Err(err),
    };
    let parent = write_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = write_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("settings.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| io::Error::other(err.to_string()))?
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{nonce}", std::process::id()));

    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = new_file_mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = new_file_mode;
        let mut temp = options.open(&temp_path)?;
        temp.write_all(contents)?;
        temp.sync_all()?;
        if let Ok(metadata) = fs::metadata(&write_path) {
            fs::set_permissions(&temp_path, metadata.permissions())?;
        }
        fs::rename(&temp_path, &write_path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn read_json_config(path: &Path) -> io::Result<(Option<String>, Value)> {
    let existing_contents = if path.exists() {
        Some(fs::read_to_string(path)?)
    } else {
        None
    };
    let root = match existing_contents.as_deref() {
        Some(contents) if contents.trim().is_empty() => json!({}),
        Some(contents) => serde_json::from_str(contents).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not valid JSON: {err}", path.display()),
            )
        })?,
        None => json!({}),
    };
    Ok((existing_contents, root))
}

fn write_json_config_if_changed(
    path: &Path,
    existing_contents: Option<&str>,
    root: &Value,
    backup_subject: &str,
) -> io::Result<bool> {
    write_json_config_if_changed_with_mode(path, existing_contents, root, backup_subject, None)
}

fn write_json_config_if_changed_with_mode(
    path: &Path,
    existing_contents: Option<&str>,
    root: &Value,
    backup_subject: &str,
    new_file_mode: Option<u32>,
) -> io::Result<bool> {
    let serialized = serde_json::to_string_pretty(root)?;
    let updated_contents = format!("{serialized}\n");
    if existing_contents == Some(updated_contents.as_str()) {
        return Ok(false);
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    if existing_contents.is_some() {
        let backup = backup_path(path)?;
        fs::copy(path, &backup)?;
        println!(
            "gensee setup: backed up previous {backup_subject} to {}",
            backup.display()
        );
    }
    write_file_atomically(path, updated_contents.as_bytes(), new_file_mode)?;
    Ok(true)
}

fn gensee_hook_command_owned_by(command: &str, provider: &str) -> bool {
    command.contains("GENSEE_HOME=") && command.trim_end().ends_with(&format!(" hook {provider}"))
}

fn command_hook_owned_by(entry: &Value, provider: &str, context: &str) -> io::Result<bool> {
    let object = entry.as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{context} hook entry must be a JSON object"),
        )
    })?;
    match object.get("command") {
        Some(Value::String(command)) => Ok(gensee_hook_command_owned_by(command, provider)),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{context} hook command must be a string"),
        )),
        None => Ok(false),
    }
}

fn merge_flat_hook_event(
    hooks: &mut serde_json::Map<String, Value>,
    event_name: &str,
    provider: &str,
    hook_entry: Value,
    integration: &str,
) -> io::Result<()> {
    let entries = hooks
        .entry(event_name.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{integration} {event_name} hooks must be a JSON array"),
            )
        })?;
    let context = format!("{integration} {event_name}");
    let mut owned = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        owned.push(command_hook_owned_by(entry, provider, &context)?);
    }
    let insert_at = owned
        .iter()
        .position(|is_owned| *is_owned)
        .unwrap_or(entries.len());
    let mut index = 0;
    entries.retain(|_| {
        let keep = !owned[index];
        index += 1;
        keep
    });
    entries.insert(insert_at.min(entries.len()), hook_entry);
    Ok(())
}

fn validate_nested_hook_groups(
    entries: &[Value],
    provider: &str,
    context: &str,
) -> io::Result<Vec<Vec<bool>>> {
    let mut owned = Vec::with_capacity(entries.len());
    for entry in entries {
        let group = entry.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{context} matcher entry must be a JSON object"),
            )
        })?;
        let commands = group
            .get("hooks")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{context} matcher hooks must be a JSON array"),
                )
            })?;
        let mut group_owned = Vec::with_capacity(commands.len());
        for command in commands {
            group_owned.push(command_hook_owned_by(command, provider, context)?);
        }
        owned.push(group_owned);
    }
    Ok(owned)
}

fn merge_nested_hook_event(
    hooks: &mut serde_json::Map<String, Value>,
    event_name: &str,
    provider: &str,
    hook_entry: Value,
    integration: &str,
) -> io::Result<()> {
    let entries = hooks
        .entry(event_name.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{integration} {event_name} hooks must be a JSON array"),
            )
        })?;
    let context = format!("{integration} {event_name}");
    let owned = validate_nested_hook_groups(entries, provider, &context)?;
    let first_owned_group = owned
        .iter()
        .position(|group| group.iter().any(|is_owned| *is_owned));

    for (entry, group_owned) in entries.iter_mut().zip(owned.iter()) {
        let commands = entry
            .get_mut("hooks")
            .and_then(Value::as_array_mut)
            .expect("nested hook groups were validated");
        let mut index = 0;
        commands.retain(|_| {
            let keep = !group_owned[index];
            index += 1;
            keep
        });
    }
    let mut group_index = 0;
    entries.retain(|entry| {
        let removed_owned_command = owned[group_index].iter().any(|is_owned| *is_owned);
        group_index += 1;
        !removed_owned_command
            || entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|commands| !commands.is_empty())
    });
    let insert_at = first_owned_group
        .unwrap_or(entries.len())
        .min(entries.len());
    entries.insert(insert_at, hook_entry);
    Ok(())
}

pub(crate) fn apply_cursor_hook_settings(root: &mut Value, command: &str) -> io::Result<()> {
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Cursor hooks must be a JSON object",
        )
    })?;
    root_object.entry("version".to_string()).or_insert(json!(1));
    let hooks = root_object
        .entry("hooks".to_string())
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Cursor hooks field must be a JSON object",
        ));
    }
    let hooks_object = hooks.as_object_mut().expect("hooks is an object");
    let hook_entry = json!({
        "command": command,
        "timeout": 30
    });
    for event_name in [
        "preToolUse",
        "postToolUse",
        "beforeShellExecution",
        "beforeSubmitPrompt",
        "stop",
    ] {
        merge_flat_hook_event(
            hooks_object,
            event_name,
            PROVIDER_CURSOR,
            hook_entry.clone(),
            "Cursor",
        )?;
    }
    Ok(())
}

fn cursor_hook_command(gensee_home: &Path, bin_path: &Path) -> String {
    format!(
        "GENSEE_HOME={} {} hook cursor",
        shell_quote(&gensee_home.display().to_string()),
        shell_quote(&bin_path.display().to_string())
    )
}

#[derive(Debug, Default)]
struct ClaudeCodeGatewaySettings {
    base_url: Option<String>,
    auth_token: Option<String>,
    api_key: Option<String>,
    custom_headers: Option<String>,
    api_key_helper: Option<String>,
}

impl ClaudeCodeGatewaySettings {
    fn is_empty(&self) -> bool {
        self.base_url.is_none()
            && self.auth_token.is_none()
            && self.api_key.is_none()
            && self.custom_headers.is_none()
            && self.api_key_helper.is_none()
    }

    fn validate(&self) -> io::Result<()> {
        let credential_count = usize::from(self.auth_token.is_some())
            + usize::from(self.api_key.is_some())
            + usize::from(self.api_key_helper.is_some());
        if credential_count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "setup: choose only one gateway credential source: --anthropic-auth-token, --anthropic-api-key, or --api-key-helper",
            ));
        }
        if self.base_url.is_none()
            && (self.auth_token.is_some()
                || self.api_key.is_some()
                || self.custom_headers.is_some()
                || self.api_key_helper.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "setup: gateway credential/header options require --anthropic-base-url",
            ));
        }
        Ok(())
    }
}

fn required_next_arg(args: &[OsString], index: usize, name: &str) -> io::Result<String> {
    args.get(index + 1)
        .and_then(|value| value.to_str())
        .map(ToString::to_string)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("setup: {name} requires a value"),
            )
        })
}

fn write_claude_code_settings(
    settings_path: &Path,
    command: &str,
    gateway: &ClaudeCodeGatewaySettings,
) -> io::Result<bool> {
    let (existing_contents, mut root) = read_json_config(settings_path)?;
    apply_claude_code_hook_settings(&mut root, command)?;
    apply_claude_code_gateway_settings(&mut root, gateway)?;
    let hooks_disabled = root
        .get("disableAllHooks")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    write_json_config_if_changed_with_mode(
        settings_path,
        existing_contents.as_deref(),
        &root,
        "settings",
        Some(0o600),
    )?;
    Ok(hooks_disabled)
}

fn apply_claude_code_gateway_settings(
    root: &mut Value,
    gateway: &ClaudeCodeGatewaySettings,
) -> io::Result<()> {
    if gateway.is_empty() {
        return Ok(());
    }
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Claude Code settings must be a JSON object",
        )
    })?;
    {
        let env_value = root_object
            .entry("env".to_string())
            .or_insert_with(|| json!({}));
        if !env_value.is_object() {
            *env_value = json!({});
        }
        let env_object = env_value.as_object_mut().expect("env is an object");

        if let Some(base_url) = gateway.base_url.as_deref() {
            env_object.insert("ANTHROPIC_BASE_URL".to_string(), json!(base_url));
        }
        if let Some(custom_headers) = gateway.custom_headers.as_deref() {
            env_object.insert(
                "ANTHROPIC_CUSTOM_HEADERS".to_string(),
                json!(custom_headers),
            );
        }
        if let Some(auth_token) = gateway.auth_token.as_deref() {
            env_object.insert("ANTHROPIC_AUTH_TOKEN".to_string(), json!(auth_token));
            env_object.remove("ANTHROPIC_API_KEY");
        }
        if let Some(api_key) = gateway.api_key.as_deref() {
            env_object.insert("ANTHROPIC_API_KEY".to_string(), json!(api_key));
            env_object.remove("ANTHROPIC_AUTH_TOKEN");
        }
        if gateway.api_key_helper.is_some() {
            env_object.remove("ANTHROPIC_AUTH_TOKEN");
            env_object.remove("ANTHROPIC_API_KEY");
        }
    }

    if gateway.auth_token.is_some() || gateway.api_key.is_some() {
        root_object.remove("apiKeyHelper");
    }
    if let Some(helper) = gateway.api_key_helper.as_deref() {
        root_object.insert("apiKeyHelper".to_string(), json!(helper));
    }
    Ok(())
}

fn write_codex_hook_settings(hooks_path: &Path, command: &str) -> io::Result<()> {
    let (existing_contents, mut root) = read_json_config(hooks_path)?;
    apply_codex_hook_settings(&mut root, command)?;
    write_json_config_if_changed(hooks_path, existing_contents.as_deref(), &root, "hooks")?;
    Ok(())
}

fn write_antigravity_hook_settings(hooks_path: &Path, command: &str) -> io::Result<()> {
    let (existing_contents, mut root) = read_json_config(hooks_path)?;
    apply_antigravity_hook_settings(&mut root, command)?;
    write_json_config_if_changed(hooks_path, existing_contents.as_deref(), &root, "hooks")?;
    Ok(())
}

fn apply_claude_code_hook_settings(root: &mut Value, command: &str) -> io::Result<()> {
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Claude Code settings must be a JSON object",
        )
    })?;
    let hooks = root_object
        .entry("hooks".to_string())
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Claude Code hooks field must be a JSON object",
        ));
    }
    let hooks_object = hooks.as_object_mut().expect("hooks is an object");
    let hook_entry = json!({
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": command
            }
        ]
    });
    for event_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"] {
        merge_nested_hook_event(
            hooks_object,
            event_name,
            PROVIDER_CLAUDE_CODE,
            hook_entry.clone(),
            "Claude Code",
        )?;
    }
    Ok(())
}

fn apply_codex_hook_settings(root: &mut Value, command: &str) -> io::Result<()> {
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex hooks must be a JSON object",
        )
    })?;
    let hooks = root_object
        .entry("hooks".to_string())
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex hooks field must be a JSON object",
        ));
    }
    let hooks_object = hooks.as_object_mut().expect("hooks is an object");
    let hook_entry = json!({
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": command,
                "statusMessage": "Checking Gensee policy",
                "timeout": 30
            }
        ]
    });
    for event_name in [
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "Stop",
    ] {
        merge_nested_hook_event(
            hooks_object,
            event_name,
            PROVIDER_CODEX,
            hook_entry.clone(),
            "Codex",
        )?;
    }
    Ok(())
}

fn apply_antigravity_hook_settings(root: &mut Value, command: &str) -> io::Result<()> {
    let root_object = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Antigravity hooks must be a JSON object",
        )
    })?;
    let policy = root_object
        .entry("gensee-policy".to_string())
        .or_insert_with(|| json!({}));
    let policy = policy.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Antigravity gensee-policy field must be a JSON object",
        )
    })?;
    let nested_hook_entry = json!({
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": command,
                "timeout": 30
            }
        ]
    });
    for event_name in ["PreToolUse", "PostToolUse"] {
        merge_nested_hook_event(
            policy,
            event_name,
            PROVIDER_ANTIGRAVITY,
            nested_hook_entry.clone(),
            "Antigravity",
        )?;
    }
    merge_flat_hook_event(
        policy,
        "PreInvocation",
        PROVIDER_ANTIGRAVITY,
        json!({
            "type": "command",
            "command": command,
            "timeout": 30
        }),
        "Antigravity",
    )?;
    Ok(())
}

fn claude_code_hook_command(gensee_home: &Path, bin_path: &Path) -> String {
    format!(
        "GENSEE_HOME={} {} hook claude-code",
        shell_quote(&gensee_home.display().to_string()),
        shell_quote(&bin_path.display().to_string())
    )
}

fn codex_hook_command(gensee_home: &Path, bin_path: &Path) -> String {
    format!(
        "GENSEE_HOME={} {} hook codex",
        shell_quote(&gensee_home.display().to_string()),
        shell_quote(&bin_path.display().to_string())
    )
}

fn antigravity_hook_command(gensee_home: &Path, bin_path: &Path) -> String {
    format!(
        "GENSEE_HOME={} {} hook antigravity",
        shell_quote(&gensee_home.display().to_string()),
        shell_quote(&bin_path.display().to_string())
    )
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "/._-+=".contains(ch))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn absolutize_for_hook(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn backup_path(path: &Path) -> io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| io::Error::other(err.to_string()))?
        .as_secs();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("settings.json");
    Ok(path.with_file_name(format!("{file_name}.bak.{timestamp}")))
}

/// `gensee policy <print-default|path|validate <file>|init [--force]>` — inspect,
/// validate, and scaffold the policy document (the user-facing policy interface).
pub(crate) fn handle_policy(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("print-default") => {
            print!("{}", policy::default_policy_json());
            Ok(())
        }
        Some("path") => {
            let (path, label) = policy::resolved_policy_source();
            match path {
                Some(path) => println!("active policy: {} [{label}]", path.display()),
                None => println!("active policy: (bundled default) [{label}]"),
            }
            if let Some(user_path) = policy::user_policy_path() {
                println!("user policy path: {}", user_path.display());
            }
            Ok(())
        }
        Some("validate") => {
            let file = args.get(1).and_then(|arg| arg.to_str()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: gensee policy validate <file>",
                )
            })?;
            let contents = fs::read_to_string(file)?;
            match Policy::from_json(&contents) {
                Ok(_) => {
                    println!(
                        "gensee policy: {file} is valid (schema_version {})",
                        policy::POLICY_SCHEMA_VERSION
                    );
                    Ok(())
                }
                Err(err) => {
                    eprintln!("gensee policy: {file} is INVALID: {err}");
                    std::process::exit(1);
                }
            }
        }
        Some("init") => {
            let force = has_arg(&args, "--force");
            let path = policy::user_policy_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "cannot determine user policy path (set GENSEE_HOME or HOME)",
                )
            })?;
            if path.exists() && !force {
                eprintln!(
                    "gensee policy: {} already exists (use --force to overwrite)",
                    path.display()
                );
                std::process::exit(1);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, policy::default_policy_json())?;
            println!("gensee policy: wrote default policy to {}", path.display());
            println!(
                "edit it (auto-loaded when GENSEE_POLICY_FILE is unset), then \
                 `gensee policy validate {}` to check.",
                path.display()
            );
            Ok(())
        }
        Some("setup") => policy_setup(args[1..].to_vec()),
        Some("get") => {
            let key = args.get(1).and_then(|arg| arg.to_str()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "usage: gensee policy get <key>")
            })?;
            let (source, _) = policy::resolved_policy_source();
            let text = match source {
                Some(path) => fs::read_to_string(path)?,
                None => policy::default_policy_json().to_string(),
            };
            let root: Value = serde_json::from_str(&text)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            match policy_value_get(&root, key) {
                Some(value) => {
                    println!("{}", serde_json::to_string_pretty(value)?);
                    Ok(())
                }
                None => {
                    eprintln!("gensee policy: key not set: {key}");
                    std::process::exit(1);
                }
            }
        }
        Some("set") => {
            let (Some(key), Some(raw)) = (
                args.get(1).and_then(|arg| arg.to_str()),
                args.get(2).and_then(|arg| arg.to_str()),
            ) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: gensee policy set <key> <value>",
                ));
            };
            // Only the configuration knobs are settable via `set`; a typo'd key
            // (e.g. `egress.requireProx`) is rejected here rather than silently
            // written and ignored. Rule sections are edited as JSON.
            if !SETTABLE_POLICY_KEYS.contains(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "unknown policy key `{key}`. settable keys: {}",
                        SETTABLE_POLICY_KEYS.join(", ")
                    ),
                ));
            }
            let path = policy::user_policy_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "cannot determine user policy path (set GENSEE_HOME or HOME)",
                )
            })?;
            // Edit the user file in place, or materialize the full default first
            // (a valid document needs all required sections present).
            let mut root: Value = if path.exists() {
                serde_json::from_str(&fs::read_to_string(&path)?).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("existing policy is not valid JSON: {err}"),
                    )
                })?
            } else {
                serde_json::from_str(policy::default_policy_json()).expect("default is valid")
            };
            policy_value_set(&mut root, key, coerce_policy_value(key, raw))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let serialized = serde_json::to_string_pretty(&root)?;
            // Reject a change that would make the document invalid, before writing.
            Policy::from_json(&serialized).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("set would make the policy invalid: {err}"),
                )
            })?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, format!("{serialized}\n"))?;
            println!("gensee policy: set {key} in {}", path.display());
            telemetry_record_policy_change(
                "policy_set_changed",
                json!({
                    "key": key,
                }),
            );
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee policy <print-default | path | validate <file> | init [--force] | setup | get <key> | set <key> <value>>",
        )),
    }
}

fn policy_setup(args: Vec<OsString>) -> io::Result<()> {
    if has_arg(&args, "--help") || has_arg(&args, "-h") {
        println!("usage: gensee policy setup");
        return Ok(());
    }
    if !args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee policy setup",
        ));
    }

    let path = policy::user_policy_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot determine user policy path (set GENSEE_HOME or HOME)",
        )
    })?;
    let mut root: Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("existing policy is not valid JSON: {err}"),
            )
        })?
    } else {
        serde_json::from_str(policy::default_policy_json()).expect("default is valid")
    };

    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    match tty {
        Ok(mut tty) => {
            let reader = tty.try_clone()?;
            let mut reader = io::BufReader::new(reader);
            run_policy_setup(&mut root, &mut reader, &mut tty)?;
        }
        Err(_) => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut reader = stdin.lock();
            let mut writer = stdout.lock();
            run_policy_setup(&mut root, &mut reader, &mut writer)?;
        }
    }

    let serialized = serde_json::to_string_pretty(&root)?;
    Policy::from_json(&serialized).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("setup would make the policy invalid: {err}"),
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, format!("{serialized}\n"))?;
    println!("gensee policy: wrote setup policy to {}", path.display());
    println!(
        "gensee policy: validate it with `gensee policy validate {}`",
        path.display()
    );
    telemetry_record_policy_change(
        "policy_setup_completed",
        json!({
            "path": path,
        }),
    );
    Ok(())
}

fn run_policy_setup<R: BufRead, W: Write>(
    root: &mut Value,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    writeln!(output, "Gensee policy setup")?;
    writeln!(
        output,
        "Press Enter to keep the current value shown in brackets."
    )?;

    for group in POLICY_SETUP_GROUPS {
        writeln!(output)?;
        writeln!(output, "{}", group.name)?;
        if !group.hint.is_empty() {
            writeln!(output, "{}", group.hint)?;
        }
        for item in group.items {
            prompt_policy_setup_item(root, item, input, output)?;
        }
    }
    prompt_artifact_definitions(root, input, output)?;
    prompt_decision_rules(root, input, output)?;
    writeln!(output)?;
    Ok(())
}

fn prompt_policy_setup_item<R: BufRead, W: Write>(
    root: &mut Value,
    item: &PolicySetupItem,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let current = policy_value_get(root, item.key).unwrap_or(&Value::Null);
    let current_display = policy_setup_value_display(current);
    write!(
        output,
        "{} - {} [{}]: ",
        item.label, item.help, current_display
    )?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let value = parse_policy_setup_value(item, trimmed)?;
    policy_value_set(root, item.key, value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("{}: {err}", item.key)))
}

fn parse_policy_setup_value(item: &PolicySetupItem, raw: &str) -> io::Result<Value> {
    let lowered = raw.to_ascii_lowercase();
    match item.value_type {
        PolicySetupValueType::Bool => match lowered.as_str() {
            "y" | "yes" | "true" | "1" | "on" => Ok(json!(true)),
            "n" | "no" | "false" | "0" | "off" => Ok(json!(false)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} expects y/n", item.key),
            )),
        },
        PolicySetupValueType::List => {
            if matches!(lowered.as_str(), "none" | "unset" | "empty" | "[]") {
                return Ok(json!([]));
            }
            Ok(json!(raw
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()))
        }
        PolicySetupValueType::Int => {
            if item.allow_null && matches!(lowered.as_str(), "none" | "unset" | "null") {
                return Ok(Value::Null);
            }
            raw.parse::<i64>().map(|value| json!(value)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} expects an integer", item.key),
                )
            })
        }
        PolicySetupValueType::Float => raw.parse::<f64>().map(|value| json!(value)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} expects a number", item.key),
            )
        }),
        PolicySetupValueType::String => {
            if item.allow_null && matches!(lowered.as_str(), "none" | "unset" | "null") {
                Ok(Value::Null)
            } else {
                Ok(json!(raw))
            }
        }
    }
}

fn policy_setup_value_display(value: &Value) -> String {
    match value {
        Value::Null => "unset".to_string(),
        Value::Array(items) if items.is_empty() => "empty".to_string(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(ToString::to_string))
            .collect::<Vec<_>>()
            .join(","),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn prompt_artifact_definitions<R: BufRead, W: Write>(
    root: &mut Value,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    writeln!(output)?;
    writeln!(output, "Artifact definitions")?;
    writeln!(
        output,
        "What Gensee treats as executable, memory, skill, or control-plane files."
    )?;

    for def in ARTIFACT_SETUP_DEFS {
        writeln!(output)?;
        writeln!(output, "{}", def.title)?;
        writeln!(output, "{}", def.help)?;
        for field in MATCHER_SETUP_FIELDS {
            let key = format!("artifact_registries.{}.{}", def.key, field.key);
            prompt_policy_setup_list(root, &key, field.label, input, output)?;
        }
    }
    Ok(())
}

fn prompt_policy_setup_list<R: BufRead, W: Write>(
    root: &mut Value,
    key: &str,
    label: &str,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let current = policy_value_get(root, key).unwrap_or(&Value::Null);
    let current_display = policy_setup_value_display(current);
    write!(output, "{} [{}]: ", label, current_display)?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let value = parse_policy_setup_list_value(trimmed);
    policy_value_set(root, key, value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("{key}: {err}")))
}

fn parse_policy_setup_list_value(raw: &str) -> Value {
    let lowered = raw.to_ascii_lowercase();
    if matches!(lowered.as_str(), "none" | "unset" | "empty" | "[]") {
        return json!([]);
    }
    json!(raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>())
}

fn prompt_decision_rules<R: BufRead, W: Write>(
    root: &mut Value,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let groups = collect_policy_rule_groups(root);
    if groups.is_empty() {
        return Ok(());
    }

    writeln!(output)?;
    writeln!(output, "Decision rules")?;
    writeln!(
        output,
        "Choose each rule action: deny blocks, ask prompts, allow lets it through."
    )?;

    for (group, rules) in groups {
        writeln!(output)?;
        writeln!(output, "{} ({})", group, rules.len())?;
        for rule in rules {
            prompt_decision_rule(root, &rule, input, output)?;
        }
    }
    Ok(())
}

fn prompt_decision_rule<R: BufRead, W: Write>(
    root: &mut Value,
    rule: &DecisionRule,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let current = root
        .pointer(&rule.pointer)
        .and_then(|node| node.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("allow");
    let current_display = policy_action_display(current);
    let summary = if rule.summary.is_empty() {
        String::new()
    } else {
        format!(" - {}", rule.summary)
    };
    write!(
        output,
        "{}{} [deny/ask/allow; current {}]: ",
        rule.name, summary, current_display
    )?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let action = parse_policy_action(trimmed)?;
    let node = root.pointer_mut(&rule.pointer).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing rule path {}", rule.pointer),
        )
    })?;
    let object = node.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("rule path {} is not an object", rule.pointer),
        )
    })?;
    object.insert("action".to_string(), json!(action));
    Ok(())
}

fn parse_policy_action(raw: &str) -> io::Result<&'static str> {
    match raw.to_ascii_lowercase().as_str() {
        "deny" | "block" => Ok("block"),
        "ask" => Ok("ask"),
        "allow" => Ok("allow"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "action must be deny, ask, or allow",
        )),
    }
}

fn policy_action_display(action: &str) -> &str {
    match action {
        "block" => "deny",
        other => other,
    }
}

#[derive(Debug, Clone)]
struct DecisionRule {
    name: String,
    pointer: String,
    summary: String,
}

fn collect_policy_rule_groups(root: &Value) -> Vec<(String, Vec<DecisionRule>)> {
    let mut file_rules = Vec::new();
    if let Some(node) = root.pointer("/secret_paths/protected") {
        file_rules.push(DecisionRule {
            name: "Protected secrets".to_string(),
            pointer: "/secret_paths/protected".to_string(),
            summary: summarize_rule_node(node),
        });
    }
    if let Some(node) = root.pointer("/persistence_writes") {
        file_rules.push(DecisionRule {
            name: "Persistence / startup writes".to_string(),
            pointer: "/persistence_writes".to_string(),
            summary: summarize_rule_node(node),
        });
    }
    if let Some(categories) = root.get("categories").and_then(Value::as_object) {
        let mut ordered = BTreeMap::new();
        for (key, node) in categories {
            ordered.insert(key, node);
        }
        for (key, node) in ordered {
            file_rules.push(DecisionRule {
                name: key.replace('_', " "),
                pointer: format!("/categories/{}", json_pointer_escape(key)),
                summary: summarize_rule_node(node),
            });
        }
    }

    let command_rules = collect_array_rules(root, "command_rules", "Command rule");
    let content_rules = collect_array_rules(root, "content_rules", "Content rule");
    let url_rules = collect_array_rules(root, "url_rules", "URL rule");

    let mut groups = Vec::new();
    if !file_rules.is_empty() {
        groups.push(("File access rules".to_string(), file_rules));
    }
    if !command_rules.is_empty() {
        groups.push(("Command rules".to_string(), command_rules));
    }
    if !content_rules.is_empty() {
        groups.push(("Executable-content rules".to_string(), content_rules));
    }
    if !url_rules.is_empty() {
        groups.push(("Network / URL rules".to_string(), url_rules));
    }
    groups
}

fn collect_array_rules(root: &Value, key: &str, fallback_prefix: &str) -> Vec<DecisionRule> {
    root.get(key)
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .enumerate()
                .map(|(index, node)| DecisionRule {
                    name: node
                        .get("id")
                        .or_else(|| node.get("rule_id"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| format!("{} {}", fallback_prefix, index + 1)),
                    pointer: format!("/{key}/{index}"),
                    summary: summarize_rule_node(node),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn summarize_rule_node(node: &Value) -> String {
    const SUMMARY_FIELDS: &[&str] = &[
        "patterns",
        "all_of",
        "commands",
        "bare_commands",
        "arg_any",
        "arg_all",
        "raw_all",
        "hosts",
        "host_substrings",
        "url_substrings",
        "segments",
        "filenames",
        "filename_suffixes",
        "path_contains",
        "exact_paths",
    ];
    let mut parts = Vec::new();
    for field in SUMMARY_FIELDS {
        if let Some(values) = node.get(*field).and_then(Value::as_array) {
            parts.extend(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string),
            );
        }
    }
    if parts.is_empty() {
        return node
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
    }
    let shown = parts.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
    if parts.len() > 4 {
        format!("{shown} ... (+{})", parts.len() - 4)
    } else {
        shown
    }
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

struct PolicySetupGroup {
    name: &'static str,
    hint: &'static str,
    items: &'static [PolicySetupItem],
}

struct PolicySetupItem {
    key: &'static str,
    value_type: PolicySetupValueType,
    label: &'static str,
    help: &'static str,
    allow_null: bool,
}

struct ArtifactSetupDef {
    key: &'static str,
    title: &'static str,
    help: &'static str,
}

struct MatcherSetupField {
    key: &'static str,
    label: &'static str,
}

#[derive(Clone, Copy)]
enum PolicySetupValueType {
    Bool,
    Float,
    Int,
    List,
    String,
}

const RESOURCE_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[
    PolicySetupItem {
        key: "resource_governance.max_read_bytes",
        value_type: PolicySetupValueType::Int,
        label: "Max read bytes",
        help: "Largest single file read the shield allows",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_file_subjects_per_tool",
        value_type: PolicySetupValueType::Int,
        label: "Max file subjects / tool",
        help: "File paths a single tool call may touch",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_shell_segments_per_tool",
        value_type: PolicySetupValueType::Int,
        label: "Max shell segments / tool",
        help: "Chained commands per Bash call",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_tool_calls_per_session",
        value_type: PolicySetupValueType::Int,
        label: "Max tool calls / session",
        help: "Total tool calls before the session is throttled",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_network_egress_per_session",
        value_type: PolicySetupValueType::Int,
        label: "Max network egress / session",
        help: "Outbound network operations per session",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_file_accessed_rate_per_min",
        value_type: PolicySetupValueType::Float,
        label: "Max file access rate / min",
        help: "File operations per minute before flagging",
        allow_null: false,
    },
    PolicySetupItem {
        key: "resource_governance.max_network_rate_per_min",
        value_type: PolicySetupValueType::Float,
        label: "Max network rate / min",
        help: "Network operations per minute before flagging",
        allow_null: false,
    },
];

const EGRESS_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[
    PolicySetupItem {
        key: "egress.allow_hosts",
        value_type: PolicySetupValueType::List,
        label: "Allowed hosts",
        help: "Comma-separated hosts the agent may connect to; empty means unrestricted",
        allow_null: false,
    },
    PolicySetupItem {
        key: "egress.proxy_url",
        value_type: PolicySetupValueType::String,
        label: "Proxy URL",
        help: "Egress proxy URL, or none to unset",
        allow_null: true,
    },
    PolicySetupItem {
        key: "egress.require_proxy",
        value_type: PolicySetupValueType::Bool,
        label: "Require proxy",
        help: "Deny direct egress that bypasses the proxy",
        allow_null: false,
    },
];

const RUNTIME_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[PolicySetupItem {
    key: "runtime.max_runtime_seconds",
    value_type: PolicySetupValueType::Int,
    label: "Max runtime seconds",
    help: "Wall-clock cap for a guarded run, or none to unset",
    allow_null: true,
}];

const LINUX_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[
    PolicySetupItem {
        key: "linux.seccomp.enabled",
        value_type: PolicySetupValueType::Bool,
        label: "Enable Linux seccomp",
        help: "Apply the Linux syscall-deny profile to managed runs",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.seccomp.deny_ptrace",
        value_type: PolicySetupValueType::Bool,
        label: "Deny ptrace",
        help: "Block ptrace and process memory read/write syscalls",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.seccomp.deny_bpf",
        value_type: PolicySetupValueType::Bool,
        label: "Deny bpf",
        help: "Block kernel BPF program management from agents",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.seccomp.deny_kernel_modules",
        value_type: PolicySetupValueType::Bool,
        label: "Deny kernel modules",
        help: "Block module load/unload syscalls",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.seccomp.deny_mount_namespace_changes",
        value_type: PolicySetupValueType::Bool,
        label: "Deny mount/namespace changes",
        help: "Block mount, unmount, pivot_root, unshare, and setns families",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.fanotify.paths",
        value_type: PolicySetupValueType::List,
        label: "Linux fanotify paths",
        help: "Comma-separated extra sensitive paths for Linux fanotify marks",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.network.mode",
        value_type: PolicySetupValueType::String,
        label: "Linux network mode",
        help: "off, monitor, deny-all, or allowlist",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.network.allow",
        value_type: PolicySetupValueType::List,
        label: "Linux network allowlist",
        help: "Comma-separated IP/CIDR destinations allowed in allowlist mode",
        allow_null: false,
    },
    PolicySetupItem {
        key: "linux.network.deny",
        value_type: PolicySetupValueType::List,
        label: "Linux network denylist",
        help: "Comma-separated IP/CIDR destinations denied before allow rules",
        allow_null: false,
    },
];

const ENFORCEMENT_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[PolicySetupItem {
    key: "enforcement.noninteractive",
    value_type: PolicySetupValueType::Bool,
    label: "Non-interactive fail-closed",
    help: "Escalate medium+ asks to deny when no human can answer",
    allow_null: false,
}];

const WATCH_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[PolicySetupItem {
    key: "watch.system_events",
    value_type: PolicySetupValueType::String,
    label: "System events",
    help: "System-event backend for gensee watch: eslogger or none",
    allow_null: false,
}];

const ALLOWLIST_POLICY_SETUP_ITEMS: &[PolicySetupItem] = &[PolicySetupItem {
    key: "allow_path_prefixes",
    value_type: PolicySetupValueType::List,
    label: "Allowed path prefixes",
    help: "Comma-separated absolute path prefixes exempt from sensitive checks",
    allow_null: false,
}];

const POLICY_SETUP_GROUPS: &[PolicySetupGroup] = &[
    PolicySetupGroup {
        name: "Resource governance",
        hint: "Per-tool and per-session quotas.",
        items: RESOURCE_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Network egress",
        hint: "Where the agent may connect, and whether it must use a proxy.",
        items: EGRESS_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Runtime",
        hint: "Run supervisor limits.",
        items: RUNTIME_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Linux host controls",
        hint: "System-level controls for agents launched on Linux.",
        items: LINUX_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Enforcement",
        hint: "How policy behaves when no human can approve an ask decision.",
        items: ENFORCEMENT_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Watch",
        hint: "Sidecar watch defaults.",
        items: WATCH_POLICY_SETUP_ITEMS,
    },
    PolicySetupGroup {
        name: "Allowlisted paths",
        hint: "Paths that should always be trusted.",
        items: ALLOWLIST_POLICY_SETUP_ITEMS,
    },
];

const ARTIFACT_SETUP_DEFS: &[ArtifactSetupDef] = &[
    ArtifactSetupDef {
        key: "executable",
        title: "Executable artifacts",
        help: "Runnable files such as scripts, skills, plugins, and git hooks.",
    },
    ArtifactSetupDef {
        key: "memory",
        title: "Memory files",
        help: "Agent memory files Gensee tracks for poisoning across turns or sessions.",
    },
    ArtifactSetupDef {
        key: "skill",
        title: "Skill / plugin locations",
        help: "Where agent skill and plugin definitions live.",
    },
    ArtifactSetupDef {
        key: "control_plane",
        title: "Control-plane files",
        help: "Gensee's own files, such as the local database and safety policy.",
    },
];

const MATCHER_SETUP_FIELDS: &[MatcherSetupField] = &[
    MatcherSetupField {
        key: "segments",
        label: "Path segments (directory names)",
    },
    MatcherSetupField {
        key: "filenames",
        label: "Exact filenames",
    },
    MatcherSetupField {
        key: "filename_prefixes",
        label: "Filename prefixes",
    },
    MatcherSetupField {
        key: "filename_suffixes",
        label: "Filename suffixes / extensions",
    },
    MatcherSetupField {
        key: "filename_contains",
        label: "Filename contains",
    },
    MatcherSetupField {
        key: "path_suffixes",
        label: "Path ends with",
    },
    MatcherSetupField {
        key: "path_contains",
        label: "Path contains",
    },
];

/// Configuration keys settable via `gensee policy set` — the env-knob
/// replacements. Rule sections (secret_paths, command_rules, …) are edited as
/// JSON, not via `set`.
const SETTABLE_POLICY_KEYS: &[&str] = &[
    "resource_governance.max_read_bytes",
    "resource_governance.max_file_subjects_per_tool",
    "resource_governance.max_shell_segments_per_tool",
    "resource_governance.max_tool_calls_per_session",
    "resource_governance.max_network_egress_per_session",
    "resource_governance.max_file_accessed_rate_per_min",
    "resource_governance.max_network_rate_per_min",
    "egress.allow_hosts",
    "egress.proxy_url",
    "egress.require_proxy",
    "runtime.max_runtime_seconds",
    "linux.seccomp.enabled",
    "linux.seccomp.deny_ptrace",
    "linux.seccomp.deny_bpf",
    "linux.seccomp.deny_kernel_modules",
    "linux.seccomp.deny_mount_namespace_changes",
    "linux.fanotify.paths",
    "linux.network.mode",
    "linux.network.allow",
    "linux.network.deny",
    "enforcement.noninteractive",
    "watch.system_events",
    "allow_path_prefixes",
];

pub(crate) fn telemetry_policy_key_bucket(key: &str) -> &'static str {
    if !SETTABLE_POLICY_KEYS.contains(&key) {
        return "custom";
    }
    match key {
        "resource_governance.max_read_bytes" => "resource_governance.max_read_bytes",
        "resource_governance.max_file_subjects_per_tool" => {
            "resource_governance.max_file_subjects_per_tool"
        }
        "resource_governance.max_shell_segments_per_tool" => {
            "resource_governance.max_shell_segments_per_tool"
        }
        "resource_governance.max_tool_calls_per_session" => {
            "resource_governance.max_tool_calls_per_session"
        }
        "resource_governance.max_network_egress_per_session" => {
            "resource_governance.max_network_egress_per_session"
        }
        "resource_governance.max_file_accessed_rate_per_min" => {
            "resource_governance.max_file_accessed_rate_per_min"
        }
        "resource_governance.max_network_rate_per_min" => {
            "resource_governance.max_network_rate_per_min"
        }
        "egress.allow_hosts" => "egress.allow_hosts",
        "egress.proxy_url" => "egress.proxy_url",
        "egress.require_proxy" => "egress.require_proxy",
        "runtime.max_runtime_seconds" => "runtime.max_runtime_seconds",
        "linux.seccomp.enabled" => "linux.seccomp.enabled",
        "linux.seccomp.deny_ptrace" => "linux.seccomp.deny_ptrace",
        "linux.seccomp.deny_bpf" => "linux.seccomp.deny_bpf",
        "linux.seccomp.deny_kernel_modules" => "linux.seccomp.deny_kernel_modules",
        "linux.seccomp.deny_mount_namespace_changes" => {
            "linux.seccomp.deny_mount_namespace_changes"
        }
        "linux.fanotify.paths" => "linux.fanotify.paths",
        "linux.network.mode" => "linux.network.mode",
        "linux.network.allow" => "linux.network.allow",
        "linux.network.deny" => "linux.network.deny",
        "enforcement.noninteractive" => "enforcement.noninteractive",
        "watch.system_events" => "watch.system_events",
        "allow_path_prefixes" => "allow_path_prefixes",
        _ => "custom",
    }
}

/// Look up a dotted key (e.g. `egress.require_proxy`) in a policy JSON value.
fn policy_value_get<'a>(root: &'a Value, key: &str) -> Option<&'a Value> {
    let mut current = root;
    for part in key.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Set a dotted key in a policy JSON value, creating intermediate objects.
fn policy_value_set(root: &mut Value, key: &str, value: Value) -> Result<(), String> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = root;
    for (index, part) in parts.iter().enumerate() {
        let object = current
            .as_object_mut()
            .ok_or_else(|| format!("`{}` is not an object", parts[..index].join(".")))?;
        if index == parts.len() - 1 {
            object.insert((*part).to_string(), value);
            return Ok(());
        }
        current = object
            .entry((*part).to_string())
            .or_insert_with(|| json!({}));
    }
    Ok(())
}

/// Coerce a CLI string value to JSON: known list keys split on `,`; otherwise
/// bool / null / integer / float / string by inspection. Type correctness is
/// enforced afterward by re-validating the whole document.
fn coerce_policy_value(key: &str, raw: &str) -> Value {
    const LIST_KEYS: &[&str] = &[
        "egress.allow_hosts",
        "linux.fanotify.paths",
        "linux.network.allow",
        "linux.network.deny",
        "allow_path_prefixes",
    ];
    if LIST_KEYS.contains(&key) {
        return Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| json!(item))
                .collect(),
        );
    }
    match raw {
        "true" => json!(true),
        "false" => json!(false),
        "null" => Value::Null,
        _ => raw
            .parse::<i64>()
            .map(|n| json!(n))
            .or_else(|_| raw.parse::<f64>().map(|n| json!(n)))
            .unwrap_or_else(|_| json!(raw)),
    }
}

pub(crate) fn handle_ingest(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("eslogger") => ingest_eslogger(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee ingest eslogger",
        )),
    }
}

/// Verify the tamper-evident alert hash chain (T8). Exits 0 if intact, 2 if a
/// row was inserted, deleted, reordered, or modified.
pub(crate) fn verify_log() -> io::Result<()> {
    let store = EventStore::default_local()?;
    let result = store.verify_alert_chain()?;
    if result.is_valid() {
        println!(
            "gensee verify-log: OK — {} chained alert(s), no tampering detected",
            result.checked
        );
        Ok(())
    } else {
        let location = result
            .broken_at
            .map(|id| format!("alert_id {id}"))
            .unwrap_or_else(|| "the tail".to_string());
        eprintln!(
            "gensee verify-log: TAMPERING DETECTED — chain broke at {} after {} valid entr{}: {}",
            location,
            result.checked,
            if result.checked == 1 { "y" } else { "ies" },
            result.reason.as_deref().unwrap_or("unknown"),
        );
        std::process::exit(2);
    }
}

pub(crate) fn handle_feedback(args: Vec<OsString>) -> io::Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("record") => feedback_record(args[1..].to_vec()),
        Some("list") => feedback_list(args[1..].to_vec()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gensee feedback record --verdict <agree|allow|deny> [--gensee <action>] \
[--event-key <k>] [--tool-use-id <id>] [--session <s>] [--rule <r>] [--path <p>] [--label <l>] [--note <n>]\n\
       gensee feedback list [--json] [--limit <n>]",
        )),
    }
}

pub(crate) fn handle_gateway_alert(args: Vec<OsString>) -> io::Result<()> {
    let store = EventStore::default_local()?;
    append_gateway_alert(&store, &args)?;
    Ok(())
}

fn append_gateway_alert(store: &EventStore, args: &[OsString]) -> io::Result<()> {
    let flags = parse_named_flags(args, "gateway-alert")?;
    let session_id = flags
        .get("session-id")
        .cloned()
        .unwrap_or_else(|| "llm-gateway".to_string());
    let evidence = flags
        .get("evidence-json")
        .map(|value| serde_json::from_str::<Value>(value))
        .transpose()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .or_else(|| Some(json!({ "source": "llm_gateway" })));
    store.append_policy_alert(&PolicyAlert {
        session_id: Some(session_id),
        tool_use_id: flags.get("tool-use-id").cloned(),
        severity: flags
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "high".to_string()),
        action: flags
            .get("action")
            .cloned()
            .unwrap_or_else(|| "block".to_string()),
        rule_id: flags
            .get("rule-id")
            .cloned()
            .unwrap_or_else(|| "policy_prompt_steganography_detected".to_string()),
        message: flags.get("message").cloned().unwrap_or_else(|| {
            "LLM gateway detected suspicious prompt steganography markers".to_string()
        }),
        path: flags.get("path").cloned(),
        evidence,
        observed_at_ms: unix_millis()?,
    })
}

/// Parse `--key value` pairs into a map. Every flag requires a value.
fn parse_feedback_flags(
    args: &[OsString],
) -> io::Result<std::collections::HashMap<String, String>> {
    parse_named_flags(args, "feedback")
}

fn parse_named_flags(
    args: &[OsString],
    label: &str,
) -> io::Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label}: non-UTF8 argument"),
            )
        })?;
        let name = key.strip_prefix("--").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label}: unexpected argument '{key}'"),
            )
        })?;
        let value = args
            .get(index + 1)
            .and_then(|arg| arg.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{label}: missing value for --{name}"),
                )
            })?;
        map.insert(name.to_string(), value.to_string());
        index += 2;
    }
    Ok(map)
}

/// Derive the FP/FN/confirmed label from the shield action and human verdict
/// (mirrors the dashboard's verdictLabel so both write the same taxonomy).
fn derive_feedback_label(gensee: Option<&str>, verdict: &str) -> String {
    let gensee = gensee.unwrap_or("");
    match verdict {
        "agree" => "confirmed",
        "allow" if matches!(gensee, "deny" | "block" | "ask" | "warn") => "false_positive",
        "deny" if matches!(gensee, "allow" | "watch") => "false_negative",
        _ => "override",
    }
    .to_string()
}

fn feedback_record(args: Vec<OsString>) -> io::Result<()> {
    let opts = parse_feedback_flags(&args)?;
    let verdict = opts.get("verdict").cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "feedback record: --verdict <agree|allow|deny> is required",
        )
    })?;
    if !matches!(verdict.as_str(), "agree" | "allow" | "deny") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "feedback record: --verdict must be agree, allow, or deny",
        ));
    }
    let gensee_action = opts.get("gensee").cloned();
    let label = opts
        .get("label")
        .cloned()
        .unwrap_or_else(|| derive_feedback_label(gensee_action.as_deref(), &verdict));
    let is_manual_overturn = !matches!(label.as_str(), "confirmed");
    let gensee_action_for_telemetry = gensee_action.clone();
    let verdict_for_telemetry = verdict.clone();
    let label_for_telemetry = label.clone();

    let store = EventStore::default_local()?;
    let id = store.record_human_feedback(
        opts.get("event-key").cloned(),
        opts.get("tool-use-id").cloned(),
        opts.get("session").cloned(),
        gensee_action,
        verdict,
        Some(label),
        opts.get("rule").cloned(),
        opts.get("path").cloned(),
        opts.get("note").cloned(),
        unix_millis()?,
    )?;
    if is_manual_overturn {
        telemetry_record_dashboard_event(
            "dashboard_manual_overturn",
            json!({
                "gensee_action": gensee_action_for_telemetry.as_deref().unwrap_or("unknown"),
                "human_verdict": verdict_for_telemetry,
                "label": label_for_telemetry,
            }),
        );
    }
    println!("gensee feedback: recorded verdict #{id}");
    Ok(())
}

fn feedback_list(args: Vec<OsString>) -> io::Result<()> {
    let mut json = false;
    let mut limit: i64 = 50;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--json") => {
                json = true;
                index += 1;
            }
            Some("--limit") => {
                limit = args
                    .get(index + 1)
                    .and_then(|arg| arg.to_str())
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "feedback list: --limit needs a number",
                        )
                    })?;
                index += 2;
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "feedback list: unexpected argument {:?}",
                        other.unwrap_or("")
                    ),
                ))
            }
        }
    }

    let store = EventStore::default_local()?;
    let rows = store.human_feedback(limit)?;
    if json {
        let array = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "feedback_id": row.feedback_id,
                    "event_key": row.event_key,
                    "tool_use_id": row.tool_use_id,
                    "session_id": row.session_id,
                    "gensee_action": row.gensee_action,
                    "human_verdict": row.human_verdict,
                    "label": row.label,
                    "rule_id": row.rule_id,
                    "path": row.path,
                    "note": row.note,
                    "created_at": row.created_at,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string(&array)?);
    } else if rows.is_empty() {
        println!("gensee feedback: no verdicts recorded");
    } else {
        for row in &rows {
            println!(
                "#{} {} -> {} [{}] {} {}",
                row.feedback_id,
                row.gensee_action.as_deref().unwrap_or("-"),
                row.human_verdict,
                row.label.as_deref().unwrap_or("-"),
                row.path.as_deref().or(row.rule_id.as_deref()).unwrap_or(""),
                row.note.as_deref().unwrap_or(""),
            );
        }
    }
    Ok(())
}

fn dashboard_state() -> io::Result<()> {
    let store = EventStore::default_local()?;
    println!("{}", serde_json::to_string(&store.dashboard_state()?)?);
    Ok(())
}

pub(crate) fn ingest_eslogger() -> io::Result<()> {
    let store = EventStore::default_local()?;
    let mut count = 0_u64;
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('{') {
            continue;
        }

        let event = system_event_from_eslogger_line(line, unix_millis()?);
        store.append_system_event(&event)?;
        count += 1;
    }

    eprintln!("gensee: ingested {count} eslogger event(s)");
    Ok(())
}

pub(crate) fn handle_agent_hook(provider: &str) -> io::Result<()> {
    let mut payload = String::new();
    io::stdin().read_to_string(&mut payload)?;

    let event = build_hook_event(&payload, provider)?;

    // Fast path: if the warm daemon is up, hand off over its socket — PreToolUse
    // waits for the decision (warm eval, no per-call store open), observational
    // events fire-and-forget off the critical path. Falls through to the
    // in-process path if the daemon is unreachable, so enforcement never
    // silently disappears.
    if dispatch_via_daemon(&payload, &event) {
        return Ok(());
    }

    let store = EventStore::default_local()?;
    if let Some(decision_json) = process_hook_event(&payload, &event, &store)? {
        print!("{decision_json}");
    }
    Ok(())
}

/// Core per-event processing shared by the in-process path and the daemon.
/// Returns hook stdout JSON when the event produces output — the PreToolUse
/// decision, or a UserPromptSubmit `additionalContext` counter-instruction when
/// the memory/skill integrity scan finds poison — and `None` for events that
/// only record into the lineage store (PostToolUse, clean UserPromptSubmit, Stop).
pub(crate) fn process_hook_event(
    payload: &str,
    event: &AgentHookEvent,
    store: &EventStore,
) -> io::Result<Option<String>> {
    store.append_hook_event(event)?;

    if matches!(
        event.hook_event_name.as_deref(),
        Some("PreToolUse" | "PermissionRequest")
    ) {
        // Parse intents from the original (un-redacted) command so the redaction
        // placeholder cannot inject shell metacharacters into the parse; the
        // stored source_command is still the redacted form.
        let original_command = original_bash_command(payload);
        let file_intents = file_intents_from_hook(event, original_command.as_deref());
        for intent in &file_intents {
            store.append_file_intent(intent)?;
        }
        let decision = adapt_decision_for_provider(
            evaluate_pretool_policy_with_store(event, &file_intents, Some(store)),
            &event.provider,
        );
        telemetry_record_policy_event(event, &decision, &file_intents);
        for finding in &decision.findings {
            store.append_policy_alert(&finding.to_policy_alert(event))?;
        }
        if should_start_process_sampler(&decision) {
            start_process_sampler(event)?;
        }
        Ok(decision_json_for_provider(
            &decision,
            &event.provider,
            event.hook_event_name.as_deref().unwrap_or("PreToolUse"),
        ))
    } else if event.hook_event_name.as_deref() == Some("PostToolUse") {
        let original_command = original_bash_command(payload);
        record_write_time_artifact_observations(
            payload,
            event,
            original_command.as_deref(),
            store,
        )?;
        if event.provider == PROVIDER_ANTIGRAVITY {
            Ok(Some(json!({}).to_string()))
        } else {
            Ok(None)
        }
    } else if event.provider == PROVIDER_ANTIGRAVITY
        && event.hook_event_name.as_deref() == Some("PreInvocation")
    {
        let findings = memory_integrity_findings(event);
        let already_notified = event
            .session_id
            .as_deref()
            .map(|session_id| store.session_has_alert(session_id, "policy_memory_poison_detected"))
            .transpose()?
            .unwrap_or(false);
        if findings.is_empty() || already_notified {
            Ok(Some(json!({}).to_string()))
        } else {
            for finding in &findings {
                store.append_policy_alert(&finding.to_policy_alert(event))?;
            }
            Ok(Some(antigravity_preinvocation_poison_json()))
        }
    } else if event.hook_event_name.as_deref() == Some("UserPromptSubmit") {
        // Session-integrity scan for context-injected poison. The framework
        // auto-loads CLAUDE.md/MEMORY.md/SOUL.md and skills into the prompt
        // without a tool call, so PreToolUse can't see it; scan those files
        // directly before the turn runs. Non-blocking: RETURN a counter-
        // instruction (additionalContext) so the turn still runs and the
        // PreToolUse rules hard-block the actual harmful action downstream.
        // Returning it (vs printing) lets the daemon path serve it too.
        let findings = memory_integrity_findings(event);
        let already_notified = event
            .session_id
            .as_deref()
            .map(|session_id| store.session_has_alert(session_id, "policy_memory_poison_detected"))
            .transpose()?
            .unwrap_or(false);
        if already_notified {
            return Ok(None);
        }
        if findings.is_empty() {
            Ok(None)
        } else {
            for finding in &findings {
                store.append_policy_alert(&finding.to_policy_alert(event))?;
            }
            // VS Code surfaces `systemMessage` to the user in chat regardless of
            // `continue`; use it so the poison notice is visible. Claude Code
            // injects `additionalContext` for the model instead.
            if event.provider == PROVIDER_VSCODE {
                Ok(Some(vscode_userpromptsubmit_poison_json()))
            } else if event.provider == PROVIDER_CURSOR {
                Ok(Some(cursor_beforesubmitprompt_poison_json()))
            } else {
                Ok(Some(userprompt_poison_context_json()))
            }
        }
    } else if event.provider == PROVIDER_ANTIGRAVITY
        && event.hook_event_name.as_deref() == Some("Stop")
    {
        Ok(Some(json!({ "decision": "allow" }).to_string()))
    } else {
        Ok(None)
    }
}

pub(crate) fn required_arg_value(args: &[OsString], name: &str) -> io::Result<String> {
    arg_value(args, name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing required argument {name}"),
        )
    })
}

pub(crate) fn optional_arg_u64(args: &[OsString], name: &str) -> Option<u64> {
    arg_value(args, name)?.parse().ok()
}

pub(crate) fn arg_value(args: &[OsString], name: &str) -> Option<String> {
    args.windows(2).find_map(|window| {
        if window[0].to_str() == Some(name) {
            window[1].to_str().map(ToString::to_string)
        } else {
            None
        }
    })
}

pub(crate) fn arg_values(args: &[OsString], name: &str) -> Vec<String> {
    args.windows(2)
        .filter_map(|window| {
            if window[0].to_str() == Some(name) {
                window[1].to_str().map(ToString::to_string)
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn has_arg(args: &[OsString], name: &str) -> bool {
    args.iter().any(|arg| arg.to_str() == Some(name))
}

pub(crate) fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join(".git").exists() {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

pub(crate) fn unix_millis() -> io::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    Ok(duration.as_millis() as u64)
}

pub(crate) fn one_line(value: &str) -> String {
    let text = value.replace('\n', "\\n").replace('\r', "\\r");
    const DISPLAY_CHARS: usize = 160;
    const ELLIPSIS: &str = "...";

    if text.chars().count() > DISPLAY_CHARS {
        let mut shortened = text
            .chars()
            .take(DISPLAY_CHARS - ELLIPSIS.chars().count())
            .collect::<String>();
        shortened.push_str(ELLIPSIS);
        shortened
    } else {
        text
    }
}

pub(crate) fn option_u32_display(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn print_usage() {
    println!(
        "gensee\n\nUSAGE:\n  gensee run [--runtime local|tclone] [--sandbox none|mac|linux] [--profile cautious] [--workspace-mode direct|staged] [--workspace <path>] [--linux-seccomp|--no-linux-seccomp] [--linux-fanotify] [--linux-network off|allowlist|deny-all|monitor] [--allow-net <ip-or-cidr>]... [--deny-net <ip-or-cidr>]... -- <agent> [args...]\n  gensee run fork <run_id> [--copies N] [--name <prefix>] [--attach tmux:right|tmux:below] [--json]\n  gensee run fork-status <job-id> [--json]\n  gensee run shell <run_id-or-container>\n  gensee run attach <run_id-or-container> [--tmux right|below]\n  gensee run send <run_id-or-container> [--no-enter] -- <prompt>\n  gensee run exec <run_id-or-container> [--json] -- <command> [args...]\n  gensee run diff <run_id-or-container>\n  gensee run merge <fork-id> --into <source-id> [--git|--filesystem|--paths <path>...] [--dry-run] [--force]\n  gensee run switch <fork-id>\n  gensee run keep <run_id-or-container> --to <path>\n  gensee run discard <session_id-or-tclone-run>\n  gensee run delete <tclone-run-or-container>|--all\n  gensee watch [--workspace <path>] [--watch-root <path>]... [--backend auto|fsevents|snapshot] [--system-events none|eslogger] [--no-sensitive-roots] [--duration-seconds <seconds>] [--interval-ms <ms>]\n  gensee watch --pid <pid> [--session-id <id>] [--linux-fanotify] [--duration-seconds <seconds>] [--interval-ms <ms>]\n  gensee run list\n  gensee setup claude-code [--gensee-home <path>]\n  gensee setup codex [--gensee-home <path>]\n  gensee setup antigravity [--gensee-home <path>]\n  gensee setup vscode [--gensee-home <path>]\n  gensee setup cursor [--gensee-home <path>]\n  gensee hook claude-code\n  gensee hook codex\n  gensee hook antigravity\n  gensee hook vscode\n  gensee hook cursor\n  gensee ingest eslogger\n  gensee verify-log\n  gensee dashboard-state\n  gensee gateway-alert --session-id <s> [--action <block|warn>] [--evidence-json <json>]\n  gensee telemetry [status|enable|disable|enable-collection|disable-collection|flush]\n  gensee policy [print-default | path | validate <file> | init | setup | get <key> | set <key> <value>]\n  gensee status --json\n  gensee debug [plan|fanotify-plan|fanotify-once|seccomp-profile|network-plan|network-apply] [--json]\n  gensee feedback record --verdict <agree|allow|deny> [--gensee <action>] [--event-key <k>] [--note <n>]\n  gensee feedback list [--json] [--limit <n>]\n  gensee timeline [--latest | --session <session_id> | --path <substring>]\n\nEXAMPLES:\n  gensee setup claude-code\n  gensee setup codex\n  gensee setup antigravity\n  gensee setup vscode\n  gensee setup cursor\n  gensee status --json\n  gensee policy setup\n  gensee watch --workspace . --watch-root ~/Downloads\n  sudo gensee watch --pid $$ --linux-fanotify --duration-seconds 10\n  gensee run --sandbox mac --profile cautious --workspace-mode staged -- claude\n  sudo gensee run --sandbox linux --linux-fanotify -- codex\n  gensee run --runtime tclone -- codex\n  gensee run fork run_123 --copies 2 --attach tmux:right --json\n  gensee run fork-status run_123_456 --json\n  gensee run shell run_123_fork_0\n  gensee run attach run_123_fork_0 --tmux right\n  gensee run send run_123_fork_0 -- 'Run cargo test and fix failures'\n  gensee run exec run_123_fork_0 -- bash -lc 'cargo test'\n  gensee run merge run_123_fork_0 --into run_123\n  gensee run switch run_123_fork_0\n  gensee run delete --all\n  gensee run --workspace-mode staged -- omnigent run path/to/agent.yaml\n\nCOMPATIBILITY:\n  gensee fork <run_id> [--copies N] [--name <prefix>]\n  gensee session list\n  gensee linux ..."
    );
}
