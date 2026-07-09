use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::policy::{LinuxNetworkMode, LinuxNetworkPolicy};
use crate::procfs::{is_descendant_or_self, read_parent_by_pid};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkEnforcementConfig {
    pub session_id: String,
    pub root_pid: Option<u32>,
    pub cgroup_path: String,
    pub network: LinuxNetworkPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkEnforcementPlan {
    pub cgroup: LinuxCgroupAttachPlan,
    pub nftables: LinuxNftablesPlan,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxCgroupAttachPlan {
    pub cgroup_path: String,
    pub root_pid: Option<u32>,
    pub process_ids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNftablesPlan {
    pub table_name: String,
    pub chain_name: String,
    pub cgroup_path: String,
    pub mode: LinuxNetworkMode,
    pub destinations: Vec<LinuxNftablesDestination>,
    pub denied_destinations: Vec<LinuxNftablesDestination>,
    pub script: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNftablesDestination {
    pub value: String,
    pub family: LinuxNftablesAddressFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxNftablesAddressFamily {
    Ipv4,
    Ipv6,
}

impl LinuxNetworkEnforcementConfig {
    pub fn new(session_id: impl Into<String>, network: LinuxNetworkPolicy) -> Self {
        let session_id = session_id.into();
        Self {
            cgroup_path: default_agent_cgroup_path(&session_id)
                .to_string_lossy()
                .to_string(),
            session_id,
            root_pid: None,
            network,
        }
    }
}

pub fn default_agent_cgroup_path(session_id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
        .join("gensee")
        .join(sanitize_nft_identifier(session_id))
}

pub fn plan_nftables_policy(config: &LinuxNetworkEnforcementConfig) -> LinuxNetworkEnforcementPlan {
    let mut warnings = Vec::new();
    let process_ids = match config.root_pid {
        Some(root_pid) => match collect_process_tree(root_pid) {
            Ok(process_ids) => process_ids,
            Err(error) => {
                warnings.push(format!("could not inspect process tree: {error}"));
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let cgroup = LinuxCgroupAttachPlan {
        cgroup_path: config.cgroup_path.clone(),
        root_pid: config.root_pid,
        process_ids,
    };
    let nftables = build_nftables_plan(config);
    warnings.extend(nftables.warnings.clone());

    LinuxNetworkEnforcementPlan {
        cgroup,
        nftables,
        warnings,
    }
}

pub fn build_nftables_plan(config: &LinuxNetworkEnforcementConfig) -> LinuxNftablesPlan {
    let table_name = format!("gensee_{}", sanitize_nft_identifier(&config.session_id));
    let chain_name = "egress".to_string();
    let mut destinations = Vec::new();
    let mut denied_destinations = Vec::new();
    let mut warnings = Vec::new();

    for denied in &config.network.denied_hosts {
        match parse_destination(denied) {
            Some(destination) => denied_destinations.push(destination),
            None => warnings.push(format!(
                "nftables network enforcement currently requires IP/CIDR denied destinations; skipped `{denied}`"
            )),
        }
    }

    for allowed in &config.network.allowed_hosts {
        match parse_destination(allowed) {
            Some(destination) => destinations.push(destination),
            None => warnings.push(format!(
                "nftables network enforcement currently requires IP/CIDR destinations; skipped `{allowed}`"
            )),
        }
    }

    let script = nftables_script(
        &table_name,
        &chain_name,
        &relative_cgroup_path(&config.cgroup_path),
        config.network.mode,
        &destinations,
        &denied_destinations,
    );

    LinuxNftablesPlan {
        table_name,
        chain_name,
        cgroup_path: config.cgroup_path.clone(),
        mode: config.network.mode,
        destinations,
        denied_destinations,
        script,
        warnings,
    }
}

pub fn collect_process_tree(root_pid: u32) -> io::Result<Vec<u32>> {
    let parent_by_pid = read_parent_by_pid()?;
    let mut pids = parent_by_pid
        .keys()
        .copied()
        .filter(|pid| is_descendant_or_self(*pid, root_pid, &parent_by_pid))
        .collect::<Vec<_>>();
    if !pids.contains(&root_pid) && Path::new("/proc").join(root_pid.to_string()).exists() {
        pids.push(root_pid);
    }
    pids.sort_unstable();
    Ok(pids)
}

#[cfg(target_os = "linux")]
pub fn attach_process_tree_to_cgroup(root_pid: u32, cgroup_path: &Path) -> io::Result<Vec<u32>> {
    create_agent_cgroup(cgroup_path)?;
    let pids = collect_process_tree(root_pid)?;
    for pid in &pids {
        std::fs::write(cgroup_path.join("cgroup.procs"), format!("{pid}\n"))?;
    }
    Ok(pids)
}

#[cfg(not(target_os = "linux"))]
pub fn attach_process_tree_to_cgroup(_root_pid: u32, _cgroup_path: &Path) -> io::Result<Vec<u32>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup network enforcement is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
pub fn create_agent_cgroup(cgroup_path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(cgroup_path)
}

#[cfg(not(target_os = "linux"))]
pub fn create_agent_cgroup(_cgroup_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup network enforcement is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
pub fn attach_current_process_to_cgroup(cgroup_path: &Path) -> io::Result<()> {
    create_agent_cgroup(cgroup_path)?;
    std::fs::write(
        cgroup_path.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn attach_current_process_to_cgroup(_cgroup_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup network enforcement is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
pub fn apply_nftables_script(script: &str) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if script.trim().is_empty() {
        return Ok(());
    }

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "nft stdin unavailable"))?
        .write_all(script.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("nft exited with status {status}")))
    }
}

#[cfg(target_os = "linux")]
pub fn delete_nftables_table(table_name: &str) -> io::Result<()> {
    use std::process::Command;

    let status = Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(table_name)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("nft exited with status {status}")))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn delete_nftables_table(_table_name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nftables network enforcement is only available on Linux",
    ))
}

#[cfg(target_os = "linux")]
pub fn remove_agent_cgroup(cgroup_path: &Path) -> io::Result<()> {
    std::fs::remove_dir(cgroup_path)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_cgroup(_cgroup_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup network enforcement is only available on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_nftables_script(_script: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nftables network enforcement is only available on Linux",
    ))
}

pub fn validate_nftables_plan_for_apply(plan: &LinuxNftablesPlan) -> io::Result<()> {
    if !plan.warnings.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot apply nftables policy with unsupported destinations: {}",
                plan.warnings.join("; ")
            ),
        ));
    }
    if plan.mode == LinuxNetworkMode::AllowListed && plan.destinations.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux network allowlist mode requires at least one IP/CIDR destination",
        ));
    }
    Ok(())
}

fn nftables_script(
    table_name: &str,
    chain_name: &str,
    cgroup_path: &str,
    mode: LinuxNetworkMode,
    destinations: &[LinuxNftablesDestination],
    denied_destinations: &[LinuxNftablesDestination],
) -> String {
    let cgroup_match = format!(
        "socket cgroupv2 level 2 \"{}\"",
        escape_nft_string(cgroup_path)
    );
    if mode == LinuxNetworkMode::Off {
        return String::new();
    }

    let mut lines = vec![
        format!("table inet {table_name} {{"),
        format!("  chain {chain_name} {{"),
        "    type filter hook output priority filter; policy accept;".to_string(),
    ];

    for destination in denied_destinations {
        match destination.family {
            LinuxNftablesAddressFamily::Ipv4 => lines.push(format!(
                "    {cgroup_match} ip daddr {} reject with icmpx admin-prohibited",
                destination.value
            )),
            LinuxNftablesAddressFamily::Ipv6 => lines.push(format!(
                "    {cgroup_match} ip6 daddr {} reject with icmpx admin-prohibited",
                destination.value
            )),
        }
    }

    if mode == LinuxNetworkMode::Monitor {
        lines.push("  }".to_string());
        lines.push("}".to_string());
        return format!("{}\n", lines.join("\n"));
    }

    for destination in destinations {
        match destination.family {
            LinuxNftablesAddressFamily::Ipv4 => lines.push(format!(
                "    {cgroup_match} ip daddr {} accept",
                destination.value
            )),
            LinuxNftablesAddressFamily::Ipv6 => lines.push(format!(
                "    {cgroup_match} ip6 daddr {} accept",
                destination.value
            )),
        }
    }
    lines.push(format!(
        "    {cgroup_match} reject with icmpx admin-prohibited"
    ));
    lines.push("  }".to_string());
    lines.push("}".to_string());
    format!("{}\n", lines.join("\n"))
}

fn parse_destination(value: &str) -> Option<LinuxNftablesDestination> {
    let address = value.split_once('/').map(|(addr, _)| addr).unwrap_or(value);
    let ip = address.parse::<IpAddr>().ok()?;
    let family = match ip {
        IpAddr::V4(_) => LinuxNftablesAddressFamily::Ipv4,
        IpAddr::V6(_) => LinuxNftablesAddressFamily::Ipv6,
    };
    Some(LinuxNftablesDestination {
        value: value.to_string(),
        family,
    })
}

fn relative_cgroup_path(path: &str) -> String {
    path.strip_prefix("/sys/fs/cgroup/")
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_string()
}

fn sanitize_nft_identifier(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        output.push_str("agent");
    }
    if output.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        output.insert(0, '_');
    }
    output
}

fn escape_nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_cgroup_path_with_safe_session_id() {
        assert_eq!(
            default_agent_cgroup_path("agent/session 1"),
            PathBuf::from("/sys/fs/cgroup/gensee/agent_session_1")
        );
    }

    #[test]
    fn plans_nftables_allowlist_and_skips_hostnames() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::AllowListed,
                allowed_hosts: vec![
                    "1.2.3.4".to_string(),
                    "2001:db8::/32".to_string(),
                    "example.com".to_string(),
                ],
                denied_hosts: vec!["169.254.169.254".to_string()],
            },
        );

        let plan = build_nftables_plan(&config);

        assert_eq!(plan.destinations.len(), 2);
        assert_eq!(plan.denied_destinations.len(), 1);
        assert_eq!(plan.warnings.len(), 1);
        assert!(validate_nftables_plan_for_apply(&plan).is_err());
        assert!(plan.script.contains("socket cgroupv2 level 2"));
        assert!(plan
            .script
            .contains("ip daddr 169.254.169.254 reject with icmpx admin-prohibited"));
        assert!(plan.script.contains("ip daddr 1.2.3.4 accept"));
        assert!(plan.script.contains("ip6 daddr 2001:db8::/32 accept"));
        assert!(plan.script.contains("reject with icmpx admin-prohibited"));
    }

    #[test]
    fn rejects_apply_for_empty_allowlist() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::AllowListed,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);
        let error = validate_nftables_plan_for_apply(&plan).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("allowlist"));
    }

    #[test]
    fn allows_apply_for_ip_only_denylist_monitor_mode() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
                allowed_hosts: Vec::new(),
                denied_hosts: vec!["169.254.169.254".to_string()],
            },
        );

        let plan = build_nftables_plan(&config);

        validate_nftables_plan_for_apply(&plan).unwrap();
        assert!(plan
            .script
            .contains("ip daddr 169.254.169.254 reject with icmpx admin-prohibited"));
    }

    #[test]
    fn monitor_mode_generates_no_reject_rule() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);

        assert!(!plan.script.contains("reject with"));
    }

    #[test]
    fn off_mode_generates_no_script() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Off,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);

        assert!(plan.script.is_empty());
    }
}
