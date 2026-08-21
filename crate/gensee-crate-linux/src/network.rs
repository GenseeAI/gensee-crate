use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::policy::{LinuxNetworkMode, LinuxNetworkPolicy, LinuxNetworkProtocol};
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
    pub endpoint_counters: Vec<LinuxNftablesEndpointCounter>,
    pub block_counters: Vec<LinuxNftablesBlockCounter>,
    pub script: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNftablesDestination {
    pub value: String,
    pub family: LinuxNftablesAddressFamily,
    pub protocol: Option<LinuxNetworkProtocol>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNftablesEndpointCounter {
    pub name: String,
    pub destination: String,
    pub protocol: LinuxNetworkProtocol,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkEndpointEvent {
    pub table_name: String,
    pub counter_name: String,
    pub destination: String,
    pub protocol: LinuxNetworkProtocol,
    pub ports: Vec<u16>,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxNftablesAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNftablesBlockCounter {
    pub name: String,
    pub destination: Option<String>,
    pub reason: LinuxNetworkBlockReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinuxNetworkBlockReason {
    DeniedDestination,
    DefaultReject,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkBlockEvent {
    pub table_name: String,
    pub counter_name: String,
    pub destination: Option<String>,
    pub reason: LinuxNetworkBlockReason,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxNetworkAttemptEvent {
    pub trace_id: String,
    pub table_name: String,
    pub chain_name: String,
    pub destination: String,
    pub protocol: LinuxNetworkProtocol,
    pub port: u16,
}

#[cfg(target_os = "linux")]
pub struct LinuxNetworkAttemptMonitor {
    child: std::process::Child,
    receiver: std::sync::mpsc::Receiver<LinuxNetworkAttemptEvent>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    exited: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_os = "linux")]
impl LinuxNetworkAttemptMonitor {
    pub fn drain(&self) -> (Vec<LinuxNetworkAttemptEvent>, u64, bool) {
        use std::sync::atomic::Ordering;
        let events = self.receiver.try_iter().collect();
        let dropped = self.dropped.swap(0, Ordering::AcqRel);
        let exited = self.exited.load(Ordering::Acquire);
        (events, dropped, exited)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxNetworkAttemptMonitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    let table_name = nft_table_name(&config.session_id);
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
    for endpoint in &config.network.allowed_endpoints {
        match parse_destination(&endpoint.destination) {
            Some(mut destination) if !endpoint.ports.is_empty() => {
                destination.protocol = Some(endpoint.protocol);
                destination.ports = endpoint.ports.clone();
                destination.ports.sort_unstable();
                destination.ports.dedup();
                destinations.push(destination);
            }
            _ => warnings.push(format!(
                "nftables endpoint enforcement requires an IP/CIDR destination and at least one port; skipped `{}`",
                endpoint.destination
            )),
        }
    }

    let block_counters = block_counters(config.network.mode, &denied_destinations);
    let endpoint_counters = destinations
        .iter()
        .filter_map(|destination| {
            destination
                .protocol
                .map(|protocol| LinuxNftablesEndpointCounter {
                    name: format!(
                        "allow_{}",
                        destination_counter_index(&destinations, destination)
                    ),
                    destination: destination.value.clone(),
                    protocol,
                    ports: destination.ports.clone(),
                })
        })
        .collect::<Vec<_>>();
    let script = nftables_script(
        &table_name,
        &chain_name,
        &relative_cgroup_path(&config.cgroup_path),
        config.network.mode,
        &destinations,
        &denied_destinations,
        &block_counters,
        &endpoint_counters,
    );

    LinuxNftablesPlan {
        table_name,
        chain_name,
        cgroup_path: config.cgroup_path.clone(),
        mode: config.network.mode,
        destinations,
        denied_destinations,
        endpoint_counters,
        block_counters,
        script,
        warnings,
    }
}

pub fn bind_nftables_plan_to_source_address(plan: &mut LinuxNftablesPlan, source_address: IpAddr) {
    let source_match = match source_address {
        IpAddr::V4(address) => format!("ip saddr {address}"),
        IpAddr::V6(address) => format!("ip6 saddr {address}"),
    };
    plan.script = nftables_script_with_match(
        &plan.table_name,
        &plan.chain_name,
        &source_match,
        "forward",
        plan.mode,
        &plan.destinations,
        &plan.denied_destinations,
        &plan.block_counters,
        &plan.endpoint_counters,
    );
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
fn trusted_nft_binary() -> io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
        let path = PathBuf::from(candidate);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && path.ancestors().skip(1).all(|ancestor| {
                std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
                })
            })
        {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "no root-owned, non-writable nft binary found in a trusted system path",
    ))
}

#[cfg(target_os = "linux")]
pub fn start_nftables_attempt_monitor(
    plan: &LinuxNftablesPlan,
) -> io::Result<LinuxNetworkAttemptMonitor> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    };

    let mut child = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
        .args(["-nn", "monitor", "trace"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "nft trace monitor stdout unavailable",
        )
    })?;
    let (sender, receiver) = mpsc::sync_channel(1024);
    let dropped = Arc::new(AtomicU64::new(0));
    let exited = Arc::new(AtomicBool::new(false));
    let thread_dropped = Arc::clone(&dropped);
    let thread_exited = Arc::clone(&exited);
    let table_name = plan.table_name.clone();
    let table_prefix = table_name
        .rsplit_once('_')
        .filter(|(_, generation)| generation.bytes().all(|byte| byte.is_ascii_digit()))
        .map(|(prefix, _)| format!("{prefix}_"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "nftables operation table is missing its numeric generation",
            )
        })?;
    let chain_name = plan.chain_name.clone();
    std::thread::Builder::new()
        .name(format!("gensee-nft-trace-{table_name}"))
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let Some(event) =
                    parse_nft_trace_attempt_for_prefix(&line, &table_prefix, &chain_name)
                else {
                    continue;
                };
                if sender.try_send(event).is_err() {
                    thread_dropped.fetch_add(1, Ordering::AcqRel);
                }
            }
            thread_exited.store(true, Ordering::Release);
        })?;
    Ok(LinuxNetworkAttemptMonitor {
        child,
        receiver,
        dropped,
        exited,
    })
}

#[cfg(test)]
fn parse_nft_trace_attempt(
    line: &str,
    expected_table: &str,
    expected_chain: &str,
) -> Option<LinuxNetworkAttemptEvent> {
    parse_nft_trace_attempt_inner(line, expected_table, expected_chain, false)
}

#[cfg(any(target_os = "linux", test))]
fn parse_nft_trace_attempt_for_prefix(
    line: &str,
    expected_table_prefix: &str,
    expected_chain: &str,
) -> Option<LinuxNetworkAttemptEvent> {
    parse_nft_trace_attempt_inner(line, expected_table_prefix, expected_chain, true)
}

#[cfg(any(target_os = "linux", test))]
fn parse_nft_trace_attempt_inner(
    line: &str,
    expected_table: &str,
    expected_chain: &str,
    table_is_prefix: bool,
) -> Option<LinuxNetworkAttemptEvent> {
    if line.len() > 64 * 1024 {
        return None;
    }
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 10
        || fields.first().copied() != Some("trace")
        || fields.get(1).copied() != Some("id")
        || fields.get(6).copied() != Some("packet:")
    {
        return None;
    }
    let table = *fields.get(4)?;
    if if table_is_prefix {
        let suffix = table.strip_prefix(expected_table)?;
        suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        table != expected_table
    } {
        return None;
    }
    let chain = *fields.get(5)?;
    if chain != expected_chain && chain != format!("{expected_chain}_input") {
        return None;
    }
    let destination = fields.windows(3).find_map(|values| {
        (matches!(values[0], "ip" | "ip6") && values[1] == "daddr").then_some(values[2])
    })?;
    let destination = destination.parse::<IpAddr>().ok()?.to_string();
    let (protocol, port) = fields.windows(3).find_map(|values| {
        let protocol = match values[0] {
            "tcp" => LinuxNetworkProtocol::Tcp,
            "udp" => LinuxNetworkProtocol::Udp,
            _ => return None,
        };
        (values[1] == "dport")
            .then(|| values[2].parse::<u16>().ok().map(|port| (protocol, port)))
            .flatten()
    })?;
    Some(LinuxNetworkAttemptEvent {
        trace_id: fields.get(2)?.to_string(),
        table_name: table.to_string(),
        chain_name: chain.to_string(),
        destination,
        protocol,
        port,
    })
}

#[cfg(target_os = "linux")]
pub fn apply_nftables_script(script: &str) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if script.trim().is_empty() {
        return Ok(());
    }

    let mut child = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
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

    let status = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
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

#[cfg(target_os = "linux")]
pub fn delete_nftables_table_if_exists(table_name: &str) -> io::Result<()> {
    use std::process::Command;

    let output = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
        .arg("-j")
        .arg("list")
        .arg("tables")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft list tables exited with status {}",
            output.status
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nftables table list: {error}"),
        )
    })?;
    let exists = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.get("table").is_some_and(|table| {
                    table.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && table.get("name").and_then(serde_json::Value::as_str) == Some(table_name)
                })
            })
        });
    if exists {
        delete_nftables_table(table_name)
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn delete_nftables_table(_table_name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nftables network enforcement is only available on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn delete_nftables_table_if_exists(_table_name: &str) -> io::Result<()> {
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

#[cfg(target_os = "linux")]
pub fn read_nftables_block_events(
    plan: &LinuxNftablesPlan,
) -> io::Result<Vec<LinuxNetworkBlockEvent>> {
    use std::process::Command;

    if plan.block_counters.is_empty() {
        return Ok(Vec::new());
    }

    let output = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
        .arg("-j")
        .arg("list")
        .arg("counters")
        .arg("table")
        .arg("inet")
        .arg(&plan.table_name)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft exited with status {}",
            output.status
        )));
    }

    parse_nftables_counter_json(plan, &output.stdout)
}

#[cfg(target_os = "linux")]
pub fn read_nftables_endpoint_events(
    plan: &LinuxNftablesPlan,
) -> io::Result<Vec<LinuxNetworkEndpointEvent>> {
    use std::process::Command;

    if plan.endpoint_counters.is_empty() {
        return Ok(Vec::new());
    }
    let output = Command::new(trusted_nft_binary()?)
        .env_clear()
        .env("LANG", "C")
        .arg("-j")
        .arg("list")
        .arg("counters")
        .arg("table")
        .arg("inet")
        .arg(&plan.table_name)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft exited with status {}",
            output.status
        )));
    }
    parse_nftables_endpoint_json(plan, &output.stdout)
}

#[cfg(not(target_os = "linux"))]
pub fn read_nftables_endpoint_events(
    _plan: &LinuxNftablesPlan,
) -> io::Result<Vec<LinuxNetworkEndpointEvent>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nftables network enforcement is only available on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn read_nftables_block_events(
    _plan: &LinuxNftablesPlan,
) -> io::Result<Vec<LinuxNetworkBlockEvent>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "nftables network enforcement is only available on Linux",
    ))
}

#[allow(clippy::too_many_arguments)]
fn nftables_script(
    table_name: &str,
    chain_name: &str,
    cgroup_path: &str,
    mode: LinuxNetworkMode,
    destinations: &[LinuxNftablesDestination],
    denied_destinations: &[LinuxNftablesDestination],
    block_counters: &[LinuxNftablesBlockCounter],
    endpoint_counters: &[LinuxNftablesEndpointCounter],
) -> String {
    let cgroup_match = format!(
        "socket cgroupv2 level {} \"{}\"",
        cgroup_path
            .split('/')
            .filter(|part| !part.is_empty())
            .count(),
        escape_nft_string(cgroup_path)
    );
    nftables_script_with_match(
        table_name,
        chain_name,
        &cgroup_match,
        "output",
        mode,
        destinations,
        denied_destinations,
        block_counters,
        endpoint_counters,
    )
}

#[allow(clippy::too_many_arguments)]
fn nftables_script_with_match(
    table_name: &str,
    chain_name: &str,
    subject_match: &str,
    hook: &str,
    mode: LinuxNetworkMode,
    destinations: &[LinuxNftablesDestination],
    denied_destinations: &[LinuxNftablesDestination],
    block_counters: &[LinuxNftablesBlockCounter],
    endpoint_counters: &[LinuxNftablesEndpointCounter],
) -> String {
    if mode == LinuxNetworkMode::Off {
        return String::new();
    }

    let mut lines = vec![format!("table inet {table_name} {{")];
    for counter in block_counters {
        lines.push(format!("  counter {} {{}}", counter.name));
    }
    for counter in endpoint_counters {
        lines.push(format!("  counter {} {{}}", counter.name));
    }
    append_nftables_chain(
        &mut lines,
        chain_name,
        subject_match,
        hook,
        mode,
        destinations,
        denied_destinations,
        block_counters,
        endpoint_counters,
    );
    // A private bridge sends remote traffic through `forward`, but traffic to
    // services on the host itself traverses `input`. Apply the identical exact
    // allowlist and default reject to both paths for capability cells.
    if hook == "forward" {
        append_nftables_chain(
            &mut lines,
            &format!("{chain_name}_input"),
            subject_match,
            "input",
            mode,
            destinations,
            denied_destinations,
            block_counters,
            endpoint_counters,
        );
    }
    lines.push("}".to_string());
    format!("{}\n", lines.join("\n"))
}

#[allow(clippy::too_many_arguments)]
fn append_nftables_chain(
    lines: &mut Vec<String>,
    chain_name: &str,
    subject_match: &str,
    hook: &str,
    mode: LinuxNetworkMode,
    destinations: &[LinuxNftablesDestination],
    denied_destinations: &[LinuxNftablesDestination],
    block_counters: &[LinuxNftablesBlockCounter],
    endpoint_counters: &[LinuxNftablesEndpointCounter],
) {
    lines.push(format!("  chain {chain_name} {{"));
    lines.push(format!(
        "    type filter hook {hook} priority filter; policy accept;"
    ));
    for (index, destination) in denied_destinations.iter().enumerate() {
        let counter_name = block_counters
            .iter()
            .find(|counter| {
                counter.reason == LinuxNetworkBlockReason::DeniedDestination
                    && counter.destination.as_deref() == Some(destination.value.as_str())
            })
            .map(|counter| counter.name.clone())
            .unwrap_or_else(|| denied_counter_name(index));
        let address = match destination.family {
            LinuxNftablesAddressFamily::Ipv4 => "ip daddr",
            LinuxNftablesAddressFamily::Ipv6 => "ip6 daddr",
        };
        lines.push(format!(
            "    {subject_match} {address} {} meta nftrace set 1 counter name {counter_name} reject with icmpx admin-prohibited",
            destination.value
        ));
    }
    if mode != LinuxNetworkMode::Monitor {
        for destination in destinations {
            let address = match destination.family {
                LinuxNftablesAddressFamily::Ipv4 => "ip daddr",
                LinuxNftablesAddressFamily::Ipv6 => "ip6 daddr",
            };
            if let Some(protocol) = destination.protocol {
                let counter = endpoint_counters
                    .iter()
                    .find(|counter| {
                        counter.destination == destination.value
                            && counter.protocol == protocol
                            && counter.ports == destination.ports
                    })
                    .expect("endpoint destination always has a counter");
                let protocol_name = match protocol {
                    LinuxNetworkProtocol::Tcp => "tcp",
                    LinuxNetworkProtocol::Udp => "udp",
                };
                let ports = if destination.ports.len() == 1 {
                    destination.ports[0].to_string()
                } else {
                    format!(
                        "{{ {} }}",
                        destination
                            .ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                lines.push(format!(
                    "    {subject_match} {address} {} meta l4proto {protocol_name} {protocol_name} dport {ports} counter name {} accept",
                    destination.value, counter.name
                ));
            } else {
                lines.push(format!(
                    "    {subject_match} {address} {} accept",
                    destination.value
                ));
            }
        }
        let default_counter_name = block_counters
            .iter()
            .find(|counter| counter.reason == LinuxNetworkBlockReason::DefaultReject)
            .map(|counter| counter.name.as_str())
            .unwrap_or(DEFAULT_REJECT_COUNTER);
        lines.push(format!(
            "    {subject_match} meta nftrace set 1 counter name {default_counter_name} reject with icmpx admin-prohibited"
        ));
    }
    lines.push("  }".to_string());
}

fn destination_counter_index(
    destinations: &[LinuxNftablesDestination],
    target: &LinuxNftablesDestination,
) -> usize {
    destinations
        .iter()
        .filter(|destination| destination.protocol.is_some())
        .position(|destination| std::ptr::eq(destination, target))
        .unwrap_or(0)
}

fn block_counters(
    mode: LinuxNetworkMode,
    denied_destinations: &[LinuxNftablesDestination],
) -> Vec<LinuxNftablesBlockCounter> {
    let mut counters = denied_destinations
        .iter()
        .enumerate()
        .map(|(index, destination)| LinuxNftablesBlockCounter {
            name: denied_counter_name(index),
            destination: Some(destination.value.clone()),
            reason: LinuxNetworkBlockReason::DeniedDestination,
        })
        .collect::<Vec<_>>();
    if matches!(
        mode,
        LinuxNetworkMode::AllowListed | LinuxNetworkMode::DenyAll
    ) {
        counters.push(LinuxNftablesBlockCounter {
            name: DEFAULT_REJECT_COUNTER.to_string(),
            destination: None,
            reason: LinuxNetworkBlockReason::DefaultReject,
        });
    }
    counters
}

fn denied_counter_name(index: usize) -> String {
    format!("deny_{index}")
}

#[cfg(any(target_os = "linux", test))]
fn parse_nftables_counter_json(
    plan: &LinuxNftablesPlan,
    data: &[u8],
) -> io::Result<Vec<LinuxNetworkBlockEvent>> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nftables counter JSON: {error}"),
        )
    })?;
    let entries = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing nftables array"))?;
    let mut events = Vec::new();
    for entry in entries {
        let Some(counter) = entry.get("counter") else {
            continue;
        };
        let Some(name) = counter.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(planned) = plan
            .block_counters
            .iter()
            .find(|planned| planned.name == name)
        else {
            continue;
        };
        let packets = counter
            .get("packets")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let bytes = counter
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if packets == 0 && bytes == 0 {
            continue;
        }
        events.push(LinuxNetworkBlockEvent {
            table_name: plan.table_name.clone(),
            counter_name: name.to_string(),
            destination: planned.destination.clone(),
            reason: planned.reason,
            packets,
            bytes,
        });
    }
    Ok(events)
}

#[cfg(any(target_os = "linux", test))]
fn parse_nftables_endpoint_json(
    plan: &LinuxNftablesPlan,
    data: &[u8],
) -> io::Result<Vec<LinuxNetworkEndpointEvent>> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nftables counter JSON: {error}"),
        )
    })?;
    let entries = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing nftables array"))?;
    let mut events = Vec::new();
    for entry in entries {
        let Some(counter) = entry.get("counter") else {
            continue;
        };
        let Some(name) = counter.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(planned) = plan
            .endpoint_counters
            .iter()
            .find(|planned| planned.name == name)
        else {
            continue;
        };
        let packets = counter
            .get("packets")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let bytes = counter
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if packets == 0 && bytes == 0 {
            continue;
        }
        events.push(LinuxNetworkEndpointEvent {
            table_name: plan.table_name.clone(),
            counter_name: name.to_string(),
            destination: planned.destination.clone(),
            protocol: planned.protocol,
            ports: planned.ports.clone(),
            packets,
            bytes,
        });
    }
    Ok(events)
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
        protocol: None,
        ports: Vec::new(),
    })
}

const DEFAULT_REJECT_COUNTER: &str = "default_block";

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

fn nft_table_name(session_id: &str) -> String {
    let (identity, generation) = session_id
        .rsplit_once('_')
        .filter(|(_, suffix)| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map_or((session_id, None), |(identity, generation)| {
            (identity, Some(generation))
        });
    let mut hash = 0xcbf29ce484222325u64;
    for byte in identity.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut readable = sanitize_nft_identifier(identity);
    readable.truncate(80);
    let base = format!("gensee_{readable}_{hash:016x}");
    generation.map_or(base.clone(), |generation| format!("{base}_{generation}"))
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
    fn nft_table_identity_is_collision_resistant_and_bounded_across_generations() {
        let hyphen = nft_table_name("op-a_7");
        let underscore = nft_table_name("op_a_7");
        assert_ne!(hyphen, underscore);
        assert!(hyphen.ends_with("_7"));
        assert!(nft_table_name(&format!("{}_{}", "x".repeat(128), u64::MAX)).len() <= 128);
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
                allowed_endpoints: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);

        assert_eq!(plan.destinations.len(), 2);
        assert_eq!(plan.denied_destinations.len(), 1);
        assert_eq!(plan.block_counters.len(), 2);
        assert_eq!(plan.warnings.len(), 1);
        assert!(validate_nftables_plan_for_apply(&plan).is_err());
        assert!(plan.script.contains("counter deny_0 {}"));
        assert!(plan.script.contains("counter default_block {}"));
        assert!(plan.script.contains("socket cgroupv2 level 2"));
        assert!(plan.script.contains(
            "ip daddr 169.254.169.254 meta nftrace set 1 counter name deny_0 reject with icmpx admin-prohibited"
        ));
        assert!(plan.script.contains("ip daddr 1.2.3.4 accept"));
        assert!(plan.script.contains("ip6 daddr 2001:db8::/32 accept"));
        assert!(plan.script.contains(
            "meta nftrace set 1 counter name default_block reject with icmpx admin-prohibited"
        ));
    }

    #[test]
    fn parses_only_exact_operation_packet_traces_with_endpoint_identity() {
        let ipv4 = "trace id a95ea7ef ip gensee_op_1 egress packet: oif \"eth0\" ip saddr 10.0.0.2 ip daddr 203.0.113.9 ip ttl 64 tcp sport 50000 tcp dport 443 tcp flags == syn";
        assert_eq!(
            parse_nft_trace_attempt(ipv4, "gensee_op_1", "egress"),
            Some(LinuxNetworkAttemptEvent {
                trace_id: "a95ea7ef".to_string(),
                table_name: "gensee_op_1".to_string(),
                chain_name: "egress".to_string(),
                destination: "203.0.113.9".to_string(),
                protocol: LinuxNetworkProtocol::Tcp,
                port: 443,
            })
        );
        let ipv6 = "trace id 00000002 ip6 gensee_op_1 egress_input packet: iif \"veth0\" ip6 saddr fd00::2 ip6 daddr 2001:db8::9 udp sport 50000 udp dport 53";
        assert_eq!(
            parse_nft_trace_attempt(ipv6, "gensee_op_1", "egress")
                .unwrap()
                .destination,
            "2001:db8::9"
        );
        assert!(parse_nft_trace_attempt(ipv4, "gensee_other", "egress").is_none());
        assert!(parse_nft_trace_attempt_for_prefix(ipv4, "gensee_op_", "egress").is_some());
        assert!(parse_nft_trace_attempt_for_prefix(ipv4, "gensee_o_", "egress").is_none());
        assert!(parse_nft_trace_attempt(
            "trace id a ip gensee_op_1 egress rule tcp dport 443",
            "gensee_op_1",
            "egress"
        )
        .is_none());
    }

    #[test]
    fn plans_protocol_and_port_scoped_endpoint_rules_with_usage_counters() {
        let config = LinuxNetworkEnforcementConfig::new(
            "cell-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::AllowListed,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: vec![crate::policy::LinuxNetworkEndpoint {
                    destination: "10.20.30.40/32".to_string(),
                    protocol: LinuxNetworkProtocol::Tcp,
                    ports: vec![8443, 443, 443],
                }],
            },
        );

        let plan = build_nftables_plan(&config);

        validate_nftables_plan_for_apply(&plan).unwrap();
        assert_eq!(plan.endpoint_counters.len(), 1);
        assert_eq!(plan.endpoint_counters[0].ports, vec![443, 8443]);
        assert!(plan.script.contains("counter allow_0 {}"));
        assert!(plan.script.contains(
            "ip daddr 10.20.30.40/32 meta l4proto tcp tcp dport { 443, 8443 } counter name allow_0 accept"
        ));
        let data = br#"{
            "nftables": [
                {"counter": {"name": "allow_0", "packets": 4, "bytes": 512}}
            ]
        }"#;
        let events = parse_nftables_endpoint_json(&plan, data).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].destination, "10.20.30.40/32");
        assert_eq!(events[0].protocol, LinuxNetworkProtocol::Tcp);
        assert_eq!(events[0].ports, vec![443, 8443]);
    }

    #[test]
    fn rebinds_cell_policy_to_private_namespace_source_address() {
        let config = LinuxNetworkEnforcementConfig::new(
            "cell-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::AllowListed,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: vec![crate::policy::LinuxNetworkEndpoint {
                    destination: "10.20.30.40/32".to_string(),
                    protocol: LinuxNetworkProtocol::Tcp,
                    ports: vec![443],
                }],
            },
        );
        let mut plan = build_nftables_plan(&config);

        bind_nftables_plan_to_source_address(&mut plan, "10.88.0.2".parse().unwrap());

        assert!(plan.script.contains("hook forward"));
        assert!(plan.script.contains("hook input"));
        assert!(plan
            .script
            .contains(&format!("chain {}_input", plan.chain_name)));
        assert!(plan
            .script
            .contains("ip saddr 10.88.0.2 ip daddr 10.20.30.40/32 meta l4proto tcp tcp dport 443"));
        assert_eq!(
            plan.script
                .matches(
                    "ip saddr 10.88.0.2 ip daddr 10.20.30.40/32 meta l4proto tcp tcp dport 443"
                )
                .count(),
            2,
            "the exact endpoint lease must constrain both forwarded and host-local traffic"
        );
        assert_eq!(
            plan.script
                .matches("ip saddr 10.88.0.2 meta nftrace set 1 counter name default_block reject")
                .count(),
            2,
            "unleased traffic must fail closed on both routing paths"
        );
        assert!(!plan.script.contains("socket cgroupv2"));
    }

    #[test]
    fn cell_monitor_policy_observes_both_routing_paths_without_default_reject() {
        let config = LinuxNetworkEnforcementConfig::new(
            "cell-monitor",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
                allowed_hosts: Vec::new(),
                denied_hosts: vec!["169.254.169.254".to_string()],
                allowed_endpoints: Vec::new(),
            },
        );
        let mut plan = build_nftables_plan(&config);

        bind_nftables_plan_to_source_address(&mut plan, "10.88.0.3".parse().unwrap());

        assert!(plan.script.contains("hook forward"));
        assert!(plan.script.contains("hook input"));
        assert_eq!(
            plan.script
                .matches("ip saddr 10.88.0.3 ip daddr 169.254.169.254")
                .count(),
            2
        );
        assert!(!plan.script.contains("counter name default_block reject"));
    }

    #[test]
    fn rejects_apply_for_empty_allowlist() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::AllowListed,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: Vec::new(),
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
                allowed_endpoints: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);

        validate_nftables_plan_for_apply(&plan).unwrap();
        assert!(plan.script.contains(
            "ip daddr 169.254.169.254 meta nftrace set 1 counter name deny_0 reject with icmpx admin-prohibited"
        ));
    }

    #[test]
    fn parses_nonzero_nftables_block_counters() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
                allowed_hosts: Vec::new(),
                denied_hosts: vec!["169.254.169.254".to_string()],
                allowed_endpoints: Vec::new(),
            },
        );
        let plan = build_nftables_plan(&config);
        let data = br#"{
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"counter": {"family": "inet", "table": "gensee_agent_1", "name": "deny_0", "packets": 2, "bytes": 128}},
                {"counter": {"family": "inet", "table": "gensee_agent_1", "name": "unknown", "packets": 3, "bytes": 192}}
            ]
        }"#;

        let events = parse_nftables_counter_json(&plan, data).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].counter_name, "deny_0");
        assert_eq!(events[0].destination.as_deref(), Some("169.254.169.254"));
        assert_eq!(events[0].packets, 2);
        assert_eq!(events[0].bytes, 128);
    }

    #[test]
    fn monitor_mode_generates_no_reject_rule() {
        let config = LinuxNetworkEnforcementConfig::new(
            "agent-1",
            LinuxNetworkPolicy {
                mode: LinuxNetworkMode::Monitor,
                allowed_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                allowed_endpoints: Vec::new(),
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
                allowed_endpoints: Vec::new(),
            },
        );

        let plan = build_nftables_plan(&config);

        assert!(plan.script.is_empty());
    }
}
