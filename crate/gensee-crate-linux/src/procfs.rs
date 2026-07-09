use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    pub pid: u32,
    pub comm: String,
    pub state: String,
    pub ppid: u32,
    pub process_group_id: u32,
    pub session_id: u32,
}

pub fn read_proc_stat(pid: u32) -> io::Result<ProcStat> {
    parse_proc_stat(&fs::read_to_string(proc_root(pid).join("stat"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid /proc stat format"))
}

pub fn parse_proc_stat(input: &str) -> Option<ProcStat> {
    let open = input.find('(')?;
    let after_open = open + 1;
    let relative_close = input[after_open..].rfind(") ")?;
    let close = after_open + relative_close;
    let pid = input[..open].trim().parse().ok()?;
    let comm = input[after_open..close].to_string();
    let fields = input[close + 2..].split_whitespace().collect::<Vec<_>>();
    Some(ProcStat {
        pid,
        comm,
        state: fields.first()?.to_string(),
        ppid: fields.get(1)?.parse().ok()?,
        process_group_id: fields.get(2)?.parse().ok()?,
        session_id: fields.get(3)?.parse().ok()?,
    })
}

pub fn read_proc_cmdline(pid: u32) -> io::Result<String> {
    let data = fs::read(proc_root(pid).join("cmdline"))?;
    Ok(data
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn read_parent_by_pid() -> io::Result<HashMap<u32, u32>> {
    let mut parent_by_pid = HashMap::new();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(parent_by_pid),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(stat) = read_proc_stat(pid) {
            parent_by_pid.insert(pid, stat.ppid);
        }
    }
    Ok(parent_by_pid)
}

pub fn is_descendant_or_self(pid: u32, root_pid: u32, parent_by_pid: &HashMap<u32, u32>) -> bool {
    let mut seen = HashSet::new();
    let mut current = pid;
    for _ in 0..256 {
        if current == root_pid {
            return true;
        }
        if !seen.insert(current) {
            return false;
        }
        let Some(parent) = parent_by_pid.get(&current).copied() else {
            return false;
        };
        if parent == 0 || parent == current {
            return false;
        }
        current = parent;
    }
    false
}

pub fn proc_root(pid: u32) -> PathBuf {
    Path::new("/proc").join(pid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_stat_with_spaces_and_parentheses_in_comm() {
        let stat = parse_proc_stat("123 (x) R 1 1 1) S 42 43 44 4 5").unwrap();
        assert_eq!(stat.pid, 123);
        assert_eq!(stat.comm, "x) R 1 1 1");
        assert_eq!(stat.state, "S");
        assert_eq!(stat.ppid, 42);
        assert_eq!(stat.process_group_id, 43);
        assert_eq!(stat.session_id, 44);
    }

    #[test]
    fn detects_descendant_processes_with_cycle_guard() {
        let parent_by_pid =
            HashMap::from([(10, 1), (11, 10), (12, 11), (20, 1), (30, 31), (31, 30)]);
        assert!(is_descendant_or_self(10, 10, &parent_by_pid));
        assert!(is_descendant_or_self(12, 10, &parent_by_pid));
        assert!(!is_descendant_or_self(20, 10, &parent_by_pid));
        assert!(!is_descendant_or_self(30, 10, &parent_by_pid));
    }
}
