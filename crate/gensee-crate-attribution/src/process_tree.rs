use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::process::Command;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub binary: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct ProcessTree {
    pub root_pid: u32,
    pub children: HashMap<u32, Vec<ProcessNode>>,
}

impl ProcessTree {
    pub fn from_root_pid(root_pid: u32) -> io::Result<Self> {
        let nodes = snapshot_processes()?;
        let mut children: HashMap<u32, Vec<ProcessNode>> = HashMap::new();

        for node in nodes {
            children.entry(node.ppid).or_default().push(node);
        }

        Ok(Self { root_pid, children })
    }

    pub fn descendants(&self) -> Vec<ProcessNode> {
        let mut result = Vec::new();
        let mut queue = VecDeque::from([self.root_pid]);
        let mut seen = HashSet::new();

        while let Some(pid) = queue.pop_front() {
            if !seen.insert(pid) {
                continue;
            }

            if let Some(children) = self.children.get(&pid) {
                for child in children {
                    result.push(child.clone());
                    queue.push_back(child.pid);
                }
            }
        }

        result
    }

    pub fn is_descendant(&self, pid: u32) -> bool {
        self.descendants().iter().any(|node| node.pid == pid)
    }

    pub fn attribution_confidence(&self, pid: u32) -> f32 {
        if pid == self.root_pid {
            return 1.0;
        }

        let mut queue = VecDeque::from([(self.root_pid, 0_u32)]);
        let mut seen = HashSet::new();

        while let Some((current, depth)) = queue.pop_front() {
            if !seen.insert(current) {
                continue;
            }

            if let Some(children) = self.children.get(&current) {
                for child in children {
                    if child.pid == pid {
                        return match depth + 1 {
                            1 => 0.85,
                            2 => 0.75,
                            3 => 0.65,
                            _ => 0.5,
                        };
                    }
                    queue.push_back((child.pid, depth + 1));
                }
            }
        }

        0.0
    }
}

fn snapshot_processes() -> io::Result<Vec<ProcessNode>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,comm="])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other("failed to snapshot process table with ps"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut nodes = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(ppid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let binary = parts.collect::<Vec<_>>().join(" ");
        if binary.is_empty() {
            continue;
        }

        nodes.push(ProcessNode {
            pid,
            ppid,
            binary,
            start_time: SystemTime::now(),
            end_time: None,
        });
    }

    Ok(nodes)
}
