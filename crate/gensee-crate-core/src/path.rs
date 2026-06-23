use std::env;
use std::path::{Component, Path, PathBuf};

pub fn normalize_agent_path(raw_path: &str, cwd: &str) -> String {
    let expanded = expand_home_path(raw_path);
    let path = if Path::new(&expanded).is_absolute() {
        PathBuf::from(expanded)
    } else {
        Path::new(cwd).join(expanded)
    };
    let mut normalized = lexical_normalize_path(&path).to_string_lossy().to_string();
    if raw_path.ends_with('/') && normalized != "/" && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn expand_home_path(raw_path: &str) -> String {
    if raw_path.starts_with("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home)
                .join(raw_path.trim_start_matches("~/"))
                .to_string_lossy()
                .to_string();
        }
    } else if raw_path == "$HOME" || raw_path == "${HOME}" {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).to_string_lossy().to_string();
        }
    } else if let Some(rest) = raw_path
        .strip_prefix("$HOME/")
        .or_else(|| raw_path.strip_prefix("${HOME}/"))
    {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest).to_string_lossy().to_string();
        }
    }
    raw_path.to_string()
}

fn lexical_normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_parent_components() {
        assert_eq!(
            normalize_agent_path("../repo/src/../README.md", "/work/project"),
            "/work/repo/README.md"
        );
    }

    #[test]
    fn preserves_trailing_slash() {
        assert_eq!(normalize_agent_path("src/../", "/repo"), "/repo/");
    }
}
