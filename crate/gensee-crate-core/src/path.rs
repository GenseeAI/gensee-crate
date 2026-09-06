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

/// Recognize concrete descendants of OS scratch roots, resolving existing
/// ancestors so a symlink cannot turn a temp exception into a workspace escape.
/// Root-wide cleanup, globs, traversal, and arbitrary TMPDIR overrides are not
/// covered. Missing leaf files are allowed only beneath a resolvable ancestor.
pub fn resolve_routine_scratch_path(path: &str) -> Option<PathBuf> {
    let input = Path::new(path);
    if !input.is_absolute()
        || path.contains(['*', '?', '[', ']', '{', '}'])
        || input
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return None;
    }
    if !is_scratch_descendant(input) {
        return None;
    }
    let resolved = resolve_concrete_path(path)?;
    is_scratch_descendant(&resolved).then_some(resolved)
}

fn is_scratch_descendant(path: &Path) -> bool {
    for root in ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"] {
        if path != Path::new(root) && path.starts_with(root) {
            return true;
        }
    }
    for prefix in ["/var/folders", "/private/var/folders"] {
        if let Ok(tail) = path.strip_prefix(prefix) {
            let parts: Vec<_> = tail.components().collect();
            if parts.len() > 3 && parts[2].as_os_str() == "T" {
                return true;
            }
        }
    }
    false
}

/// Lexical classification of recorded evidence only. Never use this to grant
/// filesystem access: historical paths must not trigger present-day filesystem I/O.
pub fn recorded_concrete_path(path: &str) -> Option<PathBuf> {
    let input = Path::new(path);
    (input.is_absolute()
        && !path.contains(['*', '?', '[', ']', '{', '}'])
        && !input
            .components()
            .any(|p| matches!(p, Component::ParentDir)))
    .then(|| input.to_path_buf())
}

pub fn recorded_scratch_path(path: &str) -> Option<PathBuf> {
    recorded_concrete_path(path).filter(|p| is_scratch_descendant(p))
}

/// Resolve a concrete absolute path, including missing leaves, without allowing
/// traversal, globs, dangling links, or inaccessible ancestors.
pub fn resolve_concrete_path(path: &str) -> Option<PathBuf> {
    let input = Path::new(path);
    if !input.is_absolute()
        || path.contains(['*', '?', '[', ']', '{', '}'])
        || input
            .components()
            .any(|p| matches!(p, Component::ParentDir))
    {
        return None;
    }
    let mut ancestor = input;
    let mut missing = Vec::new();
    let resolved = loop {
        match std::fs::canonicalize(ancestor) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not an ordinary missing leaf.
                if std::fs::symlink_metadata(ancestor).is_ok() {
                    return None;
                }
                let name = ancestor.file_name()?;
                missing.push(name);
                let parent = ancestor.parent()?;
                ancestor = parent;
            }
            Err(_) => return None,
        }
    };
    let mut resolved = resolved;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Some(resolved)
}

/// A build-directory name alone is never sufficient to hide Endpoint Security
/// evidence. Suppression requires a trusted build executable and a fixed
/// top-level build root beneath the active workspace.
pub fn endpoint_security_path_is_known_build_output(
    executable_path: Option<&str>,
    path: &str,
    workspace_root: Option<&str>,
) -> bool {
    let executable = executable_path
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let executable_name = executable.rsplit('/').next().unwrap_or_default();
    let known_build_process = matches!(
        executable_name,
        "cargo"
            | "rustc"
            | "cc"
            | "c++"
            | "clang"
            | "clang++"
            | "ld"
            | "swift"
            | "swiftc"
            | "swift-frontend"
            | "xcodebuild"
            | "xctest"
            | "npm"
            | "npx"
            | "yarn"
            | "pnpm"
            | "bun"
    );
    if !known_build_process || !endpoint_security_executable_is_trusted_build_tool(&executable) {
        return false;
    }

    let Some(workspace_root) = workspace_root.filter(|root| !root.trim().is_empty()) else {
        return false;
    };
    let workspace_root = workspace_root
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if workspace_root.is_empty() {
        return false;
    }
    let path = path.replace('\\', "/").to_ascii_lowercase();
    [
        "target",
        "dist",
        "build",
        "coverage",
        "deriveddata",
        ".build",
        "node_modules/.cache",
        "test-results",
        "testresults",
    ]
    .iter()
    .any(|relative| {
        let build_root = format!("{workspace_root}/{relative}");
        path == build_root || path.starts_with(&format!("{build_root}/"))
    })
}

fn endpoint_security_executable_is_trusted_build_tool(executable: &str) -> bool {
    if !executable.starts_with('/') {
        return false;
    }

    let fixed_prefixes = [
        "/usr/bin/",
        "/usr/local/bin/",
        "/opt/homebrew/bin/",
        "/library/developer/commandlinetools/usr/bin/",
        "/applications/xcode.app/contents/developer/",
        "/nix/store/",
    ];
    if fixed_prefixes
        .iter()
        .any(|prefix| executable.starts_with(prefix))
    {
        return true;
    }

    executable.contains("/.rustup/toolchains/") && executable.contains("/bin/")
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

    #[test]
    fn build_output_requires_trusted_process_and_top_level_workspace_root() {
        assert!(endpoint_security_path_is_known_build_output(
            Some("/Users/me/.rustup/toolchains/stable/bin/rustc"),
            "/repo/target/debug/output.o",
            Some("/repo"),
        ));
        assert!(!endpoint_security_path_is_known_build_output(
            Some("/Applications/Codex.app/Contents/MacOS/Codex"),
            "/repo/target/exfil.env",
            Some("/repo"),
        ));
        assert!(!endpoint_security_path_is_known_build_output(
            Some("/usr/bin/rustc"),
            "/repo/src/target/output.o",
            Some("/repo"),
        ));
        assert!(!endpoint_security_path_is_known_build_output(
            Some("/repo/rustc"),
            "/repo/target/output.o",
            Some("/repo"),
        ));
        for top_level in ["dist", "build", "coverage"] {
            assert!(endpoint_security_path_is_known_build_output(
                Some("/opt/homebrew/bin/npm"),
                &format!("/repo/{top_level}/asset.js"),
                Some("/repo"),
            ));
            assert!(!endpoint_security_path_is_known_build_output(
                Some("/opt/homebrew/bin/npm"),
                &format!("/repo/packages/{top_level}/source.ts"),
                Some("/repo"),
            ));
        }
    }
}
