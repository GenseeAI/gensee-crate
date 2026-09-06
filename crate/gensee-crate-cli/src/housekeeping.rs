use crate::*;

/// Presentation-only classification from recorded paths and sensor metadata.
/// Never use this function to discard evidence or authorize access.
pub(crate) fn is_routine(policy: &Policy, rule: &str, path: &str, evidence: &Value) -> bool {
    if !matches!(
        rule,
        "hook_bypass_file_mutation" | "policy_destructive_file_operation"
    ) || policy
        .document()
        .review_overrides
        .iter()
        .any(|r| r.rule_id == rule)
        || evidence.pointer("/decision/result").and_then(Value::as_str) == Some("deny")
    {
        return false;
    }
    let operation = evidence["logical_operation"].as_str().unwrap_or("");
    if !matches!(
        operation,
        "mutation" | "write" | "create" | "delete" | "rename"
    ) {
        return false;
    }
    if matches!(operation, "delete" | "rename")
        && evidence
            .pointer("/file/mode")
            .and_then(Value::as_u64)
            .is_none_or(|m| m & 0o170000 != 0o100000)
    {
        return false;
    }
    let safe_file = |p: &str| {
        if approval_memory::is_store_file(Path::new(p)) {
            return false;
        }
        gensee_crate_core::recorded_concrete_path(p).is_some() && policy.is_unprotected_path(p)
    };
    if !safe_file(path)
        || evidence
            .pointer("/file/path_truncated")
            .is_some_and(|v| v.as_bool() == Some(true) || v.as_i64() == Some(1))
        || evidence
            .pointer("/destination/path_truncated")
            .is_some_and(|v| v.as_bool() == Some(true) || v.as_i64() == Some(1))
    {
        return false;
    }
    let source = evidence
        .pointer("/file/path")
        .and_then(Value::as_str)
        .unwrap_or("");
    if operation == "rename" {
        if !safe_file(source) {
            return false;
        }
        if !policy.is_executable_artifact_path(path)
            && !policy.is_executable_artifact_path(source)
            && gensee_crate_core::recorded_scratch_path(path).is_some()
            && gensee_crate_core::recorded_scratch_path(source).is_some()
        {
            return true;
        }
    }
    let actor = &evidence["actor"];
    let executable = actor["executable_path"].as_str().unwrap_or("");
    let signing = actor["signing_id"].as_str().unwrap_or("");
    let platform = actor["platform_binary"].as_bool() == Some(true)
        || actor["platform_binary"].as_i64() == Some(1);
    let home = env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        return false;
    }
    let within = |p: &str, root: &str| {
        gensee_crate_core::recorded_concrete_path(p)
            .zip(gensee_crate_core::recorded_concrete_path(root))
            .is_some_and(|(p, r)| p != r && p.starts_with(r))
    };
    let both_within =
        |root: &str| within(path, root) && (operation != "rename" || within(source, root));
    if actor["team_id"].as_str() == Some("Q6L2SF6YDW")
        && matches!(
            signing,
            "com.anthropic.claudefordesktop" | "com.anthropic.claude-code" | "disclaimer"
        )
        && (both_within(&format!("{home}/Library/Logs/Claude"))
            || both_within(&format!(
                "{home}/Library/Saved Application State/com.anthropic.claudefordesktop.savedState"
            )))
    {
        return true;
    }
    if platform
        && signing.starts_with("com.apple.")
        && executable.starts_with("/Applications/Xcode.app/Contents/")
    {
        if both_within(&format!("{home}/Library/Developer/Xcode/DerivedData"))
            && path.contains("/Logs/")
            && (operation != "rename" || source.contains("/Logs/"))
        {
            return true;
        }
        // Per-user C is the OS cache directory; only DeveloperTools' cache qualifies.
        let cache = |p: &str| {
            let parts: Vec<_> = Path::new(p).components().collect();
            let base = if p.starts_with("/private/var/folders/") {
                4
            } else if p.starts_with("/var/folders/") {
                3
            } else {
                return false;
            };
            parts.len() > base + 4
                && parts[base + 2].as_os_str() == "C"
                && parts[base + 3].as_os_str() == "com.apple.DeveloperTools"
        };
        if cache(path) && (operation != "rename" || cache(source)) {
            return true;
        }
    }
    if platform
        && (signing == "com.apple.git" || signing == "com.apple.dt.xcode_select.tool-shim")
        && Path::new(executable)
            .file_name()
            .is_some_and(|n| n == "git")
    {
        let lock = |p: &str| {
            p.ends_with("/.git/objects/maintenance.lock")
                || p.ends_with("/.git/index.lock")
                || (p.contains("/.git/worktrees/") && p.ends_with("/index.lock"))
        };
        if lock(path) && (operation != "rename" || lock(source)) {
            return true;
        }
    }
    // Cargo's two bookkeeping databases are not its credentials or config.
    if executable.starts_with(&format!("{home}/.rustup/toolchains/"))
        && executable.ends_with("/bin/cargo")
    {
        let cache = |p: &str| {
            p == format!("{home}/.cargo/.global-cache")
                || p == format!("{home}/.cargo/.package-cache")
        };
        if cache(path) && (operation != "rename" || cache(source)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence(operation: &str, path: &str) -> Value {
        json!({"logical_operation":operation,"file":{"path":path,"mode":0o100644},"actor":{}})
    }
    #[test]
    fn temp_atomic_renames_require_safe_regular_source_and_destination() {
        let policy = Policy::load_current();
        let root = env::temp_dir().join(format!("gensee-housekeeping-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let from = root.join("cache.tmp").to_string_lossy().into_owned();
        let to = root.join("cache.json").to_string_lossy().into_owned();
        let mut e = evidence("rename", &from);
        assert!(is_routine(&policy, "hook_bypass_file_mutation", &to, &e));
        for source in ["/etc/passwd", "/tmp/.env", "/tmp/.gensee/approvals.json"] {
            e["file"]["path"] = json!(source);
            assert!(
                !is_routine(&policy, "hook_bypass_file_mutation", &to, &e),
                "{source}"
            );
        }
        e["file"]["path"] = json!(from);
        e["file"]["mode"] = json!(0o040755);
        assert!(!is_routine(&policy, "hook_bypass_file_mutation", &to, &e));
        e["file"]["mode"] = json!(0o100644);
        e["destination"] = json!({"path_truncated":1});
        assert!(!is_routine(&policy, "hook_bypass_file_mutation", &to, &e));
        e["destination"] = json!({});
        e["decision"] = json!({"result":"deny"});
        assert!(!is_routine(&policy, "hook_bypass_file_mutation", &to, &e));
    }
    #[test]
    fn scratch_executable_staging_is_never_quieted() {
        let policy = Policy::embedded_default();
        for (source, destination) in [
            ("/private/tmp/payload.tmp", "/private/tmp/tools/setup.py"),
            ("/private/tmp/setup.sh", "/private/tmp/output.tmp"),
        ] {
            assert!(!is_routine(
                &policy,
                "hook_bypass_file_mutation",
                destination,
                &evidence("rename", source)
            ));
            assert!(!is_routine(
                &policy,
                "policy_destructive_file_operation",
                destination,
                &evidence("rename", source)
            ));
        }
    }

    #[test]
    fn claude_logs_need_expected_signed_actor_and_narrow_location() {
        let p = Policy::load_current();
        let home = env::var("HOME").unwrap();
        let path = format!("{home}/Library/Logs/Claude/main.log");
        let mut e = evidence("mutation", &path);
        assert!(!is_routine(&p, "hook_bypass_file_mutation", &path, &e));
        e["actor"] = json!({"signing_id":"com.anthropic.claudefordesktop","team_id":"Q6L2SF6YDW"});
        assert!(is_routine(&p, "hook_bypass_file_mutation", &path, &e));
        assert!(!is_routine(
            &p,
            "hook_bypass_file_mutation",
            &format!("{home}/Library/Logs/other/main.log"),
            &e
        ));
        assert!(!is_routine(&p, "policy_credential_content_read", &path, &e));
        e["actor"]["team_id"] = json!("OTHER");
        assert!(!is_routine(&p, "hook_bypass_file_mutation", &path, &e));
    }
    #[test]
    fn xcode_cache_and_git_lock_cleanup_do_not_exempt_repo_deletion() {
        let p = Policy::load_current();
        let cache = "/private/var/folders/ab/cd/C/com.apple.DeveloperTools/16.2/Xcode/cache";
        let mut e = evidence("delete", cache);
        e["actor"] = json!({"signing_id":"com.apple.dt.embeddedBinaryValidationUtility","platform_binary":1,"executable_path":"/Applications/Xcode.app/Contents/Developer/usr/bin/embeddedBinaryValidationUtility"});
        assert!(is_routine(
            &p,
            "policy_destructive_file_operation",
            cache,
            &e
        ));
        assert!(!is_routine(
            &p,
            "policy_destructive_file_operation",
            "/private/var/folders/ab/cd/C/other/cache",
            &e
        ));
        e["actor"] = json!({"signing_id":"com.apple.git","platform_binary":true,"executable_path":"/Applications/Xcode.app/Contents/Developer/usr/bin/git"});
        assert!(is_routine(
            &p,
            "policy_destructive_file_operation",
            "/private/tmp/repo/.git/objects/maintenance.lock",
            &e
        ));
        assert!(!is_routine(
            &p,
            "policy_destructive_file_operation",
            "/private/tmp/repo/.git/worktrees",
            &e
        ));
        assert!(!is_routine(
            &p,
            "policy_destructive_file_operation",
            "/private/tmp/repo/.git/config",
            &e
        ));
    }
}
