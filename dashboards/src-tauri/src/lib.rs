//! Gensee Dashboard — Tauri backend.
//!
//! All data access goes through `#[tauri::command]` functions backed by a
//! read-only rusqlite connection.  Policy writes use a separate read-write
//! connection and apply `0600` permissions on creation.  No TCP server is
//! started; the WebView communicates exclusively via Tauri IPC.

use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde_json::{json, Value};
use tauri::{Emitter, Manager};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct AppState {
    /// Read-only connection shared across all query commands.
    ro: Mutex<Connection>,
    /// Directory that contains gensee.db, policy.json, etc.
    home: PathBuf,
}

// ---------------------------------------------------------------------------
// SQL helpers
// ---------------------------------------------------------------------------

/// Execute `sql` with `params` and return every row as a JSON object.
fn qjson(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<Value>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let n = stmt.column_count();
    let names: Vec<String> = (0..n)
        .map(|i| stmt.column_name(i).unwrap_or("col").to_string())
        .collect();

    let rows = stmt
        .query_map(params, |row| {
            let mut m = serde_json::Map::new();
            for (i, name) in names.iter().enumerate() {
                let v = match row.get_ref(i)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(n) => json!(n),
                    ValueRef::Real(f) => json!(f),
                    // rusqlite returns SQLite TEXT as UTF-8 bytes. Serializing
                    // the byte slice directly would produce a JSON number array
                    // (e.g. "high" → [104,105,103,104]) instead of a string.
                    ValueRef::Text(s) => json!(String::from_utf8_lossy(s).to_string()),
                    ValueRef::Blob(b) => json!(hex::encode(b)),
                };
                m.insert(name.clone(), v);
            }
            Ok(Value::Object(m))
        })
        .map_err(|e| e.to_string())?;

    rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

fn qone(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Option<Value>, String> {
    Ok(qjson(conn, sql, params)?.into_iter().next())
}

// ---------------------------------------------------------------------------
// Commands — dashboard state
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_state(state: tauri::State<AppState>) -> Result<Value, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let now_24h = chrono_now_ms() - 86_400_000i64;
    let sql = format!("
        SELECT
            (SELECT COUNT(*) FROM sessions)      AS sessions_count,
            (SELECT COUNT(*) FROM requests)      AS requests_count,
            (SELECT COUNT(*) FROM agent_events)  AS agent_events_count,
            (SELECT COUNT(*) FROM system_events) AS system_events_count,
            (SELECT COUNT(*) FROM alerts)        AS alerts_count,
            (SELECT COUNT(*) FROM alerts
              WHERE created_at >= {now_24h}
                AND severity IN ('high','critical')) AS recent_high_alerts,
            (SELECT COUNT(*) FROM artifacts)     AS artifacts_count
    ");
    qone(&conn, &sql, &[])?.ok_or_else(|| "No state row".to_string())
}

// ---------------------------------------------------------------------------
// Commands — sessions
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_sessions(
    state: tauri::State<AppState>,
    limit: Option<u32>,
    offset: Option<u32>,
    hide_empty: Option<bool>,
) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(50).min(500);
    let offset = offset.unwrap_or(0);
    let where_clause = if hide_empty.unwrap_or(false) {
        "WHERE (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.session_id) > 0
              OR (SELECT COUNT(*) FROM agent_events ae
                    JOIN requests r ON ae.request_id = r.request_id
                   WHERE r.session_id = s.session_id) > 0"
    } else {
        ""
    };
    let sql = format!("
        SELECT s.*,
            (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.session_id) AS req_count,
            (SELECT COUNT(*) FROM agent_events ae
               JOIN requests r ON ae.request_id = r.request_id
              WHERE r.session_id = s.session_id) AS event_count
          FROM sessions s {where_clause}
         ORDER BY first_event_at DESC
         LIMIT {limit} OFFSET {offset}
    ");
    qjson(&conn, &sql, &[])
}

#[tauri::command]
fn get_session(state: tauri::State<AppState>, id: String) -> Result<Option<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    qone(&conn, "SELECT * FROM sessions WHERE session_id = ?1 LIMIT 1", &[&id])
}

#[tauri::command]
fn get_session_requests(
    state: tauri::State<AppState>,
    id: String,
    limit: Option<u32>,
) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(50).min(200);
    qjson(
        &conn,
        &format!("SELECT * FROM requests WHERE session_id = ?1 ORDER BY request_id DESC LIMIT {limit}"),
        &[&id],
    )
}

#[tauri::command]
fn get_session_events(state: tauri::State<AppState>, id: String) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    qjson(&conn, "
        SELECT se.*,
            COALESCE(
                CASE WHEN se.cwd != '' THEN se.cwd END,
                json_extract(se.args, '$.event.write.target.path'),
                json_extract(se.args, '$.event.create.destination.path'),
                json_extract(se.args, '$.event.rename.destination.path'),
                json_extract(se.args, '$.event.unlink.target.path'),
                json_extract(se.args, '$.event.exec.target.path'),
                json_extract(se.args, '$.event.open.file.path')
            ) AS path,
            json_extract(se.args, '$.process.executable.path') AS process
          FROM system_events se
          JOIN requests r ON se.request_id = r.request_id
         WHERE r.session_id = ?1
         ORDER BY se.ts DESC
         LIMIT 200
    ", &[&id])
}

// ---------------------------------------------------------------------------
// Commands — agent events
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_agent_events(
    state: tauri::State<AppState>,
    request_id: Option<i64>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(500).min(500);
    let offset = offset.unwrap_or(0);
    let where_clause = match request_id {
        Some(rid) => format!("WHERE request_id = {rid}"),
        None => String::new(),
    };
    let sql = format!("SELECT * FROM agent_events {where_clause} ORDER BY ts DESC LIMIT {limit} OFFSET {offset}");
    qjson(&conn, &sql, &[])
}

// ---------------------------------------------------------------------------
// Commands — alerts
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_alerts(
    state: tauri::State<AppState>,
    severity: Option<String>,
    action: Option<String>,
    request_id: Option<i64>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<Value>, String> {
    const VALID_SEV: &[&str] = &["info", "low", "medium", "high", "critical"];
    const VALID_ACT: &[&str] = &["allow", "warn", "ask", "block"];
    let limit = limit.unwrap_or(500).min(500);
    let offset = offset.unwrap_or(0);

    let mut conditions: Vec<String> = Vec::new();
    if let Some(ref s) = severity {
        if VALID_SEV.contains(&s.as_str()) { conditions.push(format!("severity = '{s}'")); }
    }
    if let Some(ref a) = action {
        if VALID_ACT.contains(&a.as_str()) { conditions.push(format!("action = '{a}'")); }
    }
    if let Some(rid) = request_id { conditions.push(format!("request_id = {rid}")); }

    let where_clause = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    qjson(&conn, &format!("
        SELECT alert_id, request_id, entity_kind, entity_id, severity, action,
               rule_id, message, path, created_at,
               json_extract(evidence, '$.tool_use_id') AS tool_use_id
          FROM alerts {where_clause}
         ORDER BY created_at DESC
         LIMIT {limit} OFFSET {offset}
    "), &[])
}

// ---------------------------------------------------------------------------
// Commands — stats
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_activity_stats(state: tauri::State<AppState>, range: Option<String>) -> Result<Value, String> {
    let is7d = range.as_deref() == Some("7d");
    let bucket_ms: i64 = if is7d { 86_400_000 } else { 3_600_000 };
    let range_ms: i64 = if is7d { 7 * 86_400_000 } else { 86_400_000 };
    let from_ms = chrono_now_ms() - range_ms;

    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let sessions = qjson(&conn, &format!(
        "SELECT (CAST(first_event_at/{bucket_ms} AS INTEGER))*{bucket_ms} AS bucket, COUNT(*) AS count
           FROM sessions WHERE first_event_at>={from_ms} GROUP BY bucket ORDER BY bucket"
    ), &[])?;
    let agent_events = qjson(&conn, &format!(
        "SELECT (CAST(ts/{bucket_ms} AS INTEGER))*{bucket_ms} AS bucket, COUNT(*) AS count
           FROM agent_events WHERE ts>={from_ms} GROUP BY bucket ORDER BY bucket"
    ), &[])?;
    let alerts = qjson(&conn, &format!(
        "SELECT (CAST(created_at/{bucket_ms} AS INTEGER))*{bucket_ms} AS bucket, COUNT(*) AS count
           FROM alerts WHERE created_at>={from_ms} GROUP BY bucket ORDER BY bucket"
    ), &[])?;

    Ok(json!({
        "range": if is7d { "7d" } else { "24h" },
        "bucketMs": bucket_ms,
        "sessions": sessions,
        "agentEvents": agent_events,
        "alerts": alerts,
    }))
}

#[tauri::command]
fn get_severity_stats(state: tauri::State<AppState>) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    qjson(&conn, "
        SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 5 WHEN 'high' THEN 4
            WHEN 'medium' THEN 3   WHEN 'low'  THEN 2 ELSE 1 END DESC
    ", &[])
}

// ---------------------------------------------------------------------------
// Commands — artifacts
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_artifacts(state: tauri::State<AppState>, limit: Option<u32>, offset: Option<u32>) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(50).min(500);
    let offset = offset.unwrap_or(0);
    qjson(&conn, &format!("SELECT * FROM artifacts ORDER BY artifact_id DESC LIMIT {limit} OFFSET {offset}"), &[])
}

#[tauri::command]
fn get_artifact_graph(state: tauri::State<AppState>) -> Result<Value, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let facts = qjson(&conn, "
        SELECT kind, uri, current_digest, last_seen_at, is_agent_authored,
               risk_level, is_memory_artifact, is_control_plane, is_persistent_target,
               last_modified_source
          FROM artifact_facts ORDER BY last_seen_at DESC LIMIT 80
    ", &[])?;
    let edges = qjson(&conn, "
        SELECT r.relation_type AS type, r.confidence, sa.uri AS src_uri, da.uri AS dst_uri
          FROM relations r
          JOIN artifacts sa ON r.src_kind = 'artifact' AND r.src_id = sa.artifact_id
          JOIN artifacts da ON r.dst_kind = 'artifact' AND r.dst_id = da.artifact_id
         ORDER BY r.relation_id DESC LIMIT 200
    ", &[])?;
    Ok(json!({ "facts": facts, "edges": edges }))
}

#[tauri::command]
fn get_artifact_lineage(state: tauri::State<AppState>, id: i64) -> Result<Value, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let artifacts = qjson(&conn, "SELECT artifact_id, kind, uri FROM artifacts WHERE artifact_id = ?1", &[&id])?;
    if artifacts.is_empty() { return Ok(json!({ "nodes": [], "edges": [] })); }

    let relations = qjson(&conn, "
        SELECT * FROM relations
         WHERE (src_kind = 'artifact' AND src_id = ?1)
            OR (dst_kind = 'artifact' AND dst_id = ?1)
    ", &[&id])?;

    let mut related_ids: Vec<i64> = vec![id];
    for r in &relations {
        if r.get("src_kind").and_then(Value::as_str) == Some("artifact") {
            if let Some(n) = r.get("src_id").and_then(Value::as_i64) { related_ids.push(n); }
        }
        if r.get("dst_kind").and_then(Value::as_str) == Some("artifact") {
            if let Some(n) = r.get("dst_id").and_then(Value::as_i64) { related_ids.push(n); }
        }
    }
    related_ids.sort(); related_ids.dedup();
    let ids_str = related_ids.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let all = qjson(&conn, &format!("SELECT artifact_id, kind, uri FROM artifacts WHERE artifact_id IN ({ids_str})"), &[])?;

    let nodes: Vec<Value> = all.iter().map(|a| json!({
        "id":    a.get("artifact_id").unwrap_or(&Value::Null).to_string(),
        "kind":  a.get("kind"),
        "label": a.get("uri").and_then(Value::as_str).unwrap_or("").replace("file://", ""),
        "uri":   a.get("uri"),
    })).collect();

    let edges: Vec<Value> = relations.iter()
        .filter(|r| r.get("src_kind").and_then(Value::as_str) == Some("artifact")
                 && r.get("dst_kind").and_then(Value::as_str) == Some("artifact"))
        .map(|r| json!({
            "source":        r.get("src_id").unwrap_or(&Value::Null).to_string(),
            "target":        r.get("dst_id").unwrap_or(&Value::Null).to_string(),
            "relation_type": r.get("relation_type"),
            "confidence":    r.get("confidence"),
        })).collect();

    Ok(json!({ "nodes": nodes, "edges": edges }))
}

// ---------------------------------------------------------------------------
// Commands — policy
// ---------------------------------------------------------------------------

const DEFAULT_POLICY: &str = include_str!("../../../crate/gensee-crate-rules/policy/default-policy.json");

#[tauri::command]
fn get_policy(state: tauri::State<AppState>) -> Result<Value, String> {
    let path = state.home.join("policy.json");
    let text = if path.exists() {
        std::fs::read_to_string(&path).map_err(|e| e.to_string())?
    } else {
        DEFAULT_POLICY.to_string()
    };
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_policy(state: tauri::State<AppState>, body: Value) -> Result<(), String> {
    // TODO(hardening): add tauri-plugin-biometric call here before writing,
    // so Touch ID / Windows Hello is required for every policy mutation.
    // Example: app.biometric().authenticate("Confirm policy change", None).await?;
    let text = serde_json::to_string_pretty(&body).map_err(|e| e.to_string())? + "\n";
    let home = &state.home;
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;

    // Validate via gensee binary using a per-call temp file.
    validate_policy(home, &text)?;

    // Write final file with 0600 permissions.
    write_secret(home.join("policy.json"), text.as_bytes())
}

fn validate_policy(home: &Path, text: &str) -> Result<(), String> {
    let tmp = home.join(format!(".policy-validate-{}.json", uuid_hex()));
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;

    let result = try_validate(&tmp, home);
    std::fs::remove_file(&tmp).ok();
    result
}

fn try_validate(tmp: &Path, home: &Path) -> Result<(), String> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let candidates = [
        std::env::var("GENSEE_BIN").ok().map(PathBuf::from),
        Some(repo_root.join("target/release/gensee")),
        Some(repo_root.join("target/debug/gensee")),
        which_gensee(),
    ];

    let mut found = false;
    for candidate in candidates.into_iter().flatten() {
        match std::process::Command::new(&candidate)
            .args(["policy", "validate", tmp.to_str().unwrap_or("")])
            .env("GENSEE_HOME", home)
            .output()
        {
            Ok(out) if out.status.success() => { found = true; break; }
            Ok(out) => {
                let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(format!("Policy validation failed: {detail}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        }
    }

    if !found {
        return Err(
            "No gensee binary found for policy validation. \
             Build the CLI first: cargo build --release -p gensee-crate-cli, \
             or set GENSEE_BIN to the binary path.".to_string()
        );
    }
    Ok(())
}

fn which_gensee() -> Option<PathBuf> {
    std::process::Command::new("which").arg("gensee").output().ok()
        .and_then(|o| if o.status.success() {
            Some(PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        } else { None })
}

fn write_secret(path: PathBuf, data: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, data).map_err(|e| e.to_string())
    }
}

/// Tiny UUID-like hex string from OS CSPRNG bytes.
fn uuid_hex() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    hex::encode(buf)
}

// ---------------------------------------------------------------------------
// Commands — feedback
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_feedback(state: tauri::State<AppState>, limit: Option<u32>, offset: Option<u32>) -> Result<Vec<Value>, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(50).min(500);
    let offset = offset.unwrap_or(0);
    qjson(&conn, &format!("SELECT * FROM human_feedback ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}"), &[])
}

#[tauri::command]
fn record_feedback(state: tauri::State<AppState>, data: Value) -> Result<Value, String> {
    // Open a read-write connection for this write operation.
    let db_path = state.home.join("gensee.db");
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;

    let now = chrono_now_ms();
    let event_key    = data.get("event_key").and_then(Value::as_str).unwrap_or("");
    let tool_use_id  = data.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
    let session_id   = data.get("session_id").and_then(Value::as_str).unwrap_or("");
    let gensee_action= data.get("gensee_action").and_then(Value::as_str).unwrap_or("");
    let human_verdict= data.get("human_verdict").and_then(Value::as_str).unwrap_or("agree");
    let rule_id      = data.get("rule_id").and_then(Value::as_str).unwrap_or("");
    let path         = data.get("path").and_then(Value::as_str).unwrap_or("");
    let note         = data.get("note").and_then(Value::as_str).unwrap_or("");

    let label = derive_label(gensee_action, human_verdict);

    let rows = conn.query_row("
        INSERT INTO human_feedback
            (event_key, tool_use_id, session_id, gensee_action, human_verdict, label,
             rule_id, path, note, created_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
        RETURNING feedback_id
    ", rusqlite::params![
        event_key, tool_use_id, session_id, gensee_action, human_verdict, label,
        rule_id, path, note, now
    ], |row| row.get::<_, i64>(0)).map_err(|e| e.to_string())?;

    Ok(json!({ "feedback_id": rows }))
}

fn derive_label(gensee_action: &str, human_verdict: &str) -> &'static str {
    if human_verdict == "agree" { return "confirmed"; }
    if human_verdict == "allow" && matches!(gensee_action, "block" | "ask") { return "false_positive"; }
    if human_verdict == "deny"  && matches!(gensee_action, "allow" | "warn") { return "false_negative"; }
    "override"
}

// ---------------------------------------------------------------------------
// Commands — today metrics
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_today_metrics(state: tauri::State<AppState>, date: Option<String>) -> Result<Value, String> {
    let conn = state.ro.lock().map_err(|e| e.to_string())?;
    let selected_date = date.filter(|d| {
        d.len() == 10
            && d.as_bytes().get(4) == Some(&b'-')
            && d.as_bytes().get(7) == Some(&b'-')
            && d.as_bytes().iter().enumerate().all(|(i, c)| {
                matches!(i, 4 | 7) || c.is_ascii_digit()
            })
    });
    let date_expr = selected_date.as_deref().unwrap_or("now");
    let date_modifier = if selected_date.is_some() { "" } else { ", 'localtime'" };
    let date_sql = format!("date(?1{date_modifier})");

    let tool_counts = qjson(&conn, &format!("
        SELECT ae.tool_name, COUNT(*) AS count
          FROM agent_events ae
         WHERE ae.type = 'PreToolUse'
           AND date(ae.ts / 1000, 'unixepoch', 'localtime') = {date_sql}
           AND ae.tool_name IS NOT NULL
         GROUP BY ae.tool_name
         ORDER BY count DESC
         LIMIT 20
    "), &[&date_expr])?;

    let sessions = qone(&conn, &format!("
        SELECT COUNT(*) AS count FROM sessions
         WHERE date(first_event_at / 1000, 'unixepoch', 'localtime') = {date_sql}
           AND agent_id != 'system-monitor'
    "), &[&date_expr])?
        .and_then(|r| r.get("count").and_then(Value::as_i64))
        .unwrap_or(0);
    let requests = qone(&conn, &format!("
        SELECT COUNT(DISTINCT ae.request_id) AS count FROM agent_events ae
         WHERE date(ae.ts / 1000, 'unixepoch', 'localtime') = {date_sql}
    "), &[&date_expr])?
        .and_then(|r| r.get("count").and_then(Value::as_i64))
        .unwrap_or(0);
    let files_written = qone(&conn, &format!("
        SELECT COUNT(DISTINCT json_extract(ae.tool_input, '$.path')) AS count
          FROM agent_events ae
         WHERE ae.type = 'PreToolUse'
           AND ae.tool_name IN ('Write', 'Edit', 'MultiEdit', 'apply_patch')
           AND date(ae.ts / 1000, 'unixepoch', 'localtime') = {date_sql}
           AND json_extract(ae.tool_input, '$.path') IS NOT NULL
    "), &[&date_expr])?
        .and_then(|r| r.get("count").and_then(Value::as_i64))
        .unwrap_or(0);
    let files_read = qone(&conn, &format!("
        SELECT COUNT(DISTINCT json_extract(ae.tool_input, '$.path')) AS count
          FROM agent_events ae
         WHERE ae.type = 'PreToolUse' AND ae.tool_name = 'Read'
           AND date(ae.ts / 1000, 'unixepoch', 'localtime') = {date_sql}
           AND json_extract(ae.tool_input, '$.path') IS NOT NULL
    "), &[&date_expr])?
        .and_then(|r| r.get("count").and_then(Value::as_i64))
        .unwrap_or(0);
    let alerts_by_action = qjson(&conn, &format!("
        SELECT action, COUNT(*) AS count FROM alerts
         WHERE date(created_at / 1000, 'unixepoch', 'localtime') = {date_sql}
         GROUP BY action
    "), &[&date_expr])?;
    let alerts_by_severity = qjson(&conn, &format!("
        SELECT severity, COUNT(*) AS count FROM alerts
         WHERE date(created_at / 1000, 'unixepoch', 'localtime') = {date_sql}
         GROUP BY severity
    "), &[&date_expr])?;

    let by_action: serde_json::Map<String, Value> = alerts_by_action.into_iter()
        .filter_map(|row| Some((row.get("action")?.as_str()?.to_owned(), row.get("count")?.clone())))
        .collect();
    let by_severity: serde_json::Map<String, Value> = alerts_by_severity.into_iter()
        .filter_map(|row| Some((row.get("severity")?.as_str()?.to_owned(), row.get("count")?.clone())))
        .collect();
    let tool_calls = tool_counts.iter()
        .filter_map(|row| row.get("count").and_then(Value::as_i64))
        .sum::<i64>();
    let tool_count = |name: &str| tool_counts.iter()
        .find(|row| row.get("tool_name").and_then(Value::as_str) == Some(name))
        .and_then(|row| row.get("count").and_then(Value::as_i64))
        .unwrap_or(0);

    Ok(json!({
        "sessions": sessions,
        "requests": requests,
        "tool_calls": tool_calls,
        "files_written": files_written,
        "files_read": files_read,
        "web_searches": tool_count("WebSearch"),
        "web_fetches": tool_count("WebFetch"),
        "bash_commands": tool_count("Bash"),
        "alerts_by_action": by_action,
        "alerts_by_severity": by_severity,
        "top_tools": tool_counts,
    }))
}

// ---------------------------------------------------------------------------
// Real-time event stream (background thread → Tauri events)
// ---------------------------------------------------------------------------

fn start_event_stream(app: tauri::AppHandle, db_path: PathBuf) {
    std::thread::spawn(move || {
        let conn = match Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => c,
            Err(e) => { eprintln!("Event stream: cannot open DB: {e}"); return; }
        };

        let mut last_id: i64 = conn
            .query_row("SELECT COALESCE(MAX(event_id),0) FROM agent_events", [], |r| r.get(0))
            .unwrap_or(0);

        loop {
            std::thread::sleep(Duration::from_secs(1));
            if let Ok(events) = qjson(&conn,
                "SELECT * FROM agent_events WHERE event_id > ?1 ORDER BY event_id ASC LIMIT 50",
                &[&last_id])
            {
                if let Some(last) = events.last() {
                    if let Some(id) = last.get("event_id").and_then(Value::as_i64) {
                        last_id = id;
                    }
                }
                for event in events {
                    let _ = app.emit("agent-event", &event);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn resolve_db_path(home: &Path) -> PathBuf {
    if let Ok(p) = std::env::var("GENSEE_DB_PATH") { return PathBuf::from(p); }
    home.join("gensee.db")
}

fn resolve_home() -> PathBuf {
    if let Ok(p) = std::env::var("GENSEE_HOME") { return PathBuf::from(p); }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".gensee")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let home    = resolve_home();
    let db_path = resolve_db_path(&home);

    // Open read-only connection (dashboard never writes agent data).
    let ro = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .or_else(|_| Connection::open_with_flags(":memory:", OpenFlags::SQLITE_OPEN_READ_ONLY))
        .expect("Failed to open SQLite connection");

    let state = AppState { ro: Mutex::new(ro), home: home.clone() };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_state,
            get_sessions,
            get_session,
            get_session_requests,
            get_session_events,
            get_agent_events,
            get_alerts,
            get_activity_stats,
            get_severity_stats,
            get_artifacts,
            get_artifact_graph,
            get_artifact_lineage,
            get_policy,
            save_policy,
            get_feedback,
            record_feedback,
            get_today_metrics,
        ])
        .setup(move |app| {
            // Development-only: expose WebView console errors instead of leaving
            // a blank page with no diagnostics when Vite/frontend code fails.
            #[cfg(debug_assertions)]
            if let Some(window) = app.get_webview_window("main") {
                window.open_devtools();
            }

            let handle = app.handle().clone();
            start_event_stream(handle, db_path.clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running Gensee dashboard");
}
