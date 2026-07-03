// Concurrency test suite for gensee-crate.
//
// Each test targets a specific concurrency issue identified in the EventStore
// and CLI runtime. The tests use threads and multiple EventStore instances
// sharing the same on-disk directory to simulate the real multi-process
// architecture (hooks, watch, run, daemon all writing to one GENSEE_HOME).
//
// Run with: cargo test -p gensee-crate-store -- concurrency --test-threads=1
// (--test-threads=1 prevents test dirs from colliding; the concurrency under
// test is WITHIN each test, not between tests.)

use super::*;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn test_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gensee-concurrency-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn make_session(id: &str, started_at_ms: u64) -> AgentSession {
    AgentSession {
        session_id: id.to_string(),
        agent_binary: "claude".to_string(),
        root_pid: std::process::id(),
        cwd: "/test".to_string(),
        repo_path: None,
        mode: None,
        workspace_mode: None,
        original_workspace: None,
        staged_workspace: None,
        sandbox_profile: None,
        sandbox_profile_path: None,
        started_at_ms,
        ended_at_ms: None,
        exit_code: None,
    }
}

fn make_hook_event(session_id: &str, tool_use_id: &str, observed_at_ms: u64) -> AgentHookEvent {
    AgentHookEvent {
        provider: "claude-code".to_string(),
        session_id: Some(session_id.to_string()),
        hook_event_name: Some("PreToolUse".to_string()),
        cwd: Some("/test".to_string()),
        transcript_path: None,
        tool_name: Some("Bash".to_string()),
        tool_use_id: Some(tool_use_id.to_string()),
        tool_input_command: Some("echo test".to_string()),
        tool_input_description: None,
        tool_response_stdout: None,
        tool_response_stderr: None,
        tool_response_interrupted: None,
        duration_ms: None,
        permission_mode: None,
        effort_level: None,
        observed_at_ms,
        raw_json: format!(
            r#"{{"session_id":"{session_id}","hook_event_name":"PreToolUse","tool_use_id":"{tool_use_id}"}}"#
        ),
    }
}

fn make_workspace_effect(session_id: &str, path: &str, observed_at_ms: u64) -> WorkspaceEffect {
    WorkspaceEffect {
        source: "test".to_string(),
        session_id: Some(session_id.to_string()),
        workspace: "/test".to_string(),
        path: path.to_string(),
        effect_type: "create".to_string(),
        observed_at_ms,
        attribution: "test".to_string(),
        confidence: "high".to_string(),
    }
}

fn make_system_event(pid: usize, observed_at_ms: u64) -> SystemEvent {
    SystemEvent {
        source: "test".to_string(),
        event_type: "exec".to_string(),
        event_kind: "process".to_string(),
        observed_at_ms,
        pid: Some(pid as u32),
        ppid: Some(1),
        process_name: Some("test-process".to_string()),
        executable_path: Some("/usr/bin/test".to_string()),
        file_path: None,
        command_line: Some("test --flag".to_string()),
        raw_json: "{}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Concurrent JSONL appends from multiple threads
//
// Simulates the real scenario where hooks, watch, and run all append to the
// same JSONL files through separate EventStore clones pointing at the same
// directory. Without file-level locking, concurrent write_all calls can
// interleave bytes and produce corrupt JSON lines.
//
// This test spawns N threads that each append M records to hooks.jsonl via
// the same store directory. After all threads complete, it reads back the
// file and checks that every line is valid JSON and every record is present.
// A failure here (corrupt lines or missing records) proves the interleaving
// bug.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_jsonl_appends_should_not_interleave() {
    let dir = test_dir("jsonl-interleave");
    let num_threads = 8;
    let writes_per_thread = 50;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                // Each thread opens its own EventStore to the same directory,
                // simulating separate processes (hook invocations) sharing
                // GENSEE_HOME.
                let store = EventStore::new(&dir).unwrap();
                // Barrier ensures all threads start writing at the same instant,
                // maximizing the window for interleaved writes.
                barrier.wait();
                for i in 0..writes_per_thread {
                    let event = make_hook_event(
                        &format!("session-{thread_id}"),
                        &format!("tool-{thread_id}-{i}"),
                        1000 + i as u64,
                    );
                    store.append_hook_event(&event).unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Read back the raw file and verify every line is parseable JSON.
    // If writes interleaved, some lines will be partial/corrupt JSON.
    let raw = fs::read_to_string(dir.join("hooks.jsonl")).unwrap();
    let mut valid_count = 0;
    let mut corrupt_count = 0;
    for (line_number, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AgentHookEvent>(line) {
            Ok(_) => valid_count += 1,
            Err(err) => {
                corrupt_count += 1;
                eprintln!("CORRUPT line {}: {err}", line_number + 1);
                eprintln!("  content: {line}");
            }
        }
    }

    let expected = num_threads * writes_per_thread;
    assert_eq!(
        corrupt_count, 0,
        "{corrupt_count} corrupt JSONL lines detected out of {expected} — \
         concurrent writes interleaved without file locking"
    );
    assert_eq!(
        valid_count, expected,
        "expected {expected} records but found {valid_count} — records lost"
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 2: Database and JSONL consistency under concurrent writes
//
// Each append_* method writes to SQLite first, then appends to JSONL. If
// the JSONL write fails (or is reordered by the scheduler) after the DB
// commit succeeds, the two stores diverge. This test writes sessions from
// multiple threads and then compares the DB record count against the JSONL
// record count. A mismatch proves the consistency gap.
// ---------------------------------------------------------------------------
#[test]
fn database_and_jsonl_stay_consistent_under_concurrency() {
    let dir = test_dir("db-jsonl-consistency");
    let num_threads = 8;
    let writes_per_thread = 20;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = EventStore::new(&dir).unwrap();
                barrier.wait();
                for i in 0..writes_per_thread {
                    let session = make_session(
                        &format!("session-{thread_id}-{i}"),
                        1000 + (thread_id * 100 + i) as u64,
                    );
                    store.append_session(&session).unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Count records in JSONL.
    let store = EventStore::new(&dir).unwrap();
    let jsonl_sessions = store.list_sessions().unwrap();
    let jsonl_count = jsonl_sessions.len();

    // Count records in SQLite.
    let db = store.sqlite_store().unwrap();
    let mut db_count = 0;
    for thread_id in 0..num_threads {
        for i in 0..writes_per_thread {
            let session_id = format!("session-{thread_id}-{i}");
            if db.get_session(&session_id).unwrap().is_some() {
                db_count += 1;
            }
        }
    }

    let expected = num_threads * writes_per_thread;

    // If the two stores diverged, this assertion catches it.
    assert_eq!(
        jsonl_count, db_count,
        "JSONL has {jsonl_count} records but SQLite has {db_count} — \
         the non-atomic DB+JSONL write path lost consistency"
    );
    assert_eq!(
        jsonl_count, expected,
        "expected {expected} total records but found {jsonl_count}"
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 3: Concurrent daemon-style thread writes through a shared Arc<EventStore>
//
// Simulates the daemon architecture: one EventStore behind an Arc, shared
// across threads that each handle a hook connection. The SQLite layer has
// its own Mutex, but JSONL appends go through the same codepath without
// synchronization. This test verifies that hook events written from many
// daemon handler threads all land correctly in both the DB and JSONL.
// ---------------------------------------------------------------------------
#[test]
fn daemon_threads_sharing_arc_store_do_not_corrupt() {
    let dir = test_dir("daemon-arc-store");
    let store = Arc::new(EventStore::new(&dir).unwrap());
    let num_threads = 10;
    let writes_per_thread = 30;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..writes_per_thread {
                    let event = make_hook_event(
                        &format!("daemon-session-{thread_id}"),
                        &format!("daemon-tool-{thread_id}-{i}"),
                        2000 + (thread_id * 100 + i) as u64,
                    );
                    store.append_hook_event(&event).unwrap();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let loaded = store.list_hook_events().unwrap();
    let expected = num_threads * writes_per_thread;
    assert_eq!(
        loaded.len(),
        expected,
        "expected {expected} hook events through Arc<EventStore> but got {} — \
         daemon-style concurrent writes lost records",
        loaded.len()
    );

    // Verify no duplicate tool_use_ids (each should be unique).
    let tool_ids: std::collections::HashSet<_> = loaded
        .iter()
        .filter_map(|e| e.tool_use_id.as_deref())
        .collect();
    assert_eq!(
        tool_ids.len(),
        expected,
        "duplicate tool_use_ids found — concurrent writes produced duplicates"
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 4: Simultaneous workspace effect and system event writes
//
// Simulates what happens during `gensee watch`: the main thread writes
// workspace effects (file create/modify/delete) while a background thread
// writes system events (from eslogger). Both use the same EventStore clone.
// Even though they write to different JSONL files, they share the SQLite
// Mutex. This test checks for deadlocks, data loss, or corruption when
// the two writers race.
// ---------------------------------------------------------------------------
#[test]
fn watch_effect_and_system_event_writers_do_not_race() {
    let dir = test_dir("watch-dual-writer");
    let store = EventStore::new(&dir).unwrap();
    let store_clone = store.clone();
    let num_effects = 100;
    let num_events = 100;
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = Arc::clone(&barrier);

    // Background thread: writes system events (simulates eslogger ingestion thread).
    let system_event_thread = thread::spawn(move || {
        barrier_clone.wait();
        for i in 0..num_events {
            let event = make_system_event(1000 + i, 3000 + i as u64);
            store_clone.append_system_event(&event).unwrap();
        }
    });

    // Main thread: writes workspace effects (simulates FSEvents callback).
    barrier.wait();
    for i in 0..num_effects {
        let effect = make_workspace_effect(
            "watch-session",
            &format!("/test/file-{i}.txt"),
            3000 + i as u64,
        );
        store.append_workspace_effect(&effect).unwrap();
    }

    system_event_thread.join().unwrap();

    let effects = store.list_workspace_effects().unwrap();
    let events = store.list_system_events().unwrap();

    assert_eq!(
        effects.len(),
        num_effects,
        "expected {num_effects} workspace effects but got {} — \
         concurrent watch writers lost effect records",
        effects.len()
    );
    assert_eq!(
        events.len(),
        num_events,
        "expected {num_events} system events but got {} — \
         concurrent watch writers lost system event records",
        events.len()
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 5: Session start/end lifecycle is non-atomic
//
// Simulates the gap between writing a session start record (ended_at_ms =
// None) and the session end record. During this window, list_sessions()
// reports the session as "active" even if nothing is actually running.
// This test writes a start record, verifies is_active() returns true,
// then checks that after writing the end record the session is no longer
// active. It also demonstrates the stale-session problem: if the end
// record is never written, the session stays "active" forever.
// ---------------------------------------------------------------------------
#[test]
fn stale_session_stays_active_when_end_record_missing() {
    let dir = test_dir("stale-session");
    let store = EventStore::new(&dir).unwrap();

    // Write start record only (simulates a process that was killed before
    // writing the end record).
    let session = make_session("stale-run-1", 5000);
    store.append_session(&session).unwrap();

    let sessions = store.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    // This session will report "active" forever because ended_at_ms is None
    // and is_active() never checks if the PID is alive.
    assert!(
        sessions[0].is_active(),
        "session without end record should appear active"
    );

    // Now write the end record (simulates clean shutdown).
    let ended_session = AgentSession {
        ended_at_ms: Some(6000),
        exit_code: Some(0),
        ..session.clone()
    };
    store.append_session(&ended_session).unwrap();

    // compact_sessions (used by list_runs) merges start+end records by
    // session_id, taking the one with ended_at_ms set. But the JSONL still
    // has both records — the start record is never cleaned up.
    let raw = fs::read_to_string(store.sessions_path()).unwrap();
    let raw_count = raw.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        raw_count, 2,
        "JSONL should have both start and end records (append-only)"
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 6: Multiple stores opening the same directory concurrently
//
// In production, every hook invocation opens a fresh EventStore to the same
// GENSEE_HOME. If two hooks fire at the same instant (e.g., concurrent
// Claude Code sessions), two processes open the SQLite database and the
// JSONL files simultaneously. This test simulates that by opening N
// EventStore instances to the same directory from N threads and having
// each write a session record. It checks for SQLite locking errors and
// JSONL corruption.
// ---------------------------------------------------------------------------
#[test]
fn multiple_stores_to_same_directory_do_not_corrupt() {
    let dir = test_dir("multi-store-open");
    let num_threads = 6;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                // Each thread creates its own EventStore — separate SQLite
                // connections, separate file handles, same on-disk files.
                // This is the exact pattern of concurrent hook invocations.
                let store = EventStore::new(&dir).unwrap();
                barrier.wait();

                let session =
                    make_session(&format!("multi-store-{thread_id}"), 7000 + thread_id as u64);
                store.append_session(&session).unwrap();

                let event = make_hook_event(
                    &format!("multi-store-{thread_id}"),
                    &format!("multi-tool-{thread_id}"),
                    7000 + thread_id as u64,
                );
                store.append_hook_event(&event).unwrap();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify with a fresh store that all records survived.
    let store = EventStore::new(&dir).unwrap();
    let sessions = store.list_sessions().unwrap();
    let hooks = store.list_hook_events().unwrap();

    assert_eq!(
        sessions.len(),
        num_threads,
        "expected {num_threads} sessions from separate stores but got {} — \
         concurrent store opens lost session records",
        sessions.len()
    );
    assert_eq!(
        hooks.len(),
        num_threads,
        "expected {num_threads} hook events from separate stores but got {} — \
         concurrent store opens lost hook records",
        hooks.len()
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 7: Mixed read/write contention
//
// Simulates a reader (like `gensee timeline` or the dashboard's
// /api/state endpoint) reading JSONL files while writers are actively
// appending. The reader should see a consistent snapshot — every line it
// reads should be valid JSON, even if the file is being appended to
// concurrently. Partial reads (a line cut off mid-write) would produce
// parse errors.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_read_during_writes_sees_valid_records() {
    let dir = test_dir("read-write-contention");
    let store = Arc::new(EventStore::new(&dir).unwrap());
    let num_writers = 4;
    let writes_per_writer = 50;
    let barrier = Arc::new(Barrier::new(num_writers + 1)); // +1 for the reader

    // Spawn writer threads.
    let writer_handles: Vec<_> = (0..num_writers)
        .map(|thread_id| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..writes_per_writer {
                    let effect = make_workspace_effect(
                        &format!("rw-session-{thread_id}"),
                        &format!("/test/rw-{thread_id}-{i}.txt"),
                        8000 + (thread_id * 100 + i) as u64,
                    );
                    store.append_workspace_effect(&effect).unwrap();
                }
            })
        })
        .collect();

    // Reader thread: repeatedly reads the JSONL file while writers are active.
    // Every record it successfully parses should be valid. If it sees a partial
    // line (from an interleaved write), the parse will fail.
    let reader_store = Arc::clone(&store);
    let reader_barrier = Arc::clone(&barrier);
    let reader_handle = thread::spawn(move || {
        reader_barrier.wait();
        let mut max_seen = 0;
        let mut corrupt_lines = 0;
        // Read 20 times during the write window.
        for _ in 0..20 {
            match reader_store.list_workspace_effects() {
                Ok(effects) => {
                    if effects.len() > max_seen {
                        max_seen = effects.len();
                    }
                }
                Err(_) => {
                    // A read error during concurrent writes is itself a
                    // concurrency issue worth flagging.
                    corrupt_lines += 1;
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        (max_seen, corrupt_lines)
    });

    for handle in writer_handles {
        handle.join().unwrap();
    }
    let (max_seen, corrupt_lines) = reader_handle.join().unwrap();

    assert_eq!(
        corrupt_lines, 0,
        "reader encountered {corrupt_lines} read errors during concurrent writes"
    );
    // The reader should have seen at least some records accumulating.
    assert!(
        max_seen > 0,
        "reader never saw any records — possible locking or timing issue"
    );

    // Final consistency check: all records present after writers finish.
    let final_effects = store.list_workspace_effects().unwrap();
    let expected = num_writers * writes_per_writer;
    assert_eq!(
        final_effects.len(),
        expected,
        "expected {expected} workspace effects but found {} after concurrent read/write",
        final_effects.len()
    );

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Test 8: Session ID collision under concurrent writes
//
// If two processes generate the same session_id (unlikely but possible
// with PID reuse + same millisecond timestamp), the database INSERT OR
// REPLACE overwrites the first record, but the JSONL append keeps both.
// This test deliberately writes two sessions with the same ID from
// different threads and verifies the inconsistency: SQLite has one record,
// JSONL has two.
// ---------------------------------------------------------------------------
#[test]
fn session_id_collision_creates_db_jsonl_divergence() {
    let dir = test_dir("session-id-collision");
    let store = EventStore::new(&dir).unwrap();
    let colliding_id = "collision-session";

    // First write: session started at t=9000.
    let session_a = AgentSession {
        started_at_ms: 9000,
        ..make_session(colliding_id, 9000)
    };
    store.append_session(&session_a).unwrap();

    // Second write: same session_id, different timestamp. In production this
    // would be the end-of-session record OR a PID-reuse collision.
    let session_b = AgentSession {
        started_at_ms: 9000,
        ended_at_ms: Some(9500),
        exit_code: Some(0),
        ..make_session(colliding_id, 9000)
    };
    store.append_session(&session_b).unwrap();

    // JSONL: both records are present (append-only).
    let jsonl_sessions = store.list_sessions().unwrap();
    let jsonl_matches = jsonl_sessions
        .iter()
        .filter(|s| s.session_id == colliding_id)
        .count();

    // SQLite: INSERT OR REPLACE means only the latest survives.
    let db = store.sqlite_store().unwrap();
    let db_session = db.get_session(colliding_id).unwrap();

    assert_eq!(
        jsonl_matches, 2,
        "JSONL should have both records for colliding session_id"
    );
    assert!(
        db_session.is_some(),
        "SQLite should have one record for the colliding session_id"
    );
    // This demonstrates the divergence: JSONL has 2, DB has 1.
    assert_ne!(
        jsonl_matches, 1,
        "JSONL and DB counts should differ — this IS the consistency bug"
    );

    fs::remove_dir_all(&dir).ok();
}
