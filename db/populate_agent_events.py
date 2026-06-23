#!/opt/homebrew/bin/python3
"""
populate_agent_events.py — fill agent_events/system_events with synthetic
per-request event streams.

Each "request" gets one row in `sessions` and `requests`, plus a random
number of `agent_events` (tool-call hook events) and `system_events`
(kernel/process-level events), all sharing the request's request_id. This
matches the access pattern in queries.sql: "fetch every event recorded for
request X, oldest first".

Usage:
    cd db
    /opt/homebrew/bin/python3 populate_agent_events.py
"""

import json
import random
import sqlite3
import time
from pathlib import Path

import yaml

ROOT        = Path(__file__).parent
SQLITE_YAML = ROOT / "sqlite.yaml"
SCHEMA_SQL  = ROOT / "schema.sql"

NUM_REQUESTS     = 500
MIN_AGENT_EVENTS = 10
MAX_AGENT_EVENTS = 80
MIN_SYS_EVENTS   = 10
MAX_SYS_EVENTS   = 80

TOOL_NAMES  = ["Bash", "Read", "Write", "Edit", "Grep"]
HOOK_TYPES  = ["PreToolUse", "PostToolUse", "UserPromptSubmit"]
SYS_TYPES   = ["execve", "openat", "connect", "write"]


def build_request(req_idx: int) -> tuple[int, tuple, tuple, list[tuple], list[tuple]]:
    """Return (request_id, session_row, request_row, agent_event_rows,
    system_event_rows) for one synthetic request.
    """
    request_id = req_idx + 1
    session_id = f"sess_{req_idx}"
    agent_id = f"agent_{req_idx}"
    pid = 1000 + req_idx
    base_ts = int(time.time() * 1000) - random.randint(0, 86_400_000)

    session_row = (session_id, agent_id, base_ts)
    request_row = (request_id, session_id, f"prompt {req_idx}", f"response {req_idx}")

    n_agent = random.randint(MIN_AGENT_EVENTS, MAX_AGENT_EVENTS)
    agent_event_rows = []
    for i in range(n_agent):
        ts = base_ts + i * 10
        tool_name = random.choice(TOOL_NAMES)
        agent_event_rows.append((
            pid, request_id, ts, "hook", random.choice(HOOK_TYPES),
            "/workspace", "default", tool_name,
            json.dumps({"command": "ls"}), json.dumps({"output": "ok"}),
        ))

    n_sys = random.randint(MIN_SYS_EVENTS, MAX_SYS_EVENTS)
    system_event_rows = []
    for i in range(n_sys):
        ts = base_ts + i * 10
        system_event_rows.append((
            pid, request_id, ts, "kernel",
            random.choice(SYS_TYPES), "/workspace", json.dumps({"path": "/etc/passwd"}),
        ))

    return request_id, session_row, request_row, agent_event_rows, system_event_rows


def main():
    config = yaml.safe_load(SQLITE_YAML.read_text())
    db_path = (ROOT / config["sqlite"]["path"]).resolve()

    # Start fresh each run so re-running doesn't collide on primary keys. This
    # deletes whatever sqlite.path in sqlite.yaml points at, so make sure it's
    # a throwaway/synthetic database, not the application's real one.
    print(f"This will delete and recreate: {db_path}")
    for ext in ("", "-wal", "-shm"):
        candidate = db_path.with_name(db_path.name + ext)
        if candidate.exists():
            candidate.unlink()

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.executescript(SCHEMA_SQL.read_text())

    session_rows = []
    request_rows = []
    all_agent_events = []
    all_system_events = []
    request_ids = []

    for req_idx in range(NUM_REQUESTS):
        request_id, session_row, request_row, agent_event_rows, system_event_rows = build_request(req_idx)
        request_ids.append(request_id)
        session_rows.append(session_row)
        request_rows.append(request_row)
        all_agent_events.extend(agent_event_rows)
        all_system_events.extend(system_event_rows)

    conn.executemany(
        "INSERT INTO sessions (session_id, agent_id, first_event_at) VALUES (?,?,?)",
        session_rows,
    )
    conn.executemany(
        "INSERT INTO requests (request_id, session_id, original_user_prompt, final_response) VALUES (?,?,?,?)",
        request_rows,
    )
    conn.executemany(
        "INSERT INTO agent_events"
        " (pid, request_id, ts, source, type, cwd, permission_mode, tool_name, tool_input, tool_response)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        all_agent_events,
    )
    conn.executemany(
        "INSERT INTO system_events"
        " (pid, request_id, ts, source, type, cwd, args)"
        " VALUES (?,?,?,?,?,?,?)",
        all_system_events,
    )

    conn.commit()
    conn.close()

    print(f"Inserted {NUM_REQUESTS} rows into sessions/requests")
    print(f"Inserted {len(all_agent_events)} rows into agent_events")
    print(f"Inserted {len(all_system_events)} rows into system_events")
    print(f"Database: {db_path}")


if __name__ == "__main__":
    main()
