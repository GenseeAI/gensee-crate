#!/opt/homebrew/bin/python3
"""
bench.py — SQLite latency and throughput benchmarks for gensee-crate tables.

Which tables to create/benchmark and which evaluations to run are read from
sqlite.yaml's `bench:` section.

Latency evaluation:
  Insert 5,000 rows one-by-one, record each individual commit latency.
  Plot as CDF: x-axis = single request latency (ms), y-axis = cumulative fraction.

Throughput evaluation:
  Simulate a Poisson arrival process at increasing rates.
  x-axis = arrival rate (req/s)  |  y-axis = completed requests per second.
  Below saturation the line is diagonal (completion ≈ arrival).
  Above saturation it goes flat, revealing the max sustainable commit rate.

query_latency / query_throughput evaluations:
  Same as above, but for the read queries in QUERY_DEFS (see queries.sql)
  instead of per-table inserts. sessions / requests / agent_events /
  system_events are first populated with synthetic per-request event streams
  (via populate_agent_events.build_request) so the queries have realistic
  data to run against.

Outputs:  db/output/latency.png
          db/output/throughput.png
          db/output/query_latency.png
          db/output/query_throughput.png
"""

import json
import random
import sqlite3
import string
import time
from pathlib import Path

import numpy as np
import yaml
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker

from populate_agent_events import build_request, NUM_REQUESTS

# ── paths ──────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent.parent
SQLITE_YAML = Path(__file__).parent / "sqlite.yaml"
SCHEMA_SQL  = Path(__file__).parent / "schema.sql"
DB         = ROOT / "bench.db"
OUT        = Path(__file__).parent / "output"
OUT.mkdir(exist_ok=True)

# ── dummy-data helpers ─────────────────────────────────────────────────────────
HOOK_TYPES = ["PreToolUse", "PostToolUse", "UserPromptSubmit"]
TOOL_NAMES = ["Bash", "Read", "Write", "Edit", "Grep"]
SYS_TYPES  = ["execve", "openat", "connect", "write"]

def _s(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))

def _ts():
    return int(time.time() * 1000)

# ── per-table definitions ───────────────────────────────────────────────────────
# Tables themselves come straight from db/schema.sql (loaded verbatim in
# make_db()) — these entries only describe how to insert a benchmark row.
TABLE_DEFS = {
    "sessions": {
        "insert":
            "INSERT INTO sessions (session_id, agent_id, first_event_at)"
            " VALUES (?,?,?)",
        "row": lambda i: (
            f"sess_{i}", f"agent_{i}", _ts(),
        ),
    },
    "requests": {
        "insert":
            "INSERT INTO requests (request_id, session_id, original_user_prompt, final_response)"
            " VALUES (?,?,?,?)",
        "row": lambda i: (
            i + 1, f"sess_{i}", f"prompt {i}", f"response {i}",
        ),
    },
    "agent_events": {
        "insert":
            "INSERT INTO agent_events"
            " (pid, request_id, ts, source, type, cwd, permission_mode, tool_name, tool_input, tool_response)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
        "row": lambda i: (
            1000 + i, i + 1, _ts(), "hook",
            random.choice(HOOK_TYPES), "/workspace", "default",
            random.choice(TOOL_NAMES),
            json.dumps({"command": "ls"}), json.dumps({"output": "ok"}),
        ),
    },
    "system_events": {
        "insert":
            "INSERT INTO system_events"
            " (pid, request_id, ts, source, type, cwd, args)"
            " VALUES (?,?,?,?,?,?,?)",
        "row": lambda i: (
            1000 + i, i + 1, _ts(),
            "kernel", random.choice(SYS_TYPES), "/workspace",
            json.dumps({"path": f"/etc/{_s()}"}),
        ),
    },
}

# ── per-query definitions (see queries.sql) ─────────────────────────────────────
QUERY_DEFS = {
    "request_agent_events": {
        "sql": "SELECT * FROM agent_events WHERE request_id = ? ORDER BY ts",
        "params": lambda request_ids: (random.choice(request_ids),),
    },
    "request_system_events": {
        "sql": "SELECT * FROM system_events WHERE request_id = ? ORDER BY ts",
        "params": lambda request_ids: (random.choice(request_ids),),
    },
}

# ── config ─────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    config = yaml.safe_load(SQLITE_YAML.read_text())
    sqlite_cfg = config.get("sqlite", {})
    bench_cfg = config.get("bench", {})

    tables = bench_cfg.get("tables", list(TABLE_DEFS.keys()))
    unknown = set(tables) - set(TABLE_DEFS.keys())
    if unknown:
        raise ValueError(f"unknown table(s) in sqlite.yaml bench.tables: {sorted(unknown)}")

    queries = bench_cfg.get("queries", list(QUERY_DEFS.keys()))
    unknown_queries = set(queries) - set(QUERY_DEFS.keys())
    if unknown_queries:
        raise ValueError(f"unknown quer(y/ies) in sqlite.yaml bench.queries: {sorted(unknown_queries)}")

    evaluations = bench_cfg.get("evaluations", ["latency", "throughput"])
    unknown_evals = set(evaluations) - {
        "latency", "throughput", "query_latency", "query_latency_cold", "query_throughput",
    }
    if unknown_evals:
        raise ValueError(f"unknown evaluation(s) in sqlite.yaml bench.evaluations: {sorted(unknown_evals)}")

    return {"tables": tables, "queries": queries, "evaluations": evaluations, "pragmas": sqlite_cfg}

# ── database setup ─────────────────────────────────────────────────────────────
def make_db(tables: list[str], pragmas: dict) -> sqlite3.Connection:
    if DB.exists():
        DB.unlink()
    conn = sqlite3.connect(str(DB))
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute(f"PRAGMA journal_mode = {pragmas.get('journal_mode', 'wal')}")
    conn.execute(f"PRAGMA synchronous = {pragmas.get('synchronous', 'normal')}")
    conn.execute(f"PRAGMA auto_vacuum = {pragmas.get('auto_vacuum', 'full')}")
    if pragmas.get("shared_cache"):
        conn.execute("PRAGMA shared_cache = ON")
    conn.executescript(SCHEMA_SQL.read_text())
    conn.commit()
    return conn

def clear(conn, table):
    conn.execute(f"DELETE FROM {table}")
    conn.commit()

# ── query benchmark setup ────────────────────────────────────────────────────────
def populate_requests(conn) -> list[int]:
    """Fill sessions/requests/agent_events/system_events with synthetic
    per-request event streams for query benchmarks.

    Returns request_ids — one per synthetic request.
    """
    for table in ("agent_events", "system_events", "requests", "sessions"):
        clear(conn, table)

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

    print(f"  populated {NUM_REQUESTS} requests with {len(all_agent_events)} agent_events"
          f" + {len(all_system_events)} system_events")
    return request_ids

# ── latency CDF benchmark ──────────────────────────────────────────────────────
CDF_N = 5_000  # individual inserts per table

def bench_latency_cdf(conn, tables: list[str]) -> dict[str, np.ndarray]:
    """Return per-request latency samples (ms) for each table."""
    results: dict[str, np.ndarray] = {}

    for table in tables:
        sql = TABLE_DEFS[table]["insert"]
        row = TABLE_DEFS[table]["row"]
        clear(conn, table)
        samples = []

        for i in range(CDF_N):
            t0 = time.perf_counter()
            conn.execute(sql, row(i))
            conn.commit()
            samples.append((time.perf_counter() - t0) * 1000)

        results[table] = np.array(samples)
        p50 = np.percentile(samples, 50)
        p99 = np.percentile(samples, 99)
        print(f"  latency CDF  {table:25s}  p50={p50:.3f} ms  p99={p99:.3f} ms")

    return results

# ── throughput benchmark ───────────────────────────────────────────────────────
RATES    = [2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000]
POISSON_N = 200  # requests per rate sample

def bench_throughput(conn, tables: list[str]) -> dict[str, list[float]]:
    """Return completed req/s for each (table, rate) pair."""
    results: dict[str, list[float]] = {t: [] for t in tables}

    for table in tables:
        sql = TABLE_DEFS[table]["insert"]
        row = TABLE_DEFS[table]["row"]
        counter = 0
        clear(conn, table)

        for rate in RATES:
            gaps     = np.random.exponential(1.0 / rate, POISSON_N)
            arrivals = np.cumsum(gaps)   # seconds after t0

            t0 = time.perf_counter()
            for arrival in arrivals:
                remaining = (t0 + arrival) - time.perf_counter()
                if remaining > 0:
                    time.sleep(remaining)
                conn.execute(sql, row(counter))
                conn.commit()
                counter += 1
            wall = time.perf_counter() - t0

            completed_per_sec = POISSON_N / wall
            results[table].append(completed_per_sec)
            print(f"  throughput  {table:25s}  rate={rate:>7,}/s  completed={completed_per_sec:,.0f}/s")

    return results

# ── query latency CDF benchmark ─────────────────────────────────────────────────
def bench_query_latency_cdf(conn, queries: list[str], request_ids: list[str], cold: bool = False) -> dict[str, np.ndarray]:
    """Return per-query latency samples (ms) for each query in `queries`.

    If `cold` is set, SQLite's page cache is dropped (PRAGMA shrink_memory)
    before every query, so each one re-reads its b-tree pages instead of
    reusing pages cached by earlier iterations.
    """
    results: dict[str, np.ndarray] = {}
    label = "query latency CDF (cold)" if cold else "query latency CDF"

    for name in queries:
        sql = QUERY_DEFS[name]["sql"]
        params_fn = QUERY_DEFS[name]["params"]
        samples = []

        for _ in range(CDF_N):
            params = params_fn(request_ids)
            if cold:
                conn.execute("PRAGMA shrink_memory")
            t0 = time.perf_counter()
            conn.execute(sql, params).fetchall()
            samples.append((time.perf_counter() - t0) * 1000)

        results[name] = np.array(samples)
        p50 = np.percentile(samples, 50)
        p99 = np.percentile(samples, 99)
        print(f"  {label}  {name:25s}  p50={p50:.3f} ms  p99={p99:.3f} ms")

    return results

# ── query throughput benchmark ──────────────────────────────────────────────────
def bench_query_throughput(conn, queries: list[str], request_ids: list[str]) -> dict[str, list[float]]:
    """Return completed req/s for each (query, rate) pair."""
    results: dict[str, list[float]] = {q: [] for q in queries}

    for name in queries:
        sql = QUERY_DEFS[name]["sql"]
        params_fn = QUERY_DEFS[name]["params"]

        for rate in RATES:
            gaps     = np.random.exponential(1.0 / rate, POISSON_N)
            arrivals = np.cumsum(gaps)   # seconds after t0

            t0 = time.perf_counter()
            for arrival in arrivals:
                remaining = (t0 + arrival) - time.perf_counter()
                if remaining > 0:
                    time.sleep(remaining)
                conn.execute(sql, params_fn(request_ids)).fetchall()
            wall = time.perf_counter() - t0

            completed_per_sec = POISSON_N / wall
            results[name].append(completed_per_sec)
            print(f"  query throughput  {name:25s}  rate={rate:>7,}/s  completed={completed_per_sec:,.0f}/s")

    return results

# ── plotting ───────────────────────────────────────────────────────────────────
COLORS = list(plt.cm.tab10.colors)
STYLE  = {"linewidth": 1.8}

def plot_latency_cdf(results: dict[str, np.ndarray], filename: str, title: str):
    fig, ax = plt.subplots(figsize=(11, 6))

    # Horizontal reference line at p99
    ax.axhline(0.99, color="black", linestyle=":", linewidth=1, alpha=0.4)
    ax.text(0.01, 0.992, "p99", fontsize=8, color="black", alpha=0.5,
            va="bottom", transform=ax.get_yaxis_transform())

    p99_points = []  # (x, table, color) for annotation after all lines drawn
    for (table, samples), color in zip(results.items(), COLORS):
        sorted_ms = np.sort(samples)
        cdf = np.arange(1, len(sorted_ms) + 1) / len(sorted_ms)
        ax.plot(sorted_ms, cdf, label=table, color=color, **STYLE)

        p99_val = float(np.percentile(samples, 99))
        ax.plot(p99_val, 0.99, "o", color=color, markersize=6, zorder=5)
        p99_points.append((p99_val, table, color))

    # Label p99 dots — stagger alternating above/below to reduce overlap
    p99_points.sort(key=lambda t: t[0])
    for i, (x, table, color) in enumerate(p99_points):
        y_off = 0.025 if i % 2 == 0 else -0.055
        ax.annotate(f"{x:.3f} ms",
                    xy=(x, 0.99), xytext=(x, 0.99 + y_off),
                    fontsize=7.5, color=color, ha="center",
                    arrowprops=dict(arrowstyle="-", color=color, lw=0.8))

    ax.set_xscale("log")
    ax.set_xlabel("Single request latency (ms)", fontsize=13)
    ax.set_ylabel("Cumulative fraction", fontsize=13)
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(xmax=1))
    ax.legend(fontsize=10, loc="lower right")
    ax.grid(True, which="both", linestyle="--", alpha=0.35)
    fig.tight_layout()
    path = OUT / filename
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\n  -> {path}")

def _wane_index(completed: list[float], threshold: float = 0.85) -> int:
    """Return index of the first rate where completed/arrival drops below threshold."""
    for i, (r, c) in enumerate(zip(RATES, completed)):
        if c / r < threshold:
            return i
    return len(RATES) - 1  # never wanes — mark last point

def plot_throughput(results: dict[str, list[float]], filename: str, title: str):
    fig, ax = plt.subplots(figsize=(11, 6))

    # Diagonal reference line: ideal case where completed = arrival rate
    ax.plot(RATES, RATES, color="black", linestyle="--", linewidth=1.2,
            alpha=0.4, label="ideal (completed = arrival rate)", zorder=0)

    wane_points = []  # (rate, completed, table, color)
    for (table, completed), color in zip(results.items(), COLORS):
        ax.plot(RATES, completed, marker="o", markersize=5, label=table, color=color, **STYLE)

        wi = _wane_index(completed)
        wane_points.append((RATES[wi], completed[wi], table, color))
        ax.plot(RATES[wi], completed[wi], "*", color=color, markersize=12, zorder=5)

    # Label wane stars — stagger to reduce overlap
    wane_points.sort(key=lambda t: t[1])
    for i, (rx, cy, table, color) in enumerate(wane_points):
        x_off = 1.15 if i % 2 == 0 else 0.75
        ax.annotate(f"{rx/1000:.0f}K",
                    xy=(rx, cy), xytext=(rx * x_off, cy * 1.18),
                    fontsize=7.5, color=color,
                    arrowprops=dict(arrowstyle="-", color=color, lw=0.8))

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Arrival rate (requests / second, Poisson)", fontsize=13)
    ax.set_ylabel("Completed requests / second", fontsize=13)
    ax.set_title(title, fontsize=14, fontweight="bold")
    ax.set_xticks(RATES)
    ax.set_xticklabels(["2K", "5K", "10K", "20K", "50K", "100K", "200K", "500K"], rotation=40, ha="right")
    ax.legend(fontsize=10, loc="lower right")
    ax.grid(True, which="both", linestyle="--", alpha=0.35)
    fig.tight_layout()
    path = OUT / filename
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  -> {path}")

# ── main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cfg = load_config()
    tables = cfg["tables"]
    queries = cfg["queries"]
    evaluations = cfg["evaluations"]
    print(f"Tables:      {tables}")
    print(f"Queries:     {queries}")
    print(f"Evaluations: {evaluations}")

    print("\nCreating database …")
    conn = make_db(tables, cfg["pragmas"])

    if "latency" in evaluations:
        print("\n=== Latency CDF benchmark ===")
        lat = bench_latency_cdf(conn, tables)
        plot_latency_cdf(lat, "latency.png",
                          f"Insert latency CDF — {CDF_N:,} individual commits per table")

    if "throughput" in evaluations:
        print("\n=== Throughput benchmark ===")
        tp = bench_throughput(conn, tables)
        plot_throughput(tp, "throughput.png", "Throughput — Poisson arrival simulation")

    query_evals = {"query_latency", "query_latency_cold", "query_throughput"}
    if query_evals & set(evaluations):
        print("\n=== Populating requests for query benchmarks ===")
        request_ids = populate_requests(conn)

        if "query_latency" in evaluations:
            print("\n=== Query latency CDF benchmark ===")
            qlat = bench_query_latency_cdf(conn, queries, request_ids)
            plot_latency_cdf(qlat, "query_latency.png",
                              f"Query latency CDF — {CDF_N:,} individual queries")

        if "query_latency_cold" in evaluations:
            print("\n=== Query latency CDF benchmark (cold cache) ===")
            qlat_cold = bench_query_latency_cdf(conn, queries, request_ids, cold=True)
            plot_latency_cdf(qlat_cold, "query_latency_cold.png",
                              f"Query latency CDF (cold cache) — {CDF_N:,} individual queries")

        if "query_throughput" in evaluations:
            print("\n=== Query throughput benchmark ===")
            qtp = bench_query_throughput(conn, queries, request_ids)
            plot_throughput(qtp, "query_throughput.png", "Query throughput — Poisson arrival simulation")

    conn.close()
    DB.unlink()
    print("\nDone.")
