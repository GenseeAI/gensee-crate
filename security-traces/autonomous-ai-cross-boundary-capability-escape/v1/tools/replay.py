#!/usr/bin/env python3
"""Replay a normalized trace to stdout without executing recorded effects."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path, nargs="+")
    parser.add_argument(
        "--clock",
        choices=("lane", "cohort"),
        default="lane",
        help="lane uses ts_offset_ms; cohort merges unified timelines by cohort_offset_ms",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=0.0,
        help="0 emits immediately; 1 preserves relative timing; 10 is ten times faster",
    )
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--from-ms", type=int)
    parser.add_argument("--to-ms", type=int)
    args = parser.parse_args()
    if args.speed < 0:
        parser.error("--speed must be non-negative")
    if len(args.trace) > 1 and args.clock != "cohort":
        parser.error("multiple traces require --clock cohort")

    timestamp_field = "cohort_offset_ms" if args.clock == "cohort" else "ts_offset_ms"
    events = []
    for trace_index, trace in enumerate(args.trace):
        with trace.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                timestamp = event.get(timestamp_field)
                if not isinstance(timestamp, int) or isinstance(timestamp, bool):
                    raise SystemExit(f"{trace}:{line_number}: invalid {timestamp_field}")
                trial_id = event.get("trial_id")
                local_sequence = event.get("interaction_seq")
                if not isinstance(trial_id, str) or not isinstance(local_sequence, int):
                    event_id = event.get("event_id", "")
                    if isinstance(event_id, str) and "_evt_" in event_id:
                        trial_id, suffix = event_id.rsplit("_evt_", 1)
                        local_sequence = int(suffix) if suffix.isdigit() else line_number
                    else:
                        trial_id = f"input-{trace_index:06d}"
                        local_sequence = line_number
                events.append((timestamp, trial_id, local_sequence, trace_index, line_number, event))
    if args.clock == "cohort":
        events.sort(key=lambda row: row[:5])

    previous_timestamp: int | None = None
    for timestamp, _, _, _, _, event in events:
        if args.source and event.get("source") not in args.source:
            continue
        if args.from_ms is not None and timestamp < args.from_ms:
            continue
        if args.to_ms is not None and timestamp > args.to_ms:
            continue
        if args.speed and previous_timestamp is not None:
            delay = max(0, timestamp - previous_timestamp) / 1000 / args.speed
            if delay:
                time.sleep(delay)
        print(json.dumps(event, sort_keys=True), flush=True)
        previous_timestamp = timestamp
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        with open(os.devnull, "w") as devnull:
            os.dup2(devnull.fileno(), sys.stdout.fileno())
        raise SystemExit(0)
