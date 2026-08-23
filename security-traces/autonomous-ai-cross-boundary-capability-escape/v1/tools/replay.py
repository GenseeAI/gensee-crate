#!/usr/bin/env python3
"""Replay a normalized trace to stdout without executing recorded effects."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
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

    previous_timestamp: int | None = None
    with args.trace.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            timestamp = event.get("ts_offset_ms")
            if not isinstance(timestamp, int):
                raise SystemExit(f"{args.trace}:{line_number}: invalid ts_offset_ms")
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
        sys.stdout.close()
        raise SystemExit(0)
