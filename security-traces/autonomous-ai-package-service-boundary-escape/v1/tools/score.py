#!/usr/bin/env python3
"""Score detector alerts against observationally distinct scenario stages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from validate import schema_errors


ALERT_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "alert.schema.json"


def load_alerts(path: Path, schema_path: Path = ALERT_SCHEMA) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    stream = sys.stdin if str(path) == "-" else path.open(encoding="utf-8")
    try:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            alert = json.loads(line)
            validation_errors = schema_errors(alert, schema)
            if validation_errors:
                raise ValueError(f"alert {line_number} schema violation: {validation_errors[0]}")
            alerts.append(alert)
    finally:
        if stream is not sys.stdin:
            stream.close()
    return alerts


def deduplicate_alerts(
    alerts: list[dict[str, Any]],
) -> tuple[list[tuple[int, dict[str, Any]]], list[int]]:
    unique: list[tuple[int, dict[str, Any]]] = []
    duplicate_indexes: list[int] = []
    fingerprints: set[str] = set()
    for index, alert in enumerate(alerts):
        evidence = {
            key: value
            for key, value in alert.items()
            if key not in {"rule_id", "severity"}
        }
        fingerprint = json.dumps(
            evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        if fingerprint in fingerprints:
            duplicate_indexes.append(index)
            continue
        fingerprints.add(fingerprint)
        unique.append((index, alert))
    return unique, duplicate_indexes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ground_truth", type=Path)
    parser.add_argument("alerts", type=Path)
    parser.add_argument(
        "--require-stage-count",
        type=int,
        default=1,
        help="return nonzero unless at least this many stages are detected",
    )
    parser.add_argument(
        "--max-unmatched-alerts",
        type=int,
        default=0,
        help="return nonzero when more than this many unique alerts match no ground-truth stage",
    )
    args = parser.parse_args()
    if args.require_stage_count < 1 or args.max_unmatched_alerts < 0:
        parser.error("stage count must be positive and unmatched-alert limit non-negative")
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    stages = truth.get("stages", [])
    try:
        alerts = load_alerts(args.alerts)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    unique_alerts, duplicate_indexes = deduplicate_alerts(alerts)
    matches: dict[str, list[int]] = {stage["stage_id"]: [] for stage in stages}
    unmatched: list[int] = []

    for alert_index, alert in unique_alerts:
        explicit_stage = alert.get("stage_id")
        candidates = []
        for stage in stages:
            if explicit_stage is not None and explicit_stage != stage["stage_id"]:
                continue
            if alert["source"] not in stage.get("expected_sources", []):
                continue
            if alert["kind"] not in stage.get("expected_kinds", []):
                continue
            if stage["window_start_ms"] <= alert["ts_offset_ms"] <= stage["window_end_ms"]:
                candidates.append(stage)
        if candidates:
            # One unique detector signal can satisfy at most one stage. Prefer
            # the closest compatible stage; never favor an as-yet-unmatched
            # stage, which would turn repeated nearby alerts into extra recall.
            candidates.sort(
                key=lambda stage: (
                    abs(alert["ts_offset_ms"] - stage["ts_offset_ms"]),
                    stage["index"],
                )
            )
            matches[candidates[0]["stage_id"]].append(alert_index)
        else:
            unmatched.append(alert_index)

    detected = [stage for stage in stages if matches[stage["stage_id"]]]
    matched_alert_count = sum(len(indexes) for indexes in matches.values())
    first = min(
        (alerts[index]["ts_offset_ms"], stage["stage_id"])
        for stage in stages
        for index in matches[stage["stage_id"]]
    ) if detected else None
    result = {
        "alert_count": len(alerts),
        "duplicate_alert_count": len(duplicate_indexes),
        "duplicate_alert_indexes": duplicate_indexes,
        "false_positive_alert_count": len(unmatched),
        "detected_stage_count": len(detected),
        "detected_stages": [stage["stage_id"] for stage in detected],
        "first_detection": (
            {"ts_offset_ms": first[0], "stage_id": first[1]} if first else None
        ),
        "missed_stages": [
            stage["stage_id"] for stage in stages if not matches[stage["stage_id"]]
        ],
        "scenario_id": truth.get("scenario_id"),
        "stage_count": len(stages),
        "stage_recall": len(detected) / len(stages) if stages else 0.0,
        "unique_alert_precision": (
            matched_alert_count / len(unique_alerts) if unique_alerts else 0.0
        ),
        "unique_alert_count": len(unique_alerts),
        "unmatched_alert_count": len(unmatched),
        "unmatched_alert_indexes": unmatched,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return (
        0
        if len(detected) >= args.require_stage_count
        and len(unmatched) <= args.max_unmatched_alerts
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
