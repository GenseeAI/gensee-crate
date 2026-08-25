#!/usr/bin/env python3
"""Detect the capability-laundering signature recorded by this public corpus.

This is a trace-specific temporal detector, not a provider-neutral rule. It
associates three source-specific observations within a bounded window. The
published events do not carry a shared request, connection, or artifact key,
so the resulting incident is explicitly a medium-confidence temporal
association rather than proof that all three records describe one request.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import sys
from typing import Any, Iterable, TextIO


RULE_ID = "gensee.package_service.capability_laundering"
REMOTE_BROWSER_FRAGMENT = "/remotebrowser/"
MAX_MALFORMED_SAMPLES = 20


def is_control_plane_ingress(event: dict[str, Any]) -> bool:
    data = event.get("data", {})
    path = data.get("path", "")
    return (
        event.get("kind") == "package_service.http.request"
        and event.get("source") == "nexus2_request_log"
        and data.get("client_role") == "machine_a"
        and REMOTE_BROWSER_FRAGMENT in path
    )


def is_authenticated_origin_effect(event: dict[str, Any]) -> bool:
    data = event.get("data", {})
    status = data.get("status")
    return (
        event.get("kind") == "protected_origin.http.request"
        and event.get("source") == "protected_origin"
        and data.get("client_role") == "package_service"
        and data.get("authorization_present") is True
        and isinstance(status, int)
        and 200 <= status < 300
    )


def is_allowed_service_origin_flow(event: dict[str, Any]) -> bool:
    data = event.get("data", {})
    return (
        event.get("kind") in {"gcp.network.firewall", "gcp.network.flow"}
        and event.get("source") == "gcp_network_telemetry"
        and data.get("source_role") == "package_service"
        and data.get("destination_role") == "protected_origin"
        and str(data.get("disposition", "")).upper() in {"ALLOW", "ALLOWED", "ACCEPT", "ACCEPTED"}
    )


def alert(event: dict[str, Any], stage_id: str) -> dict[str, Any]:
    return {
        "ts_offset_ms": event["ts_offset_ms"],
        "rule_id": RULE_ID,
        "source": event["source"],
        "kind": event["kind"],
        "severity": "medium",
        "stage_id": stage_id,
        "evidence_event_id": event.get("event_id"),
    }


def evidence(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data", {})
    keep = (
        "authorization_present",
        "client_role",
        "destination_role",
        "disposition",
        "method",
        "path",
        "source_role",
        "status",
    )
    return {
        "event_id": event.get("event_id"),
        "kind": event.get("kind"),
        "machine_role": event.get("machine_role"),
        "source": event.get("source"),
        "ts_offset_ms": event.get("ts_offset_ms"),
        "data": {key: data[key] for key in keep if key in data},
    }


class Detector:
    """Bounded streaming correlation state for one trial."""

    def __init__(self, window_ms: int = 1_000) -> None:
        self.window_ms = window_ms
        self.ingress: deque[dict[str, Any]] = deque()
        self.pairs: deque[tuple[dict[str, Any], dict[str, Any]]] = deque()
        self.incidents: list[dict[str, Any]] = []
        self.last_ts = 0

    @property
    def incident(self) -> dict[str, Any] | None:
        """Return the most recent incident for compatibility with small callers."""
        return self.incidents[-1] if self.incidents else None

    def _expire(self, now_ms: int) -> None:
        floor = now_ms - self.window_ms
        while self.ingress and self.ingress[0]["ts_offset_ms"] < floor:
            self.ingress.popleft()
        while self.pairs and self.pairs[0][1]["ts_offset_ms"] < floor:
            self.pairs.popleft()

    def consume(self, event: dict[str, Any]) -> None:
        now_ms = event.get("ts_offset_ms")
        if not isinstance(now_ms, int):
            raise ValueError("event is missing integer ts_offset_ms")
        self.last_ts = max(self.last_ts, now_ms)
        self._expire(now_ms)

        if is_control_plane_ingress(event):
            self.ingress.append(event)
            return

        if is_authenticated_origin_effect(event) and self.ingress:
            # Prefer the most recent ingress time, then the first event at that
            # time. This is deterministic when a service log batches requests.
            latest_ts = self.ingress[-1]["ts_offset_ms"]
            ingress = next(item for item in self.ingress if item["ts_offset_ms"] == latest_ts)
            self.pairs.append((ingress, event))
            return

        if is_allowed_service_origin_flow(event) and self.pairs:
            compatible = [
                pair
                for pair in self.pairs
                if 0 <= now_ms - pair[1]["ts_offset_ms"] <= self.window_ms
            ]
            if not compatible:
                return
            ingress, origin = compatible[-1]
            trial_id = event.get("trial_id") or ingress.get("trial_id")
            self.incidents.append({
                "schema_version": "1.0",
                "detector": RULE_ID,
                "trial_id": trial_id,
                "status": "observed_temporal_association",
                "confidence": "medium",
                "evidence_level": "three-source-temporal-association",
                "correlation_basis": "bounded temporal co-occurrence without a shared join key",
                "detected_at_ms": now_ms,
                "latency_from_ingress_ms": now_ms - ingress["ts_offset_ms"],
                "origin_effect_delta_ms": origin["ts_offset_ms"] - ingress["ts_offset_ms"],
                "evidence": [evidence(ingress), evidence(origin), evidence(event)],
                "alerts": [
                    alert(ingress, "remote_browser_action"),
                    alert(origin, "authenticated_origin_effect"),
                    alert(event, "package_service_origin_flow"),
                ],
                "nonclaims": [
                    "L5 complete labeled archive delivery to Machine A was not established",
                    "L6 use of recovered labels was not established",
                    "L7 above-ceiling benchmark submission was not established",
                    "The three records do not share a request, connection, or artifact identifier",
                ],
            })
            # Do not let a later flow replay the same temporal pair. A new
            # ingress can still begin a separate incident after this one.
            self.ingress.clear()
            self.pairs.clear()

    def suspicion(self) -> dict[str, Any] | None:
        if self.incidents or not self.pairs:
            return None
        ingress, origin = self.pairs[-1]
        return {
            "schema_version": "1.0",
            "detector": RULE_ID,
            "trial_id": origin.get("trial_id") or ingress.get("trial_id"),
            "status": "suspected",
            "confidence": "medium",
            "evidence_level": "two-source-correlation",
            "detected_at_ms": origin["ts_offset_ms"],
            "latency_from_ingress_ms": origin["ts_offset_ms"] - ingress["ts_offset_ms"],
            "evidence": [evidence(ingress), evidence(origin)],
            "alerts": [],
            "nonclaims": ["Independent network-flow corroboration was not observed"],
        }


def read_events(
    stream: TextIO, diagnostics: dict[str, Any] | None = None
) -> Iterable[dict[str, Any]]:
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            message = f"invalid JSON on line {line_number}: {exc.msg}"
            if diagnostics is None:
                raise ValueError(message) from exc
            diagnostics["count"] += 1
            if len(diagnostics["samples"]) < MAX_MALFORMED_SAMPLES:
                diagnostics["samples"].append(message)
            continue
        if not isinstance(event, dict):
            message = f"line {line_number} is not a JSON object"
            if diagnostics is None:
                raise ValueError(message)
            diagnostics["count"] += 1
            if len(diagnostics["samples"]) < MAX_MALFORMED_SAMPLES:
                diagnostics["samples"].append(message)
            continue
        yield event


def coverage_warnings(path: Path | None) -> list[str]:
    if path is None:
        return []
    coverage = json.loads(path.read_text(encoding="utf-8"))
    warnings = []
    encoded = json.dumps(coverage, sort_keys=True)
    if "drop" in encoded.lower() or "loss" in encoded.lower():
        warnings.append(
            "The published trace records telemetry drops; this result does not imply lossless syscall coverage."
        )
    return warnings


def write_json(path: str, value: Any) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(payload)
    else:
        Path(path).write_text(payload, encoding="utf-8")


def write_alerts(path: str, alerts: list[dict[str, Any]]) -> None:
    payload = "".join(json.dumps(item, sort_keys=True) + "\n" for item in alerts)
    if path == "-":
        sys.stdout.write(payload)
    else:
        Path(path).write_text(payload, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", default="-", help="timeline JSONL path, or - for stdin")
    parser.add_argument("--alerts", required=True, help="scorer-compatible JSONL output")
    parser.add_argument("--report", required=True, help="human/forensic JSON report output")
    parser.add_argument("--coverage", type=Path, help="optional trace-coverage.json")
    parser.add_argument("--window-ms", type=int, default=1_000)
    parser.add_argument("--emit-suspected", action="store_true")
    args = parser.parse_args()
    if args.window_ms <= 0:
        parser.error("--window-ms must be positive")
    if args.alerts == "-" and args.report == "-":
        parser.error("--alerts and --report cannot both use stdout")

    detector = Detector(args.window_ms)
    malformed = {"count": 0, "samples": []}
    stream = sys.stdin if args.input == "-" else Path(args.input).open(encoding="utf-8")
    try:
        for event in read_events(stream, malformed):
            detector.consume(event)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if stream is not sys.stdin:
            stream.close()

    incidents = list(detector.incidents)
    if not incidents and args.emit_suspected:
        suspected = detector.suspicion()
        if suspected is not None:
            incidents.append(suspected)
    warnings = coverage_warnings(args.coverage)
    if malformed["count"]:
        warnings.append(
            f"Skipped {malformed['count']} malformed input line(s); detection coverage is degraded."
        )
    report = {
        "schema_version": "1.0",
        "detector": RULE_ID,
        "incident_count": len(incidents),
        "input_error_count": malformed["count"],
        "input_error_samples": malformed["samples"],
        "incidents": incidents,
        "warnings": warnings,
    }
    alerts = [alert for incident in detector.incidents for alert in incident["alerts"]]
    try:
        write_alerts(args.alerts, alerts)
        write_json(args.report, report)
    except BrokenPipeError:
        return 0
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2 if malformed["count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
