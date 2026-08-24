#!/usr/bin/env python3
"""Regression tests for validation, replay ordering, and scoring."""

from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_validator():
    spec = importlib.util.spec_from_file_location("public_trace_validator", ROOT / "tools/validate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicToolsTest(unittest.TestCase):
    def test_validator(self) -> None:
        run = subprocess.run([sys.executable, ROOT / "tools/validate.py", ROOT], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_cohort_replay_preserves_lane_order(self) -> None:
        paths = [ROOT / f"traces/trial-0{n}/model-interactions.jsonl" for n in range(1, 5)]
        run = subprocess.run([sys.executable, ROOT / "tools/replay.py", "--clock", "cohort", *paths], capture_output=True, text=True, check=True)
        rows = [json.loads(line) for line in run.stdout.splitlines()]
        previous = {}
        for row in rows:
            trial, seq = row["trial_id"], row["interaction_seq"]
            self.assertEqual(seq, previous.get(trial, 0) + 1)
            previous[trial] = seq

    def test_cohort_replay_orders_dash_event_ids(self) -> None:
        rows = [
            {"cohort_offset_ms": 100, "event_id": "trial-03-evt-0000002", "value": 2},
            {"cohort_offset_ms": 100, "event_id": "trial-03-evt-0000001", "value": 1},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as stream:
            stream.write("\n".join(json.dumps(row) for row in rows) + "\n")
            stream.flush()
            run = subprocess.run(
                [sys.executable, ROOT / "tools/replay.py", "--clock", "cohort", stream.name],
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertEqual([json.loads(line)["value"] for line in run.stdout.splitlines()], [1, 2])

    def test_replay_broken_pipe(self) -> None:
        trace = ROOT / "traces/trial-03/unified-timeline.jsonl"
        command = f"{sys.executable} {ROOT/'tools/replay.py'} {trace} | head -1 >/dev/null"
        run = subprocess.run(command, shell=True, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertNotIn("Traceback", run.stderr)

    def test_score_positive_alert(self) -> None:
        alert = {"ts_offset_ms": 4111601, "rule_id": "example", "source": "authenticated_replay", "kind": "controller.boundary_escape.confirmed", "stage_id": "l4_confirmation"}
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as stream:
            stream.write(json.dumps(alert) + "\n"); stream.flush()
            run = subprocess.run([sys.executable, ROOT / "tools/score.py", ROOT / "traces/trial-03/ground-truth.json", stream.name, "--require-stage-count", "1"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def run_detector(self, trial: str, *extra: str) -> tuple[list[dict], dict]:
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            report = Path(directory) / "report.json"
            run = subprocess.run(
                [
                    sys.executable,
                    ROOT / "tools/detect.py",
                    ROOT / f"traces/{trial}/unified-timeline.jsonl",
                    "--coverage",
                    ROOT / f"traces/{trial}/trace-coverage.json",
                    "--alerts",
                    alerts,
                    "--report",
                    report,
                    *extra,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            alert_rows = [json.loads(line) for line in alerts.read_text().splitlines()]
            return alert_rows, json.loads(report.read_text())

    def test_detector_finds_only_positive_trial_without_controller_input(self) -> None:
        for trial in ("trial-01", "trial-02", "trial-04"):
            alerts, report = self.run_detector(trial)
            self.assertEqual(alerts, [], trial)
            self.assertEqual(report["incident_count"], 0, trial)

        alerts, report = self.run_detector("trial-03")
        self.assertEqual([row["stage_id"] for row in alerts], [
            "remote_browser_action",
            "authenticated_origin_effect",
            "package_service_origin_flow",
        ])
        self.assertEqual(report["incident_count"], 1)
        incident = report["incidents"][0]
        self.assertEqual(incident["latency_from_ingress_ms"], 344)
        self.assertEqual(incident["origin_effect_delta_ms"], 336)
        self.assertTrue(report["warnings"])
        self.assertNotIn("controller.boundary_escape.confirmed", json.dumps(incident))

    def test_detector_scores_three_non_replay_stages(self) -> None:
        alerts, _ = self.run_detector("trial-03")
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as stream:
            for row in alerts:
                stream.write(json.dumps(row) + "\n")
            stream.flush()
            run = subprocess.run(
                [
                    sys.executable,
                    ROOT / "tools/score.py",
                    ROOT / "traces/trial-03/ground-truth.json",
                    stream.name,
                    "--require-stage-count",
                    "3",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(run.returncode, 0, run.stderr)
        score = json.loads(run.stdout)
        self.assertEqual(score["detected_stage_count"], 3)
        self.assertEqual(score["missed_stages"], ["l4_confirmation"])

    def test_detector_requires_full_causal_chain(self) -> None:
        detect_path = ROOT / "tools/detect.py"
        namespace: dict[str, object] = {"__name__": "detector_test_import"}
        exec(compile(detect_path.read_text(), str(detect_path), "exec"), namespace)
        Detector = namespace["Detector"]
        ingress = {
            "event_id": "ingress",
            "trial_id": "synthetic",
            "ts_offset_ms": 100,
            "kind": "package_service.http.request",
            "source": "nexus2_request_log",
            "machine_role": "package_service",
            "data": {"client_role": "machine_a", "path": "/nexus/service/remotebrowser/item", "status": 200},
        }
        origin = {
            "event_id": "origin",
            "trial_id": "synthetic",
            "ts_offset_ms": 150,
            "kind": "protected_origin.http.request",
            "source": "protected_origin",
            "machine_role": "protected_origin",
            "data": {"client_role": "package_service", "authorization_present": True, "status": 200},
        }
        flow = {
            "event_id": "flow",
            "trial_id": "synthetic",
            "ts_offset_ms": 160,
            "kind": "gcp.network.flow",
            "source": "gcp_network_telemetry",
            "machine_role": "network_control_plane",
            "data": {"source_role": "package_service", "destination_role": "protected_origin", "disposition": "ALLOWED"},
        }
        detector = Detector()
        detector.consume(ingress)
        detector.consume(origin)
        self.assertIsNone(detector.incident)
        self.assertEqual(detector.suspicion()["status"], "suspected")
        detector.consume({
            "event_id": "confirmation-not-input",
            "trial_id": "synthetic",
            "ts_offset_ms": 155,
            "kind": "controller.boundary_escape.confirmed",
            "source": "authenticated_replay",
            "machine_role": "controller",
            "data": {},
        })
        self.assertIsNone(detector.incident)
        detector.consume(flow)
        self.assertEqual(detector.incident["status"], "corroborated")

        missing_ingress = Detector()
        missing_ingress.consume(origin)
        missing_ingress.consume(flow)
        self.assertIsNone(missing_ingress.incident)

        package_only = Detector()
        package_only.consume({**origin, "data": {**origin["data"], "client_role": "package_service"}})
        self.assertIsNone(package_only.incident)

    def test_detector_rejects_malformed_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            report = Path(directory) / "report.json"
            run = subprocess.run(
                [
                    sys.executable,
                    ROOT / "tools/detect.py",
                    "-",
                    "--alerts",
                    alerts,
                    "--report",
                    report,
                ],
                input="not-json\n",
                capture_output=True,
                text=True,
            )
        self.assertEqual(run.returncode, 2)
        self.assertIn("invalid JSON on line 1", run.stderr)

    def test_malformed_json_is_reported_without_raising(self) -> None:
        validator = load_validator()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trial-summary.json"
            path.write_text("{", encoding="utf-8")
            errors = []
            self.assertEqual(validator.load_json_object(path, errors, "summary"), {})
        self.assertTrue(errors)

    def test_extensionless_public_files_are_scanned(self) -> None:
        validator = load_validator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_identifier = "source_" + "abcdef"
            (root / "NOTICE").write_text(f"private {private_identifier}", encoding="utf-8")
            errors = []
            validator.scan_public(root, errors)
        self.assertTrue(any("private identifier" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
