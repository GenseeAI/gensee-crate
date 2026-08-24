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
