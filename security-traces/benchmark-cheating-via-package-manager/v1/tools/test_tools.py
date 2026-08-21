#!/usr/bin/env python3
"""Regression tests for validation, replay, and scoring."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "trace_build_dataset", TOOLS / "build_dataset.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load build_dataset.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TraceToolTests(unittest.TestCase):
    def run_tool(self, name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOLS / name), *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_dataset_validates(self) -> None:
        result = self.run_tool("validate.py", str(ROOT))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_replay_is_sorted_and_filterable(self) -> None:
        trace = ROOT / "traces" / "unified-timeline.jsonl"
        result = self.run_tool("replay.py", str(trace), "--source", "nexus")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(records)
        self.assertTrue(all(record["source"] == "nexus" for record in records))
        timestamps = [record["ts_offset_ms"] for record in records]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_perfect_stage_alerts_score_every_stage(self) -> None:
        truth = json.loads((ROOT / "ground-truth.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            alerts.write_text(
                "".join(
                    json.dumps(
                        {
                            "ts_offset_ms": stage["ts_offset_ms"],
                            "rule_id": f"test-{stage['stage_id']}",
                            "stage_id": stage["stage_id"],
                            "source": stage["expected_sources"][0],
                            "kind": stage["expected_kinds"][0],
                        }
                    )
                    + "\n"
                    for stage in truth["stages"]
                )
            )
            result = self.run_tool(
                "score.py",
                str(ROOT / "ground-truth.json"),
                str(alerts),
                "--require-stage-count",
                str(len(truth["stages"])),
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        score = json.loads(result.stdout)
        self.assertEqual(score["detected_stage_count"], len(truth["stages"]))
        self.assertEqual(score["unmatched_alert_count"], 0)

    def test_duplicate_alerts_detect_only_one_stage(self) -> None:
        truth = json.loads((ROOT / "ground-truth.json").read_text())
        shared_timestamp = truth["stages"][3]["ts_offset_ms"]
        alert = {
            "ts_offset_ms": shared_timestamp,
            "rule_id": "one-redirect-alert",
            "source": truth["stages"][3]["expected_sources"][0],
            "kind": truth["stages"][3]["expected_kinds"][0],
        }
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            alerts.write_text("".join(json.dumps(alert) + "\n" for _ in range(3)))
            result = self.run_tool(
                "score.py", str(ROOT / "ground-truth.json"), str(alerts)
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        score = json.loads(result.stdout)
        self.assertEqual(score["alert_count"], 3)
        self.assertEqual(score["unique_alert_count"], 1)
        self.assertEqual(score["duplicate_alert_count"], 2)
        self.assertEqual(score["detected_stage_count"], 1)

    def test_source_and_kind_are_required_and_stage_specific(self) -> None:
        truth = json.loads((ROOT / "ground-truth.json").read_text())
        stage = truth["stages"][0]
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            alerts.write_text(
                json.dumps(
                    {
                        "ts_offset_ms": stage["ts_offset_ms"],
                        "rule_id": "wrong-evidence",
                        "source": "nexus",
                        "kind": "http.request",
                    }
                )
                + "\n"
            )
            result = self.run_tool(
                "score.py", str(ROOT / "ground-truth.json"), str(alerts)
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        score = json.loads(result.stdout)
        self.assertEqual(score["detected_stage_count"], 0)
        self.assertEqual(score["unmatched_alert_count"], 1)

    def test_sanitizer_covers_ip_dates_and_embedded_identifiers(self) -> None:
        builder = load_builder()
        controlled_ip = ".".join(str(part) for part in (203, 0, 113, 32))
        secondary_ip = ":".join(("2001", "db8", "0", "0", "0", "0", "0", "1"))
        source_start = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        account_id = "12345"
        session_id = "77"
        process_id = "9012"
        systemd_user = "user-" + account_id + ".slice"
        systemd_session = "session-" + session_id + ".scope"
        sanitizer = builder.Sanitizer(
            source_start,
            "private-run",
            "private-operation",
            "private-proof",
            None,
            controlled_ip,
        )
        source = (
            f"http://{controlled_ip}/challenge "
            f"secondary=[{secondary_ip}] "
            "2030-01-02T03:04:06.123456789+0000 "
            "Wed, 02 Jan 2030 03:04:07 GMT "
            f"Jan  2 03:04:08 {systemd_user} {systemd_session} "
            f"loginuid={account_id} pid={process_id} daemon[{process_id}]"
        )
        result = sanitizer.sanitize_string(source)
        self.assertIn(builder.CONTROLLED_IP_PLACEHOLDER, result)
        self.assertNotIn(controlled_ip, result)
        self.assertNotIn(secondary_ip, result)
        self.assertNotIn("2030-01-02", result)
        self.assertNotIn("Wed, 02 Jan 2030", result)
        self.assertNotIn(systemd_user, result)
        self.assertNotIn(systemd_session, result)
        self.assertNotIn("loginuid=" + account_id, result)
        self.assertNotIn("pid=" + process_id, result)
        self.assertNotIn("daemon[" + process_id + "]", result)

    def test_safety_scan_includes_tooling_and_rejects_literal_ip(self) -> None:
        literal_ip = ".".join(str(part) for part in (203, 0, 113, 99))
        literal_ipv6 = ":".join(("2001", "db8", "0", "0", "0", "0", "0", "2"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "tools" / "leak.py"
            tool.parent.mkdir()
            tool.write_text(
                f'ENDPOINT = "{literal_ip}"\nENDPOINT_V6 = "{literal_ipv6}"\n'
            )
            result = self.run_tool("validate.py", str(root), "--safety-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("literal IP address found in tools/leak.py", result.stdout)

    def test_structured_identifiers_are_case_insensitive_and_type_safe(self) -> None:
        builder = load_builder()
        controlled_ip = ".".join(str(part) for part in (203, 0, 113, 32))
        sanitizer = builder.Sanitizer(
            datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            "private-run",
            "private-operation",
            "private-proof",
            None,
            controlled_ip,
        )
        digest = "sha256:" + "a" * 64
        thread_key = "thread" + ".tid"
        event_key = "evt" + ".num"
        result = sanitizer.sanitize(
            {
                "ImageDigest": digest,
                "SessionID": "session-private",
                thread_key: 246813579,
                event_key: 123456789,
                "CreatedAt": "2030-01-02T03:04:06.123456789+0000",
            }
        )
        self.assertNotEqual(result["ImageDigest"], digest)
        self.assertNotEqual(result["SessionID"], "session-private")
        self.assertIsInstance(result[thread_key], int)
        self.assertLess(result[thread_key], 0)
        self.assertIsInstance(result[event_key], int)
        self.assertLess(result[event_key], 0)
        self.assertNotIn("2030-01-02", result["CreatedAt"])


if __name__ == "__main__":
    unittest.main()
