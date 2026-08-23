#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ToolTests(unittest.TestCase):
    def run_tool(self, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *arguments], cwd=ROOT, input=input_text,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_validate(self) -> None:
        result = self.run_tool("tools/validate.py", ".")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_replay_count(self) -> None:
        result = self.run_tool("tools/replay.py", "traces/unified-timeline.jsonl")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = sum(1 for line in (ROOT / "traces/unified-timeline.jsonl").read_text().splitlines() if line)
        self.assertEqual(len(result.stdout.splitlines()), expected)

    def test_score_all_stages(self) -> None:
        truth = json.loads((ROOT / "ground-truth.json").read_text())
        alerts = []
        for stage in truth["stages"]:
            alerts.append(json.dumps({
                "kind": stage["expected_kinds"][0],
                "rule_id": f"test-{stage['stage_id']}",
                "source": stage["expected_sources"][0],
                "stage_id": stage["stage_id"],
                "ts_offset_ms": stage["ts_offset_ms"],
            }))
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as stream:
            stream.write("\n".join(alerts) + "\n")
            path = Path(stream.name)
        try:
            result = self.run_tool("tools/score.py", "ground-truth.json", str(path), "--require-stage-count", "7")
            self.assertEqual(result.returncode, 0, result.stderr)
            scored = json.loads(result.stdout)
            self.assertEqual(scored["detected_stage_count"], 7)
            self.assertEqual(scored["stage_recall"], 1.0)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
