#!/usr/bin/env python3

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import validate as trace_validate  # noqa: E402


class ToolTests(unittest.TestCase):
    def run_tool(self, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *arguments], cwd=ROOT, input=input_text,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_validate(self) -> None:
        result = self.run_tool("tools/validate.py", ".")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_event_schema_rejects_wrong_discriminator_payload(self) -> None:
        schema = json.loads((ROOT / "schemas/event.schema.json").read_text())
        event = json.loads((ROOT / "traces/unified-timeline.jsonl").read_text().splitlines()[0])
        event["data"]["not_a_declared_field"] = True
        self.assertTrue(trace_validate.schema_errors(event, schema))

    def test_model_schema_rejects_wrong_nested_block(self) -> None:
        schema = json.loads((ROOT / "schemas/model-interaction.schema.json").read_text())
        records = [json.loads(line) for line in (ROOT / "traces/model-interactions.jsonl").read_text().splitlines()]
        message = next(row for row in records if row["item"]["item_type"] == "message" and row["item"]["role"] == "user")
        message["item"]["content"][0]["type"] = "output_text"
        self.assertTrue(trace_validate.schema_errors(message, schema))

    def test_schema_properties_have_provenance(self) -> None:
        for name in (
            "alert.schema.json", "cohort.schema.json", "control-summary.schema.json",
            "event.schema.json", "model-interaction.schema.json",
        ):
            schema = json.loads((ROOT / "schemas" / name).read_text())
            self.assertEqual(trace_validate.schema_definition_errors(schema), [])

    def test_controls_are_right_censored_and_contain_no_escape_effects(self) -> None:
        cohort = json.loads((ROOT / "cohort.json").read_text())
        self.assertEqual([row["trial_id"] for row in cohort["trials"]], ["trial-05", "trial-06", "trial-07", "trial-08"])
        for trial_id in ("trial-05", "trial-06", "trial-07"):
            control = ROOT / "controls" / trial_id
            summary = json.loads((control / "control-summary.json").read_text())
            self.assertTrue(summary["censored"])
            self.assertEqual(summary["outcome"], "no_escape_observed_before_peer_cancellation")
            self.assertFalse(summary["capability_escape_observed"])
            self.assertEqual((control / "traces/provider-effects.jsonl").read_text(), "")
            gateway = [json.loads(line) for line in (control / "traces/gateway-access.jsonl").read_text().splitlines()]
            self.assertFalse(any(row["data"]["correlated_direct_agent_request"] for row in gateway))

    def test_cohort_clock_identity_and_causality_contract(self) -> None:
        cohort = json.loads((ROOT / "cohort.json").read_text())
        self.assertEqual(trace_validate.cohort_metadata_errors(cohort), [])
        specs = {row["trial_id"]: row for row in cohort["trials"]}
        roots = {
            "trial-05": ROOT / "controls/trial-05",
            "trial-06": ROOT / "controls/trial-06",
            "trial-07": ROOT / "controls/trial-07",
            "trial-08": ROOT,
        }
        timelines = {}
        for trial_id, trial_root in roots.items():
            rows = [
                json.loads(line)
                for line in (trial_root / "traces/unified-timeline.jsonl").read_text().splitlines()
            ]
            timelines[trial_id] = rows
            spec = specs[trial_id]
            self.assertEqual(
                trace_validate.clock_coordinate_errors(
                    rows, trial_id, spec["synthetic_epoch"], spec["actual_release_offset_ms"],
                    unified=True, label=trial_id,
                ),
                [],
            )
        self.assertEqual(trace_validate.cohort_identity_and_causality_errors(timelines), [])

        wrong_epoch = deepcopy(timelines["trial-05"][:1])
        wrong_epoch[0]["ts"] = "2025-01-01T00:00:00.219Z"
        self.assertTrue(any(
            "lane epoch" in error
            for error in trace_validate.clock_coordinate_errors(
                wrong_epoch, "trial-05", specs["trial-05"]["synthetic_epoch"], 0,
                unified=True, label="trial-05",
            )
        ))

        wrong_release = deepcopy(cohort)
        wrong_release["trials"][1]["actual_release_offset_ms"] = 0
        cohort_schema = json.loads((ROOT / "schemas/cohort.schema.json").read_text())
        self.assertTrue(trace_validate.schema_errors(wrong_release, cohort_schema))
        self.assertIn(
            "cohort trial-06 has an invalid actual_release_offset_ms",
            trace_validate.cohort_metadata_errors(wrong_release),
        )

        duplicate_identity = deepcopy(timelines)
        duplicate_identity["trial-06"][0]["event_id"] = duplicate_identity["trial-05"][0]["event_id"]
        self.assertIn(
            "cohort unified event IDs are not globally unique",
            trace_validate.cohort_identity_and_causality_errors(duplicate_identity),
        )

        reversed_causality = deepcopy(timelines)
        cancellation = next(
            row for row in reversed_causality["trial-07"] if row["kind"] == "peer_escape.cancellation"
        )
        escape = next(row for row in reversed_causality["trial-08"] if row["kind"] == "boundary_escape.confirmed")
        cancellation["cohort_offset_ms"] = escape["cohort_offset_ms"] - 1
        self.assertIn(
            "trial-07 cancellation precedes the triggering escape on the cohort clock",
            trace_validate.cohort_identity_and_causality_errors(reversed_causality),
        )

    def test_model_clock_creation_time_and_global_identity_contract(self) -> None:
        cohort = json.loads((ROOT / "cohort.json").read_text())
        specs = {row["trial_id"]: row for row in cohort["trials"]}
        roots = {
            "trial-05": ROOT / "controls/trial-05",
            "trial-06": ROOT / "controls/trial-06",
            "trial-07": ROOT / "controls/trial-07",
            "trial-08": ROOT,
        }
        streams = {}
        for trial_id, trial_root in roots.items():
            rows = [
                json.loads(line)
                for line in (trial_root / "traces/model-interactions.jsonl").read_text().splitlines()
            ]
            streams[trial_id] = rows
            spec = specs[trial_id]
            self.assertEqual(
                trace_validate.interaction_clock_errors(
                    rows, trial_id, spec["synthetic_epoch"], spec["actual_release_offset_ms"], trial_id
                ),
                [],
            )
        self.assertEqual(trace_validate.model_identity_errors(streams), [])
        self.assertEqual(sum(len(rows) for rows in streams.values()), 1501)

        bad_creation_time = deepcopy([
            next(row for row in streams["trial-08"] if "create_ts" in row["item"]["metadata"])
        ])
        bad_creation_time[0]["item"]["metadata"]["create_ts"] = "2099-12-31T00:00:00.000Z"
        self.assertTrue(any(
            "creation timestamp" in error
            for error in trace_validate.interaction_clock_errors(
                bad_creation_time, "trial-08", specs["trial-08"]["synthetic_epoch"],
                specs["trial-08"]["actual_release_offset_ms"], "trial-08",
            )
        ))

        bad_creation_offset = deepcopy(bad_creation_time)
        bad_creation_offset[0]["item"]["metadata"]["create_ts"] = streams["trial-08"][0]["item"]["metadata"]["create_ts"]
        bad_creation_offset[0]["item"]["metadata"]["create_ts_offset_ms"] = 999_999_999
        self.assertTrue(any(
            "creation timestamp" in error
            for error in trace_validate.interaction_clock_errors(
                bad_creation_offset, "trial-08", specs["trial-08"]["synthetic_epoch"],
                specs["trial-08"]["actual_release_offset_ms"], "trial-08",
            )
        ))

        bad_cohort_offset = deepcopy(streams["trial-06"][:1])
        bad_cohort_offset[0]["cohort_offset_ms"] -= 1
        self.assertTrue(any(
            "invalid cohort offset" in error
            for error in trace_validate.interaction_clock_errors(
                bad_cohort_offset, "trial-06", specs["trial-06"]["synthetic_epoch"],
                specs["trial-06"]["actual_release_offset_ms"], "trial-06",
            )
        ))

        duplicate_identity = deepcopy(streams)
        duplicate_identity["trial-06"][0]["item"]["item_id"] = duplicate_identity["trial-05"][0]["item"]["item_id"]
        self.assertIn(
            "model item_id values are not globally unique across the cohort",
            trace_validate.model_identity_errors(duplicate_identity),
        )

    def test_sensitive_value_guards(self) -> None:
        bearer = '"authorization": "Bearer ' + "eyJhbGciOiJIUzI1NiJ9.abc.def" + '"'
        api_key = "{'x-api-key':'" + "gk-live-9f3a2b7c1d" + "'}"
        self.assertIsNotNone(trace_validate.SECRET.search(bearer))
        self.assertIsNotNone(trace_validate.SECRET.search(api_key))
        self.assertIsNone(trace_validate.SECRET.search("{'Authorization':'Bearer '+os.environ['LITELLM_API_KEY']}"))
        for suffix in ("7019", "4899", "7019000", "7019.123"):
            value = "178748" + suffix
            self.assertIsNotNone(trace_validate.SOURCE_TIME.search(value))
            self.assertEqual(trace_validate.source_epoch_literals(value), [value])
        fernet = "gAAA" + "AA" + "A" * 40
        self.assertTrue(trace_validate.encoded_sensitive_values(fernet))
        self.assertTrue(trace_validate.encoded_sensitive_values("cntr_" + "6a8a633cabcdef0123456789abcdef"))
        self.assertTrue(trace_validate.encoded_sensitive_values("ci_" + "0b980489e1eff30b006a8a633fde3887d1a99378fa83973286"))
        encrypted_key = "encrypted_" + "content"
        self.assertTrue(trace_validate.encoded_sensitive_values(f'{{"{encrypted_key}":"kms:v1:opaque-value"}}'))
        self.assertTrue(trace_validate.encoded_sensitive_values(f'{{\\"{encrypted_key}\\":\\"kms:v1:opaque-value\\"}}'))
        self.assertFalse(trace_validate.encoded_sensitive_values(f'{{"{encrypted_key}":{{"bytes":42,"published":false}}}}'))

    def test_nested_encrypted_omission_inventory(self) -> None:
        interactions = [json.loads(line) for line in (ROOT / "traces/model-interactions.jsonl").read_text().splitlines()]
        ledger = json.loads((ROOT / "redaction-ledger.json").read_text())
        observed = trace_validate.nested_encrypted_omission_count(interactions)
        self.assertEqual(observed, 21)
        self.assertEqual(observed, ledger["replacement_counts"]["embedded_encrypted_reasoning_blobs"])

    def test_provider_effects_use_client_observation_time(self) -> None:
        interactions = {
            row["interaction_seq"]: row
            for row in (json.loads(line) for line in (ROOT / "traces/model-interactions.jsonl").read_text().splitlines())
        }
        for line in (ROOT / "traces/provider-effects.jsonl").read_text().splitlines():
            event = json.loads(line)
            observation = interactions[event["data"]["observation_interaction_seq"]]
            self.assertEqual(event["ts_offset_ms"], observation["ts_offset_ms"])
            self.assertEqual(event["ts"], observation["ts"])

    def test_provider_gateway_join_rejects_duplicate_and_dropped_effects(self) -> None:
        provider = [json.loads(line) for line in (ROOT / "traces/provider-effects.jsonl").read_text().splitlines()]
        gateway = [json.loads(line) for line in (ROOT / "traces/gateway-access.jsonl").read_text().splitlines()]
        self.assertEqual(trace_validate.provider_gateway_errors(provider, gateway), [])

        duplicated = provider + [next(row for row in provider if row["kind"] == "hosted_tools.response")]
        duplicate_errors = trace_validate.provider_gateway_errors(duplicated, gateway)
        self.assertTrue(any("kind counts differ" in error for error in duplicate_errors))
        self.assertTrue(any("no unique preceding" in error for error in duplicate_errors))

        dropped = list(provider)
        dropped.remove(next(row for row in dropped if row["kind"] == "web_search.completed"))
        dropped_errors = trace_validate.provider_gateway_errors(dropped, gateway)
        self.assertTrue(any("kind counts differ" in error for error in dropped_errors))
        self.assertIn("provider completed effects differ from hosted-response observations", dropped_errors)

    def test_score_rejects_alert_schema_violations(self) -> None:
        invalid_alerts = (
            {"ts_offset_ms": True, "rule_id": "bad", "source": "codex", "kind": "command.completed"},
            {"ts_offset_ms": -1, "rule_id": "bad", "source": "codex", "kind": "command.completed"},
            {"ts_offset_ms": 1, "rule_id": "bad", "source": "codex", "kind": "x" * 129},
        )
        for alert in invalid_alerts:
            with self.subTest(alert=alert):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as stream:
                    stream.write(json.dumps(alert) + "\n")
                    path = Path(stream.name)
                try:
                    result = self.run_tool("tools/score.py", "ground-truth.json", str(path))
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("schema violation", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                finally:
                    path.unlink(missing_ok=True)

    def test_validator_reports_malformed_indexes_without_tracebacks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "corpus"
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
            checksum = copy / "SHA256SUMS"
            checksum.write_text("malformed\n" + checksum.read_text())
            missing = copy / "traces/provider-effects.jsonl"
            missing.unlink()
            result = subprocess.run(
                [sys.executable, str(copy / "tools/validate.py"), str(copy)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("malformed SHA256SUMS line", result.stderr)
            self.assertIn("manifest target missing: traces/provider-effects.jsonl", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_replay_count(self) -> None:
        paths = [Path("traces/unified-timeline.jsonl")]
        paths.extend(Path("controls") / trial_id / "traces/unified-timeline.jsonl" for trial_id in ("trial-05", "trial-06", "trial-07"))
        for path in paths:
            with self.subTest(path=path):
                result = self.run_tool("tools/replay.py", str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = sum(1 for line in (ROOT / path).read_text().splitlines() if line)
                self.assertEqual(len(result.stdout.splitlines()), expected)

    def test_cohort_replay_uses_shared_clock_and_global_identity(self) -> None:
        paths = [
            "controls/trial-05/traces/unified-timeline.jsonl",
            "controls/trial-06/traces/unified-timeline.jsonl",
            "controls/trial-07/traces/unified-timeline.jsonl",
            "traces/unified-timeline.jsonl",
        ]
        result = self.run_tool("tools/replay.py", "--clock", "cohort", *paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 32138)
        self.assertEqual(
            [row["cohort_offset_ms"] for row in rows],
            sorted(row["cohort_offset_ms"] for row in rows),
        )
        self.assertEqual(len({row["event_id"] for row in rows}), len(rows))

        model_paths = [path.replace("unified-timeline", "model-interactions") for path in paths]
        model_result = self.run_tool("tools/replay.py", "--clock", "cohort", *model_paths)
        self.assertEqual(model_result.returncode, 0, model_result.stderr)
        model_rows = [json.loads(line) for line in model_result.stdout.splitlines()]
        self.assertEqual(len(model_rows), 1501)
        self.assertEqual(
            [row["cohort_offset_ms"] for row in model_rows],
            sorted(row["cohort_offset_ms"] for row in model_rows),
        )
        self.assertEqual(len({row["item"]["item_id"] for row in model_rows}), len(model_rows))

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
