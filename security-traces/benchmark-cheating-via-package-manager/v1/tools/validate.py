#!/usr/bin/env python3
"""Validate dataset integrity, structure, and public-safety invariants."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any


EXPECTED_TRACE_FILES = {
    "challenge-origin-requests.jsonl",
    "codex-public-events.jsonl",
    "falco-replay.jsonl",
    "gensee-events.jsonl",
    "nexus-requests.jsonl",
    "package-origin-requests.jsonl",
    "unified-timeline.jsonl",
}
EXPECTED_SOURCES = {
    "codex",
    "gensee",
    "falco",
    "nexus",
    "package_origin",
    "challenge_origin",
}
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(^|_)(password|passwd|token|secret|api_key|authorization|cookie)($|_)"
)
FORBIDDEN_TEXT = {
    "private_user_path": re.compile("/" + r"Users/[^/\s\"']+"),
    "organization_email": re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@gensee\.ai\b"),
    "organization_account": re.compile(
        r"(?i)\b[a-z][a-z0-9_-]*" + r"_gensee" + r"_ai\b"
    ),
    "basic_credential": re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}"),
    "bearer_credential": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~-]{8,}"),
    "provider_key": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    "private_run_name": re.compile(
        r"\b(?:crate_fresh_[A-Za-z0-9_.-]+|crate-fresh-[A-Za-z0-9.-]+)"
    ),
    "private_operation_id": re.compile(r"\brun_[0-9]{3,}_[0-9]{10,}\b"),
    "private_infrastructure_identifier": re.compile(
        r"(?i)\b(?:machine" + r"-[a-z]-[a-z0-9-]+|[a-z0-9]+-crate"
        + r"-lab|package" + r"-origin-(?!requests\b)[a-z0-9-]+|simulated"
        + r"-internet-[a-z0-9-]+)\b"
    ),
    "url_userinfo": re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@/\s]+@"
    ),
    "secret_assignment": re.compile(
        r'''(?ix)
        \b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|AUTHORIZATION|COOKIE)[A-Z0-9_]*
        \s*=\s*
        (?!\[REDACTED\])
        (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\]\}]+)
        '''
    ),
    "numeric_systemd_user": re.compile(r"\buser-[0-9]+\.slice\b"),
    "numeric_systemd_session": re.compile(r"\bsession-[0-9]+\.scope\b"),
}
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOUBLE_COLON = ":" * 2
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}"
    rf"|{re.escape(DOUBLE_COLON)}(?:[0-9A-Fa-f]{{0,4}}:){{0,6}}[0-9A-Fa-f]{{0,4}}"
    r")(?![0-9A-Fa-f:])"
)
CHALLENGE_VALUE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{48}(?![A-Za-z0-9_-])")


def valid_ip_literals(value: str) -> list[str]:
    matches: list[tuple[int, str]] = []
    occupied: list[tuple[int, int]] = []
    for pattern in (IPV4_RE, IPV6_RE):
        for match in pattern.finditer(value):
            if any(match.start() < end and match.end() > start for start, end in occupied):
                continue
            try:
                ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            matches.append((match.start(), match.group(0)))
            occupied.append((match.start(), match.end()))
    return [candidate for _, candidate in sorted(matches)]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected an object")
        records.append(value)
    return records


def walk_values(value: Any, path: str = "") -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            values.append((child_path, child))
            values.extend(walk_values(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            values.extend(walk_values(child, f"{path}[{index}]"))
    return values


def validate_checksums(root: Path, errors: list[str]) -> None:
    index = root / "SHA256SUMS"
    if not index.is_file():
        errors.append("missing SHA256SUMS")
        return
    indexed: set[str] = set()
    for line_number, line in enumerate(index.read_text().splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)", line)
        if not match:
            errors.append(f"SHA256SUMS:{line_number}: malformed entry")
            continue
        expected, relative = match.groups()
        path = root / relative
        indexed.add(relative)
        if not path.is_file():
            errors.append(f"checksum target is missing: {relative}")
        elif sha256_file(path) != expected:
            errors.append(f"checksum mismatch: {relative}")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "__pycache__" not in path.parts
    }
    for relative in sorted(actual - indexed):
        errors.append(f"file missing from SHA256SUMS: {relative}")
    for relative in sorted(indexed - actual):
        errors.append(f"SHA256SUMS references an unexpected file: {relative}")


def validate_manifest(root: Path, errors: list[str]) -> None:
    manifest = load_json(root / "manifest.json")
    if manifest.get("dataset_version") != "1.0.0":
        errors.append("manifest dataset_version is not 1.0.0")
    if manifest.get("scenario_id") != "benchmark-cheating-via-package-manager-v1":
        errors.append("manifest scenario_id is unexpected")
    if manifest.get("outcome") != "attack_succeeded":
        errors.append("manifest outcome is unexpected")
    if manifest.get("raw_scap_included") is not False:
        errors.append("manifest must record raw_scap_included=false")
    for entry in manifest.get("files", []):
        path = root / entry.get("path", "")
        if not path.is_file():
            errors.append(f"manifest target is missing: {entry.get('path')}")
            continue
        if path.stat().st_size != entry.get("bytes"):
            errors.append(f"manifest byte count mismatch: {entry.get('path')}")
        if sha256_file(path) != entry.get("sha256"):
            errors.append(f"manifest digest mismatch: {entry.get('path')}")


def validate_unified(root: Path, errors: list[str]) -> None:
    records = load_jsonl(root / "traces" / "unified-timeline.jsonl")
    previous: int | None = None
    for index, record in enumerate(records, start=1):
        expected_keys = {
            "schema_version",
            "event_id",
            "ts_offset_ms",
            "source",
            "kind",
            "data",
        }
        if set(record) != expected_keys:
            errors.append(f"unified event {index} has unexpected keys")
        if record.get("schema_version") != "1.0":
            errors.append(f"unified event {index} has an unexpected schema version")
        if record.get("event_id") != f"evt-{index:06d}":
            errors.append(f"unified event {index} has a non-sequential ID")
        timestamp = record.get("ts_offset_ms")
        if not isinstance(timestamp, int):
            errors.append(f"unified event {index} has a non-integer timestamp")
        elif previous is not None and timestamp < previous:
            errors.append(f"unified event {index} is out of order")
        else:
            previous = timestamp
        if record.get("source") not in EXPECTED_SOURCES:
            errors.append(f"unified event {index} has an unknown source")
        if not isinstance(record.get("kind"), str) or not record.get("kind"):
            errors.append(f"unified event {index} has an invalid kind")
        if not isinstance(record.get("data"), dict):
            errors.append(f"unified event {index} has non-object data")


def validate_ground_truth(root: Path, errors: list[str]) -> None:
    truth = load_json(root / "ground-truth.json")
    stages = truth.get("stages", [])
    if truth.get("outcome") != "attack_succeeded":
        errors.append("ground truth must record attack_succeeded")
    if truth.get("challenge_value_published") is not False:
        errors.append("ground truth must record that the challenge value is omitted")
    if len(stages) != 6:
        errors.append(f"ground truth has {len(stages)} stages instead of 6")
    expected_indexes = list(range(1, len(stages) + 1))
    if [stage.get("index") for stage in stages] != expected_indexes:
        errors.append("ground-truth stage indexes are not sequential")
    if len({stage.get("stage_id") for stage in stages}) != len(stages):
        errors.append("ground-truth stage IDs are not unique")
    signatures: set[tuple[int, tuple[str, ...], tuple[str, ...]]] = set()
    for stage in stages:
        if stage.get("window_start_ms", 1) > stage.get("ts_offset_ms", 0):
            errors.append(f"stage window starts after event: {stage.get('stage_id')}")
        if stage.get("window_end_ms", -1) < stage.get("ts_offset_ms", 0):
            errors.append(f"stage window ends before event: {stage.get('stage_id')}")
        signature = (
            stage.get("ts_offset_ms"),
            tuple(stage.get("expected_sources", [])),
            tuple(stage.get("expected_kinds", [])),
        )
        if signature in signatures:
            errors.append(
                f"observationally indistinguishable stage: {stage.get('stage_id')}"
            )
        signatures.add(signature)


def validate_provenance(root: Path, errors: list[str]) -> None:
    provenance = load_json(root / "run-provenance.json")
    prompt = root / "prompt.txt"
    if provenance.get("scenario_id") != "benchmark-cheating-via-package-manager-v1":
        errors.append("run provenance scenario_id is unexpected")
    if provenance.get("model", {}).get("id") != "gpt-5.6-sol":
        errors.append("run provenance model is unexpected")
    if provenance.get("model", {}).get("reasoning_effort") != "max":
        errors.append("run provenance reasoning effort is unexpected")
    harness = provenance.get("harness", {})
    if (
        harness.get("product") != "OpenAI Codex CLI"
        or harness.get("version") != "0.148.0"
    ):
        errors.append("run provenance harness is unexpected")
    if provenance.get("gensee_baseline") != {
        "approval_prompts_enabled": False,
        "blocking_enabled": False,
        "forking_enabled": False,
        "mode": "observe-only",
    }:
        errors.append("run provenance does not describe the observe-only baseline")
    if sha256_file(prompt) != provenance.get("prompt", {}).get("published_sha256"):
        errors.append("published prompt digest does not match run provenance")


def validate_public_safety(root: Path, errors: list[str]) -> None:
    forbidden_names = {"internet-proof.txt", "codex-rollout.jsonl", "codex-events.jsonl"}
    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append(f"symlink is not allowed in dataset: {path.relative_to(root)}")
        if path.name in forbidden_names or path.suffix == ".scap":
            errors.append(f"forbidden raw artifact is present: {path.relative_to(root)}")

    scan_paths = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    ]
    for path in scan_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"unexpected binary file: {path.relative_to(root)}")
            continue
        for label, pattern in FORBIDDEN_TEXT.items():
            if pattern.search(text):
                errors.append(f"{label} found in {path.relative_to(root)}")
        if valid_ip_literals(text):
            errors.append(f"literal IP address found in {path.relative_to(root)}")
        for candidate in CHALLENGE_VALUE_RE.findall(text):
            if (
                any(character.isupper() for character in candidate)
                and any(character.islower() for character in candidate)
                and ("_" in candidate or "-" in candidate)
            ):
                errors.append(
                    f"possible literal challenge value found in {path.relative_to(root)}"
                )

        if path.suffix == ".json":
            values = walk_values(load_json(path))
        elif path.suffix == ".jsonl":
            values = []
            for record in load_jsonl(path):
                values.extend(walk_values(record))
        else:
            values = []
        for value_path, value in values:
            key = re.split(r"\.|\[", value_path)[-1].rstrip("]")
            if (
                SENSITIVE_KEY_RE.search(key)
                and isinstance(value, str)
                and value not in {"[REDACTED]", "[REDACTED_CHALLENGE_PROOF]"}
            ):
                errors.append(
                    f"secret-shaped field is not redacted: {path.relative_to(root)}:{value_path}"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument(
        "--safety-only",
        action="store_true",
        help="scan any dataset or release tree only for public-safety invariants",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    errors: list[str] = []
    if args.safety_only:
        validate_public_safety(root, errors)
        print(
            json.dumps(
                {
                    "errors": errors,
                    "files_checked": sum(
                        1 for path in root.rglob("*") if path.is_file()
                    ),
                    "ok": not errors,
                    "root": str(root),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if not errors else 1
    required = {
        "README.md",
        "METHODOLOGY.md",
        "LICENSE-DATA",
        "NOTICE",
        "manifest.json",
        "prompt.txt",
        "ground-truth.json",
        "redaction-ledger.json",
        "run-provenance.json",
        "SHA256SUMS",
    }
    for relative in sorted(required):
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")
    trace_files = {path.name for path in (root / "traces").glob("*.jsonl")}
    if trace_files != EXPECTED_TRACE_FILES:
        errors.append(
            f"trace file set mismatch: expected {sorted(EXPECTED_TRACE_FILES)}, "
            f"got {sorted(trace_files)}"
        )

    if not errors:
        validate_checksums(root, errors)
        validate_manifest(root, errors)
        validate_unified(root, errors)
        validate_ground_truth(root, errors)
        validate_provenance(root, errors)
        validate_public_safety(root, errors)
    result = {
        "errors": errors,
        "files_checked": sum(1 for path in root.rglob("*") if path.is_file()),
        "ok": not errors,
        "root": str(root),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
