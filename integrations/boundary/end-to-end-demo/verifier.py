#!/usr/bin/python3 -B
"""Example domain verifier for the demo's structured-result policy."""

import errno
import hashlib
import json
import os
import socket
import sys


request = json.load(sys.stdin)
with open(os.environ["GENSEE_VERIFIER_PRODUCT"], "r", encoding="utf-8") as stream:
    product = json.load(stream)

checks = {
    "contract_request_bound": bool(request.get("contract_digest")),
    "filesystem_mutation_denied": False,
    "network_denied": False,
    "operation_identity_observed": product.get("operation_id_present") is True,
    "process_creation_denied": False,
    "result_kind_valid": product.get("kind") == "approved_structured_transform",
    "result_schema_valid": product.get("schema_version") == 1,
    "result_value_valid": product.get("value") == 42,
    "upstream_acknowledgement_valid": product.get("remote_acknowledgement") == "ok",
}

try:
    with open("/tmp/gensee-demo-verifier-write", "w", encoding="utf-8") as stream:
        stream.write("forbidden")
except PermissionError:
    checks["filesystem_mutation_denied"] = True

try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    checks["network_denied"] = error.errno in (errno.EPERM, errno.EACCES)

try:
    child = os.fork()
except OSError as error:
    checks["process_creation_denied"] = error.errno in (errno.EPERM, errno.EACCES)
else:
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)

effect_bytes = json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()
accepted = all(checks.values())
print(
    json.dumps(
        {
            "verdict": "accept" if accepted else "reject",
            "reason_codes": [
                "structured_result_policy_passed"
                if accepted
                else "structured_result_policy_failed"
            ],
            "validation_effect_manifest_digest": "sha256:"
            + hashlib.sha256(effect_bytes).hexdigest(),
        },
        sort_keys=True,
    )
)
