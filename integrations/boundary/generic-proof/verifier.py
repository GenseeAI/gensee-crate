#!/usr/bin/python3 -B
"""Domain fixture for the generic isolated semantic-verifier protocol."""

import errno
import hashlib
import json
import os
import socket
import sys


request = json.load(sys.stdin)
checks = {
    "request_bound": bool(request.get("product_digest")),
    "filesystem_mutation_denied": False,
    "network_denied": False,
    "process_creation_denied": False,
}

try:
    with open("/tmp/gensee-verifier-escape", "w", encoding="utf-8") as stream:
        stream.write("unexpected")
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

if not all(checks.values()):
    raise SystemExit(f"isolation check failed: {checks}")

effect_bytes = json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()
print(
    json.dumps(
        {
            "verdict": "accept",
            "reason_codes": ["fixture_semantics_valid", "isolation_verified"],
            "validation_effect_manifest_digest": "sha256:"
            + hashlib.sha256(effect_bytes).hexdigest(),
        },
        sort_keys=True,
    )
)
