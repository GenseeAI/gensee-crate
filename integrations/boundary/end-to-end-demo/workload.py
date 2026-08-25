#!/usr/bin/env python3
"""Opaque producer used by the generic positive and negative demo paths."""

import json
import os
import socket
import subprocess
import sys
import time


ADDRESS = "192.0.2.2"
ALLOWED_PORT = 18080
UNEXPECTED_PORT = 18081


def connect(port: int) -> socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(2)
    connection.connect((ADDRESS, port))
    return connection


if len(sys.argv) == 2 and sys.argv[1] == "--descendant":
    os.setsid()
    held = connect(ALLOWED_PORT)
    held.sendall(b"hold")
    while True:
        time.sleep(60)

if len(sys.argv) != 2 or sys.argv[1] not in ("positive", "negative"):
    raise SystemExit("usage: workload.py <positive|negative>")

if sys.argv[1] == "negative":
    try:
        connection = connect(UNEXPECTED_PORT)
    except OSError:
        print(json.dumps({"unexpected_network_effect": "denied"}, sort_keys=True))
    else:
        connection.close()
        raise RuntimeError("contract-external endpoint was reachable")
    raise SystemExit(0)

with connect(ALLOWED_PORT) as allowed:
    allowed.sendall(b"ordinary")
    acknowledgement = allowed.recv(16).decode("ascii")
if acknowledgement != "ok":
    raise RuntimeError("approved endpoint returned an invalid acknowledgement")

subprocess.Popen(
    [sys.executable, __file__, "--descendant"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
time.sleep(0.4)

os.makedirs("out", exist_ok=True)
with open("out/result.json", "w", encoding="utf-8") as stream:
    json.dump(
        {
            "kind": "approved_structured_transform",
            "operation_id_present": bool(os.environ.get("GENSEE_OPERATION_ID")),
            "remote_acknowledgement": acknowledgement,
            "schema_version": 1,
            "value": 42,
        },
        stream,
        sort_keys=True,
    )
    stream.write("\n")
