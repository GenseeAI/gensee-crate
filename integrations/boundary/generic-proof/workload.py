#!/usr/bin/env python3
"""Opaque workload used only as a traffic and product generator."""

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

with connect(ALLOWED_PORT) as allowed:
    allowed.sendall(b"ordinary")
    if allowed.recv(16) != b"ok":
        raise RuntimeError("allowed endpoint returned the wrong response")

try:
    unexpected = connect(UNEXPECTED_PORT)
except OSError:
    unexpected_denied = True
else:
    unexpected.close()
    unexpected_denied = False

if not unexpected_denied:
    raise RuntimeError("unexpected endpoint was reachable")

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
            "allowed_roundtrip": True,
            "operation_id_present": bool(os.environ.get("GENSEE_OPERATION_ID")),
            "unexpected_endpoint_denied": unexpected_denied,
        },
        stream,
        sort_keys=True,
    )
    stream.write("\n")
