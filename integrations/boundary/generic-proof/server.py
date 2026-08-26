#!/usr/bin/env python3
"""Two-port traffic fixture for the generic privileged boundary proof."""

import socket
import sys
import threading


ADDRESS = "192.0.2.2"
ALLOWED_PORT = 18080
UNEXPECTED_PORT = 18081
LOG = sys.argv[1]


def record(event: str) -> None:
    with open(LOG, "a", encoding="utf-8") as stream:
        stream.write(event + "\n")
        stream.flush()


def serve(port: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((ADDRESS, port))
    listener.listen()
    record(f"listening:{port}")
    while True:
        connection, _ = listener.accept()
        record(f"accepted:{port}")
        threading.Thread(
            target=handle,
            args=(connection, port),
            daemon=True,
        ).start()


def handle(connection: socket.socket, port: int) -> None:
    with connection:
        data = connection.recv(64)
        if data == b"hold":
            record("descendant-established")
            while connection.recv(64):
                pass
            record("descendant-revoked")
        else:
            connection.sendall(b"ok")
            record(f"roundtrip:{port}")


for fixture_port in (ALLOWED_PORT, UNEXPECTED_PORT):
    threading.Thread(target=serve, args=(fixture_port,), daemon=True).start()

threading.Event().wait()
