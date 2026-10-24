#!/usr/bin/env python3
"""Captures real ClientHellos as tls-wire's bolero seeds and unit fixtures
(M6 plan C6, T19).

A raw TCP listener on 127.0.0.1 accepts one connection per client, reads
TLS records until the first handshake message (the ClientHello) is
complete, writes those records exactly as received and closes. The clients
are the dev image's OpenSSL 3.5 `s_client` and curl 8.14 (OpenSSL 3.5).

Usage (inside the dev container):
    python3 tests/tls/capture_client_hellos.py [--out DIR]
"""

import argparse
import pathlib
import socket
import subprocess
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORPUS = ROOT / "crates/tls-wire/src/__fuzz__/tests__parsers_never_panic_and_stay_in_bounds/corpus"

# name -> client command ({port} filled in). Each must send a ClientHello
# to 127.0.0.1:{port} and then give up when the listener closes.
CLIENTS = {
    "openssl-mlkem768": ["openssl", "s_client", "-connect", "127.0.0.1:{port}", "-groups", "X25519MLKEM768",
                         "-servername", "gw.example", "-alpn", "http/1.1"],
    "openssl-default": ["openssl", "s_client", "-connect", "127.0.0.1:{port}", "-servername", "gw.example"],
    "openssl-x25519": ["openssl", "s_client", "-connect", "127.0.0.1:{port}", "-groups", "X25519"],
    "openssl-tls12": ["openssl", "s_client", "-connect", "127.0.0.1:{port}", "-tls1_2"],
    "curl-mlkem768": ["curl", "-sk", "--curves", "X25519MLKEM768", "--max-time", "5", "https://127.0.0.1:{port}/"],
    "curl-default": ["curl", "-sk", "--max-time", "5", "https://gw.example:{port}/",
                     "--resolve", "gw.example:{port}:127.0.0.1"],
}


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise SystemExit(f"capture: peer closed after {len(buf)} of {n} bytes")
        buf += chunk
    return buf


def read_client_hello(conn: socket.socket) -> bytes:
    """The records that carry the first handshake message, verbatim."""
    raw, hs = b"", b""
    while True:
        header = read_exact(conn, 5)
        if header[0] != 22:
            raise SystemExit(f"capture: first record type {header[0]}, want handshake")
        body = read_exact(conn, int.from_bytes(header[3:5], "big"))
        raw += header + body
        hs += body
        if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            return raw


def capture(name: str, argv: list) -> bytes:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(10)
    port = srv.getsockname()[1]
    cmd = [a.format(port=port) for a in argv]
    client = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(10)
            raw = read_client_hello(conn)
    finally:
        srv.close()
        try:
            client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait()
    print(f"{name}: {len(raw)} bytes ({' '.join(cmd)})")
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=CORPUS)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, argv in CLIENTS.items():
        (args.out / f"seed-{name}").write_bytes(capture(name, argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
