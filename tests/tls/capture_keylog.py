#!/usr/bin/env python3
"""The keylog fixture for tls-core's record-protection tests (M6 plan C7,
T-N13): an OpenSSL session independent of our server.

`openssl s_server -groups X25519MLKEM768 -ciphersuites
TLS_CHACHA20_POLY1305_SHA256 -keylogfile` serves a throwaway P-256
certificate; `openssl s_client` connects through a relay here that records
the raw TLS bytes of both directions, sends a line, a KeyUpdate (`k`) and
another line. Python `cryptography` then derives each traffic secret's key
and IV (HKDF-Expand-Label), the client secret after the KeyUpdate
("traffic upd"), and decrypts one record under each (ChaCha20Poly1305).
The fixture holds the secrets, the derived keys, IVs and records with
their plaintexts, so the Rust test reproduces each step.

Usage (inside the dev container):
    python3 tests/tls/capture_keylog.py [--out FILE]
"""

import argparse
import datetime
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "crates/tls-core/src/testdata/keylog.txt"
SERVER = ["openssl", "s_server", "-accept", "127.0.0.1:{port}", "-groups", "X25519MLKEM768",
          "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-tls1_3", "-num_tickets", "0",
          "-keylogfile", "{keylog}", "-cert", "{cert}", "-key", "{key}"]
CLIENT = ["openssl", "s_client", "-connect", "127.0.0.1:{port}", "-groups", "X25519MLKEM768",
          "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-tls1_3"]
# No line but the KeyUpdate may start with "k": s_client reads such a line
# as its KeyUpdate command.
LINES = [b"The kozane keylog fixture: before the update\n", b"k\n", b"The kozane keylog fixture: after the update\n"]


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    info = length.to_bytes(2, "big") + bytes([6 + len(label)]) + b"tls13 " + label + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(t + info + bytes([i]))
        t = h.finalize()
        out += t
        i += 1
    return out[:length]


def key_iv(secret: bytes):
    return hkdf_expand_label(secret, b"key", b"", 32), hkdf_expand_label(secret, b"iv", b"", 12)


def decrypt(secret: bytes, seq: int, record: bytes) -> bytes:
    key, iv = key_iv(secret)
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    return ChaCha20Poly1305(key).decrypt(nonce, record[5:], record[:5])


def records(stream: bytes) -> list:
    out = []
    while stream:
        n = 5 + int.from_bytes(stream[3:5], "big")
        out.append(stream[:n])
        stream = stream[n:]
    return out


def throwaway_cert(d: pathlib.Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "keylog fixture")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def pump(src: socket.socket, dst: socket.socket, log: bytearray):
    while True:
        try:
            data = src.recv(65536)
        except OSError:
            data = b""
        if not data:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return
        log += data
        dst.sendall(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        throwaway_cert(d)
        sport = free_port()
        server = subprocess.Popen([a.format(port=sport, keylog=d / "keylog", cert=d / "cert.pem", key=d / "key.pem")
                                   for a in SERVER], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        time.sleep(1)
        relay = socket.socket()
        relay.bind(("127.0.0.1", 0))
        relay.listen(1)
        rport = relay.getsockname()[1]
        client = subprocess.Popen([a.format(port=rport) for a in CLIENT], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        c, _ = relay.accept()
        s = socket.create_connection(("127.0.0.1", sport))
        up, down = bytearray(), bytearray()
        threads = [threading.Thread(target=pump, args=(c, s, up)), threading.Thread(target=pump, args=(s, c, down))]
        for t in threads:
            t.start()
        time.sleep(1)
        for line in LINES:
            client.stdin.write(line)
            client.stdin.flush()
            time.sleep(1)
        client.stdin.close()
        client.terminate()
        client.wait(timeout=10)
        server.terminate()
        server.wait(timeout=10)
        for t in threads:
            t.join(timeout=10)
        keylog = {}
        for line in (d / "keylog").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            label, _, secret = line.split()
            keylog[label] = bytes.fromhex(secret)

    c_hs, s_hs = keylog["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], keylog["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
    c_ap0, s_ap0 = keylog["CLIENT_TRAFFIC_SECRET_0"], keylog["SERVER_TRAFFIC_SECRET_0"]
    c_ap1 = hkdf_expand_label(c_ap0, b"traffic upd", b"", 32)
    secrets = {"CLIENT_HANDSHAKE_TRAFFIC_SECRET": c_hs, "SERVER_HANDSHAKE_TRAFFIC_SECRET": s_hs,
               "CLIENT_TRAFFIC_SECRET_0": c_ap0, "SERVER_TRAFFIC_SECRET_0": s_ap0, "CLIENT_TRAFFIC_SECRET_1": c_ap1}

    # Client records: ClientHello, change_cipher_spec, then protected ones.
    up_protected = [r for r in records(bytes(up)) if r[0] == 23]
    down_protected = [r for r in records(bytes(down)) if r[0] == 23]
    picked = [
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", 0, down_protected[0]),  # EncryptedExtensions
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", 0, up_protected[0]),  # client Finished
        ("CLIENT_TRAFFIC_SECRET_0", 0, up_protected[1]),  # the first line
        ("CLIENT_TRAFFIC_SECRET_0", 1, up_protected[2]),  # KeyUpdate
        ("CLIENT_TRAFFIC_SECRET_1", 0, up_protected[3]),  # the line after the update
    ]
    lines = ["# tests/tls/capture_keylog.py: " + " ".join(SERVER) + " / " + " ".join(CLIENT),
             "# SECRET <name> <hex>; KEY/IV <name> <hex> (HKDF-Expand-Label, Python cryptography);",
             "# RECORD <secret> <seq> <record hex> <inner plaintext hex> (ChaCha20Poly1305, Python cryptography)"]
    for name, secret in secrets.items():
        key, iv = key_iv(secret)
        lines += [f"SECRET {name} {secret.hex()}", f"KEY {name} {key.hex()}", f"IV {name} {iv.hex()}"]
    for name, seq, rec in picked:
        plain = decrypt(secrets[name], seq, rec)
        lines.append(f"RECORD {name} {seq} {rec.hex()} {plain.hex()}")
        print(f"{name} seq {seq}: inner type {plain.rstrip(b'\\0')[-1]}, {len(plain)} bytes")
    assert decrypt(c_ap1, 0, up_protected[3]).startswith(LINES[2]), "the line after the update"
    assert decrypt(c_ap0, 1, up_protected[2]).rstrip(b"\0")[:4] == bytes([24, 0, 0, 1]), "a KeyUpdate"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
