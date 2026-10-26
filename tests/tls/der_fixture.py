#!/usr/bin/env python3
"""ECDSA P-256 signatures OpenSSL verifies, as r ‖ s and DER, for tls-wire's
DER encoder test (M6 plan C6: "the DER encoder against an OpenSSL-verified
signature").

Python `cryptography` signs with a fresh key until the set covers each
INTEGER shape: high bit set (a 0x00 pad), a leading zero byte (stripped)
for r and for s, and a plain one. Every signature is verified by
`openssl dgst -verify` before it is written; the key is discarded.

Usage (inside the dev container):
    python3 tests/tls/der_fixture.py [--out FILE]
"""

import argparse
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "crates/tls-wire/src/testdata/ecdsa_sigs.txt"


def shape(v: bytes) -> str:
    if v[0] == 0:
        return "lead0"
    return "pad" if v[0] & 0x80 else "plain"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    args = ap.parse_args()
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    want = {("r", "pad"), ("r", "lead0"), ("s", "pad"), ("s", "lead0"), ("r", "plain")}
    found = {}
    i = 0
    while want - set(found):
        msg = b"kozane tls-wire DER fixture %d" % i
        i += 1
        der = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        rb, sb = r.to_bytes(32, "big"), s.to_bytes(32, "big")
        for k in (("r", shape(rb)), ("s", shape(sb))):
            if k in want and k not in found:
                found[k] = (msg, rb + sb, der)
    lines = ["# msg-hex r||s-hex der-hex; each verified by `openssl dgst -sha256 -verify` (tests/tls/der_fixture.py)"]
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "pub.pem").write_bytes(pub)
        for k in sorted(found):
            msg, rs, der = found[k]
            (d / "msg").write_bytes(msg)
            (d / "sig").write_bytes(der)
            subprocess.run(["openssl", "dgst", "-sha256", "-verify", d / "pub.pem", "-signature", d / "sig", d / "msg"],
                           check=True, capture_output=True)
            lines.append(f"{msg.hex()} {rs.hex()} {der.hex()}")
            print(f"{k}: {len(der)}-byte DER verified")
    args.out.write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
