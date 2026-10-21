"""The Python cookie twin (tests/integration/rp_cookie.py) against the
upstream-generated cookie vectors that also pin rosenpass-core (M3b plan
C6, RT9): if either side drifts from upstream, one of the two tests fails.

Usage: python3 tests/tools/test_rp_cookie_twin.py
Prints "RP-COOKIE-TWIN-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/integration"))
import rp_cookie  # noqa: E402

VEC = ROOT / "crates/rosenpass-core/tests/vectors"


def vectors() -> dict:
    out = {}
    for line in (VEC / "cookie.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            k, v = line.split(" ", 1)
            out[k] = bytes.fromhex(v)
    return out


def main() -> int:
    v = vectors()
    spkm = (VEC / "spkm.bin").read_bytes()
    msg = v["cookie.msg"]
    checks = [
        ("keyed shake256", rp_cookie.kh(v["shake.key"], v["shake.data"]) == v["shake.out"]),
        ("root", rp_cookie.mix() == v["cookie.domain.protocol"]),
        ("cookie key", rp_cookie.cookie_key(spkm) == v["cookie.key"]),
        ("host info", rp_cookie.host_info(bytes([10, 0, 3, 1]), 41001) == v["cookie.host"]),
        ("cookie value", rp_cookie.cookie_value(v["cookie.secret"], v["cookie.host"]) == v["cookie.value"]),
        ("cookie field", rp_cookie.cookie_field(v["cookie.value"], msg[:-16]) == v["cookie.field"]),
    ]
    reply = bytes([0x86, 0, 0, 0]) + v["cookie.sidi"] + v["cookie.sealed"] + b"\0" * (1092 - 64)
    try:
        opened = rp_cookie.open_cookie_reply(spkm, reply, msg) == v["cookie.value"]
    except Exception:
        opened = False
    checks.append(("upstream's sealed reply opens", opened))
    # Deny sides: another mac, another sidi, and a flipped field.
    try:
        rp_cookie.open_cookie_reply(spkm, reply, msg[:-32] + bytes(16) + msg[-16:])
        checks.append(("another mac does not open", False))
    except Exception:
        checks.append(("another mac does not open", True))
    try:
        rp_cookie.open_cookie_reply(spkm, reply[:4] + b"\xee" * 4 + reply[8:], msg)
        checks.append(("another sidi is refused", False))
    except ValueError:
        checks.append(("another sidi is refused", True))
    good = rp_cookie.with_cookie(msg, v["cookie.value"])
    checks.append(("with_cookie validates", rp_cookie.cookie_ok(good, v["cookie.value"])))
    checks.append(("a flipped field does not", not rp_cookie.cookie_ok(good[:-1] + bytes([good[-1] ^ 1]), v["cookie.value"])))
    bad = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"RP-COOKIE-TWIN-FIXTURES {len(checks)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
