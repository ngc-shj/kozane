"""Python twin of rosenpass-core's cookie mechanism (M3b plan C1, C6), for
the integration cases that must act as a cookie-aware initiator or look
inside the gateway's CookieReplies. Written from upstream (rosenpass
9e72f1eb `hash_domains.rs`, `handle_cookie_reply`, `seal_cookie`) and
checked against the same upstream-generated vectors as the Rust side
(tests/tools/test_rp_cookie_twin.py, RT9).

The cookie tree is keyed SHAKE256: KH(k, d) = SHAKE256(k || d)[..32], and
`mix(x)` replaces the key with KH(key, x), from a zero key and the SHAKE256
protocol string down.
"""

import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../tools"))
import cookie_vectors  # noqa: E402  (the pure-Python HChaCha20, self-checked)

cookie_vectors.self_check()

PROTOCOL = b"Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 SHAKE256"
INIT_HELLO_LEN = 1092
COOKIE_REPLY = 0x86
MAC_LEN = COOKIE_LEN = 16


def kh(key: bytes, data: bytes) -> bytes:
    return hashlib.shake_256(key + data).digest(32)


def mix(*parts: bytes) -> bytes:
    key = kh(b"\0" * 32, PROTOCOL)
    for p in parts:
        key = kh(key, p)
    return key


def cookie_key(spkm: bytes) -> bytes:
    return mix(b"cookie-key", spkm)


def host_info(ip: bytes, port: int) -> bytes:
    """As rosenpass_core::cookie::host_info: ::ffff:a.b.c.d and the port."""
    return b"\0" * 10 + b"\xff\xff" + bytes(ip) + port.to_bytes(2, "big")


def cookie_value(secret: bytes, host: bytes) -> bytes:
    return mix(b"cookie-value", secret, host)[:16]


def cookie_field(value: bytes, msg_before_cookie: bytes) -> bytes:
    return mix(b"cookie", value, msg_before_cookie)[:16]


def mac_of(msg: bytes) -> bytes:
    return msg[len(msg) - MAC_LEN - COOKIE_LEN:len(msg) - COOKIE_LEN]


def with_cookie(msg: bytes, value: bytes) -> bytes:
    """`msg` with the cookie field an initiator holding `value` writes."""
    cut = len(msg) - COOKIE_LEN
    return msg[:cut] + cookie_field(value, msg[:cut])


def cookie_ok(msg: bytes, value: bytes) -> bool:
    cut = len(msg) - COOKIE_LEN
    return msg[cut:] == cookie_field(value, msg[:cut])


def open_cookie_reply(spkm: bytes, reply: bytes, init_hello: bytes) -> bytes:
    """The cookie value in a CookieReply to `init_hello`, as upstream's
    `handle_cookie_reply` opens it: XChaCha20Poly1305 under the public
    cookie key, the InitHello's mac as associated data. Raises if the reply
    is malformed, names another sender id, or does not open."""
    if len(reply) != INIT_HELLO_LEN or reply[0] != COOKIE_REPLY or reply[1:4] != b"\0\0\0":
        raise ValueError("not a CookieReply")
    if reply[4:8] != init_hello[4:8]:
        raise ValueError("CookieReply for another sidi")
    nonce, sealed = reply[8:32], reply[32:64]
    subkey = cookie_vectors.hchacha20(cookie_key(spkm), nonce[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\0" * 4 + nonce[16:], sealed, mac_of(init_hello))
