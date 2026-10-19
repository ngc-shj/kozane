"""Minimal WireGuard initiator for the negative integration cases (plan
C18). Written from the whitepaper; wireguard-go is the independent interop
oracle, this exists only to send what wireguard-go will not (wrong PSK,
unknown key, spoofed inner source) and to look inside what the gateway
sends (cookie replies, keepalives; M2.5 plan C6).
"""

import hashlib
import hmac
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../tools"))
import cookie_vectors  # noqa: E402  (the pure-Python HChaCha20, self-checked below)

cookie_vectors.self_check()

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"
MAC2_OFFSET = 132


def h(*parts: bytes) -> bytes:
    return hashlib.blake2s(b"".join(parts)).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def hmac_(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf(key: bytes, data: bytes, n: int):
    t0 = hmac_(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = hmac_(t0, prev + bytes([i]))
        out.append(prev)
    return out


def aead(key: bytes, counter: int, plain: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(b"\0" * 4 + struct.pack("<Q", counter), plain, ad)


def aead_open(key: bytes, counter: int, sealed: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(b"\0" * 4 + struct.pack("<Q", counter), sealed, ad)


def pub(k: X25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(k: X25519PrivateKey, p: bytes) -> bytes:
    return k.exchange(X25519PublicKey.from_public_bytes(p))


def mac1_key(responder_pub: bytes) -> bytes:
    return h(LABEL_MAC1, responder_pub)


def with_mac1(body: bytes, responder_pub: bytes) -> bytes:
    """An initiation from its first 116 bytes: mac1, then a zero mac2."""
    return body + mac(mac1_key(responder_pub), body) + b"\0" * 16


def with_mac2(msg: bytes, cookie: bytes) -> bytes:
    """mac2 = MAC(cookie, msg[..132]) with the 16-byte cookie as the key."""
    return msg[:MAC2_OFFSET] + mac(cookie, msg[:MAC2_OFFSET])


def open_cookie_reply(responder_pub: bytes, reply: bytes, initiation: bytes) -> bytes:
    """The cookie in a type-3 reply to `initiation`: XChaCha20Poly1305 under
    the public key HASH("cookie--" || S_pub), aad = the initiation's mac1.
    Raises if the reply is malformed or does not open."""
    if len(reply) != 64 or reply[:4] != b"\3\0\0\0":
        raise ValueError("not a cookie reply")
    nonce, sealed = reply[8:32], reply[32:]
    subkey = cookie_vectors.hchacha20(h(LABEL_COOKIE, responder_pub), nonce[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\0" * 4 + nonce[16:], sealed, initiation[116:MAC2_OFFSET])


def tai64n(offset_s: float = 0.0) -> bytes:
    t = time.time() + offset_s
    return struct.pack(">QI", 0x4000000000000000 + int(t), int((t % 1) * 1e9))


class Initiator:
    def __init__(self, static: bytes, responder_pub: bytes, psk: bytes, sender: int = 0x51515151):
        self.s = X25519PrivateKey.from_private_bytes(static)
        self.sr = responder_pub
        self.psk = psk
        self.sender = sender
        self.send_key = self.recv_key = None
        self.receiver = None
        self.counter = 0

    def initiation(self, ts_offset_s: float = 0.0) -> bytes:
        e = X25519PrivateKey.generate()
        self.e = e
        c = h(CONSTRUCTION)
        hh = h(h(c, IDENTIFIER), self.sr)
        c = kdf(c, pub(e), 1)[0]
        hh = h(hh, pub(e))
        c, k = kdf(c, dh(e, self.sr), 2)
        enc_static = aead(k, 0, pub(self.s), hh)
        hh = h(hh, enc_static)
        c, k = kdf(c, dh(self.s, self.sr), 2)
        enc_ts = aead(k, 0, tai64n(ts_offset_s), hh)
        hh = h(hh, enc_ts)
        self.c, self.h = c, hh
        msg = struct.pack("<I", 1) + struct.pack("<I", self.sender) + pub(e) + enc_static + enc_ts
        return with_mac1(msg, self.sr)

    def consume_response(self, resp: bytes) -> bool:
        """Derives transport keys; returns whether the response's empty AEAD
        opened (i.e. both sides used the same PSK)."""
        if len(resp) != 92 or resp[0] != 2:
            raise ValueError("not a response")
        sender, receiver = struct.unpack("<II", resp[4:12])
        if receiver != self.sender:
            raise ValueError("response for another initiator")
        e_r, enc_nothing = resp[12:44], resp[44:60]
        c = kdf(self.c, e_r, 1)[0]
        hh = h(self.h, e_r)
        c = kdf(c, dh(self.e, e_r), 1)[0]
        c = kdf(c, dh(self.s, e_r), 1)[0]
        c, tau, k = kdf(c, self.psk, 3)
        hh = h(hh, tau)
        ok = True
        try:
            aead_open(k, 0, enc_nothing, hh)
        except Exception:
            ok = False
        self.send_key, self.recv_key = kdf(c, b"", 2)
        self.receiver = sender
        return ok

    def transport(self, plain: bytes) -> bytes:
        plain += b"\0" * (-len(plain) % 16)
        msg = struct.pack("<II", 4, self.receiver) + struct.pack("<Q", self.counter)
        msg += aead(self.send_key, self.counter, plain, b"")
        self.counter += 1
        return msg

    def open_transport(self, msg: bytes) -> tuple:
        """(counter, plaintext) of a transport message for this session;
        raises if it is not one or does not open."""
        if len(msg) < 32 or msg[:4] != b"\4\0\0\0":
            raise ValueError("not a transport message")
        receiver, counter = struct.unpack("<IQ", msg[4:16])
        if receiver != self.sender:
            raise ValueError("transport message for another session")
        return counter, aead_open(self.recv_key, counter, msg[16:], b"")
