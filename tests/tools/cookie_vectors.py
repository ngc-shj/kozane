#!/usr/bin/env python3
"""Independent oracle for wg-core's cookie primitives (M2.5 plan C1).

Prints the golden vectors pinned in crates/wg-core/src/tests_cookie.rs:
cookie_key, make_cookie, mac16, mac2, reply_nonce and seal_cookie_reply.
Uses only hashlib.blake2s, `cryptography`'s ChaCha20Poly1305 and a
pure-Python HChaCha20, which is checked against
draft-irtf-cfrg-xchacha-03 section 2.2.1 before anything is printed.

Run: python3 tests/tools/cookie_vectors.py
"""

import hashlib
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MASK = 0xFFFFFFFF


def rotl(v, n):
    return ((v << n) & MASK) | (v >> (32 - n))


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotl(s[b] ^ s[c], 7)


def hchacha20(key, nonce16):
    s = list(struct.unpack("<4I", b"expand 32-byte k"))
    s += list(struct.unpack("<8I", key))
    s += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        quarter(s, 0, 4, 8, 12)
        quarter(s, 1, 5, 9, 13)
        quarter(s, 2, 6, 10, 14)
        quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15)
        quarter(s, 1, 6, 11, 12)
        quarter(s, 2, 7, 8, 13)
        quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_seal(key, nonce24, plaintext, aad):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\0" * 4 + nonce24[16:], plaintext, aad)


def self_check():
    # draft-irtf-cfrg-xchacha-03 section 2.2.1.
    got = hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927"))
    want = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    if got.hex() != want:
        sys.exit(f"hchacha20 self-check failed: {got.hex()}")
    # Section A.3.1, so the composition (not only HChaCha20) is checked too.
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
          b"for the future, sunscreen would be it.")
    ct = xchacha_seal(bytes(range(0x80, 0xA0)), bytes(range(0x40, 0x58)), pt,
                      bytes.fromhex("50515253c0c1c2c3c4c5c6c7"))
    if ct[-16:].hex() != "c0875924c1c7987947deafd8780acf49" or ct[:4].hex() != "bd6d179d":
        sys.exit(f"xchacha self-check failed: {ct.hex()}")


def h(*parts):
    return hashlib.blake2s(b"".join(parts)).digest()


def mac(key, *parts):
    # BLAKE2s puts the key length in its parameter block: a 16-byte key is
    # passed as 16 bytes, never zero-padded.
    return hashlib.blake2s(b"".join(parts), key=key, digest_size=16).digest()


def main():
    self_check()
    gw_public = bytes(range(32))
    secret = bytes(range(0x40, 0x60))
    ip = bytes([10, 0, 2, 2])
    port = 51820
    counter = 0x0102030405060708
    receiver = 0x04030201
    # Initiation fixture: type 1, reserved zero, then byte i = 7 * i mod 256.
    covered = bytes([1, 0, 0, 0]) + bytes((7 * i) & 0xFF for i in range(4, 132))
    mac1 = covered[116:132]

    ck = h(b"cookie--", gw_public)
    cookie = mac(secret, ip, struct.pack(">H", port))
    cookie_other_port = mac(secret, ip, struct.pack(">H", port + 1))
    mac2 = mac(cookie, covered)
    nonce = h(secret, struct.pack("<Q", counter))[:24]
    reply = (bytes([3, 0, 0, 0]) + struct.pack("<I", receiver) + nonce
             + xchacha_seal(ck, nonce, cookie, mac1))
    assert len(reply) == 64

    print("cookie_key", ck.hex())
    print("mac16", mac(bytes(range(16)), b"secureos wg-core").hex())
    print("make_cookie", cookie.hex())
    print("make_cookie_other_port", cookie_other_port.hex())
    print("mac2", mac2.hex())
    print("reply_nonce", nonce.hex())
    print("seal_cookie_reply", reply.hex())


if __name__ == "__main__":
    main()
