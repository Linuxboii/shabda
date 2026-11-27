"""A small pure-Python MD4 implementation.

Modern OpenSSL builds often drop MD4, so ``hashlib.new("md4")`` can fail. MD4 is
needed to compute NTLM hashes, so this self-contained version keeps the tool
working on stdlib alone.
"""

from __future__ import annotations

import struct


def _left_rotate(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(message: bytes) -> bytes:
    """Return the 16-byte MD4 digest of ``message``."""
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    orig_len = len(message)
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += struct.pack("<Q", (orig_len * 8) & 0xFFFFFFFFFFFFFFFF)

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    for chunk in range(0, len(message), 64):
        x = list(struct.unpack("<16I", message[chunk:chunk + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for i in range(0, 16, 4):
            a = _left_rotate(a + f(b, c, d) + x[i], 3)
            d = _left_rotate(d + f(a, b, c) + x[i + 1], 7)
            c = _left_rotate(c + f(d, a, b) + x[i + 2], 11)
            b = _left_rotate(b + f(c, d, a) + x[i + 3], 19)

        # Round 2
        for i in range(4):
            a = _left_rotate(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = _left_rotate(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = _left_rotate(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = _left_rotate(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)

        # Round 3
        for i in (0, 2, 1, 3):
            a = _left_rotate(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3)
            d = _left_rotate(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = _left_rotate(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = _left_rotate(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)
