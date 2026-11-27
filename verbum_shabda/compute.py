"""Compute hashes of text or files using the standard library."""

from __future__ import annotations

import hashlib

from .md4 import md4

# Algorithms backed directly by hashlib.
_HASHLIB_ALGOS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3_256": "sha3_256",
    "sha3_512": "sha3_512",
    "blake2b": "blake2b",
    "blake2s": "blake2s",
}

# Algorithms this tool implements itself.
_CUSTOM_ALGOS = ("md4", "ntlm")

ALGORITHMS = tuple(_HASHLIB_ALGOS) + _CUSTOM_ALGOS


def compute(algo: str, data: bytes) -> str:
    """Return the hex digest of ``data`` under ``algo``."""
    algo = algo.lower()
    if algo in _HASHLIB_ALGOS:
        return hashlib.new(_HASHLIB_ALGOS[algo], data).hexdigest()
    if algo == "md4":
        return md4(data).hex()
    if algo == "ntlm":
        # NTLM is MD4 of the UTF-16-LE encoded password.
        return md4(data.decode("utf-8", "replace").encode("utf-16-le")).hex()
    raise ValueError(f"unknown algorithm: {algo!r}")
