"""Heuristic hash identification by length, charset, and prefix."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    """A possible algorithm for a given hash, with cracking tool modes."""

    name: str
    confidence: str  # "high", "medium", or "low"
    hashcat: str  # hashcat -m mode, or "-"
    john: str  # john --format, or "-"


# Confidence ordering used for sorting (higher first).
_ORDER = {"high": 0, "medium": 1, "low": 2}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/._-]+={0,2}$")


def _is_hex(s: str) -> bool:
    return bool(_HEX_RE.match(s))


# --- Prefixed / modular-crypt-format signatures -------------------------------
# Each entry: (compiled regex, list of Candidate). First match wins.
_PREFIX_RULES: list[tuple[re.Pattern, list[Candidate]]] = [
    (re.compile(r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$"),
     [Candidate("bcrypt", "high", "3200", "bcrypt")]),
    (re.compile(r"^\$argon2id\$"),
     [Candidate("Argon2id", "high", "-", "argon2")]),
    (re.compile(r"^\$argon2i\$"),
     [Candidate("Argon2i", "high", "-", "argon2")]),
    (re.compile(r"^\$argon2d\$"),
     [Candidate("Argon2d", "high", "-", "argon2")]),
    (re.compile(r"^\$6\$"),
     [Candidate("sha512crypt (crypt $6$)", "high", "1800", "sha512crypt")]),
    (re.compile(r"^\$5\$"),
     [Candidate("sha256crypt (crypt $5$)", "high", "7400", "sha256crypt")]),
    (re.compile(r"^\$1\$"),
     [Candidate("md5crypt (crypt $1$)", "high", "500", "md5crypt")]),
    (re.compile(r"^\$apr1\$"),
     [Candidate("Apache apr1 md5crypt", "high", "1600", "md5crypt-long")]),
    (re.compile(r"^\$y\$"),
     [Candidate("yescrypt", "high", "-", "-")]),
    (re.compile(r"^(SCRYPT|\$scrypt\$|\$7\$)"),
     [Candidate("scrypt", "high", "8900", "scrypt")]),
    (re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"),
     [Candidate("phpass (WordPress/phpBB)", "high", "400", "phpass")]),
    (re.compile(r"^\$H\$[./A-Za-z0-9]{31}$"),
     [Candidate("phpass (older phpBB3)", "high", "400", "phpass")]),
    (re.compile(r"^pbkdf2_sha256\$"),
     [Candidate("Django PBKDF2-SHA256", "high", "10000", "django")]),
    (re.compile(r"^pbkdf2_sha1\$"),
     [Candidate("Django PBKDF2-SHA1", "high", "-", "django")]),
    (re.compile(r"^sha1\$"),
     [Candidate("Django salted SHA1", "high", "124", "-")]),
    (re.compile(r"^\{SSHA\}"),
     [Candidate("Salted SHA1 (LDAP {SSHA})", "high", "111", "ssha")]),
    (re.compile(r"^\{SHA\}"),
     [Candidate("SHA1 (LDAP {SHA})", "high", "101", "nsldap")]),
    (re.compile(r"^\{SSHA512\}"),
     [Candidate("Salted SHA512 (LDAP {SSHA512})", "high", "1711", "-")]),
    (re.compile(r"^\$ml\$"),
     [Candidate("macOS PBKDF2-SHA512 (10.8+)", "high", "7100", "xsha512")]),
    (re.compile(r"^0x0100[0-9a-fA-F]{40,}$"),
     [Candidate("MSSQL 2005+ (SHA1)", "high", "132", "mssql05")]),
    (re.compile(r"^0x0200[0-9a-fA-F]{128,}$"),
     [Candidate("MSSQL 2012+ (SHA512)", "high", "1731", "mssql12")]),
]


def _hex_by_length(h: str) -> list[Candidate]:
    n = len(h)
    table: dict[int, list[Candidate]] = {
        8: [
            Candidate("CRC32", "medium", "11500", "crc32"),
            Candidate("Adler-32", "low", "-", "-"),
            Candidate("CRC32B", "low", "-", "-"),
        ],
        16: [
            Candidate("MySQL323 (pre-4.1)", "medium", "200", "mysql"),
            Candidate("DES (crypt, traditional)", "low", "1500", "descrypt"),
            Candidate("CRC64", "low", "-", "-"),
        ],
        32: [
            Candidate("MD5", "high", "0", "raw-md5"),
            Candidate("NTLM", "high", "1000", "nt"),
            Candidate("MD4", "medium", "900", "raw-md4"),
            Candidate("LM", "medium", "3000", "lm"),
            Candidate("RIPEMD-128", "low", "-", "ripemd-128"),
            Candidate("double MD5", "low", "2600", "-"),
            Candidate("MD2", "low", "-", "md2"),
        ],
        40: [
            Candidate("SHA1", "high", "100", "raw-sha1"),
            Candidate("MySQL4.1+ / SHA1(SHA1) family", "medium", "300", "mysql-sha1"),
            Candidate("RIPEMD-160", "medium", "6000", "ripemd-160"),
            Candidate("SHA1(SHA1(pass))", "low", "4500", "-"),
            Candidate("Tiger-160", "low", "-", "-"),
        ],
        56: [
            Candidate("SHA-224", "high", "1300", "raw-sha224"),
            Candidate("SHA3-224", "medium", "17300", "-"),
            Candidate("Keccak-224", "low", "17700", "-"),
        ],
        64: [
            Candidate("SHA-256", "high", "1400", "raw-sha256"),
            Candidate("SHA3-256", "medium", "17400", "-"),
            Candidate("BLAKE2s-256", "low", "-", "-"),
            Candidate("Keccak-256", "low", "17800", "-"),
            Candidate("GOST R 34.11-94", "low", "6900", "gost"),
        ],
        96: [
            Candidate("SHA-384", "high", "10800", "raw-sha384"),
            Candidate("SHA3-384", "medium", "17500", "-"),
            Candidate("Keccak-384", "low", "17900", "-"),
        ],
        128: [
            Candidate("SHA-512", "high", "1700", "raw-sha512"),
            Candidate("SHA3-512", "medium", "17600", "-"),
            Candidate("BLAKE2b-512", "medium", "600", "raw-blake2"),
            Candidate("Whirlpool", "low", "6100", "whirlpool"),
            Candidate("Keccak-512", "low", "18000", "-"),
        ],
    }
    return table.get(n, [])


def identify(raw: str) -> list[Candidate]:
    """Return ranked algorithm candidates for a single hash string.

    The list is ordered by confidence (high first). An empty list means the
    input did not match any known pattern.
    """
    h = raw.strip()
    if not h:
        return []

    # MySQL 4.1+ hashes are a '*' followed by 40 uppercase hex chars.
    if re.match(r"^\*[0-9A-F]{40}$", h):
        return [Candidate("MySQL4.1+ (SHA1(SHA1(pass)))", "high", "300", "mysql-sha1")]

    # Cisco-IOS type 7 / type 5 quick wins.
    if re.match(r"^\$8\$", h):
        return [Candidate("Cisco-IOS PBKDF2-SHA256 (type 8)", "high", "9200", "cisco8")]
    if re.match(r"^\$9\$", h):
        return [Candidate("Cisco-IOS scrypt (type 9)", "high", "9300", "cisco9")]

    for pattern, cands in _PREFIX_RULES:
        if pattern.match(h):
            return list(cands)

    if _is_hex(h):
        cands = _hex_by_length(h)
        if cands:
            return sorted(cands, key=lambda c: _ORDER[c.confidence])

    # Non-hex, unprefixed: a couple of base64-ish guesses.
    if _BASE64_RE.match(h):
        n = len(h)
        guesses: list[Candidate] = []
        if n == 28:
            guesses.append(Candidate("base64 SHA-224 / SHA3-224", "low", "-", "-"))
        if n in (43, 44):
            guesses.append(Candidate("base64 SHA-256 / bcrypt-sha256", "low", "-", "-"))
        if n in (88,):
            guesses.append(Candidate("base64 SHA-512", "low", "-", "-"))
        if guesses:
            return guesses

    return []
