# verbum-shabda

Identify likely hash algorithms from a string, and compute hashes of text or files.

## The name

*verbum* is Latin for "word". *śabda* (शब्द) is Sanskrit for "sound" or "word".
A hash is a word pressed down to a fixed shape; this tool reads that shape and
tells you what kind of word it probably was.

## Features

- Identifies a single hash or a whole file of hashes
- Recognises MD5, SHA1/224/256/384/512, SHA3, NTLM, LM, MD4, bcrypt, scrypt,
  Argon2 (i/d/id), sha512crypt/sha256crypt/md5crypt, MySQL (pre-4.1 and 4.1+),
  CRC32, RIPEMD, phpass, Django PBKDF2, LDAP {SSHA}, MSSQL, and more
- Detection by **length, charset, and modular-crypt prefix**, with a
  **confidence ranking** (high / medium / low)
- Prints the matching **hashcat `-m` mode** and **john `--format`** for each guess
- `hash` subcommand computes digests of text/file/stdin (incl. NTLM and MD4,
  via a bundled pure-Python MD4 so it works even when OpenSSL drops MD4)
- `--json` output, optional ANSI color (`--no-color`, honours `NO_COLOR`)
- Pure standard library, no third-party dependencies

## Install

Requires Python 3.10+.

```sh
git clone https://github.com/Linuxboii/verbum-shabda
cd verbum-shabda
pip install .            # installs the `verbum-shabda` command
```

Or run straight from the source tree without installing:

```sh
python -m verbum_shabda --help
```

## Usage

### Identify a hash

```
$ verbum-shabda identify 5f4dcc3b5aa765d61d8327deb882cf99

  hash: 5f4dcc3b5aa765d61d8327deb882cf99
    ALGORITHM                          CONF    HASHCAT  JOHN
    ---------------------------------- ------ ------- ----------
    MD5                                high    0        raw-md5
    NTLM                               high    1000     nt
    MD4                                medium  900      raw-md4
    LM                                 medium  3000     lm
    RIPEMD-128                         low     -        ripemd-128
    double MD5                         low     2600     -
    MD2                                low     -        md2
```

Prefixed hashes resolve to a single high-confidence answer:

```
$ verbum-shabda identify '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'

  hash: $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    ALGORITHM                          CONF    HASHCAT  JOHN
    ---------------------------------- ------ ------- ----------
    bcrypt                             high    3200     bcrypt
```

Identify a file of hashes and emit JSON:

```
$ verbum-shabda identify --file hashes.txt --json
[
  {
    "hash": "...",
    "candidates": [
      { "name": "SHA-256", "confidence": "high", "hashcat": "1400", "john": "raw-sha256" }
    ]
  }
]
```

### Compute hashes

```
$ verbum-shabda hash password -a ntlm
ntlm  8846f7eaee8fb117ad06bdd830b7586c

$ verbum-shabda hash "abc" --all
md5       900150983cd24fb0d6963f7d28e17f72
sha1      a9993e364706816aba3e25717850c26c9cd0d89d
sha256    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
...

$ echo -n "data" | verbum-shabda hash -a sha512
$ verbum-shabda hash --file ./archive.zip -a sha256
```

## Notes on accuracy

Hash identification is heuristic: many algorithms share the same length and
charset (a 32-char hex string could be MD5, NTLM, MD4, or LM). The confidence
ranking reflects how common each candidate is in practice; treat lower-ranked
guesses as possibilities, not certainties.

## Scope

Defensive and educational use only. Identify and compute hashes from systems you
own or are authorized to assess. This tool does not crack hashes.

## Testing

```sh
python -m unittest
```

## License

MIT - see [LICENSE](LICENSE).
