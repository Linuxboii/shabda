"""Command-line interface for shabda."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .compute import ALGORITHMS, compute
from .identify import Candidate, identify

_COLORS = {"high": "32", "medium": "33", "low": "90"}


def _use_color(flag_no_color: bool) -> bool:
    if flag_no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _color(text: str, conf: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\x1b[{_COLORS.get(conf, '0')}m{text}\x1b[0m"


def _candidates_to_dicts(cands: list[Candidate]) -> list[dict]:
    return [
        {
            "name": c.name,
            "confidence": c.confidence,
            "hashcat": c.hashcat,
            "john": c.john,
        }
        for c in cands
    ]


def _print_identify(h: str, cands: list[Candidate], color: bool) -> None:
    print(f"\n  hash: {h}")
    if not cands:
        print("    (no known algorithm matched)")
        return
    print(f"    {'ALGORITHM':<34} {'CONF':<7} {'HASHCAT':<8} JOHN")
    print(f"    {'-'*34} {'-'*6} {'-'*7} {'-'*10}")
    for c in cands:
        name = _color(f"{c.name:<34}", c.confidence, color)
        print(f"    {name} {c.confidence:<7} {c.hashcat:<8} {c.john}")


def _read_hashes(args) -> list[str]:
    hashes: list[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            hashes = [ln.strip() for ln in fh if ln.strip()]
    if args.hash:
        hashes.extend(args.hash)
    return hashes


def cmd_identify(args) -> int:
    hashes = _read_hashes(args)
    if not hashes:
        print("error: provide a hash argument or --file", file=sys.stderr)
        return 2

    results = [(h, identify(h)) for h in hashes]

    if args.json:
        payload = [
            {"hash": h, "candidates": _candidates_to_dicts(c)} for h, c in results
        ]
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        color = _use_color(args.no_color)
        for h, cands in results:
            _print_identify(h, cands, color)
        print()

    matched = any(cands for _, cands in results)
    return 0 if matched else 1


def cmd_hash(args) -> int:
    if args.file:
        with open(args.file, "rb") as fh:
            data = fh.read()
    elif args.text is not None:
        data = args.text.encode("utf-8")
    else:
        data = sys.stdin.buffer.read()

    algos = ALGORITHMS if args.all else [args.algo]
    out = {a: compute(a, data) for a in algos}

    if args.json:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        width = max(len(a) for a in out)
        for a, digest in out.items():
            print(f"{a:<{width}}  {digest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shabda",
        description="Identify likely hash algorithms, or compute hashes of text/files.",
        epilog="Defensive/educational use only: analyze hashes from systems you own "
        "or are authorized to assess.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    ident = sub.add_parser(
        "identify", help="identify likely algorithm(s) for a hash", aliases=["id"]
    )
    ident.add_argument("hash", nargs="*", help="one or more hash strings")
    ident.add_argument("-f", "--file", help="file with one hash per line")
    ident.add_argument("--json", action="store_true", help="emit JSON")
    ident.add_argument("--no-color", action="store_true", help="disable ANSI color")
    ident.set_defaults(func=cmd_identify)

    hsh = sub.add_parser("hash", help="compute hash(es) of text or a file")
    src = hsh.add_mutually_exclusive_group()
    src.add_argument("text", nargs="?", help="text to hash (else read stdin)")
    src.add_argument("-f", "--file", help="file to hash")
    hsh.add_argument(
        "-a", "--algo", default="sha256", choices=ALGORITHMS, help="algorithm (default sha256)"
    )
    hsh.add_argument("--all", action="store_true", help="compute every supported algorithm")
    hsh.add_argument("--json", action="store_true", help="emit JSON")
    hsh.set_defaults(func=cmd_hash)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
