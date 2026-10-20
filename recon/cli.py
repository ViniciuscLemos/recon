"""Command line: `recon info FILE`, `recon strings FILE` and `recon diff OLD NEW`."""
from __future__ import annotations

import argparse
import sys

from .diff import compare
from .loader import load
from .strings import extract


def _info(path: str) -> None:
    b = load(path)
    print(f"{b.path.name}: {b.format} {b.arch}, entry at {b.entry:#x}")
    print(f"\nsections ({len(b.sections)})")
    for s in b.sections:
        flags = ("x" if s.executable else "-") + ("w" if s.writable else "-")
        print(f"  {s.name:<12} {s.address:#012x} {s.size:>8}  {flags}  entropy {s.entropy}")
    print(f"\nimports ({len(b.imports)})")
    for i in sorted(b.imports, key=lambda i: (i.library.lower(), i.name)):
        print(f"  {i.library + '!' if i.library else ''}{i.name}")
    print(f"\nstrings: {len(extract(b))} (`recon strings {path}` lists them)")


def _strings(path: str) -> None:
    for s in extract(load(path)):
        print(f"{s.address:#012x}  {s.section:<8} {s.text!r}")


def _diff(old: str, new: str) -> None:
    d = compare(load(old), load(new))
    if d.empty:
        print("no changes in imports or strings")
        return
    changes = (
        ("+", "import", d.imports_added), ("-", "import", d.imports_removed),
        ("+", "string", d.strings_added), ("-", "string", d.strings_removed),
    )
    for sign, kind, items in changes:
        for item in items:
            # strings get quotes so trailing spaces and escapes are visible
            print(f"{sign} {kind:<7} {item!r}" if kind == "string" else f"{sign} {kind:<7} {item}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recon", description="Take apart an unknown binary.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="format, sections and imports").add_argument("file")
    sub.add_parser("strings", help="printable strings with their address").add_argument("file")
    d = sub.add_parser("diff", help="imports and strings that changed between two versions")
    d.add_argument("old")
    d.add_argument("new")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            _info(args.file)
        elif args.command == "strings":
            _strings(args.file)
        else:
            _diff(args.old, args.new)
    except (FileNotFoundError, ValueError) as e:
        print(f"recon: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
