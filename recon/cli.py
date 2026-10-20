"""Command line: `recon info FILE`, `recon strings FILE` and `recon diff OLD NEW`.

`--json` prints the same thing as JSON, for scripts (and later for the agent on top of this).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import capabilities, packing
from .diff import compare
from .loader import Binary, load
from .strings import extract


def _info_data(b: Binary) -> dict:
    return {
        "file": b.path.name,
        "format": b.format,
        "arch": b.arch,
        "entry": b.entry,
        "sections": [asdict(s) for s in b.sections],
        "imports": [asdict(i) for i in b.imports],
        "exports": sorted(b.exports.values()),
        "capabilities": [asdict(c) for c in capabilities.find(b)],
        "packing": [asdict(h) for h in packing.hints(b)],
        "strings": len(extract(b)),
        "warnings": b.warnings,
    }


# a DLL like kernel32 exports over a thousand functions; the text view shows the start
_EXPORTS_SHOWN = 20


def _info(path: str, as_json: bool) -> None:
    b = load(path)
    data = _info_data(b)
    if as_json:
        print(json.dumps(data, indent=2))
        return
    entry = f"entry at {b.entry:#x}" if b.entry is not None else "no entry point"
    print(f"{b.path.name}: {b.format} {b.arch}, {entry}")
    for w in b.warnings:
        print(f"warning: {w}")
    for h in data["packing"]:
        print(f"may be packed: {h['section']}: {h['reason']}")
    print("\ncan probably")
    for c in data["capabilities"] or [{"name": "(nothing from the known imports)", "evidence": []}]:
        print(f"  {c['name']:<26} {', '.join(c['evidence'])}")
    print(f"\nsections ({len(b.sections)})")
    width = max([12, *(len(s.name) for s in b.sections)])
    for s in b.sections:
        flags = ("x" if s.executable else "-") + ("w" if s.writable else "-")
        print(f"  {s.name:<{width}} {s.address:#012x} {s.size:>8}  {flags}  entropy {s.entropy}")
    print(f"\nimports ({len(b.imports)})")
    for i in sorted(b.imports, key=lambda i: (i.library.lower(), i.name)):
        print(f"  {i.library + '!' if i.library else ''}{i.name}")
    if data["exports"]:
        print(f"\nexports ({len(data['exports'])})")
        for name in data["exports"][:_EXPORTS_SHOWN]:
            print(f"  {name}")
        if len(data["exports"]) > _EXPORTS_SHOWN:
            print(f"  ... {len(data['exports']) - _EXPORTS_SHOWN} more (`--json` lists all)")
    print(f"\nstrings: {data['strings']} (`recon strings {path}` lists them)")


def _strings(path: str, as_json: bool) -> None:
    found = extract(load(path))
    if as_json:
        print(json.dumps([asdict(s) for s in found], indent=2))
        return
    for s in found:
        print(f"{s.address:#012x}  {s.section:<8} {s.text!r}")


def _diff(old: str, new: str, as_json: bool) -> None:
    d = compare(load(old), load(new))
    if as_json:
        print(json.dumps(asdict(d), indent=2))
        return
    if d.empty:
        print("no changes in imports or strings")
        return
    changes = (
        ("+", "can", d.capabilities_added), ("-", "can", d.capabilities_removed),
        ("+", "import", d.imports_added), ("-", "import", d.imports_removed),
        ("+", "string", d.strings_added), ("-", "string", d.strings_removed),
    )
    for sign, kind, items in changes:
        for item in items:
            # strings get quotes so trailing spaces and escapes are visible
            print(f"{sign} {kind:<7} {item!r}" if kind == "string" else f"{sign} {kind:<7} {item}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recon", description="Take apart an unknown binary.")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="format, what it can probably do, sections and imports").add_argument("file")
    sub.add_parser("strings", help="printable strings with their address").add_argument("file")
    d = sub.add_parser("diff", help="what changed between two versions")
    d.add_argument("old")
    d.add_argument("new")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            _info(args.file, args.json)
        elif args.command == "strings":
            _strings(args.file, args.json)
        else:
            _diff(args.old, args.new, args.json)
    except (FileNotFoundError, ValueError) as e:
        print(f"recon: {e}", file=sys.stderr)
        return 1
    except (BrokenPipeError, OSError) as e:
        # the output went to something that stopped reading (`recon strings x | head`);
        # on Windows that shows up as EINVAL instead of a broken pipe
        if isinstance(e, BrokenPipeError) or e.errno == 22:
            # point stdout at devnull so Python's flush at exit doesn't fail again
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 0
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
