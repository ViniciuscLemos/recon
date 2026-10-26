"""Command line: `recon info FILE`, `recon strings FILE`, `recon funcs FILE`, `recon func FILE NAME`
and `recon diff OLD NEW`.

`--json` prints the same thing as JSON, for scripts (and later for the agent on top of this).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from . import capabilities, disasm, packing
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


def _func_data(f: disasm.Function, functions: dict, graph, strings: dict[int, str]) -> dict:
    return {
        "name": f.name,
        "address": f.address,
        "end": f.end,
        "instructions": f.instructions,
        "callers": sorted(functions[a].name for a in graph.predecessors(f.address)),
        "calls": sorted(functions[a].name for a in f.calls if a in functions),
        "imports": sorted(f.imports),
        "strings": [strings[a] for a in sorted(f.data_refs) if a in strings],
        "indirect_calls": f.indirect_calls,
    }


def _analyze(path: str):
    b = load(path)
    functions = disasm.find_functions(b)
    strings = {s.address: s.text for s in extract(b)}
    return functions, disasm.call_graph(functions), strings


def _funcs(path: str, as_json: bool) -> None:
    functions, graph, strings = _analyze(path)
    data = [_func_data(f, functions, graph, strings) for f in functions.values()]
    if as_json:
        print(json.dumps(data, indent=2))
        return
    width = max([8, *(len(d["name"]) for d in data)])
    print(f"{'address':<12} {'name':<{width}} {'ins':>5} {'callers':>7} {'calls':>5}  imports")
    for d in data:
        print(f"{d['address']:#012x} {d['name']:<{width}} {d['instructions']:>5} {len(d['callers']):>7} "
              f"{len(d['calls']):>5}  {', '.join(d['imports'])}")


def _func(path: str, name: str, as_json: bool) -> None:
    functions, graph, strings = _analyze(path)
    f = disasm.find(functions, name)
    if f is None:
        raise ValueError(f"no function called {name} (try `recon funcs` for the list)")
    d = _func_data(f, functions, graph, strings)
    if as_json:
        print(json.dumps(d, indent=2))
        return
    print(f"{d['name']} at {f.address:#x}..{f.end:#x}, {d['instructions']} instructions")
    for label, key in (("called by", "callers"), ("calls", "calls"), ("imports", "imports"), ("strings", "strings")):
        items = d[key]
        print(f"\n{label} ({len(items)})")
        for item in items:
            print(f"  {item!r}" if key == "strings" else f"  {item}")
    if f.indirect_calls:
        print(f"\n+ {f.indirect_calls} indirect call(s) that only resolve at run time")


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
    sub.add_parser("funcs", help="functions found in the code, with what they call").add_argument("file")
    fn = sub.add_parser("func", help="one function: who calls it, what it calls, imports and strings")
    fn.add_argument("file")
    fn.add_argument("name", help="name, FUN_ name or hex address")
    d = sub.add_parser("diff", help="what changed between two versions")
    d.add_argument("old")
    d.add_argument("new")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            _info(args.file, args.json)
        elif args.command == "strings":
            _strings(args.file, args.json)
        elif args.command == "funcs":
            _funcs(args.file, args.json)
        elif args.command == "func":
            _func(args.file, args.name, args.json)
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
