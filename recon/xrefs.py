"""Who uses something: an import, a function or a string.

Answers at the function level (which functions, not which instructions), which is what the
questions I care about need: "who calls connect?", "who uses 'admin'?".
"""
from __future__ import annotations

from dataclasses import dataclass

from .disasm import Function, call_graph, find


@dataclass
class Xref:
    kind: str  # "import", "function" or "string"
    target: str
    used_by: list[str]


def find_xrefs(functions: dict[int, Function], strings: dict[int, str], what: str) -> list[Xref]:
    """An import name wins over a function name, and both over strings, which match by substring."""
    imports = {i for f in functions.values() for i in f.imports}
    name = next((i for i in imports if i.lower() == what.lower()), None)
    if name:
        users = sorted(f.name for f in functions.values() if name in f.imports)
        return [Xref("import", name, users)]

    f = find(functions, what)
    if f is not None:
        graph = call_graph(functions)
        return [Xref("function", f.name, sorted(functions[a].name for a in graph.predecessors(f.address)))]

    found: dict[str, set[str]] = {}
    for g in functions.values():
        for a in g.data_refs:
            if a in strings and what.lower() in strings[a].lower():
                found.setdefault(strings[a], set()).add(g.name)
    return [Xref("string", text, sorted(users)) for text, users in sorted(found.items())]
