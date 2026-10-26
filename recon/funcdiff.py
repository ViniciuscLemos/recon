"""Which functions changed between two versions, and how.

Functions are paired in three passes: same name (when the binary has symbols), then identical code
(same sequence of mnemonics, so it survives moving to another address), and last the closest match
by the imports and strings each one uses. Whatever is left unpaired was added or removed.

The last pass is a guess. On a stripped binary a function that changed a lot and uses nothing
distinctive shows up as one removed and one added instead of one changed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .disasm import Function, find_functions
from .loader import Binary
from .strings import extract

# below this the two functions have too little in common to call them the same one
MIN_SIMILARITY = 0.5


@dataclass
class FunctionChange:
    kind: str  # "added", "removed" or "changed"
    name: str  # the new name, or the old one for a removed function
    old_name: str | None = None
    instructions: tuple[int, int] = (0, 0)
    imports_added: list[str] = field(default_factory=list)
    imports_removed: list[str] = field(default_factory=list)
    strings_added: list[str] = field(default_factory=list)
    strings_removed: list[str] = field(default_factory=list)
    calls_added: list[str] = field(default_factory=list)
    calls_removed: list[str] = field(default_factory=list)


@dataclass
class _Side:
    functions: dict[int, Function]
    strings: dict[int, set[str]]

    def features(self, f: Function) -> set[str]:
        return {"import:" + i for i in f.imports} | {"string:" + s for s in self.strings[f.address]}


def _side(binary: Binary) -> _Side:
    functions = find_functions(binary)
    texts = {s.address: s.text for s in extract(binary)}
    strings = {a: {texts[d] for d in f.data_refs if d in texts} for a, f in functions.items()}
    return _Side(functions, strings)


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def _pair(old: _Side, new: _Side) -> dict[int, int]:
    pairs: dict[int, int] = {}
    new_by_name = {f.name: a for a, f in new.functions.items() if f.named}
    for a, f in old.functions.items():
        if f.named and f.name in new_by_name:
            pairs[a] = new_by_name[f.name]

    def by_shape(side: _Side, taken: set[int]) -> dict[str, list[int]]:
        seen: dict[str, list[int]] = {}
        for a in sorted(side.functions):
            if a not in taken:
                seen.setdefault(side.functions[a].shape, []).append(a)
        return seen

    # identical copies (two entry stubs with the same code, say) pair up in address order, as
    # long as both versions have the same number of them
    new_shapes = by_shape(new, set(pairs.values()))
    for shape, olds in by_shape(old, set(pairs)).items():
        news = new_shapes.get(shape, [])
        if len(olds) == len(news):
            pairs.update(zip(olds, news))

    # greedy on the best scores first, so a strong match isn't stolen by a weaker one
    taken = set(pairs.values())
    # only functions sharing at least one import or string can reach the threshold, so look those
    # up instead of scoring every pair (kernel32 against kernelbase is thousands by thousands)
    new_features = {b: new.features(g) for b, g in new.functions.items() if b not in taken}
    having: dict[str, list[int]] = {}
    for b, feats in new_features.items():
        for feat in feats:
            having.setdefault(feat, []).append(b)
    candidates = []
    for a, f in old.functions.items():
        feats = old.features(f)
        if a in pairs or not feats:
            continue
        for b in {b for feat in feats for b in having.get(feat, ())}:
            if f.named and new.functions[b].named:
                continue
            score = _jaccard(feats, new_features[b])
            if score >= MIN_SIMILARITY:
                candidates.append((score, a, b))
    for _, a, b in sorted(candidates, reverse=True):
        if a not in pairs and b not in taken:
            pairs[a] = b
            taken.add(b)
    return pairs


def _names(functions: dict[int, Function], addresses) -> set[str]:
    return {functions[a].name for a in addresses if a in functions}


def compare_functions(old_binary: Binary, new_binary: Binary) -> list[FunctionChange]:
    old, new = _side(old_binary), _side(new_binary)
    pairs = _pair(old, new)
    # an old callee is "the same call" as a new one when the two got paired
    renamed = {old.functions[a].name: new.functions[b].name for a, b in pairs.items()}

    changes = []
    for a, b in pairs.items():
        f, g = old.functions[a], new.functions[b]
        old_calls = {renamed.get(n, n) for n in _names(old.functions, f.calls)}
        new_calls = _names(new.functions, g.calls)
        # same code calling a different function is still a change (main calling the new reporter)
        if f.shape == g.shape and f.imports == g.imports and old.strings[a] == new.strings[b] and old_calls == new_calls:
            continue
        changes.append(FunctionChange(
            kind="changed", name=g.name, old_name=f.name if f.name != g.name else None,
            instructions=(f.instructions, g.instructions),
            imports_added=sorted(g.imports - f.imports), imports_removed=sorted(f.imports - g.imports),
            strings_added=sorted(new.strings[b] - old.strings[a]),
            strings_removed=sorted(old.strings[a] - new.strings[b]),
            calls_added=sorted(new_calls - old_calls), calls_removed=sorted(old_calls - new_calls),
        ))

    def lone(side: _Side, address: int, kind: str) -> FunctionChange:
        f = side.functions[address]
        c = FunctionChange(kind=kind, name=f.name, instructions=(f.instructions,) * 2)
        imports, strings = sorted(f.imports), sorted(side.strings[address])
        calls = sorted(_names(side.functions, f.calls))
        if kind == "added":
            c.imports_added, c.strings_added, c.calls_added = imports, strings, calls
        else:
            c.imports_removed, c.strings_removed, c.calls_removed = imports, strings, calls
        return c

    paired_new = set(pairs.values())
    changes += [lone(new, b, "added") for b in new.functions if b not in paired_new]
    changes += [lone(old, a, "removed") for a in old.functions if a not in pairs]
    order = {"added": 0, "removed": 1, "changed": 2}
    return sorted(changes, key=lambda c: (order[c.kind], c.name))
