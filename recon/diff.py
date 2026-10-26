"""What changed between two versions of the same program.

Imports and strings are cheap to compare and already say a lot: v2 of the login sample stops
calling fopen and starts calling socket/connect/send, and a server address shows up in its strings.
When the code can be disassembled, the functions that changed come along too (see funcdiff).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import capabilities
from .funcdiff import FunctionChange, compare_functions
from .loader import Binary
from .strings import extract


@dataclass
class Diff:
    capabilities_added: list[str]
    capabilities_removed: list[str]
    imports_added: list[str]
    imports_removed: list[str]
    strings_added: list[str]
    strings_removed: list[str]
    functions: list[FunctionChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        # capabilities come from imports, so if those didn't change neither did they
        return not (self.imports_added or self.imports_removed or self.strings_added or self.strings_removed
                    or self.functions)


def _import_names(binary: Binary) -> set[str]:
    # the library is left out on purpose: the same function can come from a different DLL
    # between builds (msvcrt vs ucrt) and that isn't a change in behavior
    return {i.name for i in binary.imports}


def _string_texts(binary: Binary) -> set[str]:
    # the import table keeps every imported name (and DLL name) as text too; those already show
    # up as imports, so listing them again as strings is just noise
    names = _import_names(binary) | {i.library for i in binary.imports}
    return {s.text for s in extract(binary)} - names


def compare(old: Binary, new: Binary) -> Diff:
    old_imports, new_imports = _import_names(old), _import_names(new)
    old_strings, new_strings = _string_texts(old), _string_texts(new)
    old_caps = {c.name for c in capabilities.find(old)}
    new_caps = {c.name for c in capabilities.find(new)}
    return Diff(
        capabilities_added=sorted(new_caps - old_caps),
        capabilities_removed=sorted(old_caps - new_caps),
        imports_added=sorted(new_imports - old_imports),
        imports_removed=sorted(old_imports - new_imports),
        strings_added=sorted(new_strings - old_strings),
        strings_removed=sorted(old_strings - new_strings),
        functions=compare_functions(old, new) if old.arch == new.arch == "x86-64" else [],
    )
