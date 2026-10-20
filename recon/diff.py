"""What changed between two versions of the same program, before looking at any code.

Imports and strings are cheap to compare and already say a lot: v2 of the login sample stops
calling fopen and starts calling socket/connect/send, and a server address shows up in its strings.
"""
from __future__ import annotations

from dataclasses import dataclass

from .loader import Binary
from .strings import extract


@dataclass
class Diff:
    imports_added: list[str]
    imports_removed: list[str]
    strings_added: list[str]
    strings_removed: list[str]

    @property
    def empty(self) -> bool:
        return not (self.imports_added or self.imports_removed or self.strings_added or self.strings_removed)


def _import_names(binary: Binary) -> set[str]:
    # the library is left out on purpose: the same function can come from a different DLL
    # between builds (msvcrt vs ucrt) and that isn't a change in behavior
    return {i.name for i in binary.imports}


def _string_texts(binary: Binary) -> set[str]:
    return {s.text for s in extract(binary)}


def compare(old: Binary, new: Binary) -> Diff:
    old_imports, new_imports = _import_names(old), _import_names(new)
    old_strings, new_strings = _string_texts(old), _string_texts(new)
    return Diff(
        imports_added=sorted(new_imports - old_imports),
        imports_removed=sorted(old_imports - new_imports),
        strings_added=sorted(new_strings - old_strings),
        strings_removed=sorted(old_strings - new_strings),
    )
