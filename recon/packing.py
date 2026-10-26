"""Hints that the code is packed or encrypted.

A packed program unpacks its real code in memory when it starts, so its imports and strings say little.
"""
from __future__ import annotations

from dataclasses import dataclass

from .loader import Binary

# compressed or encrypted data sits close to 8 bits per byte; normal x86 code is around 6 to 6.5
HIGH_ENTROPY = 7.2

_PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".petite": "Petite", "PEC2": "PECompact",
}


@dataclass
class Hint:
    section: str
    reason: str


def hints(binary: Binary) -> list[Hint]:
    found = []
    for s in binary.sections:
        if s.name in _PACKER_SECTIONS:
            found.append(Hint(s.name, f"section name used by {_PACKER_SECTIONS[s.name]}"))
        if s.executable and s.entropy >= HIGH_ENTROPY:
            found.append(Hint(s.name, f"code with entropy {s.entropy}, looks compressed or encrypted"))
        if s.executable and s.writable:
            found.append(Hint(s.name, "code that can be written at runtime, typical of unpacking stubs"))
    return found
