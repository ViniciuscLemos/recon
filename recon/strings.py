"""Printable strings in the binary, with the address each one lives at.

Addresses matter more than the text: they're how the disassembler later links a string to the
code that uses it (a `lea rcx, [rip + x]` pointing at "Invalid username or password").
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .loader import Binary

MIN_LENGTH = 4
_ASCII = re.compile(rb"[\x20-\x7e\t\r\n]{%d,}" % MIN_LENGTH)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LENGTH)


@dataclass(frozen=True)
class String:
    address: int
    text: str
    encoding: str  # "ascii" or "utf-16"
    section: str


def extract(binary: Binary, *, include_code: bool = False) -> list[String]:
    found: dict[int, String] = {}
    for section in binary.sections:
        if section.executable and not include_code:
            continue
        start, data = binary.section_bytes(section.name)
        for m in _ASCII.finditer(data):
            raw = m.group().decode("ascii")
            text = raw.strip()
            if len(text) >= MIN_LENGTH:
                # keep the address on the first visible character, past any leading whitespace
                address = start + m.start() + (len(raw) - len(raw.lstrip()))
                found[address] = String(address, text, "ascii", section.name)
        for m in _UTF16.finditer(data):
            found.setdefault(start + m.start(), String(start + m.start(), m.group().decode("utf-16-le"), "utf-16", section.name))
    return sorted(found.values(), key=lambda s: s.address)


def by_address(strings: list[String]) -> dict[int, String]:
    return {s.address: s for s in strings}
