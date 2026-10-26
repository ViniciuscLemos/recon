"""Finds the functions in the code and what each one touches.

Function starts come from everything the binary already says (entry point, exports, symbols,
the x64 exception table) plus the targets of every direct call found while disassembling, until no
new ones turn up. A function runs to its exception-table end when there is one, or else to the next
known start. That's simpler than a full control-flow recovery and works well on compiler output;
hand-written or obfuscated code can fool it.

For each function it records the functions it calls, the imported APIs it calls (through the IAT on
PE or a PLT stub on ELF) and the data it points at, which is how strings get tied to code.
Only x86-64 for now.
"""
from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import dataclass, field

import capstone
from capstone import x86

from .loader import Binary

MAX_ROUNDS = 20


@dataclass
class Function:
    address: int
    end: int
    name: str
    # True when the name came from the binary (symbol or export), False for FUN_xxxxxxxx
    named: bool
    instructions: int = 0
    calls: set[int] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    data_refs: set[int] = field(default_factory=set)
    # call rax, call [rbx + 8]...: the target is only known at run time
    indirect_calls: int = 0
    # hash of the mnemonics only, so the same code at another address still matches
    shape: str = ""


def _disassembler() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def _thunks(binary: Binary, md: capstone.Cs) -> dict[int, str]:
    """Small stubs that only jump to an import: PLT stubs on ELF, `jmp [rip + iat]` on MinGW PE.

    Code calls these instead of the import, so a call to one counts as a call to the import and
    the stub itself isn't reported as a function.
    """
    stubs = dict(binary.plt)
    slots = binary.import_slots
    for section in binary.code_sections:
        start, data = binary.section_bytes(section.name)
        for ins in md.disasm(data, start):
            if ins.mnemonic != "jmp" or len(ins.operands) != 1:
                continue
            op = ins.operands[0]
            if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                slot = ins.address + ins.size + op.mem.disp
                if slot in slots:
                    stubs[ins.address] = slots[slot].name
    return stubs


def _known_starts(binary: Binary) -> set[int]:
    starts = {start for start, _ in binary.function_ranges}
    starts.update(binary.symbols)
    if binary.entry is not None:
        starts.add(binary.entry)
    return starts


def find_functions(binary: Binary) -> dict[int, Function]:
    if binary.arch != "x86-64":
        raise ValueError(f"disassembly only supports x86-64 for now, this is {binary.arch}")
    md = _disassembler()
    thunks = _thunks(binary, md)
    slots = binary.import_slots
    exact_ends = dict(binary.function_ranges)

    def in_code(address: int) -> bool:
        s = binary.section_at(address)
        return s is not None and s.executable

    starts = {a for a in _known_starts(binary) if in_code(a) and a not in thunks}
    functions: dict[int, Function] = {}
    for _ in range(MAX_ROUNDS):
        ordered = sorted(starts)
        functions = {}
        new: set[int] = set()
        for i, start in enumerate(ordered):
            section = binary.section_at(start)
            end = exact_ends.get(start)
            if end is None:
                nxt = ordered[i + 1] if i + 1 < len(ordered) else None
                end = section.address + section.size
                if nxt is not None and nxt < end:
                    end = nxt
            name = binary.symbols.get(start)
            f = Function(address=start, end=end, name=name or f"FUN_{start:08x}", named=name is not None)
            functions[start] = f
            shape = hashlib.sha1()
            for ins in md.disasm(binary.read(start, end - start), start):
                f.instructions += 1
                shape.update(ins.mnemonic.encode() + b";")
                _record(ins, f, binary, slots, thunks, new, in_code)
            f.shape = shape.hexdigest()
        new -= starts
        if not new:
            break
        starts |= new
    return functions


def _record(ins, f: Function, binary: Binary, slots, thunks, new: set[int], in_code) -> None:
    is_call = ins.mnemonic == "call"
    # a jmp to the start of another function is a tail call; plain jumps inside the function aren't
    is_jump = ins.mnemonic == "jmp"
    for op in ins.operands:
        if op.type == x86.X86_OP_IMM and (is_call or is_jump):
            target = op.imm
            if target in thunks:
                f.imports.add(thunks[target])
            elif is_call and in_code(target):
                f.calls.add(target)
                new.add(target)
            elif is_jump and not (f.address <= target < f.end) and in_code(target):
                f.calls.add(target)
        elif op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
            target = ins.address + ins.size + op.mem.disp
            if target in slots:
                # call [rip + iat] (MSVC) or a function pointer loaded from the IAT
                f.imports.add(slots[target].name)
            elif not in_code(target) and binary.section_at(target) is not None:
                f.data_refs.add(target)
            elif ins.mnemonic == "lea" and in_code(target) and not (f.address <= target < f.end) and target not in thunks:
                # the address of code taken as a value: a callback, or main on Linux, which _start
                # only hands to __libc_start_main and never calls
                new.add(target)
        elif op.type in (x86.X86_OP_REG, x86.X86_OP_MEM) and is_call:
            f.indirect_calls += 1


def call_graph(functions: dict[int, Function]):
    """Directed graph of who calls whom, with function addresses as nodes."""
    import networkx as nx

    g = nx.DiGraph()
    for f in functions.values():
        g.add_node(f.address, name=f.name)
        for target in f.calls:
            if target in functions:
                g.add_edge(f.address, target)
    return g


def function_at(functions: dict[int, Function], address: int) -> Function | None:
    """The function an address falls in, like the one holding a given instruction."""
    ordered = sorted(functions)
    i = bisect_right(ordered, address) - 1
    if i < 0:
        return None
    f = functions[ordered[i]]
    return f if address < f.end else None


def find(functions: dict[int, Function], name_or_address: str) -> Function | None:
    """Looks up a function by name, FUN_ name or hex address."""
    for f in functions.values():
        if f.name == name_or_address:
            return f
    text = name_or_address.lower().removeprefix("fun_")
    try:
        return function_at(functions, int(text, 16))
    except ValueError:
        return None
