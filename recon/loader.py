"""Opens a PE or ELF file and turns what LIEF reads into a small, format-independent model.

Everything after this module works with virtual addresses and plain dataclasses, so the rest of
RECON doesn't need to know which format it is looking at.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import lief

lief.logging.disable()


@dataclass
class Section:
    name: str
    address: int
    size: int
    entropy: float
    executable: bool
    writable: bool

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.size


@dataclass
class Import:
    library: str
    name: str
    # where the loader writes the function's address (IAT slot on PE, GOT slot on ELF)
    slot: int


@dataclass
class Binary:
    path: Path
    format: str  # "PE" or "ELF"
    arch: str  # "x86-64", "x86", "arm64", ...
    bits: int
    entry: int
    image_base: int
    sections: list[Section]
    imports: list[Import]
    exports: dict[int, str]
    # names we know for addresses: symbols, exports, entry point
    symbols: dict[int, str] = field(default_factory=dict)
    # exact function ranges when the binary carries them (.pdata on x64 PE)
    function_ranges: list[tuple[int, int]] = field(default_factory=list)
    # PLT stubs on ELF: stub address -> imported name
    plt: dict[int, str] = field(default_factory=dict)
    _content: dict[str, tuple[int, bytes]] = field(default_factory=dict, repr=False)

    def section_at(self, address: int) -> Section | None:
        return next((s for s in self.sections if s.contains(address)), None)

    def read(self, address: int, size: int) -> bytes:
        """Bytes at a virtual address, empty when it isn't backed by the file."""
        for start, data in self._content.values():
            if start <= address < start + len(data):
                offset = address - start
                return data[offset:offset + size]
        return b""

    def section_bytes(self, name: str) -> tuple[int, bytes]:
        return self._content.get(name, (0, b""))

    @property
    def code_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable and s.size]

    @property
    def import_slots(self) -> dict[int, Import]:
        return {i.slot: i for i in self.imports}


def load(path: str | Path) -> Binary:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        return _load_pe(path)
    if head == b"\x7fELF":
        return _load_elf(path)
    raise ValueError(f"{path.name} is not a PE or ELF file")


_PE_ARCH = {
    "AMD64": ("x86-64", 64),
    "I386": ("x86", 32),
    "ARM64": ("arm64", 64),
    "ARMNT": ("arm", 32),
}


def _load_pe(path: Path) -> Binary:
    config = lief.PE.ParserConfig()
    config.parse_exceptions = True
    # read the bytes ourselves: LIEF can't open paths with non-ASCII characters on Windows
    pe = lief.PE.parse(io.BytesIO(path.read_bytes()), config)
    if pe is None:
        raise ValueError(f"LIEF couldn't parse {path.name}")
    machine = pe.header.machine.name if hasattr(pe.header.machine, "name") else str(pe.header.machine).split(".")[-1]
    arch, bits = _PE_ARCH.get(machine, (machine.lower(), 64 if pe.optional_header.magic.name == "PE32_PLUS" else 32))
    base = pe.imagebase
    C = lief.PE.Section.CHARACTERISTICS

    sections, content = [], {}
    for s in pe.sections:
        chars = s.characteristics_lists
        sections.append(Section(
            name=s.name,
            address=base + s.virtual_address,
            size=max(s.virtual_size, s.size),
            entropy=round(max(s.entropy, 0.0), 2),
            executable=C.MEM_EXECUTE in chars or C.CNT_CODE in chars,
            writable=C.MEM_WRITE in chars,
        ))
        content[s.name] = (base + s.virtual_address, bytes(s.content))

    imports = [
        Import(library=lib.name, name=entry.name or f"ordinal_{entry.ordinal}", slot=base + entry.iat_address)
        for lib in pe.imports
        for entry in lib.entries
    ]
    exports = {base + f.address: f.name for f in (pe.get_export().entries if pe.has_exports else []) if f.name}

    # COFF symbols (MinGW leaves them unless the binary is stripped): value is an offset in its section
    symbols: dict[int, str] = {}
    for sym in pe.symbols:
        if not getattr(sym, "is_function", False) or sym.section_idx < 1 or sym.section_idx > len(pe.sections):
            continue
        section = pe.sections[sym.section_idx - 1]
        symbols[base + section.virtual_address + sym.value] = sym.name
    symbols.update(exports)

    ranges = [(base + e.rva_start, base + e.rva_end) for e in pe.exceptions if e.rva_end > e.rva_start]

    return Binary(
        path=path, format="PE", arch=arch, bits=bits, entry=pe.entrypoint, image_base=base,
        sections=sections, imports=imports, exports=exports, symbols=symbols,
        function_ranges=sorted(set(ranges)), _content=content,
    )


_ELF_ARCH = {
    "X86_64": ("x86-64", 64),
    "I386": ("x86", 32),
    "AARCH64": ("arm64", 64),
    "ARM": ("arm", 32),
    "RISCV": ("riscv", 64),
}


def _load_elf(path: Path) -> Binary:
    elf = lief.ELF.parse(io.BytesIO(path.read_bytes()))
    if elf is None:
        raise ValueError(f"LIEF couldn't parse {path.name}")
    machine = elf.header.machine_type.name if hasattr(elf.header.machine_type, "name") else str(elf.header.machine_type).split(".")[-1]
    arch, bits = _ELF_ARCH.get(machine, (machine.lower(), 64))
    F = lief.ELF.Section.FLAGS

    sections, content = [], {}
    for s in elf.sections:
        if not s.name or s.virtual_address == 0:
            continue
        sections.append(Section(
            name=s.name,
            address=s.virtual_address,
            size=s.size,
            entropy=round(max(s.entropy, 0.0), 2),
            executable=s.has(F.EXECINSTR),
            writable=s.has(F.WRITE),
        ))
        if s.type != lief.ELF.Section.TYPE.NOBITS:
            content[s.name] = (s.virtual_address, bytes(s.content))

    # imported functions are called through the PLT, which jumps through a GOT slot the dynamic
    # linker fills in; the relocation for that slot carries the function's name
    imports = [
        Import(library="", name=reloc.symbol.name, slot=reloc.address)
        for reloc in elf.pltgot_relocations
        if reloc.has_symbol and reloc.symbol.name
    ]
    exports = {f.address: f.name for f in elf.exported_functions if f.address and f.name}

    symbols: dict[int, str] = {}
    for sym in elf.symbols:
        if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value and sym.name:
            symbols.setdefault(sym.value, sym.name)
    symbols.update(exports)

    binary = Binary(
        path=path, format="ELF", arch=arch, bits=bits, entry=elf.entrypoint, image_base=0,
        sections=sections, imports=imports, exports=exports, symbols=symbols, _content=content,
    )
    binary.plt = _plt_stubs(binary)
    return binary


def _plt_stubs(binary: Binary) -> dict[int, str]:
    """Maps each PLT stub to the import it jumps to.

    A stub is a few instructions ending in `jmp [rip + x]`, where rip + x is the import's GOT slot.
    With CET the stubs that code calls live in .plt.sec instead of .plt. Stubs are 16 bytes, so the
    one an instruction belongs to starts at its address rounded down to 16.
    """
    import capstone

    if binary.arch != "x86-64":
        return {}
    slots = {i.slot: i.name for i in binary.imports}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    stubs: dict[int, str] = {}
    for name in (".plt", ".plt.sec", ".plt.got"):
        start, data = binary.section_bytes(name)
        for ins in md.disasm(data, start):
            if ins.mnemonic != "jmp" or len(ins.operands) != 1:
                continue
            op = ins.operands[0]
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = ins.address + ins.size + op.mem.disp
                if target in slots:
                    stubs[ins.address & ~0xF] = slots[target]
    return stubs
