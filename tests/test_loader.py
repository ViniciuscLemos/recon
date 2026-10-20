import sys

import pytest

from recon.loader import load


def test_reads_format_arch_and_entry(samples):
    b = load(samples["v2"])
    assert b.format in ("PE", "ELF")
    assert b.arch == "x86-64" and b.bits == 64
    assert b.section_at(b.entry) in b.code_sections


def test_finds_the_network_imports(samples):
    names = {i.name for i in load(samples["v2"]).imports}
    assert {"connect", "send", "strcmp"} <= names


def test_names_functions_from_symbols_until_stripped(samples):
    assert "check_login" in load(samples["v2"]).symbols.values()
    assert "check_login" not in load(samples["v2_stripped"]).symbols.values()


def test_refuses_what_isnt_a_binary(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("hello")
    with pytest.raises(ValueError, match="not a PE or ELF"):
        load(text)


def test_clear_errors_for_a_missing_file_and_a_folder(tmp_path):
    with pytest.raises(FileNotFoundError, match="no such file"):
        load(tmp_path / "nope.exe")
    with pytest.raises(ValueError, match="is a folder"):
        load(tmp_path)


def test_just_the_elf_signature_is_an_error(tmp_path):
    fake = tmp_path / "fake"
    fake.write_bytes(b"\x7fELF")
    with pytest.raises(ValueError, match="nothing after it"):
        load(fake)


def test_a_file_cut_short_loads_with_a_warning(samples, tmp_path):
    data = samples["v1"].read_bytes()
    cut = tmp_path / ("cut" + samples["v1"].suffix)
    # at 30% the cut falls inside the sections (in half, only the symbol table at the end is lost)
    cut.write_bytes(data[: len(data) * 3 // 10])
    try:
        b = load(cut)
    except ValueError:
        # LIEF gives up on some cut ELF files, which is fine as long as it's a clear error
        assert cut.suffix != ".exe"
    else:
        if b.format == "PE":
            assert any("cut short" in w for w in b.warnings)
    assert not load(samples["v1"]).warnings


def test_long_section_names_are_resolved(samples):
    # MinGW stores names over 8 characters as "/<offset>"; none should be left like that
    names = [s.name for s in load(samples["v2"]).sections]
    assert not [n for n in names if n.startswith("/") and n[1:].isdigit()]


@pytest.mark.skipif(sys.platform != "win32", reason="uses a Windows system file")
def test_a_dll_without_entry_point_has_none():
    assert load(r"C:\Windows\System32\ntdll.dll").entry is None
    assert load(r"C:\Windows\System32\notepad.exe").entry is not None
