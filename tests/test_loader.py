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
