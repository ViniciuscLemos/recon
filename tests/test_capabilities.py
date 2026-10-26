from recon.capabilities import _group_of, find
from recon.loader import load


def _by_name(binary):
    return {c.name: c.evidence for c in find(binary)}


def test_v1_reads_input_and_writes_a_file_but_has_no_network(samples):
    caps = _by_name(load(samples["v1"]))
    assert "fopen" in caps["file write"]
    assert "scanf" in "".join(caps["user input"])  # scanf, __isoc99_scanf or the UCRT's vfscanf
    assert "network" not in caps


def test_v2_talks_to_the_network(samples):
    caps = _by_name(load(samples["v2"]))
    assert {"socket", "connect", "send"} <= set(caps["network"])


def test_stripping_symbols_doesnt_hide_capabilities(samples):
    # imports have to stay in the file for the loader to resolve them, stripped or not
    assert _by_name(load(samples["v2_stripped"])) == _by_name(load(samples["v2"]))


def test_win32_ansi_and_wide_names_and_runtime_prefixes():
    assert _group_of("CreateFileW") == "file write"
    assert _group_of("ShellExecuteA") == "process"
    assert _group_of("_open") == "file write"
    assert _group_of("strcmp") is None


def test_imports_only_the_startup_code_uses_are_marked(samples):
    from recon import disasm

    b = load(samples["v2"])
    caps = {c.name: c for c in find(b, disasm.imports_from(disasm.find_functions(b)))}
    assert not caps["network"].not_from_main
    assert not caps["user input"].not_from_main
    if "dynamic loading" in caps:  # MinGW's startup code, not the program
        assert caps["dynamic loading"].not_from_main


def test_stripped_build_marks_the_same_as_with_symbols(samples):
    from recon import disasm

    def marked(path):
        b = load(path)
        return {c.name: c.not_from_main for c in find(b, disasm.imports_from(disasm.find_functions(b)))}

    # main gets guessed from the startup code, so the stripped build doesn't lose this
    assert marked(samples["v2_stripped"]) == marked(samples["v2"])
