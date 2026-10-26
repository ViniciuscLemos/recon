from pathlib import Path

import pytest

from recon import disasm
from recon.cli import main
from recon.loader import load
from recon.strings import extract
from recon.xrefs import find_xrefs


def _xrefs(path, what):
    b = load(path)
    functions = disasm.find_functions(b)
    return find_xrefs(functions, {s.address: s.text for s in extract(b)}, what)


def test_who_calls_an_import_and_who_uses_a_string(samples):
    [x] = _xrefs(samples["v2"], "connect")
    assert (x.kind, x.used_by) == ("import", ["report_attempt"])
    [x] = _xrefs(samples["v2"], "admin")
    assert (x.kind, x.used_by) == ("string", ["check_login"])
    [x] = _xrefs(samples["v2"], "hash_password")
    assert (x.kind, x.used_by) == ("function", ["check_login"])
    assert _xrefs(samples["v2"], "nothing like this") == []


def test_main_is_guessed_without_symbols(samples):
    functions = disasm.find_functions(load(samples["v2_stripped"]))
    [m] = [f for f in functions.values() if f.name == "main"]
    assert not m.named
    # the same function as in the build with symbols: it calls the network one
    assert any("connect" in functions[a].imports for a in m.calls)


def test_xrefs_command(samples, capsys):
    assert main(["xrefs", str(samples["v2_stripped"]), "10.0.0.5"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("string '10.0.0.5' used by (1)")
    assert main(["xrefs", str(samples["v2"]), "nothing like this"]) == 1


WINDOWS = Path("C:/Windows/System32")


@pytest.mark.parametrize("exe, name", [("whoami.exe", "main"), ("notepad.exe", "WinMain")])
def test_main_is_guessed_in_msvc_programs(exe, name):
    if not (WINDOWS / exe).exists():
        pytest.skip("needs Windows' own programs")
    functions = disasm.find_functions(load(WINDOWS / exe))
    assert [f for f in functions.values() if f.name == name and not f.named]
