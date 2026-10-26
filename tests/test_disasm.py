import pytest

from recon import disasm
from recon.cli import main
from recon.loader import load
from recon.strings import extract


@pytest.fixture(scope="module")
def v2(samples):
    b = load(samples["v2"])
    return b, disasm.find_functions(b)


def _by_name(functions):
    return {f.name: f for f in functions.values()}


def _strings_of(b, f):
    texts = {s.address: s.text for s in extract(b)}
    return {texts[a] for a in f.data_refs if a in texts}


def test_finds_the_sample_functions_by_symbol(v2):
    _, functions = v2
    names = _by_name(functions)
    for name in ("main", "check_login", "hash_password", "report_attempt"):
        assert names[name].named


def test_who_calls_whom(v2):
    _, functions = v2
    names = _by_name(functions)
    graph = disasm.call_graph(functions)
    assert names["hash_password"].address in names["check_login"].calls
    assert {names["check_login"].address, names["report_attempt"].address} <= names["main"].calls
    assert list(graph.predecessors(names["check_login"].address)) == [names["main"].address]


def test_imports_and_strings_land_in_the_right_function(v2):
    b, functions = v2
    names = _by_name(functions)
    assert "strcmp" in names["check_login"].imports
    assert {"socket", "connect", "send"} <= names["report_attempt"].imports
    assert "10.0.0.5" in _strings_of(b, names["report_attempt"])
    assert "admin" in _strings_of(b, names["check_login"])
    # an import stub is not a function of its own
    assert "connect" not in names


def test_stripped_binary_still_has_the_same_structure(samples):
    b = load(samples["v2_stripped"])
    functions = disasm.find_functions(b)
    network = [f for f in functions.values() if "connect" in f.imports]
    assert len(network) == 1 and not network[0].named
    assert network[0].name.startswith("FUN_")
    caller = [f for f in functions.values() if network[0].address in f.calls]
    assert len(caller) == 1
    assert "Username:" in " ".join(_strings_of(b, caller[0]))


def test_find_by_name_or_address(v2):
    _, functions = v2
    f = _by_name(functions)["check_login"]
    assert disasm.find(functions, "check_login") is f
    assert disasm.find(functions, hex(f.address)) is f
    assert disasm.find(functions, f"FUN_{f.address + 1:x}") is f
    assert disasm.find(functions, "nope") is None


def test_func_command(samples, capsys):
    assert main(["func", str(samples["v2"]), "check_login"]) == 0
    out = capsys.readouterr().out
    assert "called by (1)\n  main" in out
    assert "hash_password" in out
    assert main(["func", str(samples["v2"]), "nope"]) == 1
