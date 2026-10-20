from recon.diff import compare
from recon.loader import load


def test_v2_swaps_the_log_file_for_the_network(samples):
    d = compare(load(samples["v1"]), load(samples["v2"]))
    assert {"socket", "connect", "send"} <= set(d.imports_added)
    assert "fopen" in d.imports_removed
    assert "10.0.0.5" in d.strings_added
    assert "login.log" in d.strings_removed
    # imported names live in the file as text too, but they're reported once, as imports
    assert "connect" not in d.strings_added


def test_a_binary_against_itself_has_no_changes(samples):
    b = load(samples["v1"])
    assert compare(b, b).empty
