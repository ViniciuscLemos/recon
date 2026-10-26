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
    assert d.capabilities_added == ["network"]
    assert d.capabilities_removed == ["file write"]


def test_a_binary_against_itself_has_no_changes(samples):
    b = load(samples["v1"])
    assert compare(b, b).empty


def _by_kind(changes):
    return {(c.kind, c.name): c for c in changes}


def test_functions_that_changed_between_versions(samples):
    changes = _by_kind(compare(load(samples["v1"]), load(samples["v2"])).functions)
    assert {"connect", "send"} <= set(changes["added", "report_attempt"].imports_added)
    assert "fopen" in changes["removed", "log_attempt"].imports_removed
    main = changes["changed", "main"]
    assert main.calls_added == ["report_attempt"] and main.calls_removed == ["log_attempt"]
    assert ("changed", "check_login") in changes
    # the hash didn't change, so it isn't listed at all
    assert not any(name == "hash_password" for _, name in changes)


def test_function_changes_without_names(samples):
    changes = compare(load(samples["v1_stripped"]), load(samples["v2_stripped"])).functions
    added = [c for c in changes if c.kind == "added" and "connect" in c.imports_added]
    removed = [c for c in changes if c.kind == "removed" and "fopen" in c.imports_removed]
    assert len(added) == 1 and len(removed) == 1
    # the caller of both is main, paired even with no names because the rest of it is the same
    callers = [c for c in changes if c.kind == "changed" and added[0].name in c.calls_added]
    assert len(callers) == 1 and removed[0].name in callers[0].calls_removed
