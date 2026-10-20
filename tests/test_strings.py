from recon.loader import load
from recon.strings import extract


def test_finds_the_program_strings_with_their_address(samples):
    b = load(samples["v2"])
    strings = {s.text: s for s in extract(b)}
    assert "Invalid username or password" in strings
    assert "10.0.0.5" in strings
    found = strings["Invalid username or password"]
    assert b.read(found.address, 7) == b"Invalid"


def test_stripping_doesnt_change_the_strings(samples):
    # debug sections hold compiler paths and versions, not the program's strings
    def texts(path):
        return {s.text for s in extract(load(path))}
    assert texts(samples["v2"]) == texts(samples["v2_stripped"])


def test_every_string_has_at_least_four_visible_characters(samples):
    for s in extract(load(samples["v2"])):
        assert sum(not c.isspace() for c in s.text) >= 4, s


def test_v1_has_the_log_file_and_no_server(samples):
    texts = {s.text for s in extract(load(samples["v1"]))}
    assert "login.log" in texts
    assert "10.0.0.5" not in texts
