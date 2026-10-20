import json

from recon.cli import main


def test_diff_prints_what_v2_added_and_removed(samples, capsys):
    assert main(["diff", str(samples["v1"]), str(samples["v2"])]) == 0
    out = capsys.readouterr().out
    assert "+ import  connect" in out
    assert "- import  fopen" in out
    assert "+ string  '10.0.0.5'" in out


def test_diff_starts_with_the_capabilities(samples, capsys):
    main(["diff", str(samples["v1"]), str(samples["v2"])])
    first_lines = capsys.readouterr().out.splitlines()[:2]
    assert first_lines == ["+ can     network", "- can     file write"]


def test_json_output_can_be_parsed(samples, capsys):
    assert main(["--json", "diff", str(samples["v1"]), str(samples["v2"])]) == 0
    d = json.loads(capsys.readouterr().out)
    assert "connect" in d["imports_added"]
    assert main(["--json", "info", str(samples["v2"])]) == 0
    info = json.loads(capsys.readouterr().out)
    assert any(c["name"] == "network" for c in info["capabilities"])


def test_info_lists_sections_and_imports(samples, capsys):
    assert main(["info", str(samples["v2"])]) == 0
    out = capsys.readouterr().out
    assert "sections (" in out
    assert "connect" in out


def test_a_file_that_isnt_a_binary_is_an_error(tmp_path, capsys):
    text = tmp_path / "notes.txt"
    text.write_text("just text")
    assert main(["info", str(text)]) == 1
    assert "not a PE or ELF file" in capsys.readouterr().err
