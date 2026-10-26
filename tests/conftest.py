"""Builds the sample programs once per test run with the gcc on this machine.

On Windows that's MinGW and the samples come out as PE files, on Linux as ELF, so the same tests
cover both formats depending on where they run (CI runs both).
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SAMPLES = Path(__file__).parent.parent / "samples"


def _build(out: Path, source: str, name: str, *flags: str) -> Path:
    exe = out / (name + (".exe" if sys.platform == "win32" else ""))
    # v2 talks to the network, which on Windows means linking Winsock
    libs = ["-lws2_32"] if sys.platform == "win32" and "v2" in source else []
    subprocess.run(["gcc", "-O1", "-fno-inline", *flags, "-o", str(exe), str(SAMPLES / source), *libs], check=True)
    return exe


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    if not shutil.which("gcc"):
        pytest.skip("needs gcc to build the samples")
    out = tmp_path_factory.mktemp("samples")
    return {
        "v1": _build(out, "login_v1.c", "login_v1"),
        "v1_stripped": _build(out, "login_v1.c", "login_v1_stripped", "-s"),
        "v2": _build(out, "login_v2.c", "login_v2"),
        "v2_stripped": _build(out, "login_v2.c", "login_v2_stripped", "-s"),
    }
