from pathlib import Path

from recon.loader import Binary, Section, load
from recon.packing import hints


def _binary(*sections: Section) -> Binary:
    return Binary(path=Path("fake.exe"), format="PE", arch="x86-64", bits=64, entry=None,
                  image_base=0, sections=list(sections), imports=[], exports={})


def test_the_samples_dont_look_packed(samples):
    assert hints(load(samples["v2"])) == []


def test_upx_sections_are_recognized():
    found = hints(_binary(
        Section("UPX0", 0x1000, 0x9000, 0.0, executable=True, writable=True),
        Section("UPX1", 0xa000, 0x3000, 7.9, executable=True, writable=True),
    ))
    reasons = " | ".join(h.reason for h in found)
    assert "UPX" in reasons
    assert "entropy 7.9" in reasons
    assert "written at runtime" in reasons


def test_high_entropy_data_alone_is_fine():
    # compressed resources or images are normal; only code that looks compressed is suspicious
    assert hints(_binary(Section(".rsrc", 0x1000, 0x4000, 7.8, executable=False, writable=False))) == []
