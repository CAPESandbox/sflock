# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

"""YARA (yara-x) backed identification."""

import importlib

import pytest

from sflock.abstracts import File

# `sflock.ident` the attribute is the re-exported ident() function; fetch the module.
ident = importlib.import_module("sflock.ident")

pytestmark = pytest.mark.skipif(not ident.HAVE_YARA, reason="yara-x not installed (install with -E shellcode)")


def _udf_image(ids=(b"BEA01", b"NSR02", b"TEA01")):
    # archive_udf: 3 of the volume-recognition IDs within 0x8000..0x10000.
    buf = bytearray(0x10000)
    for i, vid in enumerate(ids):
        off = 0x8000 + i * 0x800 + 1
        buf[off : off + len(vid)] = vid
    return bytes(buf)


def test_rules_compiled():
    assert ident.archives_rules is not None
    assert ident.shellcode_rules is not None


def test_udf_detected():
    assert ident.udf(File(contents=_udf_image())) == "udf"


def test_udf_requires_three_ids():
    assert ident.udf(File(contents=_udf_image(ids=(b"BEA01", b"NSR02")))) is None


def test_udf_ids_outside_window_ignored():
    buf = bytearray(0x10000)
    buf[0x100:0x105] = b"BEA01"
    buf[0x200:0x205] = b"NSR02"
    buf[0x300:0x305] = b"TEA01"
    assert ident.udf(File(contents=bytes(buf))) is None


def test_shellcode_rules_match_fixture():
    data = open("tests/files/busybox-i686", "rb").read()
    assert "shellcode_get_eip" in ident._yara_matches(ident.shellcode_rules, data)
