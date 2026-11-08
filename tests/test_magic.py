# Copyright (C) 2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import io
import os
import zipfile

from sflock import magic
from sflock.abstracts import File


def test_magic():
    assert magic.from_file("tests/files/maldoc.xls").startswith(("Composite Document File V2", "CDF V2 Document"))
    assert magic.from_file("tests/files/test.hta_").startswith(("HTML document", "Microsoft HTML Application (HTA)"))
    assert magic.from_file("tests/files/cab2.cab").startswith("Microsoft Cabinet")


def test_magic_exception():
    assert magic.from_file("tests/files/invld.elf_").startswith("ELF")
    assert magic.from_buffer(open("tests/files/invld.elf_", "rb").read()).startswith("ELF")


def test_magic_lookup_large_in_memory_and_stream_zip(monkeypatch):
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("hello.txt", b"hello world")
    prefix = b"\x00\xff\x80\x7f" * ((2 * 1024 * 1024 + 256 * 1024) // 4)
    blob = prefix + zbuf.getvalue()

    f_mem = File(contents=blob)
    assert "Zip archive" in f_mem.magic
    assert f_mem.mime == "application/zip"

    f_stream = File(stream=io.BytesIO(blob))
    assert "Zip archive" in f_stream.magic
    assert f_stream.mime == "application/zip"

    # python-build-standalone (uv) Linux builds omit os.memfd_create; verify TemporaryFile fallback.
    monkeypatch.delattr(os, "memfd_create", raising=False)
    f_fallback = File(contents=blob)
    assert "Zip archive" in f_fallback.magic
    assert f_fallback.mime == "application/zip"
