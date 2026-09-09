# Copyright (C) 2017-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import os
import re
import tempfile

import sflock.abstracts

from sflock.abstracts import File
from sflock.ident import identify, nodejs, nodejs_patterns
from sflock.main import unpack


def test_empty():
    fd, filepath = tempfile.mkstemp()
    os.close(fd)
    assert unpack(filepath.encode()).package is None
    assert unpack(filepath.encode()).platform is None


def test_identify():
    assert identify(File(b"tests/files/script.js")) == "js"
    assert identify(File(b"tests/files/script.wsf")) == "wsf"
    assert identify(File(b"tests/files/script.vbs")) == "vbs"
    assert identify(File(b"tests/files/script.ps1")) == "ps1"
    f = unpack(contents=open("tests/files/sample.jar", "rb").read())
    assert f.package == "jar"
    f = unpack(contents=open("tests/files/sample.apk", "rb").read())
    assert f.package == "apk"
    assert identify(File(b"tests/files/maldoc_office.htm")) == "doc"
    assert identify(File(b"tests/files/maldoc.xls")) == "xls"
    assert identify(File(b"tests/files/test.hta_")) == "hta"


def test_ppt():
    f = unpack(contents=open("tests/files/ppt_1.pptx", "rb").read())
    assert f.duplicate is False
    assert f.preview is False
    assert f.selected is True
    assert f.package == "ppt"
    assert f.platform == "windows"
    assert f.get_child(b"[Content_Types].xml") is not None
    assert len(f.children) == 37


def test_doc1():
    f = unpack(b"tests/files/doc_1.docx_")
    assert f.duplicate is False
    assert f.selected is True
    assert f.preview is False
    assert f.package == "doc"
    assert f.platform == "windows"
    assert f.get_child(b"[Content_Types].xml") is not None
    assert len(f.children) == 12
    assert f.children[0].selected is False
    assert f.children[4].selected is False
    assert f.children[8].selected is False
    assert f.children[11].selected is False


def test_doc2():
    f = unpack(b"tests/files/doc_2.xlsx_")
    assert f.duplicate is False
    assert f.selected is True
    assert f.preview is False
    assert f.package == "xls"
    assert f.platform == "windows"
    assert f.get_child(b"[Content_Types].xml") is not None
    assert len(f.children) == 12
    assert f.children[0].selected is False
    assert f.children[11].selected is False


def test_oledoc1():
    f = unpack(b"tests/files/oledoc1.doc_")
    assert f.package == "doc"
    assert f.platform == "windows"


def test_url():
    f = unpack(b"tests/files/1.url")
    assert f.package == "ie"
    assert f.platform == "windows"


def test_slk():
    f = unpack(b"tests/files/1.slk")
    assert f.package == "xls"
    assert f.platform == "windows"


def test_iqy():
    f = unpack(b"tests/files/1.iqy")
    assert f.package == "xls"
    assert f.platform == "windows"


def test_nodejs_literal_prefilter():
    """Each nodejs() pattern is gated behind mandatory literal substring(s);
    a minimal sample matching the pattern must always pass the literal gate,
    or that pattern is silently disabled."""
    samples = {
        rb"^#!.*\bnode\b": b"#!/usr/bin/env node\n",
        rb"['\"]node:[a-zA-Z\/]+['\"]": b"import fs from 'node:fs'",
        rb"\bprocess\.(env|argv|cwd|exit|platform|versions|nextTick)\b": b"process.env",
        rb"\bglobal\.(?!\.)": b"global.foo",
        rb"\bBuffer\.(from|alloc|allocUnsafe|concat)\b": b"Buffer.from",
        rb"\b__dirname\b": b"__dirname",
        rb"\b__filename\b": b"__filename",
        rb"(?:require\s*\(|from\s+)['\"]child_process['\"]": b"require('child_process')",
        rb"\bspawn\(": b"spawn(",
        rb"\bexec\(": b"exec(",
        rb"\bexecSync\(": b"execSync(",
        rb"\bfork\(": b"fork(",
        rb"(?:require\s*\(|from\s+)['\"](fs|fs\/promises|path)['\"]": b"require('fs')",
        rb"\bfs\.readFile": b"fs.readFile",
        rb"\bfs\.writeFile": b"fs.writeFile",
        rb"\bfs\.promises\.": b"fs.promises.",
        rb"(?:require\s*\(|from\s+)['\"](net|os|dgram|dns|tls|http|https)['\"]": b"require('https')",
        rb"\bnet\.createServer": b"net.createServer",
        rb"\bnet\.connect": b"net.connect",
        rb"\bos\.cpus": b"os.cpus",
        rb"\bos\.userInfo": b"os.userInfo",
        rb"\bos\.networkInterfaces": b"os.networkInterfaces",
        rb"\bmodule\.exports\b": b"module.exports",
        rb"\bexports\.\w+\s*=": b"exports.foo =",
    }

    seen = set()
    for pattern_list in nodejs_patterns.values():
        for literals, pattern in pattern_list:
            seen.add(pattern)
            sample = samples[pattern]
            assert any(literal in sample for literal in literals), (literals, pattern)
            assert re.search(pattern, sample), pattern

    # Guards against a pattern being added/removed without updating this test.
    assert seen == set(samples)


def test_nodejs_scan_buffer_cap_contents(monkeypatch):
    monkeypatch.setattr(sflock.abstracts, "MAX_IDENT_SCAN_SIZE", 4096)

    markers = b" process.env module.exports require('child_process') "
    filler = b"A" * 4096

    within_cap = File(contents=markers + filler)
    assert nodejs(within_cap) == "nodejs"

    past_cap = File(contents=filler + markers)
    assert nodejs(past_cap) is None


def test_nodejs_scan_buffer_cap_stream(monkeypatch):
    monkeypatch.setattr(sflock.abstracts, "MAX_IDENT_SCAN_SIZE", 4096)

    markers = b" process.env module.exports require('child_process') "
    filler = b"A" * 4096

    fd, filepath = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as fh:
        fh.write(filler + markers)
    try:
        assert nodejs(File.from_path(filepath.encode())) is None
    finally:
        os.unlink(filepath)

    fd, filepath = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as fh:
        fh.write(markers + filler)
    try:
        assert nodejs(File.from_path(filepath.encode())) == "nodejs"
    finally:
        os.unlink(filepath)
