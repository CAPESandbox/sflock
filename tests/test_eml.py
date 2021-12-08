# Copyright (C) 2016-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import mock
import os.path
import pytest
import re

from sflock.abstracts import File
from sflock.unpack import EmlFile


def f(filename):
    return File.from_path(os.path.join("tests", "files", filename))


def test_eml_tar_nested2():
    assert "smtp mail" in f("eml_tar_nested2.eml").magic.lower()
    t = EmlFile(f("eml_tar_nested2.eml"))
    assert t.handles() is True
    files = list(t.unpack())

    assert len(files) == 1
    assert not files[0].filepath
    assert files[0].relapath == "tar_nested2.tar"
    assert "POSIX tar" in files[0].magic
    assert not files[0].selected

    assert len(files[0].children) == 1
    assert files[0].children[0].contents == b"hello world\n"
    assert files[0].children[0].magic == "ASCII text"
    assert files[0].children[0].parentdirs == ["deepfoo", "foo"]
    assert not files[0].children[0].selected


def test_eml_nested_eml():
    assert "MIME entity" in f("eml_nested_eml.eml").magic
    t = EmlFile(f("eml_nested_eml.eml"))
    assert t.handles() is True
    assert t.f.selected
    files = list(t.unpack())
    assert len(files) == 2

    assert not files[0].filepath
    assert files[0].relapath == "multipart.eml"
    assert "ASCII text" in files[0].magic
    assert len(files[0].children) == 2
    assert files[0].selected

    assert not files[0].children[0].filepath
    assert files[0].children[0].relapath == "\u60e1\u610f\u8edf\u9ad4.doc".encode("utf-8")
    assert files[0].children[0].filesize == 12
    assert files[0].children[0].extension == "txt"
    assert files[0].children[0].platforms == [
                        {"platform": "windows", "os_version": ""},
                        {"platform": "darwin", "os_version": ""},
                        {"platform": "linux", "os_version": ""},
                        {"platform": "android", "os_version": ""},
                        {"platform": "ios", "os_version": ""}
                    ]
    assert files[0].children[0].selected is False

    assert not files[0].children[1].filepath
    assert files[0].children[1].relapath == "cuckoo.png"
    assert files[0].children[1].filesize == 11970
    assert files[0].children[1].extension == "png"
    assert files[0].children[1].platforms == [
                        {"platform": "windows", "os_version": ""},
                        {"platform": "darwin", "os_version": ""},
                        {"platform": "linux", "os_version": ""},
                        {"platform": "android", "os_version": ""},
                        {"platform": "ios", "os_version": ""}
                    ]
    assert not files[0].children[1].selected

    assert files[1].relapath == "att1"
    assert "UTF-8 Unicode" in files[1].magic
    assert files[1].contents == b"\xe6\x83\xa1\xe6\x84\x8f\xe8\xbb\x9f\xe9\xab\x94"
    assert files[1].extension == "txt"
    assert files[1].platforms == [
                        {"platform": "windows", "os_version": ""},
                        {"platform": "darwin", "os_version": ""},
                        {"platform": "linux", "os_version": ""},
                        {"platform": "android", "os_version": ""},
                        {"platform": "ios", "os_version": ""}
                    ]
    assert not files[1].selected


def test_faulty_eml():
    assert f("eml_faulty.eml_").magic in ("data", "RFC 822 mail text")
    t = EmlFile(f("eml_faulty.eml_"))
    assert t.handles() is True
    files = list(t.unpack())
    assert files[0].children[0].filename == "DOC1820617988-PDF.vbs"
    assert files[0].children[0].filesize == 89851


def test_eml_exception():
    """We must ensure that re.compile is restored at all times."""
    re_compile = re.compile
    EmlFile(f("eml_faulty.eml_")).unpack()
    assert re.compile == re_compile

    with mock.patch("email.message_from_string", side_effect=Exception("test_exception")):
        with pytest.raises(Exception) as e:
            EmlFile(f("eml_faulty.eml_")).unpack()
        e.match("test_exception")
    assert re.compile == re_compile


def test_garbage():
    t = EmlFile(f("garbage.bin"))
    assert t.handles() is False
    assert not t.f.selected
    assert not t.unpack()
