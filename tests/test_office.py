# Copyright (C) 2017-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import os.path
import pytest

from sflock.abstracts import File
from sflock.main import unpack
from sflock.unpack import OfficeFile


def f(filename):
    return File.from_path(os.path.join("tests", "files", filename))


class TestOfficeFile(object):
    def test_office_plain(self):
        z = OfficeFile(f("maldoc.xls"))
        assert z.handles() is True
        assert not z.unpack()
        # Don't test z.f.selected / z.f.preview here as that logic isn't
        # performed by OfficeFile(), but rather the SFlock core.

    def test_office_plain2(self):
        f = unpack("tests/files/maldoc.xls")
        assert f.selected is True

    def test_office_pw_failure(self):
        z = OfficeFile(f("encrypted1.docx"))
        assert z.handles() is True
        assert not z.unpack()
        # TODO Failure to decrypt should also unselect the file.
        assert z.f.selected is False

    def test_office_pw_success(self):
        z = OfficeFile(f("encrypted1.docx"))
        assert z.handles() is True
        d, = z.unpack(password="Password1234_")
        assert z.f.selected is False
        assert d.magic.startswith(("Microsoft Word 2007+", "Zip archive data"))
        assert d.extension == "docx"
        assert d.selected is True
