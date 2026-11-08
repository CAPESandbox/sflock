# Copyright (C) 2015-2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import os.path

import pytest

from sflock.main import unpack
from sflock.ident import HAVE_UNICORN, identify


pytestmark = pytest.mark.skipif(not HAVE_UNICORN, reason="unicorn is not installed")


def f(filename):
    return os.path.join(b"tests", b"files", filename)


def test_shellcode64_plain():
    t = unpack(f(b"shellcode.zip"), password="infected")
    assert identify(t.children[0], check_shellcode=True) == "Shellcode_x64"
