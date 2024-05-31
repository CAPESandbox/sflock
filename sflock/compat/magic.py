# Copyright (C) 2016-2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

from __future__ import absolute_import

import logging
import magic


log = logging.getLogger(__name__)


def from_file(f, mime=False):
    try:
        return magic.from_file(f, mime)
    except magic.MagicException as e:
        return e.message


def from_buffer(buf, mime=False):
    try:
        return magic.from_buffer(buf, mime)
    except magic.MagicException as e:
        return e.message
