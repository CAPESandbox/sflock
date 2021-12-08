# Copyright (C) 2016-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import ntpath
import configparser

from sflock.abstracts import Unpacker, File
from sflock.errors import Errors


class BupFile(Unpacker):
    name = "bupfile"
    exts = ".bup"

    def supported(self):
        return True

    def handles(self):
        if super(BupFile, self).handles():
            return True

        if self.f.ole and ["Details"] in self.f.ole.listdir():
            return True
        return False

    def decrypt(self, content):
        return b"".join(b"%c" % (ch ^ 0x6A) for ch in content)

    def unpack(self, depth=0,  password=None, duplicates=None):
        entries = []

        if not self.f.ole:
            self.f.set_error(Errors.UNPACK_FAILED, "No OLE structure found")
            return []

        if ["Details"] not in self.f.ole.listdir():
            return []

        details = self.decrypt(bytearray(self.f.ole.openstream("Details").read()))

        config = configparser.ConfigParser()
        config.read_string(details.decode())

        ole = self.f.ole

        for filename in ole.listdir():
            if filename[0] == "Details" or not ole.get_size(filename[0]):
                continue

            relapath = ntpath.basename(
                config.get(filename[0], "OriginalName")
            )

            entries.append(File(
                relapath=relapath,
                contents=self.decrypt(
                    bytearray(ole.openstream(filename[0]).read())
                )
            ))

        return self.process(entries, duplicates, depth)
