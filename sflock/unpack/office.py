# Copyright (C) 2017-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

from sflock.abstracts import Unpacker
from sflock.decode import plugins


class OfficeFile(Unpacker):
    name = "office"
    package = "doc", "xls", "ppt"
    # exts = (
    #     b".doc",
    #     b".dot",
    #     b".docx",
    #     b".dotx",
    #     b".docm",
    #     b".dotm",
    #     b".docb",
    #     b".rtf",
    #     b".mht",
    #     b".mso",
    #     b".wbk",
    #     b".wiz",
    #     b".xls",
    #     b".xlt",
    #     b".xlm",
    #     b".xlsx",
    #     b".xltx",
    #     b".xlsm",
    #     b".xltm",
    #     b".xlsb",
    #     b".xla",
    #     b".xlam",
    #     b".xll",
    #     b".xlw",
    #     b".slk",
    #     b".csv",
    #     b".ppt",
    #     b".ppa",
    #     b".pot",
    #     b".pps",
    #     b".pptx",
    #     b".pptm",
    #     b".potx",
    #     b".potm",
    #     b".ppam",
    #     b".ppsx",
    #     b".ppsm",
    #     b".sldx",
    #     b".sldm",
    #     b".pub",
    # )

    def supported(self):
        return True

    def decrypt(self, password):
        if password is None:
            return

        try:
            return plugins["office"](self.f, password).decode()
        except Exception:
            return

    def unpack(self, password=None, duplicates=None):
        # Avoiding recursive imports. TODO Can this be generalized?
        from sflock import ident

        entries = []

        f = self.bruteforce(password)
        if f:
            entries.append(f)
            self.f.preview = True
            self.f.selected = False

        ret = self.process(entries, duplicates)
        f and ident(f)
        return ret
