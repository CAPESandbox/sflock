# Copyright (C) 2016-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import email
import email.header
import re

from sflock.abstracts import Unpacker, File


class EmlFile(Unpacker):
    name = "emlfile"
    exts = b".eml"

    whitelisted_content_type = [
        "text/plain",
        "text/html",
    ]

    def supported(self):
        return True

    def handles(self):
        if super(EmlFile, self).handles():
            return True

        keys = []
        lines = self.f.scan_buffer.split(b"\n")
        for line in lines[:10]:
            if b":" in line:
                keys.append(line.split(b":")[0])
        if b"From" in keys and b"To" in keys:
            return True
        return False

    def real_unpack(self, password, duplicates):
        entries = []

        e = email.message_from_string(self.f.contents.decode("latin-1"))
        for part in e.walk():
            if part.is_multipart():
                continue

            if not part.get_filename() and part.get_content_type() in self.whitelisted_content_type:
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            filename = part.get_filename()
            if filename:
                filename = email.header.make_header(email.header.decode_header(filename))
                filename_str = str(filename)
                try:
                    filename = filename_str.encode("utf-8", "surrogateescape")
                except UnicodeEncodeError:
                    filename = filename_str.encode("utf-8", "replace")
            entries.append(File(relapath=filename or b"att1", contents=payload))

        return entries

    def unpack(self, password=None, duplicates=None):
        re_compile_orig = re.compile

        # Forward flags: Python 3.14's email.feedparser calls re.compile(pattern, flags).
        def re_compile_our(pattern, *args, **kwargs):
            if isinstance(pattern, bytes):
                pattern = pattern.replace(rb"?P<end>--", rb"?P<end>--+")
            elif isinstance(pattern, str):
                pattern = pattern.replace("?P<end>--", "?P<end>--+")
            return re_compile_orig(pattern, *args, **kwargs)

        re.compile = re_compile_our
        try:
            entries = self.real_unpack(password, duplicates)
        finally:
            re.compile = re_compile_orig

        return self.process(entries, duplicates)
