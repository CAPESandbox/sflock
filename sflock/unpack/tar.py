# Copyright (C) 2015-2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import bz2
import gzip
import io
import os
import tarfile
import zlib

from sflock.abstracts import Unpacker, File
from sflock.config import MAX_TOTAL_SIZE


def _probe_decompress(opener, head):
    """True if `head` (a prefix of the file) starts a valid stream for the
    given compressed-file class. A truncated prefix may raise EOFError."""
    try:
        with opener(io.BytesIO(head)) as d:
            return bool(d.read(0x1000))
    except (OSError, EOFError, zlib.error):
        return False


class TarFile(Unpacker):
    name = "tarfile"
    mode = "r:"
    exts = b".tar"
    magic = "POSIX tar archive"

    def supported(self):
        return True

    def unpack(self, password=None, duplicates=None):
        try:
            archive = tarfile.open(mode=self.mode, fileobj=self.f.stream)
        except tarfile.ReadError as e:
            self.f.mode = "failed"
            self.f.error = e
            return []

        entries, total_size = [], 0
        with archive:
            for entry in archive:
                # Ignore anything that's not a file for now.
                if not entry.isfile() or entry.size < 0:
                    continue

                # TODO Improve this. Also take precedence for native decompression
                # utilities over the Python implementation in the future.
                total_size += entry.size
                if total_size >= MAX_TOTAL_SIZE:
                    self.f.error = "files_too_large"
                    return []

                try:
                    relapath = entry.path.encode("utf-8", "surrogateescape")
                except UnicodeEncodeError:
                    relapath = entry.path.encode("utf-8", "replace")
                entries.append(File(relapath=relapath, contents=archive.extractfile(entry).read()))

        return self.process(entries, duplicates)


class TargzFile(TarFile, Unpacker):
    name = "targzfile"
    mode = "r:gz"
    exts = b".tar.gz"

    def supported(self):
        return True

    def handles(self):
        if self.f.filename and self.f.filename.lower().endswith(b".tar.gz"):
            return True

        if "gzip compressed data, was" in self.f.magic:
            return False

        if not self.f.filesize:
            return False

        return _probe_decompress(gzip.open, self.f.header[:0x1000])

    def unpack(self, password=None, duplicates=None):
        dirpath = self.mkdtemp()

        if not self.f.filepath:
            filepath = self.temp_path(".gz")
            temporary = True
        else:
            filepath = self.f.filepath
            temporary = False

        try:
            with tarfile.open(filepath, self.mode) as _tar:
                for member in _tar:
                    if member.isdir():
                        continue

                    fname = member.name
                    if "/" in fname:
                        fname = fname.rsplit("/", 1)[1]
                    _tar.makefile(member, os.path.join(dirpath, fname))
        except tarfile.ReadError:
            outfile = open(os.path.join(dirpath, "output"), "wb")
            with gzip.open(filepath) as infile:
                try:
                    while True:
                        chunk = infile.read(0x10000)
                        if not chunk:
                            break
                        outfile.write(chunk)
                except gzip.zlib.error:
                    pass

            outfile.close()

        if temporary:
            os.unlink(filepath)
        return self.process_directory(dirpath, duplicates)


class Tarbz2File(TarFile, Unpacker):
    name = "tarbz2file"
    mode = "r:bz2"
    exts = b".tar.bz2"

    def handles(self):
        if self.f.filename and self.f.filename.lower().endswith(self.exts):
            return True

        if not self.f.filesize:
            return False

        return _probe_decompress(bz2.open, self.f.header[:0x1000])

    def unpack(self, password=None, duplicates=None):
        dirpath = self.mkdtemp()

        if not self.f.filepath:
            filepath = self.temp_path(".bz2")
            temporary = True
        else:
            filepath = self.f.filepath
            temporary = False

        f = open(os.path.join(dirpath, "output"), "wb")
        d = bz2.BZ2File(filepath, "r")

        while f.tell() < MAX_TOTAL_SIZE:
            try:
                buf = d.read(0x10000)
            except IOError:
                break
            if not buf:
                break
            f.write(buf)

        if temporary:
            os.unlink(filepath)

        filesize = f.tell()
        d.close()
        f.close()

        if filesize >= MAX_TOTAL_SIZE:
            self.f.error = "files_too_large"
            return []

        return self.process_directory(dirpath, duplicates)
