# Copyright (C) 2016 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import os
import shutil
import subprocess
import tempfile

from sflock.abstracts import Unpacker


class PGP(Unpacker):
    name = "pgpfile"
    exe = "/usr/bin/gpg"
    exts = b".pgp", b".gpg"
    magic = "PGP "

    def unpack(self, password: str = None, duplicates=None):
        dirpath = tempfile.mkdtemp()

        if self.f.filepath:
            filepath = self.f.filepath
            temporary = False
        else:
            filepath = self.f.temp_path()
            temporary = True

        try:
            # ToDo
            # locked system call occurred during sandboxing!\nip=0x7f9d2bc0fa97 sp=0x7ffdcb8d5eb8 abi=0 nr=102 syscall=getuid
            # ret = self.zipjail(filepath, dirpath, "-o", os.path.join(dirpath, "extracted"), "--passphrase=%s" % (password or ""), filepath)
            p = subprocess.Popen(
                (self.exe, "--decrypt", "--batch", "-o", os.path.join(dirpath, "extracted"), "--passphrase=%s" % (password or ""), filepath),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            _, _ = p.communicate()
            if p.returncode == 0:
                return self.process_directory(dirpath, duplicates, password)

            return []

        except Exception:
            return []

        finally:
            if temporary and os.path.exists(filepath):
                os.unlink(filepath)

            if os.path.exists(dirpath):
                shutil.rmtree(dirpath)

    def get_metadata(self):
        ret = []
        content = self.f.contents
        if not content:
            return ret

        if b"BEGIN PGP PUBLIC KEY BLOCK" in content:
            ret.append("public_key")
        elif b"BEGIN PGP PRIVATE KEY BLOCK" in content:
            ret.append("private_key")
        elif b"BEGIN PGP MESSAGE" in content:
            ret.append("encrypted_message")
        elif b"BEGIN PGP SIGNATURE" in content:
            ret.append("signature")
        elif content[0] & 0x80:
            # Binary analysis
            tag = content[0]
            if tag & 0x40:  # New format
                tag_type = tag & 0x3F
            else:  # Old format
                tag_type = (tag >> 2) & 0xF

            if tag_type in (6, 14):
                ret.append("public_key")
            elif tag_type == 5:
                ret.append("private_key")
            elif tag_type in (1, 18):
                ret.append("encrypted_message")

        return ret