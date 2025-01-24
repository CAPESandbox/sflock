# Copyright (C) 2015-2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

# By default we don't accept a collection of files to be larger than 1GB.
# May be tweaked in the future including modifying this at runtime.
MAX_TOTAL_SIZE = 1024 * 1024 * 1024


def iter_passwords():
    from importlib.resources import as_file
    from pathlib import Path

    with as_file(Path("sflock/data/password.txt")) as passwd_file:
        for line in passwd_file.read_text().splitlines():
            yield line.strip()
