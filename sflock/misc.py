# Copyright (C) 2015-2018 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import os
import importlib
from dateutil.parser import parse as dtparse
from dateutil.tz import gettz
from subprocess import run
import sflock


def import_plugins(dirpath, module_prefix, namespace, class_):
    """Import plugins of type `class` located at `dirpath` into the
    `namespace` that starts with `module_prefix`. If `dirpath` represents a
    filepath then it is converted into its containing directory."""
    if os.path.isfile(dirpath):
        dirpath = os.path.dirname(dirpath)

    for fname in os.listdir(dirpath):
        if fname.endswith(".py") and not fname.startswith("__init__"):
            module_name, _ = os.path.splitext(fname)
            importlib.import_module("%s.%s" % (module_prefix, module_name))

    plugins = {}
    for subclass in class_.__subclasses__():
        namespace[subclass.__name__] = subclass
        plugins[subclass.name.lower()] = subclass
        class_.plugins[subclass.name.lower()] = subclass
    return plugins


def data_file(*path):
    """Return the path for the filepath of an embedded file."""
    dirpath = sflock.__path__[0].encode()
    return os.path.abspath(os.path.join(dirpath, b"data", *path))


def make_list(obj):
    if isinstance(obj, (tuple, list)):
        return list(obj)
    return [obj]


def naive_to_utc(naive_datetime_str):
    """
    Parses a naive datetime string, assumes it's in the local timezone,
    and converts it to a timezone-aware UTC datetime object.

    Args:
        naive_datetime_str: A string representing a naive datetime.

    Returns:
        A timezone-aware datetime object in UTC.
    """

    naive_dt = dtparse(naive_datetime_str)
    aware_dt_local = naive_dt.replace(tzinfo=gettz())
    # If local tz is already UTC, this conversion is a no-op.
    utc_dt = aware_dt_local.astimezone(gettz('UTC'))
    return utc_dt


def get_metadata_7z(f):
    fp = f.filepath
    clean = False
    if fp is None:
        fp = f.temp_path(".bin")  # extension doesn't matter
        clean = True

    p = run([data_file(b'zipjail.elf'), fp, b'/dev/null', b'--', data_file(b"7zz.elf"), b'l', b'-slt', fp],
            capture_output=True)
    ret = []
    if p.returncode == 0:
        _, _, out = p.stdout.partition(b'----------')
        if out:
            for finfo_data in out.strip(b"\n").split(b"\n\n"):
                finfo = {}
                for line in finfo_data.decode(errors="replace").splitlines():
                    if " = " in line:
                        key, value = line.split(" = ", 1)
                        if value.strip():
                            finfo[key.strip().lower().replace(" ", "_")] = value.strip()
                if not finfo:
                    continue
                for k in ('size', 'packed_size'):
                    if k in finfo:
                        finfo[k] = int(finfo[k])
                for k in ('modified', 'created', 'accessed'):
                    if k in finfo:
                        finfo[k] = naive_to_utc(finfo[k]).isoformat()
                ret.append(finfo)

    if clean:
        os.unlink(fp)

    return ret
