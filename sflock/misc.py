# Copyright (C) 2015-2018 Jurriaan Bremer.
# This file is of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import datetime
import os
import importlib
import platform
from dateutil.parser import parse as dtparse
from subprocess import run
import sflock

def get_os():
    """Returns the operating system."""
    if platform.system() == "Linux":
        return "linux"
    if platform.system() == "Windows":
        return "windows"
    if platform.system() == "Darwin":
        return "darwin"
    return "unknown"

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

        if hasattr(subclass, "exts"):
            for ext in make_list(subclass.exts):
                class_.extensions[ext] = subclass

        if hasattr(subclass, "magic"):
            for magic in make_list(subclass.magic):
                class_.magics[magic] = subclass
    return plugins


def data_file(*path):
    """Return the path for the filepath of an embedded file."""
    dirpath = sflock.__path__[0].encode()
    return os.path.abspath(os.path.join(dirpath, b"data", *path))


def make_list(obj):
    if isinstance(obj, (tuple, list)):
        return list(obj)
    return [obj]


def get_metadata_7z(f):
    fp = f.filepath
    clean = False
    if fp is None:
        fp = f.temp_path(".bin")  # extension doesn't matter
        clean = True

    p = run([data_file(b'zipjail.elf'), fp, b'/dev/null', b'--', data_file(b"7zz.elf"), b'l', b'-slt', fp],
            capture_output=True, env=dict(os.environ, TZ="UTC"))
    ret = []
    if p.returncode == 0:
        _, _, out = p.stdout.partition(b'----------')
        if out:
            for finfo_data in out.strip(b"\n").split(b"\n\n"):
                finfo = {}
                for line in finfo_data.decode(errors="replace").splitlines():
                    key, _, value = line.partition(" = ")
                    if value.strip():
                        finfo[key.strip().lower().replace(" ", "_")] = value.strip()
                if not finfo:
                    continue
                for k in ('size', 'packed_size'):
                    if k in finfo:
                        finfo[k] = int(finfo[k])
                for k in ('modified', 'created', 'accessed'):
                    if k in finfo:
                        finfo[k] = dtparse(finfo[k]).replace(tzinfo=datetime.timezone.utc).isoformat()
                ret.append(finfo)

    if clean:
        os.unlink(fp)

    return ret
