# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

"""Lifecycle tests for lazily-loaded extracted files: fd usage, temp-dir
ownership/cleanup, and close() semantics."""

import gc
import io
import os
import zipfile

import pytest

from sflock import abstracts
from sflock.abstracts import File
from sflock.main import unpack
from sflock.unpack.tar import TargzFile, Tarbz2File, _probe_decompress
from sflock.unpack.zip7 import ZipFile

FD_DIR = "/proc/self/fd"
pytestmark = pytest.mark.skipif(not os.path.isdir(FD_DIR), reason="needs /proc")


def _fd_count():
    return len(os.listdir(FD_DIR))


def _walk(f):
    for child in f.children:
        yield child
        yield from _walk(child)


def _unpack_targz():
    # Claimed by `gzipfile` (7z under zipjail); both it and
    # `targzfile` extract through Unpacker.process_directory.
    f = unpack(b"tests/files/tar_plain2.tar.gz")
    assert f.temp_dirs, "process_directory must register its dir on the parent"
    return f


def test_no_fd_leak_and_cleanup_on_close():
    before = _fd_count()
    f = _unpack_targz()
    dirs = list(f.temp_dirs)
    children = list(_walk(f))
    backed = [c for c in children if c._temp_filepath]
    assert backed, "expected at least one temp-backed extracted file"
    for child in children:
        # Extracted children hold no open descriptor, before or after access.
        assert child._stream is None
        assert child.contents is not None
        assert child.stream is not None
        assert child._stream is None, "stream must not cache a real fd"
    for child in backed:
        assert os.path.exists(child._temp_filepath)

    # Only the root (File.from_path) keeps a stream open.
    assert _fd_count() <= before + 1

    f.close()
    assert _fd_count() == before
    assert f.temp_dirs == []
    assert not any(os.path.exists(d) for d in dirs)


def test_contents_after_close_is_none_unless_cached():
    f = _unpack_targz()
    cached, lazy = f.children[0], File(temp_filepath=f.children[0]._temp_filepath)
    data = cached.contents
    f.close()
    assert cached.contents == data
    assert lazy.contents is None
    assert lazy.filesize == 0
    assert lazy.header == b""


def test_finalizer_removes_dirs_on_gc():
    f = _unpack_targz()
    dirs = list(f.temp_dirs)
    for child in _walk(f):
        child.parent = None  # break child->parent refs so the root is collectable
    f.close = None  # ensure cleanup comes from the finalizer, not close()
    del f
    gc.collect()
    assert not any(os.path.exists(d) for d in dirs)


def test_close_is_idempotent():
    f = _unpack_targz()
    f.close()
    f.close()


def test_temp_path_from_backing_file(tmp_path):
    p = tmp_path / "blob"
    p.write_bytes(b"backing-data")
    f = File(temp_filepath=str(p).encode())
    out = f.temp_path()
    try:
        assert open(out, "rb").read() == b"backing-data"
        assert f._contents is None, "temp_path should stream from disk"
    finally:
        os.unlink(out)


def test_open_returns_independent_handle(tmp_path):
    p = tmp_path / "blob"
    p.write_bytes(b"abc")
    f = File(temp_filepath=str(p).encode())
    with f.open() as fh:
        assert fh.read() == b"abc"
    assert f._stream is None


def _msix_bytes(padding):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("padding.bin", os.urandom(padding))
        z.writestr("Registry.dat", b"x")
        z.writestr("AppxManifest.xml", b"<Package/>")
    return buf.getvalue()


def test_msix_detected_beyond_scan_window(monkeypatch):
    monkeypatch.setattr(abstracts, "MAX_IDENT_SCAN_SIZE", 1024)
    f = File(contents=_msix_bytes(64 * 1024))
    assert b"Registry.dat" not in f.scan_buffer
    assert ZipFile(f).handles() is False


def test_plain_zip_still_handled():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"hello")
    assert ZipFile(File(contents=buf.getvalue())).handles()


def test_probe_decompress_in_memory():
    data = open("tests/files/tar_plain2.tar.gz", "rb").read()
    assert _probe_decompress(__import__("gzip").open, data[:0x1000]) is True
    assert _probe_decompress(__import__("gzip").open, b"not gzip") is False
    # Truncated stream must not raise.
    assert _probe_decompress(__import__("gzip").open, data[:16]) in (True, False)
    assert TargzFile(File(contents=data)).handles()
    assert not Tarbz2File(File(contents=b"\x00" * 64)).handles()


class _FailingUnpacker(abstracts.Unpacker):
    """Creates owned temp dirs/inputs then bails out, like a failed zipjail run."""

    name = "failing"
    created = []

    def supported(self):
        return True

    def handles(self):
        return True

    def unpack(self, password=None, duplicates=None):
        dirpath = self.mkdtemp()
        with open(os.path.join(dirpath, "output"), "wb") as fh:
            fh.write(b"x" * 4096)
        _FailingUnpacker.created += [dirpath, os.path.dirname(self.temp_path(b".bin"))]
        return []


def test_failed_unpack_reclaims_temp_dirs_immediately(monkeypatch):
    monkeypatch.setattr(abstracts.Unpacker, "plugins", {"failing": _FailingUnpacker})
    _FailingUnpacker.created = []
    f = File(contents=b"data")
    abstracts.Unpacker(None).process([f], [])
    assert f.children == []
    assert _FailingUnpacker.created
    for d in _FailingUnpacker.created:
        assert not os.path.exists(d)
    assert f.temp_dirs == []


def test_direct_unpack_early_return_cleaned_on_close():
    f = File(contents=b"data")
    u = _FailingUnpacker(f)
    _FailingUnpacker.created = []
    assert u.unpack() == []
    assert all(os.path.exists(d) for d in _FailingUnpacker.created)
    f.close()
    assert not any(os.path.exists(d) for d in _FailingUnpacker.created)
