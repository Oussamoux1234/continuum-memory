#!/usr/bin/env python3
"""Stage an explicitly reviewed wheel; this is not signature verification."""

import configparser
import os
import stat
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath


WHEEL_NAME = "continuum_memory-0.1.0.dev0-py3-none-any.whl"
DIST_INFO = "continuum_memory-0.1.0.dev0.dist-info/"
MAX_WHEEL_BYTES = 16 * 1024 * 1024


def stage_wheel(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_absolute() or source.resolve(strict=True) != source or source.name != WHEEL_NAME:
        raise ValueError("expected canonical absolute path to the reviewed Continuum wheel")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_WHEEL_BYTES:
            raise ValueError("wheel must be a bounded regular file with one link")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_WHEEL_BYTES + 1)
        if len(payload) != info.st_size:
            raise ValueError("wheel changed while staging")
    finally:
        os.close(descriptor)
    # The caller creates this private, root-owned directory. Never overwrite a path.
    with destination.open("xb") as handle:
        handle.write(payload)
    with zipfile.ZipFile(destination) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)) or len(names) > 4096:
            raise ValueError("duplicate or excessive wheel members")
        if sum(member.file_size for member in bundle.infolist()) > 64 * 1024 * 1024:
            raise ValueError("expanded wheel is too large")
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or "\\" in member.filename or str(path) != member.filename.rstrip("/"):
                raise ValueError("unsafe wheel member path")
            if mode & 0o170000 not in (0, 0o100000, 0o040000):
                raise ValueError("non-regular wheel member")
        for name in ("METADATA", "entry_points.txt"):
            if bundle.getinfo(DIST_INFO + name).file_size > 1024 * 1024:
                raise ValueError("wheel metadata is too large")
        fields = BytesParser().parsebytes(bundle.read(DIST_INFO + "METADATA"))
        if fields.get_all("Name") != ["continuum-memory"] or fields.get_all("Version") != ["0.1.0.dev0"]:
            raise ValueError("unexpected wheel metadata")
        if fields.get_all("Requires-Dist"):
            raise ValueError("approval runtime wheel must have no runtime dependencies")
        entrypoints = configparser.ConfigParser()
        entrypoints.read_string(bundle.read(DIST_INFO + "entry_points.txt").decode("utf-8"))
        if entrypoints.get("console_scripts", "continuum-polkit-helper", fallback=None) != "continuum_memory.polkit_helper:main":
            raise ValueError("unexpected approval helper entry point")
        if "continuum_memory/polkit_helper.py" not in names:
            raise ValueError("approval helper payload missing")


if __name__ == "__main__":
    if os.geteuid() != 0 or len(sys.argv) != 3:
        raise SystemExit("installer staging requires root and explicit source/destination")
    stage_wheel(sys.argv[1], sys.argv[2])
