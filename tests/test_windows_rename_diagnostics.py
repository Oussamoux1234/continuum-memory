"""One-shot native rename diagnostics, not a production fallback or acceptance.

Every case uses a fresh explicit-owner synthetic directory and files, retaining
the production ancestor/parent pins and source DELETE handle. Only numeric/boolean
API metadata is emitted. The production replacement tests remain the release gate.
"""

import ctypes
import json
import os
import tempfile
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.windows_boundary import (
    DELETE, FILE_READ_ATTRIBUTES, GENERIC_WRITE, READ_CONTROL,
    WindowsBoundary, _RenameInfo, local_path,
)


FILE_TRAVERSE = 0x20
FILE_ADD_FILE = 0x2
PARENT_ACCESS = READ_CONTROL | FILE_READ_ATTRIBUTES
SOURCE_ACCESS = GENERIC_WRITE | DELETE
BEFORE = b"synthetic-before"
AFTER = b"synthetic-after"

# case, padded buffer, extra directory access, absolute target / NULL root
CASES = (
    (1, False, 0, False),
    (2, True, 0, False),
    (3, False, FILE_TRAVERSE, False),
    (4, True, FILE_TRAVERSE, False),
    (5, True, FILE_TRAVERSE | FILE_ADD_FILE, False),
    (6, True, 0, True),
)


@unittest.skipUnless(os.name == "nt", "Native rename diagnostics require Windows")
class NativeRenameDiagnosticsTest(unittest.TestCase):
    def test_numeric_only_native_rename_matrix(self):
        boundary = WindowsBoundary()
        with tempfile.TemporaryDirectory(prefix="continuum-rename-diagnostic-") as temporary:
            for case, padded, extra_access, absolute in CASES:
                with self.subTest(case=case):
                    home = Path(temporary) / ("case-%d" % case)
                    boundary.create_directory(home)
                    source_path, target_path = home / "source.tmp", home / "méta.head"
                    boundary.write_new(source_path, AFTER)
                    boundary.write_new(target_path, BEFORE)
                    source_identity = boundary.inspect(source_path)
                    target_identity = boundary.inspect(target_path)
                    name = local_path(target_path) if absolute else target_path.name
                    encoded = name.encode("utf-16-le")
                    size = (ctypes.sizeof(_RenameInfo) + len(encoded) + 2 if padded
                            else max(ctypes.sizeof(_RenameInfo), _RenameInfo.name.offset + len(encoded)))
                    with boundary.open_private(
                        home, directory=True, access=PARENT_ACCESS | extra_access
                    ) as parent:
                        with boundary.open_private(source_path, access=SOURCE_ACCESS) as source:
                            if case == 1:
                                # Exercise the actual production constructor. Capture
                                # last-error before any context-manager native cleanup.
                                ctypes.set_last_error(0)
                                try:
                                    boundary._rename(source, parent, name)
                                except MemoryError:
                                    error = ctypes.get_last_error()
                                    succeeded = False
                                else:
                                    error, succeeded = 0, True
                            else:
                                buffer = ctypes.create_string_buffer(size)
                                info = _RenameInfo.from_buffer(buffer)
                                info.replace = 1
                                info.root = None if absolute else parent
                                info.length = len(encoded)
                                ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.name.offset,
                                               encoded, len(encoded))
                                ctypes.set_last_error(0)
                                result = boundary.kernel.SetFileInformationByHandle(source, 3, buffer, size)
                                # This must be the first operation after the native call.
                                error = ctypes.get_last_error()
                                succeeded = bool(result)
                                if succeeded:
                                    error = 0
                            record = {
                                "case": case, "success": succeeded, "winerror": error,
                                "pointer_size": ctypes.sizeof(ctypes.c_void_p),
                                "struct_size": ctypes.sizeof(_RenameInfo),
                                "root_offset": _RenameInfo.root.offset,
                                "length_offset": _RenameInfo.length.offset,
                                "name_offset": _RenameInfo.name.offset,
                                "buffer_bytes": size, "name_bytes": len(encoded),
                                "parent_access": PARENT_ACCESS | extra_access | 1,
                                "source_access": SOURCE_ACCESS | READ_CONTROL | FILE_READ_ATTRIBUTES | 1,
                                "share_flags": 3, "rename_class": 3, "replace_flags": 1,
                                "root_present": not absolute,
                            }
                            print("native-rename-diagnostic " + json.dumps(record, sort_keys=True), flush=True)
                            self.assertTrue(boundary._info(source, False) == source_identity,
                                            "Source identity changed during the native operation")
                        # Reopen only after closing the source DELETE handle; normal
                        # private opens deliberately do not share DELETE access.
                        self.assertTrue(boundary.read(target_path) == (AFTER if succeeded else BEFORE),
                                        "Native rename produced unexpected destination content")
                        expected_identity = source_identity if succeeded else target_identity
                        self.assertTrue(boundary.inspect(target_path) == expected_identity,
                                        "Native rename produced unexpected destination identity")
                        if succeeded:
                            self.assertFalse(os.path.lexists(source_path))
                        else:
                            self.assertTrue(boundary.inspect(source_path) == source_identity,
                                            "Failed rename changed source identity")
                            self.assertTrue(boundary.read(source_path) == AFTER,
                                            "Failed rename changed source content")


if __name__ == "__main__":
    unittest.main()
