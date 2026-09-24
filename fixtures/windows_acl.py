"""Synthetic Windows ACL changes for native rejection tests, never real vaults."""

import ctypes

from continuum_memory.windows_boundary import BOOL, DWORD, POINTER, WindowsBoundary


def set_fixture_acl(path, *, broad=False):
    boundary = WindowsBoundary()
    descriptor = POINTER()
    sid = boundary.sid
    sddl = "O:%sD:P(A;;FA;;;%s)%s" % (sid, sid, "(A;;FR;;;WD)" if broad else "")
    if not boundary.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise RuntimeError("Synthetic ACL creation failed")
    try:
        present, defaulted, dacl = BOOL(), BOOL(), POINTER()
        getter = boundary.security.GetSecurityDescriptorDacl
        getter.argtypes, getter.restype = [POINTER, POINTER, POINTER, POINTER], BOOL
        if not getter(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise RuntimeError("Synthetic ACL extraction failed")
        setter = boundary.security.SetNamedSecurityInfoW
        setter.argtypes = [ctypes.c_wchar_p, DWORD, DWORD, POINTER, POINTER, POINTER, POINTER]
        setter.restype = DWORD
        if setter(str(path), 1, 0x80000004, None, None, dacl, None):
            raise RuntimeError("Synthetic ACL change failed")
    finally:
        boundary.kernel.LocalFree(descriptor)
