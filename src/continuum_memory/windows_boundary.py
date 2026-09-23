"""Experimental Windows filesystem boundary; not enabled by the vault runtime.

Only local fixed NTFS volumes and unambiguous DOS drive paths are accepted.
Private objects have one protected, explicit full-control ACE for the process
user. Ancestors are held without delete sharing during the entire operation.
This module does not establish a boundary against the same user or an admin.
"""

import ctypes
import os
import re
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass

from .errors import MemoryError


DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
BYTE = ctypes.c_ubyte
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
POINTER = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
READ_CONTROL = 0x00020000
FILE_READ_ATTRIBUTES = 0x80
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_ALL_ACCESS = 0x001F01FF
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE = ctypes.c_void_p(-1).value
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


class _FileInfo(ctypes.Structure):
    _fields_ = [(name, DWORD) for name in (
        "attributes", "creation_low", "creation_high", "access_low", "access_high",
        "write_low", "write_high", "volume", "size_high", "size_low", "links",
        "index_high", "index_low",
    )]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", DWORD), ("descriptor", POINTER), ("inherit", BOOL)]


class _Acl(ctypes.Structure):
    _fields_ = [("revision", BYTE), ("reserved", BYTE), ("size", WORD),
                ("count", WORD), ("reserved2", WORD)]


class _Ace(ctypes.Structure):
    _fields_ = [("kind", BYTE), ("flags", BYTE), ("size", WORD), ("mask", DWORD)]


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    index: int


def local_path(value):
    """Reject aliases before Win32 can normalize them or reach another namespace."""
    try:
        path = os.fspath(value)
    except TypeError:
        raise MemoryError("unsafe_windows_path", "An absolute local Windows path is required.") from None
    if not isinstance(path, str):
        raise MemoryError("unsafe_windows_path", "An absolute local Windows path is required.")
    path = path.replace("/", "\\")
    if not re.match(r"^[A-Za-z]:\\", path):
        raise MemoryError("unsafe_windows_path", "An absolute local Windows path is required.")
    try:
        too_long = len(path.encode("utf-16-le")) // 2 >= 248
    except UnicodeError:
        too_long = True
    parts = path[3:].split("\\")
    if too_long or any(
        not part or part in (".", "..") or part.endswith((".", " "))
        or _RESERVED.match(part) or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
        for part in parts
    ):
        raise MemoryError("unsafe_windows_path", "The Windows path is ambiguous or unsupported.")
    return path[0].upper() + path[1:]


def _failure():
    # Native errors may include sensitive paths; callers receive a fixed message.
    return MemoryError("windows_boundary_error", "The Windows boundary operation failed closed.")


class WindowsBoundary:
    """Handle-based experimental primitives; no global state or new dependency."""

    def __init__(self):
        if os.name != "nt":
            raise MemoryError("unsupported_platform", "This boundary requires native Windows.")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        self._bind()
        self.sid = self._process_sid()

    def _bind(self):
        signatures = (
            (self.kernel, "CreateFileW", HANDLE, [LPWSTR, DWORD, DWORD, POINTER, DWORD, DWORD, HANDLE]),
            (self.kernel, "CreateDirectoryW", BOOL, [LPWSTR, POINTER]),
            (self.kernel, "CloseHandle", BOOL, [HANDLE]),
            (self.kernel, "GetFileInformationByHandle", BOOL, [HANDLE, POINTER]),
            (self.kernel, "GetFileType", DWORD, [HANDLE]),
            (self.kernel, "GetCurrentProcess", HANDLE, []),
            (self.kernel, "GetDriveTypeW", DWORD, [LPWSTR]),
            (self.kernel, "GetVolumeInformationW", BOOL,
             [LPWSTR, LPWSTR, DWORD, POINTER, POINTER, POINTER, LPWSTR, DWORD]),
            (self.kernel, "QueryDosDeviceW", DWORD, [LPWSTR, LPWSTR, DWORD]),
            (self.kernel, "LocalFree", POINTER, [POINTER]),
            (self.kernel, "ReadFile", BOOL, [HANDLE, POINTER, DWORD, POINTER, POINTER]),
            (self.kernel, "WriteFile", BOOL, [HANDLE, POINTER, DWORD, POINTER, POINTER]),
            (self.kernel, "FlushFileBuffers", BOOL, [HANDLE]),
            (self.security, "OpenProcessToken", BOOL, [HANDLE, DWORD, POINTER]),
            (self.security, "GetTokenInformation", BOOL, [HANDLE, DWORD, POINTER, DWORD, POINTER]),
            (self.security, "ConvertSidToStringSidW", BOOL, [POINTER, POINTER]),
            (self.security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", BOOL,
             [LPWSTR, DWORD, POINTER, POINTER]),
            (self.security, "GetSecurityInfo", DWORD,
             [HANDLE, DWORD, DWORD, POINTER, POINTER, POINTER, POINTER, POINTER]),
            (self.security, "GetSecurityDescriptorControl", BOOL, [POINTER, POINTER, POINTER]),
            (self.security, "GetAce", BOOL, [POINTER, DWORD, POINTER]),
            (self.security, "IsValidSid", BOOL, [POINTER]),
            (self.security, "GetLengthSid", DWORD, [POINTER]),
        )
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments

    def _close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise _failure()

    def _sid_string(self, sid):
        text = POINTER()
        if not sid or not self.security.IsValidSid(sid):
            raise _failure()
        if not self.security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise _failure()
        try:
            return ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def _process_sid(self):
        token = HANDLE()
        if not self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
            raise _failure()
        try:
            size = DWORD()
            self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                raise _failure()
            data = ctypes.create_string_buffer(size.value)
            if not self.security.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
                raise _failure()
            return self._sid_string(POINTER.from_buffer(data).value)
        finally:
            self._close(token)

    @contextmanager
    def _attributes(self):
        descriptor = POINTER()
        # No inherited ACEs, group grants, generic rights, or default owner.
        sddl = "O:%sD:P(A;;FA;;;%s)" % (self.sid, self.sid)
        if not self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise _failure()
        try:
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def _volume(self, root):
        if self.kernel.GetDriveTypeW(root) != 3:  # DRIVE_FIXED only, never SMB/removable.
            raise MemoryError("unsupported_filesystem", "A local fixed NTFS volume is required.")
        device = ctypes.create_unicode_buffer(32768)
        if not self.kernel.QueryDosDeviceW(root[:2], device, len(device)):
            raise _failure()
        if not re.fullmatch(r"\\Device\\HarddiskVolume\d+", device.value, re.I):
            raise MemoryError("unsupported_filesystem", "Drive aliases are not supported.")
        name = ctypes.create_unicode_buffer(32)
        flags = DWORD()
        if not self.kernel.GetVolumeInformationW(root, None, 0, None, None, ctypes.byref(flags), name, len(name)):
            raise _failure()
        if name.value != "NTFS" or not flags.value & 8:
            raise MemoryError("unsupported_filesystem", "NTFS with persistent ACLs is required.")

    def _open(self, path, access=READ_CONTROL | FILE_READ_ATTRIBUTES, create=False, attributes=None):
        handle = self.kernel.CreateFileW(
            path, access, 3, ctypes.byref(attributes) if attributes is not None else None,
            1 if create else 3,  # CREATE_NEW / OPEN_EXISTING; never truncate.
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, None,
        )
        # Share READ|WRITE, deliberately not DELETE. This also fails if an
        # already-open handle has incompatible delete access.
        if handle in (None, INVALID_HANDLE):
            raise _failure()
        return handle

    def _info(self, handle, directory):
        info = _FileInfo()
        if self.kernel.GetFileType(handle) != 1 or not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise _failure()
        if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise MemoryError("unsafe_reparse_point", "Reparse points are not allowed.")
        if bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise MemoryError("unsafe_file", "The Windows object has the wrong type.")
        if not directory and info.links != 1:
            raise MemoryError("unsafe_file", "Private files must have exactly one hardlink.")
        return FileIdentity(info.volume, (info.index_high << 32) | info.index_low)

    def _private_acl(self, handle):
        owner, dacl, descriptor = POINTER(), POINTER(), POINTER()
        status = self.security.GetSecurityInfo(
            handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
        )
        if status:
            raise _failure()
        try:
            if self._sid_string(owner) != self.sid:
                raise MemoryError("unsafe_owner", "The Windows object has a different owner.")
            control, revision = WORD(), DWORD()
            if not self.security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise _failure()
            if control.value & 0x1004 != 0x1004 or not dacl:
                raise MemoryError("unsafe_permissions", "A protected owner-only DACL is required.")
            acl = _Acl.from_address(dacl.value)
            if acl.count != 1:
                raise MemoryError("unsafe_permissions", "Only the explicit owner ACE is allowed.")
            address = POINTER()
            if not self.security.GetAce(dacl, 0, ctypes.byref(address)):
                raise _failure()
            ace = _Ace.from_address(address.value)
            if ace.kind != 0 or ace.flags != 0 or ace.mask != FILE_ALL_ACCESS or ace.size < 16:
                raise MemoryError("unsafe_permissions", "The private ACE is unsupported.")
            sid = address.value + ctypes.sizeof(_Ace)
            if not self.security.IsValidSid(sid) or self.security.GetLengthSid(sid) + ctypes.sizeof(_Ace) != ace.size:
                raise MemoryError("unsafe_permissions", "The private ACE is invalid.")
            if self._sid_string(sid) != self.sid:
                raise MemoryError("unsafe_permissions", "The private ACE names another principal.")
        finally:
            self.kernel.LocalFree(descriptor)

    @contextmanager
    def _parents(self, path):
        self._volume(path[:3])
        with ExitStack() as handles:
            current = path[:3]
            for part in [""] + path[3:].split("\\")[:-1]:
                if part:
                    current = current.rstrip("\\") + "\\" + part
                handle = self._open(current, FILE_READ_ATTRIBUTES)
                handles.callback(self._close, handle)
                self._info(handle, True)
            yield

    @contextmanager
    def open_private(self, path, directory=False, access=READ_CONTROL | FILE_READ_ATTRIBUTES):
        """Keep leaf and ancestors pinned for the caller's complete operation."""
        path = local_path(path)
        with self._parents(path):
            handle = self._open(path, access | READ_CONTROL | FILE_READ_ATTRIBUTES)
            try:
                self._info(handle, directory)
                self._private_acl(handle)
                yield handle
                self._info(handle, directory)
                self._private_acl(handle)
            finally:
                self._close(handle)

    def inspect(self, path, directory=False):
        with self.open_private(path, directory) as handle:
            return self._info(handle, directory)

    def create_directory(self, path):
        """Create one private directory under existing ancestors; never chmod an existing object."""
        path = local_path(path)
        with self._parents(path), self._attributes() as attributes:
            if not self.kernel.CreateDirectoryW(path, ctypes.byref(attributes)):
                raise _failure()
            return self.inspect(path, directory=True)

    def write_new(self, path, data):
        if not isinstance(data, bytes) or len(data) > 65536:
            raise MemoryError("invalid_request", "Private material must be bounded bytes.")
        path = local_path(path)
        with self._parents(path), self.open_private(path.rsplit("\\", 1)[0], directory=True), self._attributes() as attributes:
            handle = self._open(path, GENERIC_WRITE | READ_CONTROL, True, attributes)
            try:
                self._info(handle, False)
                self._private_acl(handle)
                offset = 0
                while offset < len(data):
                    written = DWORD()
                    chunk = ctypes.create_string_buffer(data[offset:])
                    if not self.kernel.WriteFile(handle, chunk, len(data) - offset, ctypes.byref(written), None) or not written.value:
                        raise _failure()
                    offset += written.value
                if not self.kernel.FlushFileBuffers(handle):
                    raise _failure()
                self._info(handle, False)
                self._private_acl(handle)
            finally:
                self._close(handle)

    def read(self, path, maximum=4096):
        if type(maximum) is not int or not 0 <= maximum <= 65536:
            raise MemoryError("invalid_request", "The private read bound is invalid.")
        with self.open_private(path, access=GENERIC_READ) as handle:
            result = bytearray()
            while len(result) <= maximum:
                size = min(4096, maximum + 1 - len(result))
                buffer, received = ctypes.create_string_buffer(size), DWORD()
                if not self.kernel.ReadFile(handle, buffer, size, ctypes.byref(received), None):
                    raise _failure()
                if not received.value:
                    return bytes(result)
                result.extend(buffer.raw[:received.value])
                if len(result) > maximum:
                    raise MemoryError("unsafe_file", "Private material is unexpectedly large.")
