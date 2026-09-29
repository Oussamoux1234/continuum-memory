"""Bounded raw child-pipe barriers without background readers or buffered prefetch."""

import os
import select
import time


def read_line(stream, timeout=10, maximum=1024):
    deadline = time.monotonic() + timeout
    data = bytearray()
    descriptor = stream.fileno()
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        peek = kernel.PeekNamedPipe
        peek.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        peek.restype = wintypes.BOOL
        handle = msvcrt.get_osfhandle(descriptor)
    while len(data) < maximum:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Synthetic child did not reach its bounded barrier")
        if os.name == "nt":
            available = wintypes.DWORD()
            if not peek(handle, None, 0, None, ctypes.byref(available), None):
                raise EOFError("Synthetic child pipe closed before the barrier")
            if not available.value:
                time.sleep(min(remaining, 0.01))
                continue
        elif not select.select([descriptor], [], [], remaining)[0]:
            raise TimeoutError("Synthetic child did not reach its bounded barrier")
        chunk = os.read(descriptor, 1)
        if not chunk:
            raise EOFError("Synthetic child pipe closed before the barrier")
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)
    raise ValueError("Synthetic barrier exceeded its byte limit")
