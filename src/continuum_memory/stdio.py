"""Bounded pipe I/O, including on platforms whose selectors cannot watch pipes.

Two fixed daemon workers perform raw descriptor I/O only. The main thread owns
framing and dispatch. On timeout the bridge exits instead of draining arbitrary
input or waiting for a blocked OS pipe; process exit releases the descriptors.
"""

import os
import queue
import threading
import time
from typing import Optional

from .security import MAX_FRAME_BYTES
from .transport import CHUNK_BYTES, READ_TIMEOUT, WRITE_TIMEOUT


class FrameFailure(Exception):
    pass


class StdioTransport:
    def __init__(self, input_fd: int, output_fd: int):
        if os.name == "nt":
            import msvcrt
            msvcrt.setmode(input_fd, os.O_BINARY)
            msvcrt.setmode(output_fd, os.O_BINARY)
        self.input_fd = input_fd
        self.output_fd = output_fd
        self.incoming: queue.Queue = queue.Queue(maxsize=1)
        self.outgoing: queue.Queue = queue.Queue(maxsize=1)
        self.stopped = threading.Event()
        self.pending = bytearray()
        self.arrival: Optional[float] = None
        threading.Thread(target=self._reader, daemon=True, name="mcp-input").start()
        threading.Thread(target=self._writer, daemon=True, name="mcp-output").start()

    def _reader(self) -> None:
        while not self.stopped.is_set():
            try:
                chunk = os.read(self.input_fd, CHUNK_BYTES)
            except OSError:
                chunk = b""
            item = (chunk, time.monotonic())
            while not self.stopped.is_set():
                try:
                    self.incoming.put(item, timeout=0.1)
                    break
                except queue.Full:
                    pass
            if not chunk:
                return

    def _writer(self) -> None:
        while not self.stopped.is_set():
            try:
                payload, done, errors = self.outgoing.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                offset = 0
                while offset < len(payload):
                    sent = os.write(self.output_fd, memoryview(payload)[offset:])
                    if not sent:
                        raise OSError("Disconnected pipe")
                    offset += sent
            except OSError:
                errors.append(True)
            finally:
                done.set()

    def read_frame(self) -> Optional[bytes]:
        frame = bytearray()
        deadline = self.arrival + READ_TIMEOUT if self.pending and self.arrival is not None else None
        while True:
            newline = self.pending.find(b"\n")
            take = newline + 1 if newline >= 0 else len(self.pending)
            if len(frame) + take > MAX_FRAME_BYTES:
                raise FrameFailure("Frame too large")
            frame.extend(self.pending[:take])
            del self.pending[:take]
            if newline >= 0:
                return bytes(frame[:-1])
            if len(frame) == MAX_FRAME_BYTES:
                raise FrameFailure("Frame too large")
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise FrameFailure("Incomplete frame")
            try:
                chunk, arrival = self.incoming.get(timeout=remaining)
            except queue.Empty:
                raise FrameFailure("Incomplete frame") from None
            if not chunk:
                if frame:
                    raise FrameFailure("Incomplete frame")
                return None
            if deadline is not None and arrival > deadline:
                raise FrameFailure("Incomplete frame")
            self.pending.extend(chunk)
            self.arrival = arrival
            if deadline is None:
                deadline = arrival + READ_TIMEOUT

    def write_frame(self, payload: bytes) -> bool:
        done = threading.Event()
        errors = []
        self.outgoing.put_nowait((payload, done, errors))
        return done.wait(WRITE_TIMEOUT) and not errors

    def close(self) -> None:
        self.stopped.set()
