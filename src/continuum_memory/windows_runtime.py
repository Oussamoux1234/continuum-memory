"""Bounded Windows pipe I/O with a single owning-thread application dispatcher.

Workers receive neither Store nor Kernel. All connection/request state is bounded;
the first native pipe instance remains held until after Store has been closed.
"""

import os
import queue
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass, field

from .errors import MemoryError
from .transport import CLIENT_TIMEOUT, MAX_CONNECTIONS, READ_TIMEOUT, WRITE_TIMEOUT
from .windows_pipe import CANCEL_GRACE_MS, FATAL_CANCEL_EXIT, PipeServer, connect

DRAIN_ACK = b"continuum-response-read-v1\n"
SHUTDOWN_TIMEOUT = max(READ_TIMEOUT, WRITE_TIMEOUT) + CANCEL_GRACE_MS / 1000 + 1


class _Reply:
    def __init__(self):
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.cancelled = False
        self.dispatched = False
        self.value = None


@dataclass(frozen=True)
class Request:
    """One immutable frame/deadline, with a never-reused reply state machine."""

    raw: bytes
    deadline: float
    _state: _Reply = field(default_factory=_Reply, repr=False, compare=False)

    def claim(self):
        with self._state.lock:
            if self._state.cancelled or self._state.dispatched or time.monotonic() >= self.deadline:
                return False
            self._state.dispatched = True
            return True

    def cancel(self):
        with self._state.lock:
            self._state.cancelled = True
            self._state.value = None
            self._state.ready.set()

    def complete(self, response):
        with self._state.lock:
            if not self._state.cancelled and time.monotonic() < self.deadline:
                self._state.value = response
            self._state.ready.set()

    @property
    def reply(self):
        with self._state.lock:
            return self._state.value

    def wait(self, stopping):
        while not stopping.is_set():
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._state.ready.wait(min(0.05, remaining)):
                return self.reply
        self.cancel()
        return None


class _Worker:
    """Raw pipe I/O only. No application handler or SQLite object is reachable."""

    def __init__(self, pipe, incoming, stopping, failed, number):
        self.pipe, self.incoming = pipe, incoming
        self.stopping, self.failed = stopping, failed
        self.thread = threading.Thread(target=self.run, name="memory-pipe-%d" % number, daemon=True)

    def run(self):
        try:
            while not self.stopping.is_set():
                request = None
                try:
                    with self.pipe.accept(timeout=READ_TIMEOUT, stopping=self.stopping) as connection:
                        raw = connection.receive()
                        request = Request(raw[:-1], time.monotonic() + CLIENT_TIMEOUT)
                        if self.stopping.is_set():
                            continue
                        try:
                            self.incoming.put_nowait(request)
                        except queue.Full:
                            continue
                        response = request.wait(self.stopping)
                        if response is None or self.stopping.is_set():
                            continue
                        connection.deadline = time.monotonic() + WRITE_TIMEOUT
                        connection.send(response)
                        # DisconnectNamedPipe discards unread bytes. This fixed
                        # bounded acknowledgment confirms drainage, not authority.
                        if connection.receive(len(DRAIN_ACK)) != DRAIN_ACK:
                            raise MemoryError("invalid_frame", "The local response acknowledgment is invalid.")
                except (MemoryError, OSError):
                    # Native peer/IO failures affect only this bounded exchange.
                    pass
                finally:
                    if request is not None:
                        request.cancel()
        except BaseException:
            self.failed.set()
            self.stopping.set()


class PipePool:
    """The persistent first instance is the native cooperative daemon lock."""

    def __init__(self, binding):
        self.pipes, self.workers = [], []
        self.incoming = queue.Queue(maxsize=MAX_CONNECTIONS)
        self.stopping, self.failed = threading.Event(), threading.Event()
        self.started = False
        try:
            for number in range(MAX_CONNECTIONS):
                self.pipes.append(PipeServer(binding, max_instances=MAX_CONNECTIONS,
                                             anchor=self.pipes[0] if self.pipes else None))
            self.workers = [_Worker(pipe, self.incoming, self.stopping, self.failed, number)
                            for number, pipe in enumerate(self.pipes)]
        except BaseException:
            self.close()
            raise

    def start(self):
        if self.started or self.stopping.is_set():
            raise MemoryError("pipe_runtime_invalid", "The local pipe runtime cannot be restarted.")
        self.started = True
        try:
            for worker in self.workers:
                worker.thread.start()
        except BaseException:
            self.stop_workers()
            raise

    def check(self):
        if self.failed.is_set() or not self.pipes or self.pipes[0].handle is None:
            raise MemoryError("pipe_runtime_failed", "The local pipe runtime failed closed.")
        self.pipes[0].api.require_process_context()
        self.pipes[0].api._private_acl(self.pipes[0].handle)

    def stop_workers(self):
        self.stopping.set()
        deadline = time.monotonic() + SHUTDOWN_TIMEOUT
        for worker in self.workers:
            if worker.thread.ident is not None:
                worker.thread.join(max(0, deadline - time.monotonic()))
        if any(worker.thread.is_alive() for worker in self.workers):
            # Never close a pipe handle or free buffers beneath uncertain native
            # IO. This shares the transport's exceptional cancellation fail-stop.
            os._exit(FATAL_CANCEL_EXIT)
        while True:
            try:
                self.incoming.get_nowait().cancel()
            except queue.Empty:
                break

    def close(self):
        self.stop_workers()
        with ExitStack() as cleanup:
            # LIFO leaves the first-instance ownership handle until last.
            for pipe in self.pipes:
                cleanup.callback(pipe.close)
        self.pipes.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class WindowsMemoryServer:
    def __init__(self, pool, handler):
        self.pool, self.handler = pool, handler
        self.owner_thread = threading.get_ident()

    def serve_forever(self, poll_interval=0.05, ownership_check=lambda: None, stop_requested=lambda: False):
        if threading.get_ident() != self.owner_thread:
            raise MemoryError("pipe_runtime_invalid", "Application dispatch requires its owning thread.")
        self.pool.start()
        while not stop_requested():
            self.pool.check()
            ownership_check()
            try:
                request = self.pool.incoming.get(timeout=poll_interval)
            except queue.Empty:
                continue
            if request.claim():
                request.complete(self.handler(request.raw))

    def server_close(self):
        self.pool.stop_workers()


def exchange(binding, payload):
    """Peer-verified one-request exchange; a drain ACK cannot revoke a reply."""
    with connect(binding, timeout=CLIENT_TIMEOUT) as connection:
        connection.send(payload)
        response = connection.receive()
        try:
            connection.send(DRAIN_ACK)
        except (MemoryError, OSError):
            # We have already obtained the complete bounded response. The caller
            # still validates JSON/envelope semantics; ACK is only drainage.
            pass
        return response
