"""Guard the plaintext SQLite runtime on native Windows; no encryption claim.

The vault and database are pinned against replacement until SQLite closes. Each
operation revalidates their ACLs and all present sidecars before SQLite can use
them. A hostile process running as this same user or administrator is outside
this boundary: it can change ACLs or bytes, and needs OS key custody separately.
"""

import os
import sqlite3
from contextlib import ExitStack
from pathlib import Path

from .windows_boundary import WindowsBoundary


class VaultGuard:
    def __init__(self, path):
        self.path = Path(path)
        self.boundary = WindowsBoundary()
        self.stack = ExitStack()
        try:
            self.directory = self.stack.enter_context(self.boundary.open_private(self.path.parent, directory=True))
            self.database = self.stack.enter_context(self.boundary.open_private(self.path))
            self.validate()
        except BaseException:
            self.stack.close()
            raise

    def validate(self):
        self.boundary._info(self.directory, True)
        self.boundary._private_acl(self.directory, directory=True)
        self.boundary._info(self.database, False)
        self.boundary._private_acl(self.database, inherited=True)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.path) + suffix)
            if os.path.lexists(sidecar):
                self.boundary.inspect(sidecar)

    def close(self):
        self.stack.close()


class GuardedConnection(sqlite3.Connection):
    """Main-thread connection; guard is attached before the first SQL statement."""
    guard = None

    def _validate(self):
        if self.guard is not None:
            self.guard.validate()

    def execute(self, *args, **kwargs):
        return self.cursor().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self.cursor().executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self.cursor().executescript(*args, **kwargs)

    def cursor(self, factory=None):
        if factory not in (None, GuardedCursor):
            raise ValueError("The Windows connection requires guarded cursors.")
        return super().cursor(factory=GuardedCursor)

    def commit(self):
        self._validate()
        return super().commit()

    def rollback(self):
        self._validate()
        return super().rollback()

    def close(self):
        try:
            super().close()
        finally:
            if self.guard is not None:
                guard, self.guard = self.guard, None
                guard.close()


class GuardedCursor(sqlite3.Cursor):
    def execute(self, *args, **kwargs):
        self.connection._validate()
        return super().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        self.connection._validate()
        return super().executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        self.connection._validate()
        return super().executescript(*args, **kwargs)


def connect(path):
    guard = VaultGuard(path)
    try:
        connection = sqlite3.connect(str(path), timeout=5.0, isolation_level=None, factory=GuardedConnection)
    except BaseException:
        guard.close()
        raise
    connection.guard = guard
    return connection
