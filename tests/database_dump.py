"""Read-only logical SQL snapshots of an already-open fixture connection.

The sqlcipher3 DB-API connection lacks CPython's iterdump convenience method.
Reuse its Python serializer on the same SQLCipher connection: this never opens
a stdlib SQLite connection or provides a plaintext fallback. This private stdlib
helper is tested on every supported CPython ABI; dump text is never executed.
"""

from sqlite3.dump import _iterdump


def database_dump(connection):
    return _iterdump(connection)
