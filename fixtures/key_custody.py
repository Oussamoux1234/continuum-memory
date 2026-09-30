"""Real filesystem crash barriers, not native encryption or owner approval."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import signal
import sys
from unittest.mock import patch

from continuum_memory import storage_key_custody as custody


CRASH_EXIT = 73
OLD_KEY = b"o" * 32
NEW_KEY = b"n" * 32
JOURNAL = b'{"synthetic":"filesystem-only"}\n'


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


@contextmanager
def custody_fault(boundary, *, crash=False, kill=False, cleanup=False):
    """Intercept real syscalls only during the scoped custody helper call."""
    sync, replace, unlink = os.fsync, os.replace, os.unlink
    sync_count = 0
    fired = []

    def trigger(name):
        if name != boundary or fired:
            return
        fired.append(name)
        if kill:
            os.kill(os.getpid(), signal.SIGKILL)
        if crash:
            os._exit(CRASH_EXIT)
        raise OSError("Synthetic key-custody boundary failure")

    def synced(descriptor):
        nonlocal sync_count
        sync_count += 1
        if cleanup:
            name = "custody:cleanup_dir_fsync"
        else:
            name = {1: "custody:next_fsync", 2: "custody:pre_rename_dir_fsync",
                    3: "custody:post_rename_dir_fsync"}.get(sync_count, "custody:extra_fsync")
        trigger(name + ":before")
        result = sync(descriptor)
        trigger(name + ":after")
        return result

    def replaced(*args, **kwargs):
        trigger("custody:rename:before")
        result = replace(*args, **kwargs)
        trigger("custody:rename:after")
        return result

    def removed(*args, **kwargs):
        trigger("custody:unlink:before")
        result = unlink(*args, **kwargs)
        trigger("custody:unlink:after")
        return result

    with patch.object(custody.os, "fsync", side_effect=synced), \
            patch.object(custody.os, "replace", side_effect=replaced), \
            patch.object(custody.os, "unlink", side_effect=removed):
        yield fired


def main():
    operation, directory, boundary, death = sys.argv[1:]
    directory = Path(directory)
    with custody_fault(boundary, crash=True, kill=death == "kill", cleanup=operation != "promote"):
        if operation == "promote":
            custody.promote_prepared_key(directory, digest(OLD_KEY), digest(NEW_KEY))
        elif operation == "remove-next":
            custody.remove_verified_rotation_material(directory, "storage.key.next", digest(NEW_KEY))
        elif operation == "remove-journal":
            custody.remove_verified_rotation_material(directory, "storage.rotation.json", digest(JOURNAL))
        else:
            raise ValueError("Unknown fixture operation")


if __name__ == "__main__":
    main()
