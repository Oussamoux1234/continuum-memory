"""Bounded, process-local continuation state; tokens convey no read authority."""

from collections import OrderedDict
import time

from .errors import MemoryError
from .security import random_id


MAX_CURSORS = 256
CURSOR_TTL_SECONDS = 600
MAX_CURSOR_BYTES = 64


class Cursors:
    """Only opaque bindings, one keyset tuple and a snapshot are retained.

    No query, body, evidence or unbounded result-ID list is cached. Restart,
    expiry and capacity eviction all invalidate tokens with the same error.
    """

    def __init__(self):
        self.entries = OrderedDict()

    def _prune(self):
        now = time.monotonic()
        for token, state in list(self.entries.items()):
            if state["expires"] <= now:
                del self.entries[token]

    def read(self, token, binding):
        self._prune()
        state = self.entries.get(token) if isinstance(token, str) and len(token) <= MAX_CURSOR_BYTES else None
        if state is None or state["binding"] != binding:
            raise MemoryError("invalid_cursor", "The continuation is unavailable; restart the query.")
        return state

    def issue(self, binding, recorded, after):
        self._prune()
        while len(self.entries) >= MAX_CURSORS:
            self.entries.popitem(last=False)
        token = random_id("cur")
        self.entries[token] = {"binding": binding, "recorded": recorded, "after": after,
                               "expires": time.monotonic() + CURSOR_TTL_SECONDS}
        return token
