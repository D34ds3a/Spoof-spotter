import copy
import time


class SafeBrowsingCache:

    def __init__(self, clock=None):
        if clock is None:
            clock = time.monotonic

        self._clock = clock
        self._entries = {}

    def get(self, prefix_b64):
        entry = self._entries.get(prefix_b64)

        if entry is None:
            return None

        if self._clock() >= entry["expires_at"]:
            del self._entries[prefix_b64]
            return None

        return copy.deepcopy(entry["full_hashes"])

    def set(
        self,
        prefix_b64,
        full_hashes,
        duration_seconds,
    ):
        if duration_seconds <= 0:
            return

        self._entries[prefix_b64] = {
            "expires_at": (
                self._clock()
                + duration_seconds
            ),
            "full_hashes": (
                copy.deepcopy(
                    full_hashes
                )
            ),
        }

    def clear(self):
        self._entries.clear()