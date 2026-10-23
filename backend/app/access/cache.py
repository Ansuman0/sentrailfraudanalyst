"""Permission-set cache, correct by construction (I10).

The key is (user_id, session_version, role_id). Every action that can change what a user may do (role change, membership change,
suspension, role permission edit, template or catalogue sync) bumps users.session_version, and rbac reads the current session_version from
the database on every request, so a stale entry can never be returned: after a bump the key simply no longer matches.
Entries age out after MAX_AGE_SECONDS and the cache is bounded, only to keep memory flat.
"""
import time
from collections import OrderedDict
from threading import Lock

MAX_ENTRIES = 2048
MAX_AGE_SECONDS = 300

_lock = Lock()
_entries: "OrderedDict[tuple, tuple[float, object]]" = OrderedDict()
stats = {"hits": 0, "misses": 0}


def get_or_load(key: tuple, loader):
    now = time.monotonic()
    with _lock:
        hit = _entries.get(key)
        if hit and now - hit[0] < MAX_AGE_SECONDS:
            _entries.move_to_end(key)
            stats["hits"] += 1
            return hit[1]
        stats["misses"] += 1
    value = loader()
    with _lock:
        _entries[key] = (now, value)
        _entries.move_to_end(key)
        while len(_entries) > MAX_ENTRIES:
            _entries.popitem(last=False)
    return value


def clear():
    with _lock:
        _entries.clear()
