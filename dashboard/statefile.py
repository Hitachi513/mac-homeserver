"""Crash-safe JSON state files: atomic writes, one `.bak` of the last readable copy, and recovery from it.

save() writes a `.tmp`, fsyncs it, moves the previous readable file to `<name>.bak`, then replaces the
real file. At every moment at least one complete copy exists, so a reader never gets a half-written or
empty file. load() falls back to `.bak` when the real file is missing or unusable; when neither can be
read it returns the default and marks the path "degraded", so callers can refuse to act on a list that
may have been silently emptied. Callbacks fire once per state change, not on every load.
"""
import json
import os
import threading

_MISSING = object()
_guard = threading.Lock()
_locks = {}
_status = {}  # path -> "main" | "bak" | "degraded" | "empty"


def _lock(path):
    with _guard:
        lk = _locks.get(path)
        if lk is None:
            lk = _locks[path] = threading.RLock()
        return lk


def _read(path):
    """(data, None) or (_MISSING, "missing"|"bad"). `bad` covers empty, truncated and non-JSON files."""
    try:
        with open(path) as f:
            raw = f.read()
    except OSError:
        return _MISSING, "missing"
    if not raw.strip():
        return _MISSING, "bad"
    try:
        return json.loads(raw), None
    except ValueError:
        return _MISSING, "bad"


def save(path, obj, indent=None):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    with _lock(path):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f, ensure_ascii=False, indent=indent)
                f.flush()
                os.fsync(f.fileno())
            old, _ = _read(path)  # only keep a backup we know is readable
            if old is not _MISSING and os.path.exists(path):
                try:
                    os.replace(path, path + ".bak")
                except OSError:
                    pass
            os.replace(tmp, path)
            try:  # make the rename durable as well
                dfd = os.open(d, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass


def load(path, default=None, validate=None, on_recover=None, on_degraded=None):
    """Return the parsed state; fall back to `.bak`, then to `default`.

    on_recover: called once when a load starts using the backup.
    on_degraded: called once when neither the file nor the backup is usable.
    """
    with _lock(path):
        prev = _status.get(path)
        data, why = _read(path)
        if data is not _MISSING and validate is not None and not validate(data):
            data, why = _MISSING, "bad"
        if data is not _MISSING:
            _status[path] = "main"
            return data
        backup, _ = _read(path + ".bak")
        if backup is not _MISSING and validate is not None and not validate(backup):
            backup = _MISSING
        if backup is not _MISSING:
            _status[path] = "bak"
            if prev != "bak" and on_recover:
                on_recover()
            return backup
        # Both copies are unusable. A missing file on a fresh install is normal; a file that was
        # there and is now gone (or unreadable) is not, so it counts as degraded too.
        if why == "bad" or prev in ("main", "bak"):
            _status[path] = "degraded"
            if prev != "degraded" and on_degraded:
                on_degraded()
        else:
            _status[path] = "empty"
        return default


def degraded(path):
    """True while the last load could read neither the file nor its backup."""
    with _guard:
        return _status.get(path) == "degraded"
