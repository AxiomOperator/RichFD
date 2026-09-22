"""Append-only JSON-lines audit log of every change."""

import json
import logging
import threading
import time
from collections import deque

from .config import settings

_log = logging.getLogger("richrule.audit")
_lock = threading.Lock()
# Recent entries kept in memory in case the log file is not writable (dev runs).
_recent: deque[dict] = deque(maxlen=1000)


def record(user: str, action: str, detail: dict | None = None, ok: bool = True) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": user,
        "action": action,
        "ok": ok,
        "detail": detail or {},
    }
    with _lock:
        _recent.append(entry)
        try:
            settings.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with settings.audit_log.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            _log.warning("cannot write audit log %s: %s", settings.audit_log, e)
    from . import notify

    notify.dispatch(entry)


def tail(limit: int = 200) -> list[dict]:
    """Most recent entries, newest first."""
    try:
        with settings.audit_log.open() as f:
            lines = deque(f, maxlen=limit)
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        entries = list(_recent)[-limit:]
    return entries[::-1]
