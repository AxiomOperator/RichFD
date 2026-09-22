"""Lockout protection: apply runtime changes that auto-revert unless confirmed.

Only one pending change set exists at a time. If the browser that made a change
cannot reach the server to confirm it (because the change cut off access), the
timer fires and the change is undone.
"""

import threading
import time
import uuid
from dataclasses import dataclass, field

from . import audit
from .fw import Applied, FwError, Op, firewall
from .history import history


@dataclass
class Pending:
    id: str
    user: str
    ops: list[Op]
    applied: list[Applied]
    persist: bool
    deadline: float
    timer: threading.Timer = field(repr=False)

    def view(self) -> dict:
        return {
            "id": self.id,
            "user": self.user,
            "ops": [op.model_dump() for op in self.ops],
            "persist": self.persist,
            "seconds_left": max(0, round(self.deadline - time.time())),
        }


_lock = threading.Lock()
_pending: Pending | None = None


def current() -> Pending | None:
    return _pending


def begin(ops: list[Op], user: str, seconds: int, persist: bool) -> Pending:
    """Apply ``ops`` to runtime and arm the revert timer."""
    global _pending
    with _lock:
        if _pending is not None:
            raise FwError("Another safe-apply change is awaiting confirmation", 409)
        applied = firewall.apply(ops, "runtime")
        pid = uuid.uuid4().hex
        timer = threading.Timer(seconds, _expire, args=(pid,))
        timer.daemon = True
        _pending = Pending(pid, user, ops, applied, persist, time.time() + seconds, timer)
        timer.start()
        return _pending


def _take(pid: str) -> Pending:
    global _pending
    if _pending is None or _pending.id != pid:
        raise FwError("No such pending change (it may already have been reverted)", 404)
    p, _pending = _pending, None
    p.timer.cancel()
    return p


def confirm(pid: str, user: str) -> Pending:
    """Keep the runtime change; also write it to permanent config if requested."""
    with _lock:
        p = _take(pid)
    with history.change(user, "safe-apply confirm: " + "; ".join(o.describe() for o in p.ops[:3])):
        if p.persist:
            firewall.apply(p.ops, "permanent")
    audit.record(user, "safe-apply confirm", {"ops": [o.describe() for o in p.ops], "persist": p.persist})
    return p


def revert(pid: str, user: str, reason: str = "manual") -> list[str]:
    with _lock:
        p = _take(pid)
    with history.change(user, f"safe-apply revert ({reason})"):
        errors = firewall.undo(p.applied)
    audit.record(user, f"safe-apply revert ({reason})", {"ops": [o.describe() for o in p.ops], "errors": errors})
    return errors


def _expire(pid: str) -> None:
    try:
        revert(pid, "system", "timeout")
    except FwError:
        pass
