"""Common wrapper for every change made through the API: history snapshot + audit record."""

from contextlib import contextmanager

from . import audit
from .auth import Session
from .fw import FwError
from .history import history


def _label(action: str, detail: dict) -> str:
    bits = []
    if ops := detail.get("ops"):
        bits.append("; ".join(ops[:3]) + (f" (+{len(ops) - 3} more)" if len(ops) > 3 else ""))
    for k in ("zone", "policy", "name", "service", "value", "target"):
        if k in detail and not isinstance(detail[k], (list, dict)):
            bits.append(f"{k}={detail[k]}")
    return f"{action}: {', '.join(bits)}" if bits else action


@contextmanager
def changing(session: Session, action: str, detail: dict | None = None):
    """Snapshot config around the change and audit it (failures are audited too).

    The yielded dict can be extended by the caller with result details.
    """
    detail = dict(detail or {})
    try:
        with history.change(session.user, _label(action, detail)):
            yield detail
    except FwError as e:
        audit.record(session.user, action, {**detail, "error": e.message}, ok=False)
        raise
    audit.record(session.user, action, detail)
