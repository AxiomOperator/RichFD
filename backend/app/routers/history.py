from fastapi import APIRouter, Depends, Query

from .. import audit
from ..auth import Session, require_user
from ..history import history

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def log(limit: int = Query(200, ge=1, le=2000), session: Session = Depends(require_user)):
    status = history.status()
    return {**status, "entries": history.log(limit) if status["enabled"] else []}


@router.post("/check")
def check_now(session: Session = Depends(require_user)):
    """Look for changes made outside richrule right now."""
    return {"found": history.check_external()}


@router.get("/{commit}")
def show(commit: str, session: Session = Depends(require_user)):
    return history.show(commit)


@router.get("/{commit}/compare")
def compare(commit: str, session: Session = Depends(require_user)):
    """Diff showing what restoring this snapshot would change."""
    return history.diff_to_current(commit)


@router.post("/{commit}/restore")
def restore(commit: str, session: Session = Depends(require_user)):
    try:
        history.restore(commit, session.user)
    except Exception as e:
        audit.record(session.user, "restore snapshot", {"commit": commit[:12], "error": str(e)}, ok=False)
        raise
    audit.record(session.user, "restore snapshot", {"commit": commit[:12]})
    return {"ok": True}
