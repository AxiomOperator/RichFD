from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import audit, safe_apply
from ..auth import Session, require_user
from ..config import settings
from ..fw import FwError, Op, Target, firewall

router = APIRouter(prefix="/api", tags=["changes"])


class OpsRequest(BaseModel):
    ops: list[Op] = Field(min_length=1)
    target: Target = "both"
    # Runtime-only: firewalld removes the added items after this many seconds.
    timeout: int = Field(0, ge=0)


@router.post("/ops")
def apply_ops(body: OpsRequest, session: Session = Depends(require_user)):
    """Apply a batch of changes atomically (all or nothing)."""
    if body.timeout and body.target != "runtime":
        raise FwError("timeout is only valid with target 'runtime'")
    detail = {"ops": [o.describe() for o in body.ops], "target": body.target, "timeout": body.timeout}
    try:
        firewall.apply(body.ops, body.target, body.timeout)
    except FwError as e:
        audit.record(session.user, "change", {**detail, "error": e.message}, ok=False)
        raise
    audit.record(session.user, "change", detail)
    return {"ok": True}


class SafeApplyRequest(BaseModel):
    ops: list[Op] = Field(min_length=1)
    # Write the change to permanent config as well once confirmed.
    persist: bool = True


@router.get("/safe-apply")
def safe_apply_status(session: Session = Depends(require_user)):
    p = safe_apply.current()
    return p.view() if p else None


@router.post("/safe-apply")
def safe_apply_begin(body: SafeApplyRequest, session: Session = Depends(require_user)):
    p = safe_apply.begin(body.ops, session.user, settings.safe_apply_seconds, body.persist)
    audit.record(session.user, "safe-apply begin", {"ops": [o.describe() for o in body.ops]})
    return p.view()


@router.post("/safe-apply/{pid}/confirm")
def safe_apply_confirm(pid: str, session: Session = Depends(require_user)):
    safe_apply.confirm(pid, session.user)
    return {"ok": True}


@router.post("/safe-apply/{pid}/revert")
def safe_apply_revert(pid: str, session: Session = Depends(require_user)):
    errors = safe_apply.revert(pid, session.user)
    return {"ok": not errors, "errors": errors}
