from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from .. import risk, safe_apply
from ..auth import Session, require_user
from ..changes import changing
from ..config import settings
from ..fw import KINDS, FwError, Op, Target, firewall
from ..history import history

router = APIRouter(prefix="/api", tags=["changes"])


class OpsRequest(BaseModel):
    ops: list[Op] = Field(min_length=1)
    target: Target = "both"
    # Runtime-only: firewalld removes the added items after this many seconds.
    timeout: int = Field(0, ge=0)


_SETTINGS_KEY = {"service": "services", "port": "ports", "protocol": "protocols", "source-port": "source_ports",
                 "forward-port": "forward_ports", "icmp-block": "icmp_blocks", "rich-rule": "rules_str"}


@router.post("/ops")
def apply_ops(body: OpsRequest, session: Session = Depends(require_user)):
    """Apply a batch of changes atomically (all or nothing)."""
    if body.timeout and body.target != "runtime":
        raise FwError("timeout is only valid with target 'runtime'")
    detail = {"ops": [o.describe() for o in body.ops], "target": body.target}
    if body.timeout:
        detail["timeout"] = body.timeout
    with changing(session, "change", detail):
        firewall.apply(body.ops, body.target, body.timeout)
        if body.timeout:
            # Expiry of timed items is expected; don't report it as an external change.
            for o in body.ops:
                if o.action == "add" and o.kind in _SETTINGS_KEY:
                    _, fields, _ = KINDS[o.kind]
                    vals = [str(o.value.get(f, "")) for f in fields]
                    if o.kind == "rich-rule":
                        from ..richrule import normalize

                        vals = [normalize(vals[0])]
                    history.expect_expiry(o.zone, o.scope, _SETTINGS_KEY[o.kind],
                                          vals[0] if len(vals) == 1 else vals, body.timeout)
    return {"ok": True}


class RiskRequest(BaseModel):
    ops: list[Op] = []
    target: Target = "both"
    zone_target: dict | None = None  # {"zone": ..., "target": ...} for a proposed target change


@router.post("/risk")
def analyze_risk(body: RiskRequest, request: Request, session: Session = Depends(require_user)):
    """Check a proposed change for lock-out risks before applying it."""
    client = request.client.host if request.client else None
    return risk.analyze(body.ops, body.target, client, body.zone_target)


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
    with changing(session, "safe-apply begin", {"ops": [o.describe() for o in body.ops]}):
        p = safe_apply.begin(body.ops, session.user, settings.safe_apply_seconds, body.persist)
    return p.view()


@router.post("/safe-apply/{pid}/confirm")
def safe_apply_confirm(pid: str, session: Session = Depends(require_user)):
    safe_apply.confirm(pid, session.user)
    return {"ok": True}


@router.post("/safe-apply/{pid}/revert")
def safe_apply_revert(pid: str, session: Session = Depends(require_user)):
    errors = safe_apply.revert(pid, session.user)
    return {"ok": not errors, "errors": errors}
