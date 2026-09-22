from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..auth import Session, require_user
from ..changes import changing
from ..fw import FwError, firewall

router = APIRouter(prefix="/api/policies", tags=["policies"])

PolicyTarget = Literal["CONTINUE", "ACCEPT", "DROP", "REJECT"]


@router.get("")
def list_policies(session: Session = Depends(require_user)):
    return firewall.policies_overview()


@router.get("/{name}")
def get_policy(name: str, session: Session = Depends(require_user)):
    views = {}
    for cfg in ("runtime", "permanent"):
        try:
            views[cfg] = firewall.policy(name, cfg)
        except FwError as e:
            if "INVALID_POLICY" not in e.message:
                raise
            views[cfg] = None
    if views["runtime"] is None and views["permanent"] is None:
        raise FwError(f"Policy '{name}' does not exist", 404)
    return {"name": name, **views}


class CreatePolicy(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_+-]{1,17}$")
    ingress_zones: list[str] = Field(min_length=1)
    egress_zones: list[str] = Field(min_length=1)
    target: PolicyTarget = "CONTINUE"
    priority: int = Field(-1, ge=-32768, le=32767)
    short: str = ""
    description: str = ""


@router.post("")
def create_policy(body: CreatePolicy, session: Session = Depends(require_user)):
    if body.priority == 0:
        raise FwError("Policy priority cannot be 0")
    with changing(session, "create policy", {"policy": body.name, "ingress": body.ingress_zones,
                                             "egress": body.egress_zones}):
        firewall.create_policy(body.name, body.model_dump())
    return {"ok": True, "note": "Policy created in permanent config; reload to activate it."}


class UpdatePolicy(BaseModel):
    target: PolicyTarget | None = None
    priority: int | None = Field(None, ge=-32768, le=32767)
    short: str | None = None
    description: str | None = None
    disable: bool | None = None


@router.patch("/{name}")
def update_policy(name: str, body: UpdatePolicy, session: Session = Depends(require_user)):
    fields = body.model_dump(exclude_none=True)
    if fields.get("priority") == 0:
        raise FwError("Policy priority cannot be 0")
    with changing(session, "update policy", {"policy": name, **fields}):
        firewall.update_policy(name, fields)
    return {"ok": True, "note": "Saved to permanent config; reload to apply."}


@router.delete("/{name}")
def delete_policy(name: str, session: Session = Depends(require_user)):
    with changing(session, "delete policy", {"policy": name}):
        firewall.delete_policy(name)
    return {"ok": True, "note": "Removed from permanent config (built-in policies are reset); reload to apply."}
