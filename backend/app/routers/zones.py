from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..auth import Session, require_user
from ..changes import changing
from ..fw import FwError, firewall

router = APIRouter(prefix="/api/zones", tags=["zones"])

ZoneTarget = Literal["default", "ACCEPT", "DROP", "%%REJECT%%"]


@router.get("")
def list_zones(session: Session = Depends(require_user)):
    return firewall.zones_overview()


@router.get("/{zone}")
def get_zone(zone: str, session: Session = Depends(require_user)):
    """Both runtime and permanent views; either is null if the zone only exists in the other."""
    views = {}
    for cfg in ("runtime", "permanent"):
        try:
            views[cfg] = firewall.zone(zone, cfg)
        except FwError as e:
            if "INVALID_ZONE" not in e.message:
                raise
            views[cfg] = None
    if views["runtime"] is None and views["permanent"] is None:
        raise FwError(f"Zone '{zone}' does not exist", 404)
    return {"name": zone, **views}


class CreateZone(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_+-]{1,17}$")
    target: ZoneTarget = "default"
    short: str = ""
    description: str = ""


@router.post("")
def create_zone(body: CreateZone, session: Session = Depends(require_user)):
    with changing(session, "create zone", {"zone": body.name, "target": body.target}):
        firewall.create_zone(body.name, body.target, body.short, body.description)
    return {"ok": True, "note": "Zone created in permanent config; reload to activate it."}


class UpdateZone(BaseModel):
    target: ZoneTarget | None = None
    short: str | None = None
    description: str | None = None


@router.patch("/{zone}")
def update_zone(zone: str, body: UpdateZone, session: Session = Depends(require_user)):
    fields = body.model_dump(exclude_none=True)
    with changing(session, "update zone", {"zone": zone, **fields}):
        firewall.update_zone(zone, fields)
    return {"ok": True}


@router.post("/{zone}/reset")
def reset_zone(zone: str, session: Session = Depends(require_user)):
    with changing(session, "reset zone to defaults", {"zone": zone}):
        firewall.reset_zone(zone)
    return {"ok": True, "note": "Zone reset in permanent config; reload to apply."}


@router.delete("/{zone}")
def delete_zone(zone: str, session: Session = Depends(require_user)):
    with changing(session, "delete zone", {"zone": zone}):
        firewall.delete_zone(zone)
    return {"ok": True, "note": "Zone removed from permanent config; reload to apply."}
