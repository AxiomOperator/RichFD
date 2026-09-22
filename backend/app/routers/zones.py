from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import audit
from ..auth import Session, require_user
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
    firewall.create_zone(body.name, body.target, body.short, body.description)
    audit.record(session.user, "create zone", body.model_dump())
    return {"ok": True, "note": "Zone created in permanent config; reload to activate it."}


class UpdateZone(BaseModel):
    target: ZoneTarget | None = None
    short: str | None = None
    description: str | None = None


@router.patch("/{zone}")
def update_zone(zone: str, body: UpdateZone, session: Session = Depends(require_user)):
    fields = body.model_dump(exclude_none=True)
    firewall.update_zone(zone, fields)
    audit.record(session.user, "update zone", {"zone": zone, **fields})
    return {"ok": True}


@router.post("/{zone}/reset")
def reset_zone(zone: str, session: Session = Depends(require_user)):
    firewall.reset_zone(zone)
    audit.record(session.user, "reset zone to defaults", {"zone": zone})
    return {"ok": True, "note": "Zone reset in permanent config; reload to apply."}


@router.delete("/{zone}")
def delete_zone(zone: str, session: Session = Depends(require_user)):
    firewall.delete_zone(zone)
    audit.record(session.user, "delete zone", {"zone": zone})
    return {"ok": True, "note": "Zone removed from permanent config; reload to apply."}
