from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import audit
from ..auth import Session, require_user
from ..fw import firewall

router = APIRouter(prefix="/api", tags=["status"])


@router.get("/status")
def status(session: Session = Depends(require_user)):
    return firewall.status()


class ReloadRequest(BaseModel):
    complete: bool = False


@router.post("/reload")
def reload(body: ReloadRequest, session: Session = Depends(require_user)):
    firewall.reload(body.complete)
    audit.record(session.user, "complete-reload" if body.complete else "reload")
    return {"ok": True}


@router.post("/runtime-to-permanent")
def runtime_to_permanent(session: Session = Depends(require_user)):
    firewall.runtime_to_permanent()
    audit.record(session.user, "runtime-to-permanent")
    return {"ok": True}


class PanicRequest(BaseModel):
    enabled: bool


@router.post("/panic")
def panic(body: PanicRequest, session: Session = Depends(require_user)):
    firewall.set_panic(body.enabled)
    audit.record(session.user, "panic on" if body.enabled else "panic off")
    return {"ok": True}


class LogDeniedRequest(BaseModel):
    value: Literal["all", "unicast", "broadcast", "multicast", "off"]


@router.post("/log-denied")
def log_denied(body: LogDeniedRequest, session: Session = Depends(require_user)):
    firewall.set_log_denied(body.value)
    audit.record(session.user, "set log-denied", {"value": body.value})
    return {"ok": True}


class DefaultZoneRequest(BaseModel):
    zone: str


@router.post("/default-zone")
def default_zone(body: DefaultZoneRequest, session: Session = Depends(require_user)):
    firewall.set_default_zone(body.zone)
    audit.record(session.user, "set default zone", {"zone": body.zone})
    return {"ok": True}
