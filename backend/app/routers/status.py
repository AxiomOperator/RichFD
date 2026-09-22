from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..auth import Session, require_user
from ..changes import changing
from ..fw import firewall

router = APIRouter(prefix="/api", tags=["status"])


@router.get("/status")
def status(session: Session = Depends(require_user)):
    return firewall.status()


class ReloadRequest(BaseModel):
    complete: bool = False


@router.post("/reload")
def reload(body: ReloadRequest, session: Session = Depends(require_user)):
    with changing(session, "complete-reload" if body.complete else "reload"):
        firewall.reload(body.complete)
    return {"ok": True}


@router.post("/runtime-to-permanent")
def runtime_to_permanent(session: Session = Depends(require_user)):
    with changing(session, "runtime-to-permanent"):
        firewall.runtime_to_permanent()
    return {"ok": True}


class PanicRequest(BaseModel):
    enabled: bool


@router.post("/panic")
def panic(body: PanicRequest, session: Session = Depends(require_user)):
    with changing(session, "panic on" if body.enabled else "panic off"):
        firewall.set_panic(body.enabled)
    return {"ok": True}


class LogDeniedRequest(BaseModel):
    value: Literal["all", "unicast", "broadcast", "multicast", "off"]


@router.post("/log-denied")
def log_denied(body: LogDeniedRequest, session: Session = Depends(require_user)):
    with changing(session, "set log-denied", {"value": body.value}):
        firewall.set_log_denied(body.value)
    return {"ok": True}


class DefaultZoneRequest(BaseModel):
    zone: str


@router.post("/default-zone")
def default_zone(body: DefaultZoneRequest, session: Session = Depends(require_user)):
    with changing(session, "set default zone", {"zone": body.zone}):
        firewall.set_default_zone(body.zone)
    return {"ok": True}


@router.get("/direct")
def direct(session: Session = Depends(require_user)):
    """Direct rules, chains and passthroughs (deprecated firewalld feature; read-only)."""
    return firewall.direct()
