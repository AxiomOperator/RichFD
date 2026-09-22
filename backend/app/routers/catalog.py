from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import audit
from ..auth import Session, require_user
from ..fw import Config, Target, firewall

router = APIRouter(prefix="/api", tags=["catalog"])


@router.get("/services")
def services(session: Session = Depends(require_user)):
    return firewall.services()


@router.get("/icmptypes")
def icmp_types(session: Session = Depends(require_user)):
    return firewall.icmp_types()


@router.get("/ipsets")
def ipsets(session: Session = Depends(require_user)):
    return {cfg: firewall.ipsets(cfg) for cfg in ("runtime", "permanent")}


class CreateIPSet(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,31}$")
    type: Literal[
        "hash:ip", "hash:ip,port", "hash:ip,port,ip", "hash:ip,port,net", "hash:ip,mark",
        "hash:net", "hash:net,net", "hash:net,port", "hash:net,port,net", "hash:net,iface",
        "hash:mac",
    ] = "hash:ip"
    family: Literal["", "inet", "inet6"] = ""
    description: str = ""


@router.post("/ipsets")
def create_ipset(body: CreateIPSet, session: Session = Depends(require_user)):
    firewall.create_ipset(body.name, body.type, body.family, body.description)
    audit.record(session.user, "create ipset", body.model_dump())
    return {"ok": True, "note": "IP set created in permanent config; reload to activate it."}


@router.delete("/ipsets/{name}")
def delete_ipset(name: str, session: Session = Depends(require_user)):
    firewall.delete_ipset(name)
    audit.record(session.user, "delete ipset", {"name": name})
    return {"ok": True}


class IPSetEntry(BaseModel):
    action: Literal["add", "remove"]
    entry: str
    target: Target = "both"


@router.post("/ipsets/{name}/entries")
def ipset_entry(name: str, body: IPSetEntry, session: Session = Depends(require_user)):
    firewall.ipset_entry(name, body.entry, body.action, body.target)
    audit.record(session.user, f"ipset {body.action} entry", {"name": name, **body.model_dump()})
    return {"ok": True}
