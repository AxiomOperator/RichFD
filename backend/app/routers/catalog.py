from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..auth import Session, require_user
from ..changes import changing
from ..fw import FwError, Target, firewall
from ..transfer import parse_address_list

router = APIRouter(prefix="/api", tags=["catalog"])


@router.get("/services")
def services(session: Session = Depends(require_user)):
    return firewall.services()


class PortSpec(BaseModel):
    port: str = Field(pattern=r"^\d{1,5}(-\d{1,5})?$")
    protocol: Literal["tcp", "udp", "sctp", "dccp"]


class ServiceSpec(BaseModel):
    short: str = ""
    description: str = ""
    ports: list[PortSpec] = []
    protocols: list[str] = []
    source_ports: list[PortSpec] = []
    modules: list[str] = []
    helpers: list[str] = []
    includes: list[str] = []
    destination: dict[Literal["ipv4", "ipv6"], str] = {}


class CreateService(ServiceSpec):
    name: str = Field(pattern=r"^[A-Za-z0-9_.+-]{1,64}$")


def _spec(body: ServiceSpec) -> dict:
    d = body.model_dump()
    if not (d["ports"] or d["protocols"] or d["source_ports"] or d["includes"] or d["helpers"] or d["modules"]):
        raise FwError("A service needs at least one port, protocol, source port, helper or include")
    return d


@router.post("/services")
def create_service(body: CreateService, session: Session = Depends(require_user)):
    spec = _spec(body)
    with changing(session, "create service", {"service": body.name}):
        firewall.create_service(body.name, spec)
    return {"ok": True, "note": "Service created in permanent config; reload to use it at runtime."}


@router.put("/services/{name}")
def update_service(name: str, body: ServiceSpec, session: Session = Depends(require_user)):
    spec = _spec(body)
    with changing(session, "update service", {"service": name}):
        firewall.update_service(name, spec)
    return {"ok": True, "note": "Saved to permanent config; reload to apply."}


@router.delete("/services/{name}")
def delete_service(name: str, session: Session = Depends(require_user)):
    with changing(session, "delete service", {"service": name}):
        firewall.delete_service(name)
    return {"ok": True, "note": "Removed (built-in services are reset to defaults); reload to apply."}


@router.get("/helpers")
def helpers(session: Session = Depends(require_user)):
    return firewall.helpers()


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
    with changing(session, "create ipset", {"name": body.name, "type": body.type}):
        firewall.create_ipset(body.name, body.type, body.family, body.description)
    return {"ok": True, "note": "IP set created in permanent config; reload to activate it."}


@router.delete("/ipsets/{name}")
def delete_ipset(name: str, session: Session = Depends(require_user)):
    with changing(session, "delete ipset", {"name": name}):
        firewall.delete_ipset(name)
    return {"ok": True}


class IPSetEntry(BaseModel):
    action: Literal["add", "remove"]
    entry: str
    target: Target = "both"


@router.post("/ipsets/{name}/entries")
def ipset_entry(name: str, body: IPSetEntry, session: Session = Depends(require_user)):
    with changing(session, f"ipset {body.action} entry", {"name": name, "value": body.entry, "target": body.target}):
        firewall.ipset_entry(name, body.entry, body.action, body.target)
    return {"ok": True}


class IPSetImport(BaseModel):
    text: str
    target: Target = "both"


@router.post("/ipsets/{name}/import")
def ipset_import(name: str, body: IPSetImport, session: Session = Depends(require_user)):
    """Bulk-add addresses/networks from a text list (one per line; '#' comments allowed)."""
    entries, invalid = parse_address_list(body.text)
    if not entries:
        raise FwError("No valid addresses found" + (f" (invalid: {', '.join(invalid[:5])})" if invalid else ""))
    with changing(session, "ipset import", {"name": name, "target": body.target, "count": len(entries)}) as d:
        added = firewall.ipset_add_entries(name, entries, body.target)
        d["added"] = added
    return {"ok": True, "added": added, "invalid": invalid[:50], "parsed": len(entries)}
