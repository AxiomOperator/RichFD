from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from .. import audit, automation, backups, connections, ddns, denied, fail2ban, richrule, scheduler
from ..auth import Session, require_user
from ..changes import changing
from ..fw import FwError, Op, Target, firewall
from ..richrule import RichRule
from ..transfer import parse_address_list

router = APIRouter(prefix="/api", tags=["tools"])


# -- automation export -------------------------------------------------------------------


class AutomationRequest(BaseModel):
    format: Literal["ansible", "bash"] = "ansible"
    zones: list[str] | None = None  # None = all
    policies: list[str] | None = None
    services: bool = True
    ipsets: bool = True
    # Export only these rich rules of one zone/policy
    rules: list[str] | None = None
    scope: Literal["zone", "policy"] = "zone"
    name: str | None = None


@router.post("/automation/export")
def automation_export(body: AutomationRequest, session: Session = Depends(require_user)):
    if body.rules is not None:
        if not body.name:
            raise FwError("name is required when exporting rules")
        rules = [richrule.normalize(r) for r in body.rules]
        fn = automation.to_ansible if body.format == "ansible" else automation.to_bash
        text = fn({}, only_rules=rules, target=(body.scope, body.name))
    else:
        data = automation.collect(body.zones, body.policies, body.services, body.ipsets)
        text = automation.to_ansible(data) if body.format == "ansible" else automation.to_bash(data)
    return {"format": body.format, "filename": "firewalld.yml" if body.format == "ansible" else "firewalld.sh",
            "content": text}


# -- connections ----------------------------------------------------------------------------


@router.get("/connections")
def list_connections(session: Session = Depends(require_user)):
    return connections.connections()


class TerminateRequest(BaseModel):
    ip: str


@router.post("/connections/terminate")
def terminate(body: TerminateRequest, session: Session = Depends(require_user)):
    result = connections.terminate(body.ip)
    audit.record(session.user, "terminate connections", {"value": body.ip, **result})
    return result


# -- denied dashboard -----------------------------------------------------------------------


@router.get("/denied/stats")
def denied_stats(hours: int = Query(24, ge=1, le=24 * 30), port: int | None = Query(None, ge=0, le=65535),
                 session: Session = Depends(require_user)):
    return denied.stats(hours, port)


# -- bulk IP rules ----------------------------------------------------------------------------


class BulkRulesRequest(BaseModel):
    text: str
    zone: str
    scope: Literal["zone", "policy"] = "zone"
    action: Literal["accept", "drop", "reject"] = "drop"
    service: str = ""
    port: str = ""
    protocol: Literal["tcp", "udp"] = "tcp"
    priority: int = Field(0, ge=-32768, le=32767)
    target: Target = "both"
    preview: bool = True


def _bulk_rules(body: BulkRulesRequest) -> tuple[list[str], list[str]]:
    addrs, invalid = parse_address_list(body.text)
    if not addrs:
        raise FwError("No addresses found" + (f" (invalid: {', '.join(invalid[:5])})" if invalid else ""))
    if len(addrs) > 5000:
        raise FwError(f"{len(addrs)} addresses: use an IP set for lists this long")
    rules = []
    for a in addrs:
        fam = "ipv6" if ":" in a else "ipv4"
        parts = ["rule"]
        if body.priority:
            parts.append(f'priority="{body.priority}"')
        parts += [f'family="{fam}"', f'source address="{a}"']
        if body.service:
            parts.append(f'service name="{body.service}"')
        elif body.port:
            parts.append(f'port port="{body.port}" protocol="{body.protocol}"')
        parts.append(body.action)
        try:
            rules.append(richrule.normalize(" ".join(parts)))
        except richrule.RuleError as e:
            raise FwError(f"{a}: {e}") from None
    return rules, invalid


@router.post("/bulk/rules")
def bulk_rules(body: BulkRulesRequest, session: Session = Depends(require_user)):
    """Generate one rich rule per address in a pasted/uploaded list (preview, then apply)."""
    rules, invalid = _bulk_rules(body)
    if body.preview:
        return {"rules": rules, "invalid": invalid}
    if not session.is_admin:
        raise FwError("Read-only account: changes are not allowed", 403)
    ops = [Op(action="add", kind="rich-rule", zone=body.zone, scope=body.scope, value={"rule": r}) for r in rules]
    with changing(session, "bulk rules", {"ops": [o.describe() for o in ops[:20]], "count": len(ops), "target": body.target}):
        firewall.apply(ops, body.target)
    return {"ok": True, "added": len(rules), "invalid": invalid}


# -- DDNS ------------------------------------------------------------------------------------


@router.get("/ddns")
def ddns_list(session: Session = Depends(require_user)):
    return ddns.list_entries()


class DdnsRequest(BaseModel):
    hostname: str
    rule: RichRule
    zone: str
    scope: Literal["zone", "policy"] = "zone"
    interval: int = Field(300, ge=60, le=86400)


@router.post("/ddns")
def ddns_create(body: DdnsRequest, session: Session = Depends(require_user)):
    entry = ddns.create(body.hostname, body.rule.model_dump(), body.zone, body.scope, body.interval, session.user)
    audit.record(session.user, "create ddns rule", {"name": body.hostname, "zone": body.zone,
                                                     "resolved": entry.get("resolved", [])})
    return entry


@router.post("/ddns/{entry_id}/refresh")
def ddns_refresh(entry_id: str, session: Session = Depends(require_user)):
    return ddns.refresh(entry_id, session.user)


@router.delete("/ddns/{entry_id}")
def ddns_delete(entry_id: str, session: Session = Depends(require_user)):
    ddns.delete(entry_id, session.user)
    audit.record(session.user, "delete ddns rule", {"id": entry_id})
    return {"ok": True}


# -- IP list feeds -------------------------------------------------------------------------


@router.get("/feeds")
def feeds_list(session: Session = Depends(require_user)):
    return scheduler.feeds()


class FeedRequest(BaseModel):
    url: str = Field(pattern=r"^https?://")
    interval_hours: int = Field(24, ge=1, le=24 * 30)


@router.put("/feeds/{ipset}")
def feed_set(ipset: str, body: FeedRequest, session: Session = Depends(require_user)):
    scheduler.register_feed(ipset, body.url, body.interval_hours)
    audit.record(session.user, "set ip list feed", {"name": ipset, "value": body.url})
    return scheduler.refresh_feed(ipset, session.user)


@router.post("/feeds/{ipset}/refresh")
def feed_refresh(ipset: str, session: Session = Depends(require_user)):
    return scheduler.refresh_feed(ipset, session.user)


@router.delete("/feeds/{ipset}")
def feed_delete(ipset: str, session: Session = Depends(require_user)):
    scheduler.remove_feed(ipset)
    audit.record(session.user, "remove ip list feed", {"name": ipset})
    return {"ok": True}


# -- fail2ban -------------------------------------------------------------------------------


@router.get("/fail2ban")
def f2b_status(session: Session = Depends(require_user)):
    return fail2ban.status()


@router.get("/fail2ban/jails/{jail}")
def f2b_jail(jail: str, session: Session = Depends(require_user)):
    return {**fail2ban.jail(jail), "managed_settings": fail2ban.read_settings(jail)}


class BanRequest(BaseModel):
    ip: str
    action: Literal["ban", "unban"]


@router.post("/fail2ban/jails/{jail}/ban")
def f2b_ban(jail: str, body: BanRequest, session: Session = Depends(require_user)):
    (fail2ban.ban if body.action == "ban" else fail2ban.unban)(jail, body.ip)
    audit.record(session.user, f"fail2ban {body.action}", {"name": jail, "value": body.ip})
    return {"ok": True}


class JailSettings(BaseModel):
    enabled: Literal["true", "false"] | None = None
    port: str | None = None
    maxretry: str | None = None
    findtime: str | None = None
    bantime: str | None = None
    banaction: str | None = None
    backend: str | None = None
    logpath: str | None = None
    filter: str | None = None
    ignoreip: str | None = None


@router.put("/fail2ban/jails/{jail}")
def f2b_configure(jail: str, body: JailSettings, session: Session = Depends(require_user)):
    written = fail2ban.write_settings(jail, body.model_dump())
    audit.record(session.user, "fail2ban configure jail", {"name": jail, **written})
    return {"ok": True, "settings": written}


@router.delete("/fail2ban/jails/{jail}/settings")
def f2b_reset(jail: str, session: Session = Depends(require_user)):
    fail2ban.delete_settings(jail)
    audit.record(session.user, "fail2ban remove jail override", {"name": jail})
    return {"ok": True}


# -- backups ---------------------------------------------------------------------------------


@router.get("/backups")
def backups_list(session: Session = Depends(require_user)):
    return {"backups": backups.list_backups(), "settings": backups.auto_settings()}


class BackupCreate(BaseModel):
    name: str = Field("", max_length=60)


@router.post("/backups")
def backups_create(body: BackupCreate, session: Session = Depends(require_user)):
    b = backups.create(body.name or "manual", session.user)
    audit.record(session.user, "create backup", {"name": b["id"]})
    return b


@router.post("/backups/upload")
async def backups_upload(file: UploadFile = File(...), session: Session = Depends(require_user)):
    b = backups.upload(file.filename or "upload", await file.read(), session.user)
    audit.record(session.user, "upload backup", {"name": b["id"]})
    return b


@router.get("/backups/{backup_id}")
def backups_inspect(backup_id: str, session: Session = Depends(require_user)):
    return backups.inspect(backup_id)


@router.get("/backups/{backup_id}/download")
def backups_download(backup_id: str, session: Session = Depends(require_user)):
    return FileResponse(backups.path_for_download(backup_id), media_type="application/gzip",
                        filename=f"richfd-{backup_id}.tar.gz")


@router.post("/backups/{backup_id}/restore")
def backups_restore(backup_id: str, session: Session = Depends(require_user)):
    try:
        result = backups.restore(backup_id, session.user)
    except FwError as e:
        audit.record(session.user, "restore backup", {"name": backup_id, "error": e.message}, ok=False)
        raise
    audit.record(session.user, "restore backup", {"name": backup_id, "mode": result["mode"]})
    return {"ok": True, **result}


@router.delete("/backups/{backup_id}")
def backups_delete(backup_id: str, session: Session = Depends(require_user)):
    backups.delete(backup_id)
    audit.record(session.user, "delete backup", {"name": backup_id})
    return {"ok": True}


class BackupSettings(BaseModel):
    auto: bool | None = None
    interval_hours: int | None = Field(None, ge=1, le=24 * 30)
    keep: int | None = Field(None, ge=1, le=365)


@router.put("/backups/settings")
def backups_settings(body: BackupSettings, session: Session = Depends(require_user)):
    s = backups.set_auto_settings(body.model_dump())
    audit.record(session.user, "backup settings", s)
    return s
