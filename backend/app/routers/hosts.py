from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .. import audit, hosts, notify, tokens
from ..auth import Session, require_user
from ..fw import FwError

router = APIRouter(prefix="/api", tags=["hosts & settings"])


# -- remote hosts (console side) -----------------------------------------------------


@router.get("/hosts")
def list_hosts(session: Session = Depends(require_user)):
    return hosts.list_hosts()


class HostIn(BaseModel):
    name: str = ""
    url: str
    token: str
    verify_tls: bool = True
    ca_pem: str = ""


@router.post("/hosts")
def add_host(body: HostIn, session: Session = Depends(require_user)):
    h = hosts.add(body.name, body.url, body.token, body.verify_tls, body.ca_pem)
    audit.record(session.user, "add host", {"name": h["name"], "url": h["url"]})
    return {k: v for k, v in h.items() if k != "token"}


class HostUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    token: str | None = None
    verify_tls: bool | None = None
    ca_pem: str | None = None


@router.patch("/hosts/{host_id}")
def update_host(host_id: str, body: HostUpdate, session: Session = Depends(require_user)):
    hosts.update(host_id, body.model_dump())
    audit.record(session.user, "update host", {"id": host_id})
    return {"ok": True}


@router.delete("/hosts/{host_id}")
def remove_host(host_id: str, session: Session = Depends(require_user)):
    hosts.remove(host_id)
    audit.record(session.user, "remove host", {"id": host_id})
    return {"ok": True}


@router.post("/hosts/{host_id}/test")
async def test_host(host_id: str, session: Session = Depends(require_user)):
    return await hosts.test(hosts.get(host_id))


@router.api_route("/h/{host_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                  include_in_schema=False)
async def proxy(host_id: str, path: str, request: Request, session: Session = Depends(require_user)):
    """Forward an API call to a remote richrule agent."""
    return await hosts.proxy(host_id, path, request, session.user, session.role)


# -- agent tokens (this host, used by remote consoles) ------------------------------


@router.get("/tokens")
def list_tokens(session: Session = Depends(require_user)):
    return tokens.list_tokens()


class TokenIn(BaseModel):
    name: str


@router.post("/tokens")
def create_token(body: TokenIn, session: Session = Depends(require_user)):
    if session.via_token:
        raise FwError("Tokens cannot create tokens", 403)
    try:
        token = tokens.create(body.name.strip())
    except ValueError as e:
        raise FwError(str(e), 409) from None
    audit.record(session.user, "create agent token", {"name": body.name})
    return {"name": body.name, "token": token}


@router.delete("/tokens/{name}")
def revoke_token(name: str, session: Session = Depends(require_user)):
    if session.via_token:
        raise FwError("Tokens cannot revoke tokens", 403)
    tokens.revoke(name)
    audit.record(session.user, "revoke agent token", {"name": name})
    return {"ok": True}


# -- notifications -----------------------------------------------------------------


@router.get("/settings/notifications")
def get_notifications(session: Session = Depends(require_user)):
    return notify.public_settings()


class NotificationsIn(BaseModel):
    webhook_url: str | None = None
    syslog: bool | None = None
    email_to: str | None = None
    email_from: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_starttls: bool | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None  # None/omitted keeps the stored password
    events: str | None = None


@router.put("/settings/notifications")
def put_notifications(body: NotificationsIn, session: Session = Depends(require_user)):
    notify.update_settings({k: v for k, v in body.model_dump().items() if v is not None})
    audit.record(session.user, "update notification settings")
    return notify.public_settings()


@router.post("/settings/notifications/test")
def test_notifications(session: Session = Depends(require_user)):
    entry = {"ts": "", "user": session.user, "action": "test notification", "ok": True,
             "detail": {"label": "This is a test from richrule"}}
    results = notify.deliver(entry)
    if not results:
        raise FwError("No notification channel is configured")
    return results
