"""Multi-host console: manage other richrule instances ("agents") from this one.

Every richrule install is also an agent: it accepts ``Authorization: Bearer <token>`` for
tokens created on that host (see tokens.py). The console stores each remote host's URL and
token, and proxies ``/api/h/<host>/<path>`` to ``<url>/api/<path>``, forwarding the console
user's name (for the remote audit log) and role (viewers stay read-only remotely).
"""

import re
import secrets
import ssl

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from . import store

_HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
                "proxy-authorization", "proxy-authenticate", "content-length", "content-encoding", "host"}


def _load() -> list[dict]:
    return store.load("hosts").get("hosts", [])


def list_hosts(public: bool = True) -> list[dict]:
    hosts = _load()
    if public:
        return [{k: v for k, v in h.items() if k != "token"} | {"token_set": bool(h.get("token"))} for h in hosts]
    return hosts


def get(host_id: str) -> dict:
    for h in _load():
        if h["id"] == host_id:
            return h
    raise HTTPException(404, f"Unknown host {host_id}")


def _validate_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+$", url):
        raise HTTPException(400, "URL must look like https://host:8443 (no path)")
    return url


def add(name: str, url: str, token: str, verify_tls: bool, ca_pem: str = "") -> dict:
    if not token.strip():
        raise HTTPException(400, "An agent token is required (create one on the remote host)")
    hosts = _load()
    host = {"id": secrets.token_hex(4), "name": name.strip() or url, "url": _validate_url(url), "token": token.strip(),
            "verify_tls": verify_tls, "ca_pem": ca_pem.strip()}
    hosts.append(host)
    store.save("hosts", {"hosts": hosts})
    return host


def update(host_id: str, fields: dict) -> None:
    hosts = _load()
    for h in hosts:
        if h["id"] == host_id:
            for k in ("name", "verify_tls", "ca_pem"):
                if k in fields and fields[k] is not None:
                    h[k] = fields[k]
            if fields.get("url"):
                h["url"] = _validate_url(fields["url"])
            if fields.get("token"):
                h["token"] = fields["token"].strip()
            store.save("hosts", {"hosts": hosts})
            return
    raise HTTPException(404, f"Unknown host {host_id}")


def remove(host_id: str) -> None:
    hosts = [h for h in _load() if h["id"] != host_id]
    store.save("hosts", {"hosts": hosts})


def _verify(host: dict):
    if not host.get("verify_tls", True):
        return False
    if host.get("ca_pem"):
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=host["ca_pem"])
        return ctx
    return True


def _client(host: dict, timeout: float | None = 30) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=host["url"], verify=_verify(host), timeout=timeout)


def _headers(host: dict, user: str, role: str, extra: dict | None = None) -> dict:
    h = {"Authorization": f"Bearer {host.get('token', '')}", "X-Richrule-User": user, "X-Richrule-Role": role}
    if extra:
        h.update(extra)
    return h


async def test(host: dict) -> dict:
    try:
        async with _client(host, timeout=10) as c:
            r = await c.get("/api/status", headers=_headers(host, "console-test", "viewer"))
        if r.status_code != 200:
            detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
            return {"ok": False, "error": f"HTTP {r.status_code}: {detail}"}
        st = r.json()
        return {"ok": True, "version": st.get("version"), "state": st.get("state"), "default_zone": st.get("default_zone")}
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def proxy(host_id: str, path: str, request: Request, user: str, role: str):
    host = get(host_id)
    if path.startswith(("h/", "hosts")) or path in ("login", "logout", "me"):
        raise HTTPException(400, "Not proxied")
    body = await request.body()
    fwd = {k: v for k, v in request.headers.items()
           if k.lower() in ("content-type", "accept")}
    stream = path.endswith("/stream")
    client = _client(host, timeout=None if stream else 60)
    try:
        req = client.build_request(request.method, f"/api/{path}", params=request.query_params,
                                   content=body or None, headers=_headers(host, user, role, fwd))
        resp = await client.send(req, stream=True)
    except httpx.HTTPError as e:
        await client.aclose()
        raise HTTPException(502, f"Host {host['name']} unreachable: {e}") from None

    async def body_iter():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()
            await client.aclose()

    headers = {k: v for k, v in resp.headers.items() if k.lower() not in _HOP_HEADERS and k.lower() != "set-cookie"}
    return StreamingResponse(body_iter(), status_code=resp.status_code, headers=headers,
                             media_type=resp.headers.get("content-type"))
