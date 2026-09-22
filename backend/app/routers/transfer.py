import json
import time
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from .. import transfer
from ..auth import Session, require_user
from ..changes import changing
from ..fw import FwError, firewall

router = APIRouter(prefix="/api", tags=["import/export"])


def _download(content: bytes | str, filename: str, media: str) -> Response:
    return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/export")
def export(
    format: Literal["json", "xml", "tar"] = "json",
    kind: Literal["zone", "policy", "service", "ipset"] | None = None,
    name: str | None = None,
    sections: str | None = Query(None, description="comma-separated: zones,policies,services,ipsets"),
    session: Session = Depends(require_user),
):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if format == "tar":
        return _download(transfer.export_tarball(), f"firewalld-{stamp}.tar.gz", "application/gzip")
    if format == "xml":
        if not kind or not name:
            raise FwError("XML export needs kind and name")
        return _download(transfer.export_xml(kind, name), f"{name}.xml", "application/xml")
    zones = [name] if kind == "zone" and name else None
    secs = [s for s in (sections or "").split(",") if s] or (["zones"] if zones else None)
    bundle = transfer.export_bundle(zones, secs)
    if kind and name and kind != "zone":
        section = {"policy": "policies", "service": "services", "ipset": "ipsets"}[kind]
        bundle = {k: v for k, v in bundle.items() if k not in transfer.KINDS}
        bundle[section] = {name: transfer.export_bundle(None, [section])[section][name]}
    fname = f"{name or 'firewalld'}-{stamp}.json"
    return _download(json.dumps(bundle, indent=2), fname, "application/json")


async def _read_upload(file: UploadFile) -> dict:
    content = await file.read()
    if len(content) > 20_000_000:
        raise FwError("File too large")
    name = file.filename or ""
    if name.endswith(".xml") or content.lstrip().startswith(b"<"):
        return transfer.parse_xml(name, content)
    try:
        return transfer.validate_bundle(json.loads(content))
    except json.JSONDecodeError as e:
        raise FwError(f"Not valid JSON or XML: {e}") from None


@router.post("/import/preview")
async def import_preview(file: UploadFile = File(...), session: Session = Depends(require_user)):
    bundle = await _read_upload(file)
    return {"bundle": bundle, "plan": transfer.preview(bundle)}


class ImportApply(BaseModel):
    bundle: dict
    only: list[str] | None = None  # "kind/name" keys to import; all when omitted
    reload: bool = False


@router.post("/import/apply")
def import_apply(body: ImportApply, session: Session = Depends(require_user)):
    keys = body.only or [f"{k}/{n}" for k in transfer.KINDS for n in body.bundle.get(k, {})]
    with changing(session, "import", {"objects": keys[:50], "reload": body.reload}) as d:
        results = transfer.apply_bundle(body.bundle, body.only)
        errors = [r for r in results if r["result"] == "error"]
        d["results"] = [f"{r['kind']}/{r['name']}: {r['result']}" for r in results]
        if body.reload and not errors:
            firewall.reload()
    return {"ok": not errors, "results": results, "reloaded": body.reload and not errors}
