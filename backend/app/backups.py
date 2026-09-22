"""Named configuration backups: create, list, download, upload, restore, delete.

A backup is a tar.gz in ``<state>/backups`` holding ``meta.json``, ``bundle.json`` (the JSON
export: always available) and, when readable, ``firewalld/`` (the raw /etc/firewalld tree).
Restoring prefers the raw tree (exact); otherwise it imports the bundle. Uploads accept a
RichFD backup, a raw ``/etc/firewalld`` tarball (as produced by Export → tar.gz) or a JSON
export. Every restore is wrapped in a config-history snapshot, so it can itself be undone.
"""

import io
import json
import os
import re
import socket
import tarfile
import tempfile
import time
from pathlib import Path

from . import store, transfer
from .config import settings
from .fw import FwError, firewall

ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9-]{0,40}$")


def _dir() -> Path:
    d = settings.state_dir / "backups"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]


def _path(backup_id: str) -> Path:
    if not ID_RE.match(backup_id):
        raise FwError("Invalid backup id")
    p = _dir() / f"{backup_id}.tar.gz"
    if not p.exists():
        raise FwError("No such backup", 404)
    return p


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o600
    tar.addfile(info, io.BytesIO(data))


def create(name: str, user: str, source: str = "manual") -> dict:
    bundle = transfer.export_bundle()
    has_files = os.access(settings.firewalld_dir, os.R_OK | os.X_OK)
    meta = {"name": name or "backup", "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "host": socket.gethostname(),
            "user": user, "source": source, "has_files": has_files,
            "zones": len(bundle.get("zones", {})), "policies": len(bundle.get("policies", {}))}
    backup_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{_slug(name) or 'backup'}"
    path = _dir() / f"{backup_id}.tar.gz"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w:gz") as tar:
        _add_bytes(tar, "meta.json", json.dumps(meta, indent=2).encode())
        _add_bytes(tar, "bundle.json", json.dumps(bundle, indent=2).encode())
        if has_files:
            tar.add(settings.firewalld_dir, arcname="firewalld")
    return {"id": backup_id, **meta, "size": path.stat().st_size}


def _meta(path: Path) -> dict:
    try:
        with tarfile.open(path, "r:gz") as tar:
            m = tar.extractfile("meta.json")
            return json.loads(m.read()) if m else {}
    except (tarfile.TarError, KeyError, json.JSONDecodeError, OSError):
        return {}


def list_backups() -> list[dict]:
    out = []
    for p in sorted(_dir().glob("*.tar.gz"), reverse=True):
        backup_id = p.name[: -len(".tar.gz")]
        if ID_RE.match(backup_id):
            out.append({"id": backup_id, **_meta(p), "size": p.stat().st_size})
    return out


def path_for_download(backup_id: str) -> Path:
    return _path(backup_id)


def delete(backup_id: str) -> None:
    _path(backup_id).unlink()


def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = []
    for m in tar.getmembers():
        name = m.name.lstrip("./")
        if m.name.startswith("/") or ".." in Path(m.name).parts:
            raise FwError(f"Unsafe path in archive: {m.name}")
        if not (m.isfile() or m.isdir()):
            continue  # skip links, devices
        if name in ("meta.json", "bundle.json") or name == "firewalld" or name.startswith("firewalld/"):
            members.append(m)
    return members


def upload(filename: str, content: bytes, user: str) -> dict:
    """Store an uploaded backup/tarball/JSON export as a new backup."""
    if len(content) > 50_000_000:
        raise FwError("File too large")
    name = Path(filename).stem.replace(".tar", "") or "upload"
    backup_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{_slug('upload-' + name)}"
    path = _dir() / f"{backup_id}.tar.gz"
    meta = {"name": f"Uploaded {filename}", "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "host": "", "user": user, "source": "upload"}
    stripped = content.lstrip()
    if stripped.startswith(b"{"):
        try:
            bundle = transfer.validate_bundle(json.loads(content))
        except json.JSONDecodeError as e:
            raise FwError(f"Not valid JSON: {e}") from None
        meta.update(host=bundle.get("host", ""), has_files=False, zones=len(bundle.get("zones", {})),
                    policies=len(bundle.get("policies", {})))
        with tarfile.open(path, "w:gz") as tar:
            _add_bytes(tar, "meta.json", json.dumps(meta).encode())
            _add_bytes(tar, "bundle.json", json.dumps(bundle).encode())
    else:
        try:
            src = tarfile.open(fileobj=io.BytesIO(content), mode="r:*")
        except tarfile.TarError:
            raise FwError("Not a tar archive or JSON export") from None
        with src:
            members = _safe_members(src)
            names = {m.name.lstrip("./") for m in members}
            if not any(n.startswith("firewalld/") for n in names) and "bundle.json" not in names:
                raise FwError("Archive contains neither firewalld/ nor bundle.json")
            if "meta.json" in names:
                old = json.loads(src.extractfile(next(m for m in members if m.name.lstrip("./") == "meta.json")).read())
                meta.update({k: old.get(k) for k in ("host", "zones", "policies")})
                meta["name"] = f"Uploaded: {old.get('name', filename)}"
            meta["has_files"] = any(n.startswith("firewalld/") for n in names)
            with tarfile.open(path, "w:gz") as tar:
                _add_bytes(tar, "meta.json", json.dumps(meta).encode())
                for m in members:
                    if m.name.lstrip("./") == "meta.json":
                        continue
                    m.name = m.name.lstrip("./")
                    tar.addfile(m, src.extractfile(m) if m.isfile() else None)
    os.chmod(path, 0o600)
    return {"id": backup_id, **meta, "size": path.stat().st_size}


def inspect(backup_id: str) -> dict:
    """What a backup contains and, for raw backups, which files a restore would change."""
    path = _path(backup_id)
    info: dict = {"id": backup_id, **_meta(path), "files": [], "changes": []}
    with tarfile.open(path, "r:gz") as tar:
        members = _safe_members(tar)
        for m in members:
            n = m.name.lstrip("./")
            if n.startswith("firewalld/") and m.isfile():
                rel = n[len("firewalld/"):]
                info["files"].append(rel)
                current = settings.firewalld_dir / rel
                try:
                    if not current.exists():
                        info["changes"].append({"file": rel, "change": "added"})
                    elif current.read_bytes() != tar.extractfile(m).read():
                        info["changes"].append({"file": rel, "change": "modified"})
                except PermissionError:
                    pass
        if info["files"] and os.access(settings.firewalld_dir, os.R_OK | os.X_OK):
            backed = set(info["files"])
            for p in settings.firewalld_dir.rglob("*"):
                rel = str(p.relative_to(settings.firewalld_dir))
                if p.is_file() and rel not in backed:
                    info["changes"].append({"file": rel, "change": "removed"})
        if "bundle.json" in {m.name.lstrip("./") for m in members} and not info["files"]:
            bundle = json.loads(tar.extractfile("bundle.json").read())
            info["plan"] = transfer.preview(bundle)
    return info


def restore(backup_id: str, user: str) -> dict:
    from .history import History, history

    path = _path(backup_id)
    with history.change(user, f"Restore backup {backup_id}"):
        with tarfile.open(path, "r:gz") as tar, tempfile.TemporaryDirectory() as tmp:
            members = _safe_members(tar)
            names = {m.name.lstrip("./") for m in members}
            if any(n.startswith("firewalld/") for n in names):
                if not os.access(settings.firewalld_dir, os.W_OK):
                    raise FwError(f"Cannot write {settings.firewalld_dir}; restoring files needs root", 503)
                for m in members:
                    m.name = m.name.lstrip("./")
                tar.extractall(tmp, members=[m for m in members if m.name.startswith("firewalld")], filter="data")
                src = Path(tmp) / "firewalld"
                for p in src.rglob("*"):
                    os.chmod(p, 0o750 if p.is_dir() else 0o640)
                History._mirror(src, settings.firewalld_dir)
                firewall.reload()
                return {"mode": "files"}
            bundle = json.loads(tar.extractfile("bundle.json").read())
            results = transfer.apply_bundle(bundle)
            errors = [r for r in results if r["result"] == "error"]
            if errors:
                raise FwError("Import errors: " + "; ".join(f"{r['kind']}/{r['name']}: {r['error']}" for r in errors[:5]))
            firewall.reload()
            return {"mode": "bundle", "results": results}


# -- automatic backups ---------------------------------------------------------------------

DEFAULTS = {"auto": True, "interval_hours": 24, "keep": 14}


def auto_settings() -> dict:
    return {**DEFAULTS, **store.load("backup_settings")}


def set_auto_settings(values: dict) -> dict:
    s = auto_settings()
    for k in DEFAULTS:
        if k in values and values[k] is not None:
            s[k] = values[k]
    s["interval_hours"] = max(1, int(s["interval_hours"]))
    s["keep"] = max(1, int(s["keep"]))
    store.save("backup_settings", s)
    return s


def auto_backup_due() -> None:
    s = auto_settings()
    if not s["auto"]:
        return
    autos = [b for b in list_backups() if b.get("source") == "auto"]
    last = autos[0]["created"] if autos else None
    if last:
        try:
            age = time.time() - time.mktime(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            age = 1e9
        if age < s["interval_hours"] * 3600:
            return
    create("automatic", "system", source="auto")
    for old in [b for b in list_backups() if b.get("source") == "auto"][s["keep"]:]:
        try:
            delete(old["id"])
        except FwError:
            pass
