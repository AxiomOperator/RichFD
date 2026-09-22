"""Fail2ban integration: jail status, banned addresses, ban/unban, and jail settings.

Talks to the running server with ``fail2ban-client`` and writes jail settings to one override
file per jail, ``/etc/fail2ban/jail.d/richfd-<jail>.local``, so RichFD never edits the
distribution's jail.conf / jail.local. Settings take effect after ``fail2ban-client reload``.
"""

import configparser
import os
import re
import shutil
import subprocess
from pathlib import Path

from .fw import FwError

CLIENT = "fail2ban-client"
CONF_DIR = Path(os.environ.get("RICHRULE_FAIL2BAN_DIR", "/etc/fail2ban"))
JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SETTINGS = ("enabled", "port", "maxretry", "findtime", "bantime", "banaction", "backend", "logpath", "filter", "ignoreip")

# Replaced in tests.
runner = subprocess.run


def _client(*args: str, check: bool = True) -> str:
    if not shutil.which(CLIENT) and runner is subprocess.run:
        raise FwError("fail2ban is not installed (dnf install fail2ban fail2ban-firewalld)", 503)
    try:
        r = runner([CLIENT, *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FwError(f"fail2ban-client failed: {e}", 503) from None
    if check and r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise FwError(f"fail2ban: {msg[-1] if msg else 'error'}", 400 if "does not exist" in "".join(msg) else 503)
    return r.stdout


def _kv(output: str) -> dict[str, str]:
    """Parse fail2ban-client's tree output ('|- Currently failed:\t3')."""
    out = {}
    for line in output.splitlines():
        line = line.strip().lstrip("|`- ").strip()
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def _jail_valid(jail: str) -> str:
    if not JAIL_RE.match(jail):
        raise FwError(f"Invalid jail name: {jail}")
    return jail


def status() -> dict:
    installed = bool(shutil.which(CLIENT)) or runner is not subprocess.run
    if not installed:
        return {"installed": False, "running": False, "jails": [], "filters": _filters(),
                "hint": "Install with: dnf install fail2ban fail2ban-firewalld && systemctl enable --now fail2ban"}
    try:
        _client("ping")
    except FwError as e:
        return {"installed": True, "running": False, "jails": [], "filters": _filters(), "error": e.message,
                "hint": "Start it with: systemctl enable --now fail2ban"}
    names = [j.strip() for j in _kv(_client("status")).get("jail list", "").split(",") if j.strip()]
    jails = [jail(n) for n in names]
    version = _client("version", check=False).strip()
    return {"installed": True, "running": True, "version": version, "jails": jails, "filters": _filters(),
            "managed": sorted(p.stem.removeprefix("richfd-") for p in CONF_DIR.glob("jail.d/richfd-*.local"))
            if CONF_DIR.exists() else []}


def jail(name: str) -> dict:
    _jail_valid(name)
    kv = _kv(_client("status", name))
    banned = kv.get("banned ip list", "").split()
    info = {
        "name": name,
        "currently_failed": int(kv.get("currently failed", 0) or 0),
        "total_failed": int(kv.get("total failed", 0) or 0),
        "currently_banned": int(kv.get("currently banned", 0) or 0),
        "total_banned": int(kv.get("total banned", 0) or 0),
        "banned": banned,
        "files": kv.get("file list", "") or kv.get("journal matches", ""),
    }
    for key in ("bantime", "findtime", "maxretry"):
        try:
            info[key] = int(_client("get", name, key).strip())
        except (FwError, ValueError):
            info[key] = None
    try:
        actions = _client("get", name, "actions").strip().splitlines()
        info["actions"] = [a.strip() for a in actions[-1].split(",")] if actions else []
    except FwError:
        info["actions"] = []
    info["uses_firewalld"] = any("firewall" in a for a in info["actions"])
    return info


def ban(name: str, ip: str) -> None:
    _client("set", _jail_valid(name), "banip", _ip(ip))


def unban(name: str, ip: str) -> None:
    _client("set", _jail_valid(name), "unbanip", _ip(ip))


def _ip(ip: str) -> str:
    import ipaddress

    try:
        return str(ipaddress.ip_network(ip, strict=False)) if "/" in ip else str(ipaddress.ip_address(ip))
    except ValueError:
        raise FwError(f"Invalid address: {ip}") from None


def _filters() -> list[str]:
    d = CONF_DIR / "filter.d"
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.conf"))


def _override(name: str) -> Path:
    return CONF_DIR / "jail.d" / f"richfd-{name}.local"


def read_settings(name: str) -> dict:
    """Settings RichFD manages for a jail (from its override file)."""
    _jail_valid(name)
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(_override(name))
    return dict(cp[name]) if cp.has_section(name) else {}


def write_settings(name: str, values: dict, reload: bool = True) -> dict:
    """Create/update ``jail.d/richfd-<jail>.local`` and reload fail2ban."""
    _jail_valid(name)
    clean = {}
    for k, v in values.items():
        if k not in SETTINGS or v is None or v == "":
            continue
        v = str(v).strip()
        if "\n" in v or "\r" in v:
            raise FwError(f"{k}: value must be a single line")
        if k in ("maxretry",) and not v.isdigit():
            raise FwError("maxretry must be a number")
        if k in ("findtime", "bantime") and not re.fullmatch(r"-?\d+[smhdw]?", v):
            raise FwError(f"{k} must look like 600, 10m, 1h, 1d or -1 (permanent)")
        if k == "enabled" and v not in ("true", "false"):
            raise FwError("enabled must be true or false")
        if k == "filter" and v not in _filters() and _filters():
            raise FwError(f"Unknown filter {v}")
        clean[k] = v
    path = _override(name)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = [f"# Managed by RichFD. Edit from the Fail2ban page or remove this file to revert.", f"[{name}]"]
        body += [f"{k} = {v}" for k, v in clean.items()]
        path.write_text("\n".join(body) + "\n")
        os.chmod(path, 0o644)
    except PermissionError:
        raise FwError(f"Cannot write {path}; RichFD must run as root to configure fail2ban", 503) from None
    if reload:
        _client("reload")
    return clean


def delete_settings(name: str) -> None:
    _jail_valid(name)
    try:
        _override(name).unlink(missing_ok=True)
    except PermissionError:
        raise FwError("RichFD must run as root to configure fail2ban", 503) from None
    _client("reload")
