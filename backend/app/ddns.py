"""Dynamic DNS rules: rich rules whose source is a hostname.

firewalld only accepts addresses, so a DDNS rule stores a rule *template* plus a hostname.
The scheduler resolves the name periodically and keeps one concrete rich rule per resolved
address in the target zone/policy (runtime + permanent): rules for addresses the name no
longer resolves to are removed, new ones added. If resolution fails, the existing rules are
kept untouched.
"""

import ipaddress
import re
import secrets
import socket
import threading
import time

from . import audit, richrule, store
from .fw import FwError, Op, firewall
from .richrule import RichRule

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")
_lock = threading.Lock()

# Replaced in tests.
resolver = socket.getaddrinfo


def is_hostname(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return False
    except ValueError:
        return bool(HOSTNAME_RE.match(value))


def _load() -> list[dict]:
    return store.load("ddns").get("entries", [])


def _save(entries: list[dict]) -> None:
    store.save("ddns", {"entries": entries})


def list_entries() -> list[dict]:
    return _load()


def resolve(hostname: str, family: str) -> list[str]:
    fam = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}.get(family, socket.AF_UNSPEC)
    try:
        infos = resolver(hostname, None, fam, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FwError(f"Cannot resolve {hostname}: {e.strerror or e}", 502) from None
    ips = sorted({i[4][0] for i in infos})
    return [ip for ip in ips if not ipaddress.ip_address(ip).is_unspecified]


def _concrete(template: dict, ip: str) -> str:
    rule = RichRule.model_validate(template)
    fam = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ipv4"
    src = rule.source.model_copy(update={"addr": ip, "mac": "", "ipset": ""}) if rule.source else None
    return richrule.render(rule.model_copy(update={"family": fam, "source": src}))


def validate_template(template: dict, hostname: str) -> None:
    if not is_hostname(hostname):
        raise FwError(f"Not a valid hostname: {hostname}")
    t = RichRule.model_validate(template)
    if not t.source:
        raise FwError("A DDNS rule needs a source (the hostname)")
    # Render once with a documentation address to validate the rest of the rule.
    try:
        _concrete(template, "192.0.2.1" if t.family != "ipv6" else "2001:db8::1")
    except richrule.RuleError as e:
        raise FwError(f"Invalid rule: {e}") from None


def create(hostname: str, template: dict, zone: str, scope: str, interval: int, user: str) -> dict:
    validate_template(template, hostname)
    entry = {
        "id": secrets.token_hex(4),
        "hostname": hostname.rstrip("."),
        "template": template,
        "zone": zone,
        "scope": scope,
        "interval": max(60, int(interval)),
        "applied": {},
        "last_check": 0,
        "last_error": "",
        "created_by": user,
    }
    with _lock:
        entries = _load()
        entries.append(entry)
        _save(entries)
    return refresh(entry["id"], user)


def _apply_tolerant(op: Op) -> None:
    """Apply to runtime and permanent separately, ignoring 'already there' / 'not there'."""
    for cfg in ("runtime", "permanent"):
        try:
            firewall.apply([op], cfg)
        except FwError as e:
            if e.status != 409:
                raise


def refresh(entry_id: str, user: str = "ddns") -> dict:
    from .history import history

    with _lock:
        entries = _load()
        entry = next((e for e in entries if e["id"] == entry_id), None)
        if entry is None:
            raise FwError("No such DDNS rule", 404)
        fam = entry["template"].get("family") or ""
        entry["last_check"] = time.time()
        try:
            ips = resolve(entry["hostname"], fam)
        except FwError as e:
            entry["last_error"] = e.message
            _save(entries)
            return entry
        desired = {ip: _concrete(entry["template"], ip) for ip in ips}
        applied: dict[str, str] = entry.get("applied", {})
        to_remove = {ip: r for ip, r in applied.items() if desired.get(ip) != r}
        to_add = {ip: r for ip, r in desired.items() if applied.get(ip) != r}
        entry["last_error"] = ""
        if to_add or to_remove:
            label = f"DDNS {entry['hostname']}: " + ", ".join(
                [f"+{ip}" for ip in to_add] + [f"-{ip}" for ip in to_remove])
            try:
                with history.change(user, label):
                    for rule in to_remove.values():
                        _apply_tolerant(Op(action="remove", kind="rich-rule", zone=entry["zone"],
                                           scope=entry["scope"], value={"rule": rule}))
                    for rule in to_add.values():
                        _apply_tolerant(Op(action="add", kind="rich-rule", zone=entry["zone"],
                                           scope=entry["scope"], value={"rule": rule}))
                entry["applied"] = desired
                audit.record(user, "ddns update", {"label": label, "zone": entry["zone"]})
            except FwError as e:
                entry["last_error"] = e.message
                audit.record(user, "ddns update", {"hostname": entry["hostname"], "error": e.message}, ok=False)
        entry["resolved"] = ips
        _save(entries)
        return entry


def delete(entry_id: str, user: str) -> None:
    from .history import history

    with _lock:
        entries = _load()
        entry = next((e for e in entries if e["id"] == entry_id), None)
        if entry is None:
            raise FwError("No such DDNS rule", 404)
        with history.change(user, f"Remove DDNS rule {entry['hostname']}"):
            for rule in entry.get("applied", {}).values():
                _apply_tolerant(Op(action="remove", kind="rich-rule", zone=entry["zone"], scope=entry["scope"],
                                   value={"rule": rule}))
        _save([e for e in entries if e["id"] != entry_id])


def refresh_due() -> None:
    now = time.time()
    for e in _load():
        if now - e.get("last_check", 0) >= e.get("interval", 300):
            try:
                refresh(e["id"])
            except FwError:
                pass
