"""Warn before changes that could lock someone out.

The current connections worth protecting (established SSH sessions, and the browser's own
connection when it is not local) are simulated with the tester against the firewall before
and after the proposed change. Anything that flips from ACCEPT to blocked is 'danger'.
Some changes are flagged heuristically as well (target DROP on an active zone, removing
bindings, panic mode, ...).
"""

import copy
import ipaddress
import re
import subprocess

from . import richrule
from .config import settings
from .fw import Op, Target
from .tester import Evaluator, Packet, Snapshot, load_snapshot

_VIEW_KEY = {
    "service": "services",
    "port": "ports",
    "protocol": "protocols",
    "source-port": "source_ports",
    "forward-port": "forward_ports",
    "icmp-block": "icmp_blocks",
    "rich-rule": "rich_rules",
    "interface": "interfaces",
    "source": "sources",
    "ingress-zone": "ingress_zones",
    "egress-zone": "egress_zones",
}
_BOOL_KEY = {"masquerade": "masquerade", "forward": "forward", "icmp-block-inversion": "icmp_block_inversion"}


def _item(op: Op):
    v = op.value
    match op.kind:
        case "service" | "icmp-block" | "interface" | "ingress-zone" | "egress-zone":
            return v.get("name", "")
        case "protocol" | "source":
            return v.get("value", "")
        case "port" | "source-port":
            return {"port": str(v.get("port", "")), "protocol": v.get("protocol", "")}
        case "forward-port":
            return {"port": str(v.get("port", "")), "protocol": v.get("protocol", ""),
                    "to_port": v.get("to_port", ""), "to_addr": v.get("to_addr", "")}
        case "rich-rule":
            try:
                text = richrule.normalize(v.get("rule", ""))
                return {"rule": text, "parsed": richrule.parse(text).model_dump()}
            except richrule.RuleError:
                return None
    return None


def apply_to_snapshot(snap: Snapshot, ops: list[Op]) -> Snapshot:
    """Return a copy of the snapshot with the ops applied (runtime simulation)."""
    new = copy.deepcopy(snap)
    for op in ops:
        container = new.policies if op.scope == "policy" else new.zones
        view = container.get(op.zone)
        if view is None:
            continue
        if op.kind in _BOOL_KEY:
            view[_BOOL_KEY[op.kind]] = op.action == "add"
            continue
        item = _item(op)
        if item is None:
            continue
        items = view.setdefault(_VIEW_KEY[op.kind], [])
        key = (lambda x: x["rule"]) if op.kind == "rich-rule" else (lambda x: x)
        if op.action == "add":
            if all(key(x) != key(item) for x in items):
                items.append(item)
        else:
            view[_VIEW_KEY[op.kind]] = [x for x in items if key(x) != key(item)]
    return new


# -- who could be locked out -------------------------------------------------------


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _route_iface(ip: str) -> str:
    m = re.search(r"\bdev (\S+)", _run(["ip", "route", "get", ip]))
    return m.group(1) if m else ""


def _ssh_ports() -> set[int]:
    ports = set()
    for line in _run(["ss", "-Htlnp"]).splitlines():
        if "sshd" in line:
            m = re.search(r":(\d+)\s", line.split()[3] + " ")
            if m:
                ports.add(int(m.group(1)))
    return ports or {22}


def _split_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host.strip("[]").split("%")[0], int(port)


def protected_connections(client_ip: str | None) -> list[dict]:
    conns = []
    ssh = _ssh_ports()
    for line in _run(["ss", "-Htn", "state", "established"]).splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local_ip, local_port = _split_hostport(parts[2])
            peer_ip, _ = _split_hostport(parts[3])
            ip = ipaddress.ip_address(peer_ip)
        except ValueError:
            continue
        if local_port not in ssh or ip.is_loopback:
            continue
        if ip.version == 6 and ip.ipv4_mapped:
            peer_ip = str(ip.ipv4_mapped)
        conns.append({"what": f"SSH session from {peer_ip}", "src": peer_ip, "port": local_port})
    if client_ip:
        try:
            ip = ipaddress.ip_address(client_ip)
            if not ip.is_loopback:
                conns.append({"what": f"your browser connection from {client_ip}", "src": client_ip, "port": settings.port})
        except ValueError:
            pass
    # de-duplicate
    seen, out = set(), []
    for c in conns:
        k = (c["src"], c["port"])
        if k not in seen:
            seen.add(k)
            c["interface"] = _route_iface(c["src"])
            out.append(c)
    return out


# -- analysis ------------------------------------------------------------------------


def _active_zones(snap: Snapshot) -> set[str]:
    return {n for n, z in snap.zones.items() if z.get("interfaces") or z.get("sources")} | {snap.default_zone}


def analyze(ops: list[Op], target: Target, client_ip: str | None, zone_target: dict | None = None,
            snap: Snapshot | None = None, conns: list[dict] | None = None) -> dict:
    warnings: list[dict] = []
    snap = snap or load_snapshot("runtime")
    after = apply_to_snapshot(snap, ops)
    if zone_target:
        z = after.zones.get(zone_target["zone"])
        if z is not None:
            z["target"] = zone_target["target"]
    active = _active_zones(snap)
    ssh = _ssh_ports() if conns is None else {22}

    for op in ops:
        if op.scope != "zone" or op.zone not in active or op.action != "remove":
            continue
        if op.kind in ("interface", "source"):
            warnings.append({"level": "warning", "message":
                f"Removing {op.kind} {next(iter(op.value.values()), '')} from active zone {op.zone}: its traffic moves to "
                f"{'the default zone' if op.kind == 'interface' else 'interface-based zone selection'}."})
        if op.kind == "service" and op.value.get("name") == "ssh":
            warnings.append({"level": "warning", "message": f"Removing the ssh service from active zone {op.zone}."})
        if op.kind == "port" and op.value.get("protocol") == "tcp":
            try:
                if any(_port_match(op.value["port"], p) for p in ssh | {settings.port}):
                    warnings.append({"level": "warning", "message":
                        f"Removing port {op.value['port']}/tcp from active zone {op.zone} (SSH or richrule port)."})
            except (KeyError, ValueError):
                pass
    if zone_target and zone_target["zone"] in active and zone_target["target"] in ("DROP", "%%REJECT%%"):
        warnings.append({"level": "warning", "message":
            f"Setting target {zone_target['target'].strip('%')} on active zone {zone_target['zone']}: everything not "
            f"explicitly allowed will be blocked (after reload)."})

    connections = protected_connections(client_ip) if conns is None else conns
    checked = []
    for c in connections:
        pkt = Packet(src=c["src"], protocol="tcp", dst_port=c["port"], interface=c.get("interface", ""))
        try:
            before = Evaluator(snap, pkt).run()
            post = Evaluator(after, pkt).run()
        except Exception:
            continue
        checked.append({"what": c["what"], "before": before["verdict"], "after": post["verdict"],
                        "decided_by": post["decided_by"]})
        if before["verdict"] == "ACCEPT" and post["verdict"] != "ACCEPT":
            warnings.append({"level": "danger", "message":
                f"This change would block {c['what']} (port {c['port']}): {post['verdict']} by {post['decided_by']}."})

    level = "danger" if any(w["level"] == "danger" for w in warnings) else ("warning" if warnings else "ok")
    return {
        "level": level,
        "warnings": warnings,
        "connections": checked,
        # Force safe apply when a runtime change is dangerous.
        "force_safe": level == "danger" and target != "permanent",
    }


def _port_match(spec: str, port: int) -> bool:
    if "-" in str(spec):
        lo, hi = str(spec).split("-", 1)
        return int(lo) <= port <= int(hi)
    return int(spec) == port
