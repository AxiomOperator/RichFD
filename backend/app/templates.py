"""One-click recipes that expand into ordinary change batches.

A template has a parameter schema (rendered as a form by the UI) and a ``build`` function
that returns a plan: an ordered list of steps. ``preview`` shows the plan; ``apply`` runs it.

Step kinds:
- ``ops``: a batch of zone/policy changes (applied to the user's chosen target)
- ``ipset-create``: create a permanent IP set (activated by the reload step)
- ``ipset-fill``: set an IP set's entries from a list or a download
- ``reload``: reload firewalld so permanent-only objects become active
"""

import ipaddress
import re
import urllib.request

from . import richrule
from .fw import FwError, Op, firewall
from .transfer import parse_address_list

COUNTRY_URLS = {
    "ipv4": "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone",
    "ipv6": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone",
}

TEMPLATES = [
    {
        "id": "ssh-from-subnet",
        "title": "Allow SSH only from a subnet",
        "description": "Accept SSH from one network and remove the unrestricted ssh service from the zone.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "subnet", "label": "Allowed network", "type": "text", "placeholder": "192.168.1.0/24"},
            {"name": "remove_open", "label": "Remove the unrestricted ssh service", "type": "bool", "default": True},
        ],
    },
    {
        "id": "rate-limit-ssh",
        "title": "Rate-limit SSH",
        "description": "Accept new SSH connections only up to a rate (slows down brute-force attempts); optionally log the rest.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "rate", "label": "Max new connections", "type": "text", "default": "10/m", "placeholder": "10/m"},
            {"name": "log", "label": "Log connections over the limit", "type": "bool", "default": True},
            {"name": "remove_open", "label": "Remove the unrestricted ssh service", "type": "bool", "default": True},
        ],
    },
    {
        "id": "block-country",
        "title": "Block a country",
        "description": "Create an IP set with a country's address blocks (downloaded from ipdeny.com, or pasted) and drop traffic from it.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "country", "label": "Country code", "type": "text", "placeholder": "e.g. kp"},
            {"name": "family", "label": "Family", "type": "select", "options": ["ipv4", "ipv6"], "default": "ipv4"},
            {"name": "addresses", "label": "Address list (optional; leave empty to download)", "type": "textarea"},
            {"name": "log", "label": "Log dropped packets", "type": "bool", "default": False},
            {"name": "reload", "label": "Reload firewalld to activate now", "type": "bool", "default": True},
        ],
    },
    {
        "id": "port-forward",
        "title": "Port-forward to a host or container",
        "description": "Forward an incoming port to another address (e.g. a container or VM) and enable masquerading.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "port", "label": "Incoming port", "type": "text", "placeholder": "8080"},
            {"name": "protocol", "label": "Protocol", "type": "select", "options": ["tcp", "udp"], "default": "tcp"},
            {"name": "to_addr", "label": "Destination address", "type": "text", "placeholder": "172.17.0.2"},
            {"name": "to_port", "label": "Destination port (optional)", "type": "text", "placeholder": "80"},
            {"name": "masquerade", "label": "Enable masquerading on the zone", "type": "bool", "default": True},
        ],
    },
    {
        "id": "block-address",
        "title": "Block an address or network",
        "description": "Drop or reject everything from one address or network.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "address", "label": "Address or network", "type": "text", "placeholder": "203.0.113.7"},
            {"name": "action", "label": "Action", "type": "select", "options": ["drop", "reject"], "default": "drop"},
            {"name": "log", "label": "Log blocked packets", "type": "bool", "default": False},
        ],
    },
    {
        "id": "allow-service-from",
        "title": "Allow a service from an address",
        "description": "Accept one service only from a given address, network or IP set.",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "service", "label": "Service", "type": "service"},
            {"name": "source", "label": "Source (address, network or ipset:name)", "type": "text", "placeholder": "10.0.0.0/8"},
        ],
    },
    {
        "id": "web-server",
        "title": "Web server",
        "description": "Open HTTP and HTTPS (and optionally HTTP/3 over UDP 443).",
        "params": [
            {"name": "zone", "label": "Zone", "type": "zone"},
            {"name": "http3", "label": "Also allow HTTP/3 (443/udp)", "type": "bool", "default": True},
        ],
    },
]

_BY_ID = {t["id"]: t for t in TEMPLATES}


def _family(addr: str) -> str:
    try:
        return "ipv6" if ipaddress.ip_network(addr, strict=False).version == 6 else "ipv4"
    except ValueError:
        raise FwError(f"Invalid address or network: {addr}") from None


def _rule(text: str) -> str:
    try:
        return richrule.normalize(text)
    except richrule.RuleError as e:
        raise FwError(f"Template produced an invalid rule ({e}): {text}") from None


def _rate(value: str) -> str:
    if not re.fullmatch(r"\d+/[smhd]", value.strip()):
        raise FwError("Rate must look like 10/m (per s, m, h or d)")
    return value.strip()


def build(template_id: str, params: dict) -> dict:
    t = _BY_ID.get(template_id)
    if not t:
        raise FwError(f"Unknown template {template_id}", 404)
    p = {x["name"]: x.get("default") for x in t["params"]}
    p.update({k: v for k, v in params.items() if v is not None})
    zone = str(p.get("zone") or "")
    if not zone:
        raise FwError("Choose a zone")
    op = lambda action, kind, **value: Op(action=action, kind=kind, zone=zone, value=value)
    steps, notes = [], []

    def has_service(name: str) -> bool:
        views = [firewall.zone(zone, cfg) for cfg in ("runtime", "permanent") if _exists(zone, cfg)]
        return any(name in v["services"] for v in views)

    match template_id:
        case "ssh-from-subnet":
            subnet = str(p.get("subnet") or "").strip()
            fam = _family(subnet)
            ops = [op("add", "rich-rule", rule=_rule(f'rule family="{fam}" source address="{subnet}" service name="ssh" accept'))]
            if p.get("remove_open") and has_service("ssh"):
                ops.append(op("remove", "service", name="ssh"))
            steps.append({"kind": "ops", "ops": ops})
            notes.append("Other networks can no longer reach SSH in this zone. Keep safe apply on if you are connected over SSH.")
        case "rate-limit-ssh":
            rate = _rate(str(p.get("rate") or "10/m"))
            ops = [op("add", "rich-rule", rule=_rule(f'rule service name="ssh" accept limit value="{rate}"'))]
            if p.get("log"):
                ops.append(op("add", "rich-rule", rule=_rule(
                    'rule priority="1" service name="ssh" log prefix="ssh-ratelimit: " level="info" limit value="1/m" drop')))
            if p.get("remove_open") and has_service("ssh"):
                ops.append(op("remove", "service", name="ssh"))
            steps.append({"kind": "ops", "ops": ops})
            notes.append("Connections over the limit are rejected by the zone target (or dropped and logged, if enabled).")
        case "block-country":
            cc = str(p.get("country") or "").strip().lower()
            fam = p.get("family") or "ipv4"
            text = str(p.get("addresses") or "").strip()
            if not text and not re.fullmatch(r"[a-z]{2}", cc):
                raise FwError("Enter a two-letter country code, or paste an address list")
            name = f"block-{cc or 'list'}-{'v6' if fam == 'ipv6' else 'v4'}"
            steps.append({"kind": "ipset-create", "name": name, "type": "hash:net",
                          "family": "inet6" if fam == "ipv6" else "inet",
                          "description": f"Blocked networks for {cc.upper() or 'custom list'} (richrule template)"})
            if text:
                entries, invalid = parse_address_list(text)
                if invalid:
                    raise FwError(f"Invalid entries: {', '.join(invalid[:5])}")
                steps.append({"kind": "ipset-fill", "name": name, "entries": entries})
            else:
                steps.append({"kind": "ipset-fill", "name": name, "url": COUNTRY_URLS[fam].format(cc=cc)})
            log = ' log prefix="geo-block: " level="info" limit value="1/m"' if p.get("log") else ""
            steps.append({"kind": "ops", "target": "permanent",
                          "ops": [op("add", "rich-rule", rule=_rule(f'rule family="{fam}" source ipset="{name}"{log} drop'))]})
            if p.get("reload"):
                steps.append({"kind": "reload"})
                notes.append("Reloading applies the permanent configuration and discards runtime-only changes.")
            else:
                notes.append("New IP sets only become active after a reload.")
        case "port-forward":
            port = str(p.get("port") or "").strip()
            to_addr = str(p.get("to_addr") or "").strip()
            if not port or not to_addr:
                raise FwError("Incoming port and destination address are required")
            fam = _family(to_addr)
            to_port = str(p.get("to_port") or "").strip()
            ops = [op("add", "rich-rule", rule=_rule(
                f'rule family="{fam}" forward-port port="{port}" protocol="{p.get("protocol") or "tcp"}"'
                + (f' to-port="{to_port}"' if to_port else "") + f' to-addr="{to_addr}"'))]
            if p.get("masquerade") and not _masq(zone):
                ops.append(op("add", "masquerade"))
            steps.append({"kind": "ops", "ops": ops})
            notes.append("Forwarding to another host needs IP forwarding (firewalld enables it with masquerading).")
        case "block-address":
            addr = str(p.get("address") or "").strip()
            fam = _family(addr)
            action = "reject" if p.get("action") == "reject" else "drop"
            log = ' log prefix="blocked: " level="info" limit value="1/m"' if p.get("log") else ""
            steps.append({"kind": "ops", "ops": [op("add", "rich-rule", rule=_rule(
                f'rule priority="-100" family="{fam}" source address="{addr}"{log} {action}'))]})
            notes.append("Priority -100 makes the block win over services and other allow rules.")
        case "allow-service-from":
            svc = str(p.get("service") or "").strip()
            src = str(p.get("source") or "").strip()
            if not svc or not src:
                raise FwError("Service and source are required")
            if src.startswith("ipset:"):
                rule = f'rule source ipset="{src[6:]}" service name="{svc}" accept'
            else:
                rule = f'rule family="{_family(src)}" source address="{src}" service name="{svc}" accept'
            steps.append({"kind": "ops", "ops": [op("add", "rich-rule", rule=_rule(rule))]})
        case "web-server":
            ops = [op("add", "service", name=s) for s in ("http", "https") if not has_service(s)]
            if p.get("http3") and not has_service("http3"):
                ops.append(op("add", "service", name="http3") if _service_exists("http3")
                           else op("add", "port", port="443", protocol="udp"))
            if not ops:
                raise FwError("The zone already allows these services")
            steps.append({"kind": "ops", "ops": ops})
    return {"template": template_id, "title": t["title"], "steps": steps, "notes": notes}


def _exists(zone: str, cfg: str) -> bool:
    return zone in firewall.zone_names(cfg)


def _masq(zone: str) -> bool:
    return any(firewall.zone(zone, cfg)["masquerade"] for cfg in ("runtime", "permanent") if _exists(zone, cfg))


def _service_exists(name: str) -> bool:
    return any(s["name"] == name for s in firewall.services())


def describe(plan: dict) -> list[str]:
    lines = []
    for s in plan["steps"]:
        if s["kind"] == "ops":
            where = f" [{s['target']}]" if s.get("target") else ""
            lines += [o.describe() + where for o in s["ops"]]
        elif s["kind"] == "ipset-create":
            lines.append(f"create IP set {s['name']} ({s['type']}, {s['family']}) [permanent]")
        elif s["kind"] == "ipset-fill":
            src = f"download {s['url']}" if s.get("url") else f"{len(s['entries'])} entries"
            lines.append(f"fill IP set {s['name']} from {src} [permanent]")
        elif s["kind"] == "reload":
            lines.append("reload firewalld")
    return lines


def download_list(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "richrule"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read(20_000_000).decode("utf-8", "replace")
    except Exception as e:
        raise FwError(f"Download failed ({url}): {e}", 502) from None
    entries, _ = parse_address_list(text)
    if not entries:
        raise FwError(f"No addresses found at {url}", 502)
    return entries


def run(plan: dict, target: str) -> list[str]:
    """Execute a plan (the caller wraps this in history.change). Returns a log of what happened."""
    done = []
    for s in plan["steps"]:
        if s["kind"] == "ops":
            ops = [o if isinstance(o, Op) else Op.model_validate(o) for o in s["ops"]]
            firewall.apply(ops, s.get("target") or target)
            done += [o.describe() for o in ops]
        elif s["kind"] == "ipset-create":
            if s["name"] not in firewall.call(lambda c: c.config().getIPSetNames()):
                firewall.create_ipset(s["name"], s["type"], s["family"], s.get("description", ""))
                done.append(f"created IP set {s['name']}")
        elif s["kind"] == "ipset-fill":
            entries = s.get("entries") or download_list(s["url"])
            firewall.call(lambda c: c.config().getIPSetByName(s["name"]).setEntries(entries))
            done.append(f"IP set {s['name']}: {len(entries)} entries")
        elif s["kind"] == "reload":
            firewall.reload()
            done.append("reloaded firewalld")
    return done
