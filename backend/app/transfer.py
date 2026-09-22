"""Import and export of firewalld configuration.

- JSON bundle: zones, policies, services and IP sets (permanent settings) in one document.
- XML: one zone / policy / service / IP set in firewalld's native file format, generated and
  parsed with firewalld's own io writers/readers.
- tar.gz of /etc/firewalld (needs read access, i.e. running as root).
- Plain-text address lists into an IP set.
"""

import io
import ipaddress
import re
import socket
import tarfile
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree

from firewall.core.io.ipset import IPSet, ipset_reader, ipset_writer
from firewall.core.io.policy import Policy, policy_reader, policy_writer
from firewall.core.io.service import Service, service_reader, service_writer
from firewall.core.io.zone import Zone, zone_reader, zone_writer
from firewall.errors import FirewallError

from .config import settings
from .fw import FwError, firewall

FORMAT = "richrule-export"
KINDS = ("zones", "policies", "services", "ipsets")
_DEFAULT_ZONE_TARGET = "{chain}_{zone}"


# -- export ----------------------------------------------------------------------------


def export_bundle(zones: list[str] | None = None, sections: list[str] | None = None) -> dict:
    sections = sections or list(KINDS)
    bundle: dict = {
        "format": FORMAT,
        "version": 1,
        "host": socket.gethostname(),
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "default_zone": firewall.status()["default_zone"],
    }
    if "zones" in sections:
        names = zones or firewall.zone_names("permanent")
        bundle["zones"] = {z: _clean(firewall.raw_zone(z)) for z in names}
    if "policies" in sections:
        bundle["policies"] = {p: _clean(firewall.raw_policy(p)) for p in firewall.policy_names("permanent")}
    if "services" in sections:
        # Only custom or locally modified services; shipped ones exist everywhere already.
        bundle["services"] = {
            s["name"]: _clean(firewall.raw_service(s["name"]))
            for s in firewall.services()
            if not s.get("builtin") or s.get("modified")
        }
    if "ipsets" in sections:
        bundle["ipsets"] = {i["name"]: firewall.raw_ipset(i["name"]) for i in firewall.ipsets("permanent")}
    return bundle


def _clean(d: dict) -> dict:
    return {k: ([list(x) for x in v] if isinstance(v, list) and v and isinstance(v[0], tuple) else v)
            for k, v in d.items() if k not in ("UNUSED", "version")}


def export_xml(kind: str, name: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        if kind == "zone":
            obj, conf, writer = Zone(), firewall.raw_zone(name), zone_writer
            if conf.get("target") == "default":
                conf["target"] = _DEFAULT_ZONE_TARGET
        elif kind == "policy":
            obj, conf, writer = Policy(), firewall.raw_policy(name), policy_writer
        elif kind == "service":
            obj, conf, writer = Service(), firewall.raw_service(name), service_writer
        elif kind == "ipset":
            raw = firewall.raw_ipset(name)
            obj, writer = IPSet(), ipset_writer
            conf = {"short": raw["short"], "description": raw["description"], "type": raw["type"],
                    "options": raw["options"], "entries": raw["entries"]}
        else:
            raise FwError(f"Unknown kind {kind}")
        for k, v in conf.items():
            if k != "UNUSED":
                setattr(obj, k, v)
        obj.name, obj.filename, obj.path = name, f"{name}.xml", d
        writer(obj)
        return (Path(d) / f"{name}.xml").read_text()


def export_tarball() -> bytes:
    root = settings.firewalld_dir
    try:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(root, arcname="firewalld")
        return buf.getvalue()
    except PermissionError:
        raise FwError(f"Cannot read {root}; the full-config archive needs richrule to run as root", 503) from None


# -- import ----------------------------------------------------------------------------


def parse_xml(filename: str, content: bytes) -> dict:
    """Parse one firewalld XML file into a bundle with a single object."""
    name = Path(filename).name
    if name.endswith(".xml"):
        name = name[:-4]
    if not name:
        raise FwError("File name is required to name the imported object (e.g. myzone.xml)")
    try:
        root = ElementTree.fromstring(content).tag
    except ElementTree.ParseError as e:
        raise FwError(f"Not valid XML: {e}") from None
    readers = {"zone": (zone_reader, "zones"), "policy": (policy_reader, "policies"),
               "service": (service_reader, "services"), "ipset": (ipset_reader, "ipsets")}
    if root not in readers:
        raise FwError(f"Unsupported XML root element <{root}> (expected zone, policy, service or ipset)")
    reader, section = readers[root]
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / f"{name}.xml").write_bytes(content)
        try:
            obj = reader(f"{name}.xml", d)
        except FirewallError as e:
            raise FwError(f"Invalid {root} file: {e}") from None
        conf = obj.export_config_dict()
    if root == "zone" and _DEFAULT_ZONE_TARGET in str(conf.get("target", "")):
        conf["target"] = "default"
    if root == "ipset":
        conf = {"short": conf.get("short", ""), "description": conf.get("description", ""),
                "type": conf.get("type", ""), "options": conf.get("options", {}), "entries": conf.get("entries", [])}
    return {"format": FORMAT, "version": 1, section: {name: _clean(conf)}}


def validate_bundle(bundle: dict) -> dict:
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        raise FwError(f"Not a {FORMAT} document")
    for k in KINDS:
        if k in bundle and not isinstance(bundle[k], dict):
            raise FwError(f"'{k}' must be an object mapping names to settings")
    return bundle


def _current(kind: str, name: str) -> dict | None:
    try:
        return {"zones": firewall.raw_zone, "policies": firewall.raw_policy,
                "services": firewall.raw_service, "ipsets": firewall.raw_ipset}[kind](name)
    except FwError:
        return None


def preview(bundle: dict) -> list[dict]:
    """What importing the bundle would do, per object."""
    validate_bundle(bundle)
    plan = []
    for kind in KINDS:
        for name, conf in bundle.get(kind, {}).items():
            cur = _current(kind, name)
            if cur is None:
                plan.append({"kind": kind, "name": name, "action": "create", "changes": sorted(conf)})
                continue
            cur = _clean(cur)
            changed = sorted(k for k in conf if _norm(conf.get(k)) != _norm(cur.get(k)))
            plan.append({"kind": kind, "name": name, "action": "update" if changed else "unchanged", "changes": changed})
    return plan


def _norm(v):
    if isinstance(v, list):
        return sorted(repr(list(x) if isinstance(x, (list, tuple)) else x) for x in v)
    return v


def apply_bundle(bundle: dict, only: list[str] | None = None) -> list[dict]:
    """Create/replace objects in the permanent config. ``only`` limits to 'kind/name' keys."""
    validate_bundle(bundle)
    put = {"zones": firewall.put_zone, "policies": firewall.put_policy,
           "services": firewall.put_service, "ipsets": firewall.put_ipset}
    results = []
    # Services and IP sets first: zones and policies may reference them.
    for kind in ("services", "ipsets", "zones", "policies"):
        for name, conf in bundle.get(kind, {}).items():
            if only is not None and f"{kind}/{name}" not in only:
                continue
            try:
                results.append({"kind": kind, "name": name, "result": put[kind](name, conf)})
            except FwError as e:
                results.append({"kind": kind, "name": name, "result": "error", "error": e.message})
    return results


# -- IP set lists ----------------------------------------------------------------------


def parse_address_list(text: str) -> tuple[list[str], list[str]]:
    """Addresses/networks from a text or CSV list. Returns (valid, invalid).

    Accepts one entry per line, or CSV/TSV with addresses in any column; '#' and ';'
    start comments. Words (CSV headers, hostnames, labels) are ignored; only tokens that look
    like addresses but don't parse are reported as invalid.
    """
    valid, invalid = [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        for token in re.split(r"[\s,\t|]+", line):
            token = token.strip().strip('"\'')
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
                valid.append(str(net.network_address) if net.num_addresses == 1 else str(net))
            except ValueError:
                if re.fullmatch(r"[0-9a-fA-F.:/]+", token) and re.search(r"\d", token) and re.search(r"[.:]", token):
                    invalid.append(token)
    return list(dict.fromkeys(valid)), invalid
