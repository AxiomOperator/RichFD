"""'Why is this blocked?' — simulate how firewalld handles a new incoming connection.

This models firewalld's nftables INPUT path for traffic addressed to this host:

1. zone selection: a zone whose sources match the packet's source address (by ingress
   priority), else the zone bound to the incoming interface, else the default zone;
2. policies with ingress = that zone (or ANY) and egress = HOST (or ANY) and negative priority;
3. the zone: rich rules with priority < 0, then priority-0 rich rules in firewalld's
   order (log → deny → allow, where services / ports / protocols / source ports / ICMP
   live in "allow"), then rich rules with priority > 0;
4. policies with positive priority;
5. the zone target (default = reject, except ICMP which is allowed).

Forward-ports are applied before INPUT (DNAT), so a match there is reported as a redirect.
It is a best-effort model, not a packet tracer: things firewalld cannot see from its own
config (NetworkManager rules, other nftables tables, conntrack state) are not considered.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field

from .fw import FwError, firewall

PROTO_NUMBERS = {"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "ipv6-icmp": 58,
                 "icmpv6": 58, "ospf": 89, "vrrp": 112, "sctp": 132, "dccp": 33}
PORT_PROTOS = ("tcp", "udp", "sctp", "dccp")


class Packet(BaseModel):
    src: str
    protocol: str = "tcp"
    dst_port: int | None = Field(None, ge=0, le=65535)
    src_port: int | None = Field(None, ge=0, le=65535)
    dst: str = ""
    interface: str = ""
    icmp_type: str = ""
    config: Literal["runtime", "permanent"] = "runtime"


@dataclass
class Snapshot:
    """Everything the evaluator needs, in richrule's view format (see fw._zone_view)."""

    zones: dict[str, dict]
    policies: dict[str, dict]
    default_zone: str
    services: dict[str, dict]
    ipsets: dict[str, list[str]]
    active_policies: set[str] = field(default_factory=set)


def load_snapshot(config: str = "runtime") -> Snapshot:
    zones = {z: firewall.zone(z, config) for z in firewall.zone_names(config)}
    policies = {}
    for p in firewall.policy_names(config):
        try:
            policies[p] = firewall.policy(p, config)
        except FwError:
            pass
    services = {s["name"]: s for s in firewall.services()}  # cached; parsed from XML
    ipsets = {s["name"]: s["entries"] for s in firewall.ipsets(config)}
    status = firewall.status()
    return Snapshot(zones, policies, status["default_zone"], services, ipsets)


# -- helpers --------------------------------------------------------------------------


def _net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _ip_in(ip, value: str, ipsets: dict[str, list[str]]) -> bool | None:
    """Does ``ip`` match an address, network or ``ipset:name``? None = cannot tell (e.g. MAC)."""
    if value.startswith("ipset:"):
        return _ip_in_ipset(ip, value[6:], ipsets)
    net = _net(value)
    if net is None:
        return None  # MAC address or something we cannot evaluate
    return ip.version == net.version and ip in net


def _ip_in_ipset(ip, name: str, ipsets: dict[str, list[str]]) -> bool | None:
    if name not in ipsets:
        return None
    for entry in ipsets[name]:
        first = entry.split(",")[0]  # hash:ip,port etc.: match on the address part
        net = _net(first)
        if net is not None and ip.version == net.version and ip in net:
            return True
    return False


def _port_in(port: int | None, spec: str) -> bool | None:
    if port is None:
        return None
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return int(lo) <= port <= int(hi)
    return port == int(spec)


def _proto_eq(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    na = PROTO_NUMBERS.get(a, int(a) if a.isdigit() else None)
    nb = PROTO_NUMBERS.get(b, int(b) if b.isdigit() else None)
    return na is not None and na == nb


def _is_icmp(proto: str) -> bool:
    return proto.lower() in ("icmp", "ipv6-icmp", "icmpv6", "1", "58")


class Evaluator:
    def __init__(self, snap: Snapshot, pkt: Packet):
        self.s = snap
        self.p = pkt
        try:
            self.ip = ipaddress.ip_address(pkt.src)
        except ValueError:
            raise FwError(f"Invalid source address: {pkt.src}") from None
        self.dst = None
        if pkt.dst:
            try:
                self.dst = ipaddress.ip_address(pkt.dst)
            except ValueError:
                raise FwError(f"Invalid destination address: {pkt.dst}") from None
        self.family = "ipv4" if self.ip.version == 4 else "ipv6"
        self.steps: list[dict] = []
        self.notes: list[str] = []

    def step(self, stage: str, item: str, result: str, detail: str = "", verdict: str | None = None):
        self.steps.append({"stage": stage, "item": item, "result": result, "detail": detail, "verdict": verdict})

    # -- matching ---------------------------------------------------------------

    def _match_service(self, name: str) -> tuple[bool | None, str]:
        svc = self.s.services.get(name)
        if not svc:
            return False, f"service {name} not defined"
        proto = self.p.protocol
        for port in svc.get("ports", []):
            if _proto_eq(port["protocol"], proto) and proto in PORT_PROTOS:
                m = _port_in(self.p.dst_port, port["port"])
                if m:
                    return True, f"{name} includes {port['port']}/{port['protocol']}"
                if m is None:
                    return None, f"{name} opens {port['port']}/{port['protocol']} (no destination port given)"
        for pr in svc.get("protocols", []):
            if _proto_eq(pr, proto):
                return True, f"{name} includes protocol {pr}"
        for port in svc.get("source_ports", []):
            if _proto_eq(port["protocol"], proto):
                m = _port_in(self.p.src_port, port["port"])
                if m:
                    return True, f"{name} includes source port {port['port']}/{port['protocol']}"
        return False, ""

    def _match_port(self, port: str, protocol: str, src: bool = False) -> bool | None:
        if not _proto_eq(protocol, self.p.protocol):
            return False
        return _port_in(self.p.src_port if src else self.p.dst_port, port)

    def match_rule(self, parsed: dict) -> tuple[bool | None, str]:
        """True/False, or None when it depends on something we don't know."""
        if parsed.get("family") and parsed["family"] != self.family:
            return False, f"family {parsed['family']}"
        unknown = []
        if src := parsed.get("source"):
            if src.get("mac"):
                m = None
                unknown.append("source MAC")
            elif src.get("ipset"):
                m = _ip_in_ipset(self.ip, src["ipset"], self.s.ipsets)
            else:
                m = _ip_in(self.ip, src["addr"], self.s.ipsets)
            if m is not None and src.get("invert"):
                m = not m
            if m is False:
                return False, "source does not match"
            if m is None and not src.get("mac"):
                unknown.append("source ipset contents")
        if dst := parsed.get("destination"):
            if self.dst is None:
                unknown.append("destination address")
            else:
                if dst.get("ipset"):
                    m = _ip_in_ipset(self.dst, dst["ipset"], self.s.ipsets)
                else:
                    m = _ip_in(self.dst, dst["addr"], self.s.ipsets)
                if m is not None and dst.get("invert"):
                    m = not m
                if m is False:
                    return False, "destination does not match"
        el = parsed.get("element")
        if el:
            t = el["type"]
            if t == "service":
                m, why = self._match_service(el["name"])
            elif t == "port":
                m, why = self._match_port(el["port"], el["protocol"]), f"port {el['port']}/{el['protocol']}"
            elif t == "source-port":
                m, why = self._match_port(el["port"], el["protocol"], src=True), f"source port {el['port']}/{el['protocol']}"
            elif t == "protocol":
                m, why = _proto_eq(el["value"], self.p.protocol), f"protocol {el['value']}"
            elif t in ("icmp-block", "icmp-type"):
                if not _is_icmp(self.p.protocol):
                    m, why = False, "not ICMP"
                elif not self.p.icmp_type:
                    m, why = None, "ICMP type not given"
                else:
                    m, why = el["name"] == self.p.icmp_type, f"icmp type {el['name']}"
            else:  # masquerade, forward-port, tcp-mss-clamp: not part of the INPUT decision
                return False, f"{t} does not filter incoming traffic"
            if m is False:
                return False, "element does not match"
            if m is None:
                unknown.append(why)
        if unknown:
            return None, "depends on " + ", ".join(unknown)
        return True, ""

    @staticmethod
    def _verdict_of(parsed: dict) -> str | None:
        a = parsed.get("action")
        if not a:
            el = parsed.get("element") or {}
            return "REJECT" if el.get("type") == "icmp-block" else None
        return {"accept": "ACCEPT", "reject": "REJECT", "drop": "DROP"}.get(a["type"])

    def _run_rules(self, stage: str, rules: list[dict]) -> tuple[str, str] | None:
        for r in rules:
            parsed = r.get("parsed")
            if not parsed:
                self.step(stage, r["rule"], "unknown", "could not parse rule")
                continue
            m, why = self.match_rule(parsed)
            verdict = self._verdict_of(parsed)
            if m is True:
                logs = " (logged)" if parsed.get("log") or parsed.get("audit") else ""
                if verdict:
                    self.step(stage, r["rule"], "match", f"verdict {verdict}{logs}", verdict)
                    return verdict, r["rule"]
                self.step(stage, r["rule"], "match", f"no terminal action{logs}; continuing")
            elif m is None:
                self.step(stage, r["rule"], "unknown", why)
                self.notes.append(f"Rule might match ({why}): {r['rule']}")
            else:
                self.step(stage, r["rule"], "no-match", why)
        return None

    # -- zone selection ---------------------------------------------------------------

    def pick_zone(self) -> tuple[str, str]:
        candidates = []
        for name, z in self.s.zones.items():
            for src in z.get("sources", []):
                m = _ip_in(self.ip, src, self.s.ipsets)
                if m:
                    candidates.append((z.get("ingress_priority", 0), name, src))
        if candidates:
            candidates.sort()
            prio, name, src = candidates[0]
            others = [c[1] for c in candidates[1:]]
            extra = f" (also matched by {', '.join(others)}, lower precedence)" if others else ""
            return name, f"source {self.p.src} matches binding {src}{extra}"
        if self.p.interface:
            for name, z in self.s.zones.items():
                if self.p.interface in z.get("interfaces", []):
                    return name, f"interface {self.p.interface} is bound to zone {name}"
            return self.s.default_zone, f"interface {self.p.interface} is not bound to a zone → default zone"
        return self.s.default_zone, "no source binding matches and no interface given → default zone"

    # -- the walk ----------------------------------------------------------------------

    def _policies(self, zone: str, negative: bool) -> list[tuple[str, dict]]:
        out = []
        for name, p in self.s.policies.items():
            if p.get("disable"):
                continue
            ing, egr = p.get("ingress_zones", []), p.get("egress_zones", [])
            if not ((zone in ing or "ANY" in ing) and ("HOST" in egr or "ANY" in egr)):
                continue
            prio = p.get("priority", -1)
            if (prio < 0) == negative:
                out.append((name, p))
        return sorted(out, key=lambda x: x[1].get("priority", -1))

    def _run_policy(self, name: str, p: dict) -> tuple[str, str] | None:
        stage = f"policy {name} (priority {p.get('priority')})"
        if hit := self._zone_body(stage, p, is_policy=True):
            return hit
        target = p.get("target", "CONTINUE")
        if target in ("ACCEPT", "REJECT", "DROP"):
            self.step(stage, f"target {target}", "match", f"policy target {target}", target)
            return target, f"policy {name} target {target}"
        self.step(stage, "target CONTINUE", "no-match", "continue to next stage")
        return None

    def _zone_body(self, stage: str, z: dict, is_policy: bool = False) -> tuple[str, str] | None:
        rules = z.get("rich_rules", [])
        by_prio = lambda cond: sorted((r for r in rules if r.get("parsed") and cond(r["parsed"].get("priority", 0))),
                                      key=lambda r: r["parsed"].get("priority", 0))
        unparsed = [r for r in rules if not r.get("parsed")]
        if hit := self._run_rules(f"{stage} · rich rules (priority < 0)", by_prio(lambda p: p < 0)):
            return hit
        zero = by_prio(lambda p: p == 0) + unparsed
        log_rules = [r for r in zero if r.get("parsed") and not self._verdict_of(r["parsed"])]
        deny = [r for r in zero if r.get("parsed") and self._verdict_of(r["parsed"]) in ("REJECT", "DROP")]
        allow = [r for r in zero if r.get("parsed") and self._verdict_of(r["parsed"]) == "ACCEPT"]
        self._run_rules(f"{stage} · log rules", log_rules)
        if hit := self._run_rules(f"{stage} · deny rules", deny):
            return hit
        # ICMP blocks (deny stage)
        if _is_icmp(self.p.protocol) and self.p.icmp_type:
            blocks = z.get("icmp_blocks", [])
            inverted = z.get("icmp_block_inversion", False)
            blocked = (self.p.icmp_type in blocks) != inverted
            if blocked:
                why = "not in the allowed list (inversion on)" if inverted else "in icmp-blocks"
                self.step(f"{stage} · icmp blocks", self.p.icmp_type, "match", why, "REJECT")
                return "REJECT", f"icmp-block {self.p.icmp_type}"
        # allow stage
        for svc in z.get("services", []):
            m, why = self._match_service(svc)
            if m:
                self.step(f"{stage} · services", svc, "match", why, "ACCEPT")
                return "ACCEPT", f"service {svc}"
            if m is None:
                self.step(f"{stage} · services", svc, "unknown", why)
                self.notes.append(why)
        for p in z.get("ports", []):
            if self._match_port(p["port"], p["protocol"]):
                self.step(f"{stage} · ports", f"{p['port']}/{p['protocol']}", "match", "", "ACCEPT")
                return "ACCEPT", f"port {p['port']}/{p['protocol']}"
        for pr in z.get("protocols", []):
            if _proto_eq(pr, self.p.protocol):
                self.step(f"{stage} · protocols", pr, "match", "", "ACCEPT")
                return "ACCEPT", f"protocol {pr}"
        for p in z.get("source_ports", []):
            if self._match_port(p["port"], p["protocol"], src=True):
                self.step(f"{stage} · source ports", f"{p['port']}/{p['protocol']}", "match", "", "ACCEPT")
                return "ACCEPT", f"source port {p['port']}/{p['protocol']}"
        checked = len(z.get("services", [])) + len(z.get("ports", [])) + len(z.get("protocols", []))
        if checked:
            self.step(f"{stage} · services/ports", f"{checked} entries checked", "no-match", "nothing opens this traffic")
        if hit := self._run_rules(f"{stage} · allow rules", allow):
            return hit
        if hit := self._run_rules(f"{stage} · rich rules (priority > 0)", by_prio(lambda p: p > 0)):
            return hit
        return None

    def run(self) -> dict:
        zone, reason = self.pick_zone()
        z = self.s.zones.get(zone)
        if z is None:
            raise FwError(f"Zone {zone} not found in {self.p.config} configuration", 404)
        self.step("zone selection", zone, "match", reason)

        # DNAT happens before filtering.
        for fp in z.get("forward_ports", []):
            if self._match_port(fp["port"], fp["protocol"]):
                dest = f"{fp.get('to_addr') or 'this host'}:{fp.get('to_port') or fp['port']}"
                self.step("forward ports (prerouting)", f"{fp['port']}/{fp['protocol']} → {dest}", "match",
                          "packet is redirected before the INPUT filter", "FORWARDED" if fp.get("to_addr") else None)
                if fp.get("to_addr"):
                    return self._result(zone, reason, "FORWARDED", f"forward-port {fp['port']}/{fp['protocol']} → {dest}")
                self.notes.append(f"Port redirected locally to {dest}; the filter sees the new port.")
                if fp.get("to_port"):
                    self.p = self.p.model_copy(update={"dst_port": int(fp["to_port"].split("-")[0])})

        for name, p in self._policies(zone, negative=True):
            if hit := self._run_policy(name, p):
                return self._result(zone, reason, *hit)
        if hit := self._zone_body(f"zone {zone}", z):
            return self._result(zone, reason, *hit)
        for name, p in self._policies(zone, negative=False):
            if hit := self._run_policy(name, p):
                return self._result(zone, reason, *hit)

        target = z.get("target", "default")
        if target == "ACCEPT":
            verdict, by = "ACCEPT", f"zone {zone} target ACCEPT"
        elif target == "DROP":
            verdict, by = "DROP", f"zone {zone} target DROP"
        elif _is_icmp(self.p.protocol) and target == "default":
            verdict, by = "ACCEPT", f"zone {zone} target default allows ICMP"
        else:
            verdict, by = "REJECT", f"zone {zone} target {'REJECT' if target == '%%REJECT%%' else 'default (reject)'}"
        self.step(f"zone {zone} · target", target, "match", by, verdict)
        return self._result(zone, reason, verdict, by)

    def _result(self, zone: str, reason: str, verdict: str, by: str) -> dict:
        return {
            "zone": zone,
            "zone_reason": reason,
            "verdict": verdict,
            "decided_by": by,
            "steps": self.steps,
            "notes": list(dict.fromkeys(self.notes)),
            "packet": self.p.model_dump(),
        }


def evaluate(pkt: Packet, snap: Snapshot | None = None) -> dict:
    return Evaluator(snap or load_snapshot(pkt.config), pkt).run()
