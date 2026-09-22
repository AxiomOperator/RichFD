"""Structured rich rule model <-> firewalld rich rule strings.

firewalld's own ``Rich_Rule`` dataclasses do all validation: a structured rule is
converted into those objects, rendered to a string, and re-parsed so the result is
exactly what firewalld would accept and store.
"""

from typing import Annotated, Literal, Union

from firewall.core import rich as fwrich
from firewall.errors import FirewallError
from pydantic import BaseModel, Field


class RuleError(ValueError):
    """A rich rule failed firewalld's validation."""


class Limit(BaseModel):
    value: str  # e.g. "3/m"
    burst: int = 0


class Source(BaseModel):
    addr: str = ""
    mac: str = ""
    ipset: str = ""
    invert: bool = False


class Destination(BaseModel):
    addr: str = ""
    ipset: str = ""
    invert: bool = False


class ServiceElement(BaseModel):
    type: Literal["service"]
    name: str


class PortElement(BaseModel):
    type: Literal["port"]
    port: str
    protocol: str


class SourcePortElement(BaseModel):
    type: Literal["source-port"]
    port: str
    protocol: str


class ProtocolElement(BaseModel):
    type: Literal["protocol"]
    value: str


class IcmpBlockElement(BaseModel):
    type: Literal["icmp-block"]
    name: str


class IcmpTypeElement(BaseModel):
    type: Literal["icmp-type"]
    name: str


class MasqueradeElement(BaseModel):
    type: Literal["masquerade"]


class ForwardPortElement(BaseModel):
    type: Literal["forward-port"]
    port: str
    protocol: str
    to_port: str = ""
    to_addr: str = ""


class TcpMssClampElement(BaseModel):
    type: Literal["tcp-mss-clamp"]
    value: str = ""


Element = Annotated[
    Union[
        ServiceElement,
        PortElement,
        SourcePortElement,
        ProtocolElement,
        IcmpBlockElement,
        IcmpTypeElement,
        MasqueradeElement,
        ForwardPortElement,
        TcpMssClampElement,
    ],
    Field(discriminator="type"),
]


class LogSpec(BaseModel):
    type: Literal["log"]
    prefix: str = ""
    level: str = ""
    limit: Limit | None = None


class NFLogSpec(BaseModel):
    type: Literal["nflog"]
    group: int = 0
    prefix: str = ""
    threshold: int = 0
    limit: Limit | None = None


Log = Annotated[Union[LogSpec, NFLogSpec], Field(discriminator="type")]


class Audit(BaseModel):
    limit: Limit | None = None


class Action(BaseModel):
    type: Literal["accept", "reject", "drop", "mark"]
    reject_type: str = ""  # reject only, e.g. "icmp-host-prohibited"
    set: str = ""  # mark only, e.g. "0x1/0xff"
    limit: Limit | None = None


class RichRule(BaseModel):
    family: Literal["", "ipv4", "ipv6"] = ""
    priority: int = 0
    source: Source | None = None
    destination: Destination | None = None
    element: Element | None = None
    log: Log | None = None
    audit: Audit | None = None
    action: Action | None = None


def _limit(spec: Limit | None):
    return fwrich.Rich_Limit(spec.value, spec.burst) if spec else None


def _to_fw(rule: RichRule) -> fwrich.Rich_Rule:
    el = rule.element
    element = None
    match el:
        case ServiceElement():
            element = fwrich.Rich_Service(el.name)
        case PortElement():
            element = fwrich.Rich_Port(el.port, el.protocol)
        case SourcePortElement():
            element = fwrich.Rich_SourcePort(el.port, el.protocol)
        case ProtocolElement():
            element = fwrich.Rich_Protocol(el.value)
        case IcmpBlockElement():
            element = fwrich.Rich_IcmpBlock(el.name)
        case IcmpTypeElement():
            element = fwrich.Rich_IcmpType(el.name)
        case MasqueradeElement():
            element = fwrich.Rich_Masquerade()
        case ForwardPortElement():
            element = fwrich.Rich_ForwardPort(el.port, el.protocol, el.to_port, el.to_addr)
        case TcpMssClampElement():
            element = fwrich.Rich_Tcp_Mss_Clamp(el.value)

    log = None
    match rule.log:
        case LogSpec() as lg:
            log = fwrich.Rich_Log(lg.prefix, lg.level, _limit(lg.limit))
        case NFLogSpec() as lg:
            log = fwrich.Rich_NFLog(lg.group, lg.prefix, lg.threshold, _limit(lg.limit))

    action = None
    if a := rule.action:
        limit = _limit(a.limit)
        action = {
            "accept": lambda: fwrich.Rich_Accept(limit),
            "reject": lambda: fwrich.Rich_Reject(a.reject_type, limit),
            "drop": lambda: fwrich.Rich_Drop(limit),
            "mark": lambda: fwrich.Rich_Mark(a.set, limit),
        }[a.type]()

    src = rule.source
    dst = rule.destination
    return fwrich.Rich_Rule(
        family=rule.family,
        priority=rule.priority,
        source=fwrich.Rich_Source(src.addr, src.mac, src.ipset, src.invert) if src else None,
        destination=fwrich.Rich_Destination(dst.addr, dst.ipset, dst.invert) if dst else None,
        element=element,
        log=log,
        audit=fwrich.Rich_Audit(_limit(rule.audit.limit)) if rule.audit else None,
        action=action,
    )


def _limit_from(lim) -> Limit | None:
    return Limit(value=f"{lim.rate}/{lim.duration}", burst=lim.burst) if lim else None


def _from_fw(r: fwrich.Rich_Rule) -> RichRule:
    element = None
    match r.element:
        case fwrich.Rich_Service(name=name):
            element = ServiceElement(type="service", name=name)
        case fwrich.Rich_Port(port=port, protocol=proto):
            element = PortElement(type="port", port=port, protocol=proto)
        case fwrich.Rich_SourcePort(port=port, protocol=proto):
            element = SourcePortElement(type="source-port", port=port, protocol=proto)
        case fwrich.Rich_Protocol(value=value):
            element = ProtocolElement(type="protocol", value=value)
        case fwrich.Rich_IcmpBlock(name=name):
            element = IcmpBlockElement(type="icmp-block", name=name)
        case fwrich.Rich_IcmpType(name=name):
            element = IcmpTypeElement(type="icmp-type", name=name)
        case fwrich.Rich_Masquerade():
            element = MasqueradeElement(type="masquerade")
        case fwrich.Rich_ForwardPort() as fp:
            element = ForwardPortElement(
                type="forward-port",
                port=fp.port,
                protocol=fp.protocol,
                to_port=fp.to_port or "",
                to_addr=fp.to_address or "",
            )
        case fwrich.Rich_Tcp_Mss_Clamp(value=value):
            element = TcpMssClampElement(type="tcp-mss-clamp", value=value or "")

    log = None
    match r.log:
        case fwrich.Rich_Log() as lg:
            log = LogSpec(
                type="log", prefix=lg.prefix or "", level=lg.level or "", limit=_limit_from(lg.limit)
            )
        case fwrich.Rich_NFLog() as lg:
            log = NFLogSpec(
                type="nflog",
                group=lg.group,
                prefix=lg.prefix or "",
                threshold=lg.threshold,
                limit=_limit_from(lg.limit),
            )

    action = None
    match r.action:
        case fwrich.Rich_Accept() as a:
            action = Action(type="accept", limit=_limit_from(a.limit))
        case fwrich.Rich_Reject() as a:
            action = Action(type="reject", reject_type=a.type or "", limit=_limit_from(a.limit))
        case fwrich.Rich_Drop() as a:
            action = Action(type="drop", limit=_limit_from(a.limit))
        case fwrich.Rich_Mark() as a:
            action = Action(type="mark", set=a.set, limit=_limit_from(a.limit))

    src, dst = r.source, r.destination
    return RichRule(
        family=r.family or "",
        priority=r.priority or 0,
        source=Source(addr=src.addr, mac=src.mac, ipset=src.ipset, invert=src.invert)
        if src
        else None,
        destination=Destination(addr=dst.addr, ipset=dst.ipset, invert=dst.invert)
        if dst
        else None,
        element=element,
        log=log,
        audit=Audit(limit=_limit_from(r.audit.limit)) if r.audit else None,
        action=action,
    )


def parse(rule_str: str) -> RichRule:
    """Parse and validate a rich rule string."""
    try:
        return _from_fw(fwrich.Rich_Rule(rule_str=rule_str))
    except FirewallError as e:
        raise RuleError(str(e)) from None


def normalize(rule_str: str) -> str:
    """Validate a rich rule string and return firewalld's canonical form."""
    try:
        return str(fwrich.Rich_Rule(rule_str=rule_str))
    except FirewallError as e:
        raise RuleError(str(e)) from None


def render(rule: RichRule) -> str:
    """Render a structured rule to a validated, canonical rich rule string."""
    try:
        text = str(_to_fw(rule))
    except FirewallError as e:
        raise RuleError(str(e)) from None
    # Re-parse to run firewalld's whole-rule checks (element/action compatibility etc.).
    return normalize(text)
