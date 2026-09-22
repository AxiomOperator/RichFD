"""Thin wrapper over firewalld's D-Bus client.

Every change is expressed as an ``Op`` (add/remove one item of one kind in one zone)
so that changes can be batched, applied to runtime and/or permanent config, audited,
and undone generically.
"""

import threading
from dataclasses import dataclass
from typing import Any, Callable, Literal

import dbus
from firewall.client import FirewallClient, FirewallClientIPSetSettings, FirewallClientZoneSettings
from firewall.errors import FirewallError
from pydantic import BaseModel

from . import richrule

Config = Literal["runtime", "permanent"]
Target = Literal["runtime", "permanent", "both"]

# firewalld error codes that mean "request conflicts with current state".
_CONFLICT_CODES = ("ALREADY_ENABLED", "NOT_ENABLED", "ZONE_CONFLICT", "NAME_CONFLICT", "ALREADY_SET")


class FwError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def _wrap_error(e: Exception) -> FwError:
    if isinstance(e, dbus.exceptions.DBusException):
        msg = e.get_dbus_message() or str(e)
        name = e.get_dbus_name() or ""
        if "NotAuthorized" in name or "AccessDenied" in name:
            return FwError(f"Not authorized by firewalld: {msg}", 403)
        if "org.freedesktop.DBus.Error" in name:
            return FwError(f"D-Bus error: {msg}", 503)
    else:
        try:
            msg = str(e)
        except Exception:  # FirewallError.__str__ fails on unknown codes
            msg = getattr(e, "msg", None) or repr(e)
    status = 409 if msg.split(":", 1)[0].strip() in _CONFLICT_CODES else 400
    return FwError(msg, status)


# kind -> (method suffix, value fields in call order, runtime call accepts timeout)
KINDS: dict[str, tuple[str, tuple[str, ...], bool]] = {
    "service": ("Service", ("name",), True),
    "port": ("Port", ("port", "protocol"), True),
    "protocol": ("Protocol", ("value",), True),
    "source-port": ("SourcePort", ("port", "protocol"), True),
    "forward-port": ("ForwardPort", ("port", "protocol", "to_port", "to_addr"), True),
    "icmp-block": ("IcmpBlock", ("name",), True),
    "rich-rule": ("RichRule", ("rule",), True),
    "interface": ("Interface", ("name",), False),
    "source": ("Source", ("value",), False),
    "masquerade": ("Masquerade", (), True),
    "forward": ("Forward", (), True),
    "icmp-block-inversion": ("IcmpBlockInversion", (), False),
}

Kind = Literal[
    "service",
    "port",
    "protocol",
    "source-port",
    "forward-port",
    "icmp-block",
    "rich-rule",
    "interface",
    "source",
    "masquerade",
    "forward",
    "icmp-block-inversion",
]


class Op(BaseModel):
    action: Literal["add", "remove"]
    kind: Kind
    zone: str
    value: dict[str, Any] = {}

    def inverse(self) -> "Op":
        return self.model_copy(update={"action": "remove" if self.action == "add" else "add"})

    def describe(self) -> str:
        vals = " ".join(str(v) for v in self.value.values() if v != "")
        return f"{self.action} {self.kind} {vals} (zone {self.zone})".replace("  ", " ")


def _args(op: Op) -> list[str]:
    _, fields, _ = KINDS[op.kind]
    try:
        args = [str(op.value.get(f, "") if f in ("to_port", "to_addr") else op.value[f]) for f in fields]
    except KeyError as e:
        raise FwError(f"{op.kind}: missing field {e.args[0]!r}") from None
    if op.kind == "rich-rule":
        try:
            args = [richrule.normalize(args[0])]
        except richrule.RuleError as e:
            raise FwError(f"Invalid rich rule: {e}") from None
    return args


@dataclass
class Applied:
    op: Op
    config: Config


def _ports(pairs) -> list[dict]:
    return [{"port": p, "protocol": proto} for p, proto in pairs]


def _zone_view(s: dict) -> dict:
    rules = []
    for text in s.get("rules_str", []):
        try:
            parsed = richrule.parse(text).model_dump()
        except richrule.RuleError:
            parsed = None
        rules.append({"rule": text, "parsed": parsed})
    return {
        "short": s.get("short", ""),
        "description": s.get("description", ""),
        "target": s.get("target", "default"),
        "services": sorted(s.get("services", [])),
        "ports": _ports(s.get("ports", [])),
        "protocols": s.get("protocols", []),
        "source_ports": _ports(s.get("source_ports", [])),
        "forward_ports": [
            {"port": p, "protocol": proto, "to_port": tp, "to_addr": ta}
            for p, proto, tp, ta in s.get("forward_ports", [])
        ],
        "icmp_blocks": s.get("icmp_blocks", []),
        "icmp_block_inversion": bool(s.get("icmp_block_inversion", False)),
        "masquerade": bool(s.get("masquerade", False)),
        "forward": bool(s.get("forward", False)),
        "interfaces": s.get("interfaces", []),
        "sources": s.get("sources", []),
        "rich_rules": rules,
        "ingress_priority": s.get("ingress_priority", 0),
        "egress_priority": s.get("egress_priority", 0),
    }


class Firewall:
    """Serializes all D-Bus access; dbus-python proxies are not thread-safe."""

    def __init__(self, client_factory: Callable[[], Any] = FirewallClient):
        self._factory = client_factory
        self._client = None
        self.lock = threading.RLock()

    # -- plumbing ---------------------------------------------------------

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = self._factory()
            except (FirewallError, dbus.exceptions.DBusException) as e:
                raise FwError(f"Cannot connect to firewalld: {e}", 503) from None
        return self._client

    def call(self, fn: Callable[[Any], Any]) -> Any:
        """Run ``fn(client)`` under the lock, translating firewalld errors."""
        with self.lock:
            try:
                return fn(self.client)
            except FwError:
                raise
            except dbus.exceptions.DBusException as e:
                if "org.freedesktop.DBus.Error" in (e.get_dbus_name() or ""):
                    self._client = None  # firewalld restarted; reconnect next time
                raise _wrap_error(e) from None
            except FirewallError as e:
                raise _wrap_error(e) from None

    # -- reads ------------------------------------------------------------

    def status(self) -> dict:
        def f(c):
            return {
                "version": str(c.get_property("version")),
                "state": str(c.get_property("state")),
                "default_zone": c.getDefaultZone(),
                "panic_mode": bool(c.queryPanicMode()),
                "log_denied": c.getLogDenied(),
                "active_zones": c.getActiveZones(),
            }

        return self.call(f)

    def zone_names(self, config: Config) -> list[str]:
        if config == "runtime":
            return sorted(self.call(lambda c: c.getZones()))
        return sorted(self.call(lambda c: c.config().getZoneNames()))

    def zone(self, zone: str, config: Config) -> dict:
        if config == "runtime":
            s = self.call(lambda c: c.getZoneSettings(zone).getSettingsDict())
            return _zone_view(s)

        def f(c):
            obj = c.config().getZoneByName(zone)
            view = _zone_view(obj.getSettings().getSettingsDict())
            # builtin: shipped with firewalld (cannot be deleted, only reset);
            # default: unmodified from the shipped definition.
            view["builtin"] = bool(obj.get_property("builtin"))
            view["modified"] = not bool(obj.get_property("default"))
            return view

        return self.call(f)

    def zones_overview(self) -> list[dict]:
        runtime = set(self.zone_names("runtime"))
        permanent = set(self.zone_names("permanent"))
        st = self.status()
        active = st["active_zones"]
        out = []
        for name in sorted(runtime | permanent):
            out.append(
                {
                    "name": name,
                    "runtime": name in runtime,
                    "permanent": name in permanent,
                    "default": name == st["default_zone"],
                    "active": name in active,
                    "interfaces": active.get(name, {}).get("interfaces", []),
                    "sources": active.get(name, {}).get("sources", []),
                }
            )
        return out

    def services(self) -> list[dict]:
        def f(c):
            out = []
            for name in sorted(c.listServices()):
                s = c.getServiceSettings(name)
                out.append(
                    {
                        "name": name,
                        "short": s.getShort(),
                        "description": s.getDescription(),
                        "ports": _ports(s.getPorts()),
                    }
                )
            return out

        return self.call(f)

    def icmp_types(self) -> list[str]:
        return sorted(self.call(lambda c: c.listIcmpTypes()))

    def ipsets(self, config: Config) -> list[dict]:
        def f(c):
            out = []
            if config == "runtime":
                for name in sorted(c.getIPSets()):
                    s = c.getIPSetSettings(name)
                    out.append({"name": name, "type": s.getType(), "options": s.getOptions(),
                                "entries": [str(e) for e in c.getEntries(name)]})
            else:
                for name in sorted(c.config().getIPSetNames()):
                    obj = c.config().getIPSetByName(name)
                    s = obj.getSettings()
                    out.append({"name": name, "type": s.getType(), "options": s.getOptions(),
                                "entries": [str(e) for e in s.getEntries()]})
            return out

        return self.call(f)

    # -- item changes -----------------------------------------------------

    def _apply_one(self, c, op: Op, config: Config, timeout: int = 0) -> None:
        suffix, _, takes_timeout = KINDS[op.kind]
        args = _args(op)
        if config == "runtime":
            method = getattr(c, f"{op.action}{suffix}")
            if op.action == "add" and takes_timeout and timeout:
                method(op.zone, *args, timeout)
            else:
                method(op.zone, *args)
        else:
            zone_obj = c.config().getZoneByName(op.zone)
            getattr(zone_obj, f"{op.action}{suffix}")(*args)

    def apply(self, ops: list[Op], target: Target, timeout: int = 0) -> list[Applied]:
        """Apply ops in order; on any failure undo what was done and raise.

        Returns the list of applied (op, config) pairs so callers can undo them later.
        """
        configs: list[Config] = ["runtime", "permanent"] if target == "both" else [target]
        done: list[Applied] = []

        def f(c):
            try:
                for op in ops:
                    for cfg in configs:
                        self._apply_one(c, op, cfg, timeout if cfg == "runtime" else 0)
                        done.append(Applied(op, cfg))
            except Exception:
                self._undo(c, done)
                raise
            return done

        return self.call(f)

    def _undo(self, c, applied: list[Applied]) -> list[str]:
        errors = []
        for a in reversed(applied):
            try:
                self._apply_one(c, a.op.inverse(), a.config)
            except Exception as e:  # keep undoing the rest
                errors.append(f"{a.op.inverse().describe()} [{a.config}]: {_wrap_error(e).message}")
        return errors

    def undo(self, applied: list[Applied]) -> list[str]:
        return self.call(lambda c: self._undo(c, applied))

    # -- zone-level -------------------------------------------------------

    def create_zone(self, name: str, target: str, short: str, description: str) -> None:
        def f(c):
            s = FirewallClientZoneSettings()
            s.setTarget(target)
            s.setShort(short)
            s.setDescription(description)
            c.config().addZone(name, s)

        self.call(f)

    def delete_zone(self, name: str) -> None:
        self.call(lambda c: c.config().getZoneByName(name).remove())

    def reset_zone(self, name: str) -> None:
        """Revert a built-in zone's permanent config to the shipped defaults."""
        self.call(lambda c: c.config().getZoneByName(name).loadDefaults())

    def update_zone(self, name: str, fields: dict) -> None:
        """Update permanent-only zone properties (target, short, description)."""

        def f(c):
            z = c.config().getZoneByName(name)
            if "target" in fields:
                z.setTarget(fields["target"])
            if "short" in fields:
                z.setShort(fields["short"])
            if "description" in fields:
                z.setDescription(fields["description"])

        self.call(f)

    def set_default_zone(self, name: str) -> None:
        self.call(lambda c: c.setDefaultZone(name))

    # -- global -----------------------------------------------------------

    def reload(self, complete: bool = False) -> None:
        self.call(lambda c: c.complete_reload() if complete else c.reload())

    def runtime_to_permanent(self) -> None:
        self.call(lambda c: c.runtimeToPermanent())

    def set_panic(self, on: bool) -> None:
        self.call(lambda c: c.enablePanicMode() if on else c.disablePanicMode())

    def set_log_denied(self, value: str) -> None:
        self.call(lambda c: c.setLogDenied(value))

    # -- ipsets (permanent config; reload to activate) ----------------------

    def create_ipset(self, name: str, type_: str, family: str, description: str) -> None:
        def f(c):
            s = FirewallClientIPSetSettings()
            s.setType(type_)
            s.setDescription(description)
            if family:
                s.addOption("family", family)
            c.config().addIPSet(name, s)

        self.call(f)

    def delete_ipset(self, name: str) -> None:
        self.call(lambda c: c.config().getIPSetByName(name).remove())

    def ipset_entry(self, name: str, entry: str, action: Literal["add", "remove"], target: Target) -> None:
        def f(c):
            if target in ("runtime", "both"):
                (c.addEntry if action == "add" else c.removeEntry)(name, entry)
            if target in ("permanent", "both"):
                obj = c.config().getIPSetByName(name)
                (obj.addEntry if action == "add" else obj.removeEntry)(entry)

        self.call(f)


firewall = Firewall()
