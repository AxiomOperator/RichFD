"""In-memory stand-in for firewalld's FirewallClient, so API tests need no root or D-Bus."""

import copy

import pytest
from fastapi.testclient import TestClient
from firewall.client import FirewallClientPolicySettings, FirewallClientServiceSettings, FirewallClientZoneSettings
from firewall import errors
from firewall.errors import FirewallError

from app import fw as fwmod
from app import safe_apply
from app.config import settings

LIST_KINDS = {
    "Service": "services",
    "Port": "ports",
    "Protocol": "protocols",
    "SourcePort": "source_ports",
    "ForwardPort": "forward_ports",
    "IcmpBlock": "icmp_blocks",
    "RichRule": "rules_str",
    "Interface": "interfaces",
    "Source": "sources",
}
BOOL_KINDS = {
    "Masquerade": "masquerade",
    "Forward": "forward",
    "IcmpBlockInversion": "icmp_block_inversion",
}


def _new_zone():
    return FirewallClientZoneSettings().getSettingsDict()


class ZoneStore:
    """Implements add*/remove* for one zone's settings dict (permanent-style, no zone arg)."""

    def __init__(self, settings):
        self.s = settings

    def __getattr__(self, name):
        for prefix in ("add", "remove"):
            if name.startswith(prefix):
                suffix = name[len(prefix):]
                if suffix in LIST_KINDS:
                    return lambda *a: self._list(prefix, LIST_KINDS[suffix], a)
                if suffix in BOOL_KINDS:
                    return lambda *a: self._bool(prefix, BOOL_KINDS[suffix])
        raise AttributeError(name)

    def _list(self, action, key, args):
        item = args[0] if len(args) == 1 else tuple(args)
        items = self.s[key]
        if action == "add":
            if item in items:
                raise FirewallError(errors.ALREADY_ENABLED, f"'{item}' already in zone")  # ALREADY_ENABLED
            items.append(item)
        else:
            if item not in items:
                raise FirewallError(errors.NOT_ENABLED, f"'{item}' not in zone")  # NOT_ENABLED
            items.remove(item)

    def _bool(self, action, key):
        want = action == "add"
        if self.s[key] == want:
            raise FirewallError(errors.ALREADY_ENABLED if want else errors.NOT_ENABLED, key)
        self.s[key] = want

    def getSettings(self):
        return FirewallClientZoneSettings(dict(self.s))

    def remove(self):
        self.on_remove()

    def get_property(self, prop):
        return {"builtin": True, "default": True}[prop]


class FakeConfig:
    def __init__(self, fake):
        self.fake = fake

    def getZoneNames(self):
        return list(self.fake.permanent)

    def getZoneByName(self, name):
        if name not in self.fake.permanent:
            raise FirewallError(errors.INVALID_ZONE, name)
        store = ZoneStore(self.fake.permanent[name])
        store.on_remove = lambda: self.fake.permanent.pop(name)
        return store

    def addZone(self, name, settings):
        self.fake.permanent[name] = settings.getSettingsDict()

    def getPolicyNames(self):
        return list(self.fake.perm_policies)

    def getPolicyByName(self, name):
        if name not in self.fake.perm_policies:
            raise FirewallError(errors.INVALID_POLICY, name)
        return FakePolicyObj(self.fake.perm_policies, name)

    def addPolicy(self, name, settings):
        self.fake.perm_policies[name] = copy.deepcopy(settings.getSettingsDict())

    def getServiceNames(self):
        return list(self.fake.services)

    def getServiceByName(self, name):
        if name not in self.fake.services:
            raise FirewallError(errors.INVALID_SERVICE, name)
        return FakeServiceObj(self.fake.services, name)

    def addService(self, name, settings):
        self.fake.services[name] = {"settings": copy.deepcopy(settings.getSettingsDict()), "builtin": False}

    def getIPSetNames(self):
        return list(self.fake.ipsets)


class FakePolicyObj:
    def __init__(self, store, name):
        self.store, self.name = store, name

    def getSettings(self):
        return FirewallClientPolicySettings(copy.deepcopy(self.store[self.name]))

    def update(self, settings):
        self.store[self.name] = copy.deepcopy(settings.getSettingsDict())

    def get_property(self, prop):
        return {"builtin": False, "default": False}[prop]

    def remove(self):
        del self.store[self.name]


class FakeServiceObj:
    def __init__(self, store, name):
        self.store, self.name = store, name

    def getSettings(self):
        return FirewallClientServiceSettings(copy.deepcopy(self.store[self.name]["settings"]))

    def update(self, settings):
        self.store[self.name]["settings"] = copy.deepcopy(settings.getSettingsDict())

    def get_property(self, prop):
        return {"builtin": self.store[self.name]["builtin"], "default": True}[prop]

    def remove(self):
        del self.store[self.name]

    def loadDefaults(self):
        pass


class FakeClient:
    fail_on = None  # (action, kind-suffix) that raises, to test rollback

    def __init__(self):
        self.runtime = {"public": _new_zone(), "trusted": _new_zone()}
        self.runtime["public"]["services"] = ["ssh"]
        self.permanent = copy.deepcopy(self.runtime)
        self.timeouts = []
        pol = FirewallClientPolicySettings().getSettingsDict()
        pol.update({"ingress_zones": ["public"], "egress_zones": ["HOST"], "priority": -10, "target": "CONTINUE"})
        self.rt_policies = {"pub-host": copy.deepcopy(pol)}
        self.perm_policies = {"pub-host": copy.deepcopy(pol)}
        svc = lambda ports: {"settings": {**FirewallClientServiceSettings().getSettingsDict(), "ports": ports}, "builtin": True}
        self.services = {"ssh": svc([("22", "tcp")]), "http": svc([("80", "tcp")]), "https": svc([("443", "tcp")])}
        self.ipsets = {}

    def __getattr__(self, name):
        for prefix in ("add", "remove"):
            if name.startswith(prefix) and name[len(prefix):] in {**LIST_KINDS, **BOOL_KINDS}:
                suffix = name[len(prefix):]

                def call(zone, *args, _p=prefix, _s=suffix):
                    if self.fail_on == (_p, _s):
                        raise FirewallError(errors.INVALID_PORT, "injected failure")
                    fields = len(fwmod.KINDS[_kind(_s)][1])
                    if len(args) > fields:  # trailing timeout
                        self.timeouts.append(args[fields])
                        args = args[:fields]
                    getattr(ZoneStore(self.runtime[zone]), f"{_p}{_s}")(*args)

                return call
        raise AttributeError(name)

    def config(self):
        return FakeConfig(self)

    def get_property(self, prop):
        return {"version": "2.4.4", "state": "RUNNING"}[prop]

    def getDefaultZone(self):
        return "public"

    def queryPanicMode(self):
        return False

    def getLogDenied(self):
        return "off"

    def getActiveZones(self):
        return {"public": {"interfaces": ["eth0"], "sources": []}}

    def getZones(self):
        return list(self.runtime)

    def getZoneSettings(self, zone):
        if zone not in self.runtime:
            raise FirewallError(errors.INVALID_ZONE, zone)
        return FirewallClientZoneSettings(dict(self.runtime[zone]))

    def reload(self):
        self.runtime = copy.deepcopy(self.permanent)
        self.rt_policies = copy.deepcopy(self.perm_policies)

    def getPolicies(self):
        return list(self.rt_policies)

    def getActivePolicies(self):
        return {"pub-host": {}}

    def getPolicySettings(self, name):
        if name not in self.rt_policies:
            raise FirewallError(errors.INVALID_POLICY, name)
        return FirewallClientPolicySettings(copy.deepcopy(self.rt_policies[name]))

    def setPolicySettings(self, name, settings, timeout=0):
        self.rt_policies[name] = copy.deepcopy(settings.getSettingsDict())

    def listServices(self):
        return list(self.services)

    def getServiceSettings(self, name):
        return FirewallClientServiceSettings(copy.deepcopy(self.services[name]["settings"]))

    def getIPSets(self):
        return list(self.ipsets)

    def getEntries(self, name):
        return self.ipsets[name]

    def getHelpers(self):
        return ["ftp", "tftp"]


def _kind(suffix):
    return next(k for k, (s, _, _) in fwmod.KINDS.items() if s == suffix)


@pytest.fixture
def fake(monkeypatch, tmp_path):
    client = FakeClient()
    monkeypatch.setattr(fwmod.firewall, "_client", client)
    monkeypatch.setattr(settings, "audit_log", tmp_path / "audit.log")
    monkeypatch.setattr(settings, "dev_user", "tester")
    monkeypatch.setattr(settings, "_secret", b"x" * 32)
    safe_apply._pending = None
    monkeypatch.setattr(settings, "state_dir", tmp_path / "state")
    # Fresh history bound to temp dirs; a fake /etc/firewalld with one zone file.
    fwdir = tmp_path / "etc-firewalld"
    (fwdir / "zones").mkdir(parents=True)
    (fwdir / "zones" / "public.xml").write_text("<zone/>")
    from app.history import history

    monkeypatch.setattr(history, "fw_dir", fwdir)
    monkeypatch.setattr(history, "repo", tmp_path / "history")
    monkeypatch.setattr(history, "tree", tmp_path / "history" / "tree")
    monkeypatch.setattr(history, "_git_ok", None)
    monkeypatch.setattr(history, "_runtime", None)
    client.fwdir = fwdir
    yield client
    if safe_apply._pending:
        safe_apply._pending.timer.cancel()
        safe_apply._pending = None


@pytest.fixture
def api(fake):
    from app.main import app

    client = TestClient(app)
    r = client.post("/api/login", json={"username": "tester", "password": "x"})
    assert r.status_code == 200
    client.headers["X-CSRF-Token"] = r.json()["csrf"]
    return client
