import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app import denied, notify, risk, tokens, transfer
from app.config import settings
from app.fw import Op
from app.history import history
from app.richrule import normalize, parse
from app.tester import Evaluator, Packet, Snapshot


def rule(text):
    t = normalize(text)
    return {"rule": t, "parsed": parse(t).model_dump()}


def zone(**kw):
    base = {"target": "default", "services": [], "ports": [], "protocols": [], "source_ports": [],
            "forward_ports": [], "icmp_blocks": [], "icmp_block_inversion": False, "masquerade": False,
            "interfaces": [], "sources": [], "rich_rules": [], "ingress_priority": 0}
    return {**base, **kw}


SERVICES = {"ssh": {"name": "ssh", "ports": [{"port": "22", "protocol": "tcp"}], "protocols": [], "source_ports": []},
            "http": {"name": "http", "ports": [{"port": "80", "protocol": "tcp"}], "protocols": [], "source_ports": []}}


def snap(zones, policies=None, default="public", ipsets=None):
    return Snapshot(zones, policies or {}, default, SERVICES, ipsets or {})


# -- tester ---------------------------------------------------------------------------


def test_tester_service_accept():
    r = Evaluator(snap({"public": zone(services=["ssh"])}), Packet(src="10.1.1.1", dst_port=22)).run()
    assert r["verdict"] == "ACCEPT" and r["decided_by"] == "service ssh"


def test_tester_default_reject_and_icmp():
    s = snap({"public": zone()})
    assert Evaluator(s, Packet(src="10.1.1.1", dst_port=8080)).run()["verdict"] == "REJECT"
    assert Evaluator(s, Packet(src="10.1.1.1", protocol="icmp")).run()["verdict"] == "ACCEPT"


def test_tester_source_binding_and_deny_before_allow():
    s = snap({
        "public": zone(services=["ssh"]),
        "trusted": zone(target="ACCEPT", sources=["192.168.0.0/16"]),
        "block": zone(sources=["192.168.5.0/24"], ingress_priority=-10,
                      services=["ssh"], rich_rules=[rule('rule family="ipv4" source address="192.168.5.7" drop')]),
    })
    r = Evaluator(s, Packet(src="192.168.5.7", dst_port=22)).run()
    assert r["zone"] == "block" and r["verdict"] == "DROP"  # deny rules run before services
    r = Evaluator(s, Packet(src="192.168.1.1", dst_port=9999)).run()
    assert r["zone"] == "trusted" and r["verdict"] == "ACCEPT"


def test_tester_priorities_and_policies():
    z = zone(services=["http"], rich_rules=[rule('rule priority="-5" family="ipv4" source address="10.0.0.0/8" reject')])
    s = snap({"public": z})
    assert Evaluator(s, Packet(src="10.2.3.4", dst_port=80)).run()["verdict"] == "REJECT"
    pol = {"ingress_zones": ["ANY"], "egress_zones": ["HOST"], "priority": -100, "target": "CONTINUE",
           "rich_rules": [rule('rule family="ipv4" source address="10.2.3.4" accept')], "services": [], "ports": [],
           "protocols": [], "source_ports": [], "icmp_blocks": []}
    s = snap({"public": z}, {"allow-me": pol})
    r = Evaluator(s, Packet(src="10.2.3.4", dst_port=80)).run()
    assert r["verdict"] == "ACCEPT" and "policy allow-me" in r["steps"][-1]["stage"]


def test_tester_ipset_and_forward_port():
    s = snap({"public": zone(rich_rules=[rule('rule source ipset="bad" drop')],
                             forward_ports=[{"port": "8080", "protocol": "tcp", "to_port": "80", "to_addr": "172.17.0.2"}])},
             ipsets={"bad": ["203.0.113.0/24"]})
    assert Evaluator(s, Packet(src="203.0.113.9", dst_port=22)).run()["verdict"] == "DROP"
    r = Evaluator(s, Packet(src="198.51.100.1", dst_port=8080)).run()
    assert r["verdict"] == "FORWARDED"


def test_tester_unknown_source_port_noted():
    s = snap({"public": zone(rich_rules=[rule('rule source-port port="53" protocol="udp" accept')])})
    r = Evaluator(s, Packet(src="1.1.1.1", protocol="udp", dst_port=5000)).run()
    assert r["verdict"] == "REJECT" and any("source port" in n for n in r["notes"])


def test_tester_api(api):
    r = api.post("/api/tester", json={"src": "10.0.0.1", "protocol": "tcp", "dst_port": 22})
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "ACCEPT"


# -- risk -----------------------------------------------------------------------------


def test_risk_detects_lockout():
    s = snap({"public": zone(services=["ssh"], interfaces=["eth0"])})
    conns = [{"what": "SSH session from 10.9.9.9", "src": "10.9.9.9", "port": 22, "interface": "eth0"}]
    ops = [Op(action="remove", kind="service", zone="public", value={"name": "ssh"})]
    r = risk.analyze(ops, "both", None, snap=s, conns=conns)
    assert r["level"] == "danger" and r["force_safe"]
    assert any("block SSH session" in w["message"] for w in r["warnings"])
    ok = risk.analyze([Op(action="add", kind="service", zone="public", value={"name": "http"})], "both", None,
                      snap=s, conns=conns)
    assert ok["level"] == "ok"


def test_risk_zone_target_drop():
    s = snap({"public": zone(services=["ssh"], interfaces=["eth0"])})
    r = risk.analyze([], "permanent", None, zone_target={"zone": "public", "target": "DROP"}, snap=s, conns=[])
    assert r["level"] == "warning"


def test_risk_api(api):
    r = api.post("/api/risk", json={"ops": [{"action": "remove", "kind": "service", "zone": "public",
                                             "value": {"name": "ssh"}}], "target": "both"})
    assert r.status_code == 200
    assert r.json()["level"] in ("warning", "danger")


# -- policies -------------------------------------------------------------------------


def test_policy_ops(api, fake):
    ops = [{"action": "add", "kind": "rich-rule", "zone": "pub-host", "scope": "policy",
            "value": {"rule": 'rule family="ipv4" source address="10.0.0.0/8" service name="http" accept'}},
           {"action": "add", "kind": "service", "zone": "pub-host", "scope": "policy", "value": {"name": "https"}}]
    r = api.post("/api/ops", json={"ops": ops})
    assert r.status_code == 200, r.text
    p = api.get("/api/policies/pub-host").json()
    assert p["runtime"]["services"] == ["https"] and p["permanent"]["services"] == ["https"]
    assert p["runtime"]["rich_rules"][0]["parsed"]["element"]["name"] == "http"
    # zone-only kinds are rejected for policies
    bad = [{"action": "add", "kind": "interface", "zone": "pub-host", "scope": "policy", "value": {"name": "eth1"}}]
    assert api.post("/api/ops", json={"ops": bad}).status_code == 400
    assert api.post("/api/ops", json={"ops": ops}).status_code == 409


def test_policy_crud(api, fake):
    r = api.post("/api/policies", json={"name": "lan-to-wan", "ingress_zones": ["trusted"], "egress_zones": ["public"],
                                        "target": "ACCEPT", "priority": 10})
    assert r.status_code == 200, r.text
    assert fake.perm_policies["lan-to-wan"]["target"] == "ACCEPT"
    api.patch("/api/policies/lan-to-wan", json={"priority": 20, "disable": True})
    assert fake.perm_policies["lan-to-wan"]["priority"] == 20
    assert api.patch("/api/policies/lan-to-wan", json={"priority": 0}).status_code == 400
    assert api.delete("/api/policies/lan-to-wan").status_code == 200
    assert "lan-to-wan" not in fake.perm_policies


# -- services -------------------------------------------------------------------------


def test_custom_service(api, fake):
    body = {"name": "myapp", "short": "My app", "ports": [{"port": "9000-9010", "protocol": "tcp"}], "protocols": ["gre"]}
    assert api.post("/api/services", json=body).status_code == 200
    assert fake.services["myapp"]["settings"]["ports"] == [("9000-9010", "tcp")]
    svc = next(s for s in api.get("/api/services").json() if s["name"] == "myapp")
    assert not svc["builtin"] and svc["protocols"] == ["gre"]
    assert api.put("/api/services/myapp", json={"ports": []}).status_code == 400  # needs something
    assert api.put("/api/services/myapp", json={"ports": [{"port": "9000", "protocol": "udp"}]}).status_code == 200
    assert api.delete("/api/services/myapp").status_code == 200 and "myapp" not in fake.services


# -- roles & tokens -----------------------------------------------------------------


def test_viewer_is_read_only(fake, monkeypatch):
    from app.main import app

    monkeypatch.setenv("RICHRULE_DEV_ROLE", "viewer")
    c = TestClient(app)
    r = c.post("/api/login", json={"username": "v", "password": "x"})
    assert r.json()["role"] == "viewer"
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    assert c.get("/api/zones").status_code == 200
    assert c.post("/api/tester", json={"src": "1.2.3.4", "dst_port": 22}).status_code == 200
    r = c.post("/api/ops", json={"ops": [{"action": "add", "kind": "service", "zone": "public", "value": {"name": "http"}}]})
    assert r.status_code == 403 and "Read-only" in r.json()["detail"]


def test_bearer_token(fake):
    from app.main import app

    token = tokens.create("console1")
    c = TestClient(app)
    assert c.get("/api/status", headers={"Authorization": "Bearer rr_nope"}).status_code == 401
    h = {"Authorization": f"Bearer {token}", "X-Richrule-User": "alice"}
    assert c.get("/api/status", headers=h).status_code == 200
    # No CSRF needed for token auth; audit records the forwarded user.
    r = c.post("/api/ops", headers=h, json={"ops": [{"action": "add", "kind": "service", "zone": "public",
                                                    "value": {"name": "http"}}]})
    assert r.status_code == 200
    audit = c.get("/api/audit", headers=h).json()
    assert audit[0]["user"] == "alice@console1"
    viewer = {**h, "X-Richrule-Role": "viewer"}
    r = c.post("/api/reload", headers=viewer, json={})
    assert r.status_code == 403
    assert tokens.revoke("console1")
    assert c.get("/api/status", headers=h).status_code == 401


# -- history ---------------------------------------------------------------------------


def test_history_snapshots_and_restore(api, fake, monkeypatch):
    from app.fw import firewall

    zfile = fake.fwdir / "zones" / "public.xml"
    orig = firewall.apply

    def apply_and_write(ops, target, timeout=0):
        # Like firewalld: permanent changes rewrite the zone file.
        done = orig(ops, target, timeout)
        svcs = "".join(f"<service name='{s}'/>" for s in fake.permanent["public"]["services"])
        zfile.write_text(f"<zone>{svcs}</zone>")
        return done

    monkeypatch.setattr(firewall, "apply", apply_and_write)
    api.post("/api/ops", json={"ops": [{"action": "add", "kind": "service", "zone": "public", "value": {"name": "http"}}]})
    h = api.get("/api/history").json()
    assert h["enabled"]
    assert h["entries"][-1]["message"] == "Initial snapshot"
    assert "add service http" in h["entries"][0]["message"] and h["entries"][0]["author"] == "tester"
    api.post("/api/ops", json={"ops": [{"action": "add", "kind": "service", "zone": "public", "value": {"name": "https"}}]})
    zfile.write_text("<zone><service name='telnet'/></zone>")  # edited outside richrule
    found = api.post("/api/history/check").json()["found"]
    assert found and "zones/public.xml" in " ".join(found["files"])
    entries = api.get("/api/history").json()["entries"]
    assert entries[0]["external"] and entries[0]["author"] == "external"
    good = next(e for e in entries if not e["external"] and "https" in e["message"])
    diff = api.get(f"/api/history/{entries[0]['id']}").json()["diff"]
    assert "telnet" in diff
    cmp = api.get(f"/api/history/{good['id']}/compare").json()["diff"]
    assert "-<zone><service name='telnet'/></zone>" in cmp
    assert api.post(f"/api/history/{good['id']}/restore").status_code == 200
    assert zfile.read_text() == "<zone><service name='ssh'/><service name='http'/><service name='https'/></zone>"
    assert api.get("/api/history/zzzzzzz").status_code in (400, 404)


def test_external_runtime_change_detected(api, fake):
    history.check_external()  # baseline
    fake.runtime["trusted"]["ports"].append(("5555", "tcp"))
    found = history.check_external()
    assert found and any("5555" in line for line in found["runtime_changes"])
    audit = api.get("/api/audit").json()
    assert audit[0]["action"] == "external change detected"
    assert history.check_external() is None


def test_timed_rule_expiry_not_external(api, fake):
    ops = [{"action": "add", "kind": "port", "zone": "public", "value": {"port": "7777", "protocol": "tcp"}}]
    assert api.post("/api/ops", json={"ops": ops, "target": "runtime", "timeout": 5}).status_code == 200
    fake.runtime["public"]["ports"].remove(("7777", "tcp"))  # firewalld expires it
    assert history.check_external() is None


# -- notifications ----------------------------------------------------------------------


def test_webhook_notification(fake):
    received = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    notify.update_settings({"webhook_url": f"http://127.0.0.1:{srv.server_port}/hook"})
    res = notify.deliver({"user": "bob", "action": "change", "ok": True, "detail": {"ops": ["add service ssh (zone public)"]}})
    assert res == {"webhook": "ok"}
    assert "bob: change" in received[0]["text"] and "add service ssh" in received[0]["text"]
    s = notify.public_settings()
    assert "smtp_password" not in s and s["smtp_password_set"] is False


# -- denied log ---------------------------------------------------------------------------


def test_parse_denied_line():
    msg = ("filter_IN_public_REJECT: IN=wlp0s20f3 OUT= MAC=aa:bb SRC=203.0.113.5 DST=192.168.1.10 LEN=60 "
           "TOS=0x00 PREC=0x00 TTL=52 ID=1 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0")
    e = denied.parse_message(msg)
    assert e["zone"] == "public" and e["action"] == "REJECT" and e["kind"] == "denied"
    assert (e["src"], e["dpt"], e["proto"], e["in"]) == ("203.0.113.5", 22, "tcp", "wlp0s20f3")
    assert denied.parse_message("usb 1-1: new device") is None
    e = denied.parse_message("my-rule: IN=eth0 OUT= SRC=fe80::1 DST=ff02::1 PROTO=ICMPv6 TYPE=135 CODE=0")
    assert e["kind"] == "logged" and e["proto"] == "ipv6-icmp" and e["prefix"] == "my-rule"


# -- import / export ------------------------------------------------------------------------


ZONE_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP"><short>Lab</short><service name="ssh"/><port port="8080" protocol="tcp"/>
<rule family="ipv4"><source address="10.0.0.0/8"/><accept/></rule></zone>"""


def test_xml_import_preview_apply(api, fake):
    r = api.post("/api/import/preview", files={"file": ("lab.xml", ZONE_XML, "application/xml")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["plan"] == [{"kind": "zones", "name": "lab", "action": "create", "changes": data["plan"][0]["changes"]}]
    r = api.post("/api/import/apply", json={"bundle": data["bundle"]})
    assert r.status_code == 200 and r.json()["ok"], r.text
    lab = fake.permanent["lab"]
    assert lab["target"] == "DROP" and lab["ports"] == [("8080", "tcp")]
    assert lab["rules_str"] == ['rule family="ipv4" source address="10.0.0.0/8" accept']
    again = api.post("/api/import/preview", files={"file": ("lab.xml", ZONE_XML, "application/xml")}).json()
    assert again["plan"][0]["action"] == "unchanged"


def test_json_export_roundtrip(api, fake):
    r = api.get("/api/export?format=json")
    bundle = r.json()
    assert bundle["format"] == "richrule-export" and "public" in bundle["zones"] and "pub-host" in bundle["policies"]
    assert "ssh" not in bundle["services"]  # shipped, unmodified services are skipped
    xml = api.get("/api/export?format=xml&kind=zone&name=public").text
    assert "<zone" in xml and 'name="ssh"' in xml
    plan = transfer.preview(bundle)
    assert all(p["action"] == "unchanged" for p in plan if p["kind"] == "zones")


def test_address_list_parsing():
    ok, bad = transfer.parse_address_list("# comment\n1.2.3.4\n10.0.0.0/8, 2001:db8::/32 ; note\nnope\n1.2.3.4/32")
    assert ok == ["1.2.3.4", "10.0.0.0/8", "2001:db8::/32"] and bad == ["nope"]


# -- templates -------------------------------------------------------------------------------


def test_template_preview_and_apply(api, fake):
    r = api.post("/api/templates/preview", json={"template": "ssh-from-subnet",
                                                 "params": {"zone": "public", "subnet": "192.168.1.0/24"}})
    assert r.status_code == 200, r.text
    steps = r.json()["steps"]
    assert any("source address=\"192.168.1.0/24\"" in s for s in steps) and any("remove service ssh" in s for s in steps)
    r = api.post("/api/templates/apply", json={"template": "ssh-from-subnet", "target": "both",
                                               "params": {"zone": "public", "subnet": "192.168.1.0/24"}})
    assert r.status_code == 200, r.text
    assert fake.runtime["public"]["services"] == [] and len(fake.permanent["public"]["rules_str"]) == 1
    bad = api.post("/api/templates/preview", json={"template": "rate-limit-ssh", "params": {"zone": "public", "rate": "lots"}})
    assert bad.status_code == 400


@pytest.mark.parametrize("tid,params", [
    ("rate-limit-ssh", {"zone": "public"}),
    ("port-forward", {"zone": "public", "port": "8080", "to_addr": "172.17.0.2", "to_port": "80"}),
    ("block-address", {"zone": "public", "address": "203.0.113.7", "log": True}),
    ("allow-service-from", {"zone": "public", "service": "http", "source": "ipset:office"}),
    ("web-server", {"zone": "public"}),
    ("block-country", {"zone": "public", "addresses": "203.0.113.0/24\n198.51.100.0/24"}),
])
def test_templates_build(api, tid, params):
    r = api.post("/api/templates/preview", json={"template": tid, "params": params})
    assert r.status_code == 200, r.text
    assert r.json()["steps"]


def test_direct_and_misc_endpoints(api, fake):
    fake.getAllChains = lambda: [("ipv4", "filter", "mychain")]
    fake.getAllRules = lambda: [("ipv4", "filter", "mychain", 0, ["-j", "ACCEPT"])]
    fake.getAllPassthroughs = lambda: []

    class D:
        def getSettings(self):
            class S:
                getAllChains = staticmethod(lambda: [])
                getAllRules = staticmethod(lambda: [])
                getAllPassthroughs = staticmethod(lambda: [("ipv4", ["-A", "INPUT"])])
            return S()

    orig = fake.config
    fake.config = lambda: type("C", (), {"direct": lambda self: D(), **{k: getattr(orig(), k) for k in ("getZoneNames",)}})()
    d = api.get("/api/direct").json()
    assert d["runtime"]["rules"][0]["args"] == ["-j", "ACCEPT"]
    assert d["permanent"]["passthroughs"][0]["args"] == ["-A", "INPUT"]
    fake.config = orig
    assert api.get("/api/helpers").json() == ["ftp", "tftp"]


def test_ipset_import(api, fake, monkeypatch):
    calls = {}
    monkeypatch.setattr("app.fw.firewall.ipset_add_entries", lambda n, e, t: calls.setdefault("x", (n, e, t)) and {"runtime": len(e)})
    r = api.post("/api/ipsets/blk/import", json={"text": "1.2.3.4\n5.6.7.0/24\nbad", "target": "runtime"})
    assert r.status_code == 200, r.text
    assert calls["x"] == ("blk", ["1.2.3.4", "5.6.7.0/24"], "runtime") and r.json()["invalid"] == ["bad"]


def test_settings_endpoints(api):
    r = api.put("/api/settings/notifications", json={"syslog": False, "webhook_url": ""})
    assert r.status_code == 200
    assert api.post("/api/settings/notifications/test").status_code == 400  # nothing configured
    t = api.post("/api/tokens", json={"name": "c1"}).json()
    assert t["token"].startswith("rr_")
    assert [x["name"] for x in api.get("/api/tokens").json()] == ["c1"]
    assert api.post("/api/tokens", json={"name": "c1"}).status_code == 409
    assert api.delete("/api/tokens/c1").status_code == 200


def test_tls_default_secure_cookies(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("RICHRULE_TLS_CERT", "/x.pem")
    assert Settings().secure_cookies is True
    monkeypatch.delenv("RICHRULE_TLS_CERT")
    assert Settings().secure_cookies is False
