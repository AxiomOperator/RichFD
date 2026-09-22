import time

from fastapi.testclient import TestClient

from app import safe_apply
from app.config import settings

RULE = 'rule family="ipv4" source address="10.0.0.0/8" service name="http" accept'


def test_requires_login(fake):
    from app.main import app

    assert TestClient(app).get("/api/status").status_code == 401


def test_csrf_required(api):
    del api.headers["X-CSRF-Token"]
    r = api.post("/api/reload", json={})
    assert r.status_code == 403


def test_status_and_zones(api):
    assert api.get("/api/status").json()["default_zone"] == "public"
    zones = {z["name"]: z for z in api.get("/api/zones").json()}
    assert zones["public"]["active"] and zones["public"]["default"]
    z = api.get("/api/zones/public").json()
    assert z["runtime"]["services"] == ["ssh"]
    assert api.get("/api/zones/nope").status_code == 404


def test_add_rich_rule_both(api, fake):
    ops = [{"action": "add", "kind": "rich-rule", "zone": "public", "value": {"rule": RULE}}]
    r = api.post("/api/ops", json={"ops": ops})
    assert r.status_code == 200, r.text
    z = api.get("/api/zones/public").json()
    for cfg in ("runtime", "permanent"):
        [entry] = z[cfg]["rich_rules"]
        assert entry["rule"] == RULE
        assert entry["parsed"]["element"] == {"type": "service", "name": "http"}
    # Adding again conflicts.
    assert api.post("/api/ops", json={"ops": ops}).status_code == 409


def test_invalid_rich_rule(api):
    ops = [{"action": "add", "kind": "rich-rule", "zone": "public", "value": {"rule": "rule bogus"}}]
    r = api.post("/api/ops", json={"ops": ops})
    assert r.status_code == 400
    assert "Invalid rich rule" in r.json()["detail"]


def test_batch_is_atomic(api, fake):
    fake.fail_on = ("add", "Port")
    ops = [
        {"action": "add", "kind": "service", "zone": "public", "value": {"name": "http"}},
        {"action": "add", "kind": "port", "zone": "public", "value": {"port": "8080", "protocol": "tcp"}},
    ]
    assert api.post("/api/ops", json={"ops": ops}).status_code == 400
    assert fake.runtime["public"]["services"] == ["ssh"]
    assert fake.permanent["public"]["services"] == ["ssh"]


def test_runtime_timeout(api, fake):
    ops = [{"action": "add", "kind": "port", "zone": "public", "value": {"port": "8080", "protocol": "tcp"}}]
    r = api.post("/api/ops", json={"ops": ops, "target": "runtime", "timeout": 30})
    assert r.status_code == 200, r.text
    assert fake.timeouts == [30]
    assert fake.permanent["public"]["ports"] == []
    bad = api.post("/api/ops", json={"ops": ops, "target": "both", "timeout": 30})
    assert bad.status_code == 400


def test_render_and_parse(api):
    r = api.post("/api/rich-rules/render", json={
        "family": "ipv4",
        "source": {"addr": "10.0.0.0/8"},
        "element": {"type": "service", "name": "http"},
        "action": {"type": "accept"},
    }).json()
    assert r == {"valid": True, "rule": RULE}
    p = api.post("/api/rich-rules/parse", json={"rule": RULE}).json()
    assert p["valid"] and p["parsed"]["source"]["addr"] == "10.0.0.0/8"
    assert api.post("/api/rich-rules/parse", json={"rule": "nope"}).json()["valid"] is False


def test_safe_apply_confirm_persists(api, fake):
    ops = [{"action": "remove", "kind": "service", "zone": "public", "value": {"name": "ssh"}}]
    p = api.post("/api/safe-apply", json={"ops": ops}).json()
    assert fake.runtime["public"]["services"] == []
    assert fake.permanent["public"]["services"] == ["ssh"]
    assert api.post(f"/api/safe-apply/{p['id']}/confirm").status_code == 200
    assert fake.permanent["public"]["services"] == []
    assert api.get("/api/safe-apply").json() is None


def test_safe_apply_times_out(api, fake, monkeypatch):
    monkeypatch.setattr(settings, "safe_apply_seconds", 0.2)
    ops = [{"action": "remove", "kind": "service", "zone": "public", "value": {"name": "ssh"}}]
    assert api.post("/api/safe-apply", json={"ops": ops}).status_code == 200
    assert fake.runtime["public"]["services"] == []
    deadline = time.time() + 3
    while safe_apply.current() and time.time() < deadline:
        time.sleep(0.05)
    assert fake.runtime["public"]["services"] == ["ssh"]
    assert fake.permanent["public"]["services"] == ["ssh"]


def test_audit_log(api):
    api.post("/api/reload", json={})
    entries = api.get("/api/audit").json()
    assert entries[0]["action"] == "reload"
    assert entries[0]["user"] == "tester"
