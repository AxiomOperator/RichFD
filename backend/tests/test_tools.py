import io
import json
import socket
import subprocess
import tarfile

import pytest
import yaml

from app import automation, backups, connections, ddns, denied, fail2ban, scheduler, templates
from app.config import settings


def test_bash_and_ansible_export(api, fake, tmp_path):
    fake.permanent["public"]["rules_str"] = ['rule family="ipv4" source address="10.0.0.0/8" service name="http" accept']
    fake.permanent["public"]["ports"] = [("8080", "tcp")]
    fake.permanent["public"]["forward_ports"] = [("80", "tcp", "8080", "")]
    r = api.post("/api/automation/export", json={"format": "bash", "zones": ["public"], "policies": ["pub-host"]})
    assert r.status_code == 200, r.text
    script = r.json()["content"]
    f = tmp_path / "x.sh"
    f.write_text(script)
    assert subprocess.run(["bash", "-n", str(f)]).returncode == 0
    assert "--add-rich-rule='rule family=\"ipv4\" source address=\"10.0.0.0/8\" service name=\"http\" accept'" in script
    assert "--add-forward-port=port=80:proto=tcp:toport=8080" in script
    assert "--new-policy=pub-host" in script and "--add-egress-zone=HOST" in script
    r = api.post("/api/automation/export", json={"format": "ansible", "zones": ["public"], "policies": ["pub-host"]})
    play = yaml.safe_load(r.json()["content"])
    tasks = play[0]["tasks"]
    rich = next(t for t in tasks if t["name"] == "public: rich rules")
    assert rich["ansible.posix.firewalld"]["rich_rule"] == "{{ item }}"
    assert rich["loop"] == ['rule family="ipv4" source address="10.0.0.0/8" service name="http" accept']
    assert any("port_forward" in t.get("ansible.posix.firewalld", {}) for t in tasks)
    assert play[0]["handlers"][0]["ansible.builtin.command"] == "firewall-cmd --reload"


def test_export_selected_rules(api):
    rules = ['rule family="ipv4" source address="192.0.2.1" drop']
    r = api.post("/api/automation/export", json={"format": "ansible", "rules": rules, "scope": "zone", "name": "public"})
    play = yaml.safe_load(r.json()["content"])
    assert play[0]["tasks"][-1]["loop"] == rules
    r = api.post("/api/automation/export", json={"format": "bash", "rules": rules, "scope": "policy", "name": "p1"})
    assert "--policy=p1 --add-rich-rule=" in r.json()["content"]


SS = """tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))
tcp   ESTAB  0 0   192.168.1.10:22 8.8.4.4:51234 users:(("sshd",pid=1200,fd=4))
tcp   ESTAB  0 0   192.168.1.10:40000 142.250.1.1:443 users:(("firefox",pid=77,fd=9))
udp   UNCONN 0 0   [::]:5353 [::]:*
"""


def test_parse_ss_and_direction(monkeypatch):
    class R:
        stdout, stderr, returncode = SS, "", 0

    monkeypatch.setattr(connections, "_run", lambda cmd, timeout=10: R())
    monkeypatch.setattr(connections.shutil, "which", lambda x: None)
    d = connections.connections()
    rows = {(r["local_port"], r["peer_addr"]): r for r in d["sockets"]}
    assert rows[("22", "8.8.4.4")]["direction"] == "in" and rows[("22", "8.8.4.4")]["peer_class"] == "public"
    assert rows[("40000", "142.250.1.1")]["direction"] == "out"
    assert rows[("22", "0.0.0.0")]["direction"] == "listen" and rows[("22", "0.0.0.0")]["process"] == "sshd"
    assert "conntrack-tools" in d["conntrack_error"]


def test_terminate_rejects_loopback():
    with pytest.raises(Exception):
        connections.terminate("127.0.0.1")


def test_denied_stats_api(api, monkeypatch):
    import datetime

    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    msgs = [f"filter_IN_public_DROP: IN=eth0 OUT= SRC=198.51.100.{i % 4} DST=10.0.0.1 PROTO=TCP SPT=5 DPT={22 if i < 7 else 80}"
            for i in range(10)]
    entries = [dict(denied.parse_message(m), ts=now) for m in msgs]
    monkeypatch.setattr(denied, "_read", lambda args: entries)
    r = api.get("/api/denied/stats?hours=6&port=22").json()
    assert r["total"] == 10 and r["top_ports"][0] == {"port": "22/tcp", "count": 7}
    assert sum(b["count"] for b in r["timeline"]) == 10 and r["bucket_minutes"] == 5
    assert sum(x["count"] for x in r["top_sources_on_port"]) == 7


def test_bulk_rules(api, fake):
    text = "ip,note\n203.0.113.5,scanner\n2001:db8::7,v6\n203.0.113.500,typo\n"
    r = api.post("/api/bulk/rules", json={"text": text, "zone": "public", "action": "drop", "port": "22", "preview": True})
    data = r.json()
    assert data["rules"] == ['rule family="ipv4" source address="203.0.113.5" port port="22" protocol="tcp" drop',
                             'rule family="ipv6" source address="2001:db8::7" port port="22" protocol="tcp" drop']
    assert data["invalid"] == ["203.0.113.500"]
    r = api.post("/api/bulk/rules", json={"text": text, "zone": "public", "action": "drop", "port": "22", "preview": False})
    assert r.json()["added"] == 2
    assert len(fake.runtime["public"]["rules_str"]) == 2 and len(fake.permanent["public"]["rules_str"]) == 2


# -- fail2ban -------------------------------------------------------------------------------


class FakeF2B:
    def __init__(self):
        self.banned = {"sshd": ["203.0.113.9"]}
        self.calls = []

    def __call__(self, cmd, **kw):
        args = cmd[1:]
        self.calls.append(args)
        out, rc = "", 0
        if args == ["ping"]:
            out = "Server replied: pong"
        elif args == ["status"]:
            out = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd"
        elif args[:1] == ["status"]:
            b = self.banned.get(args[1])
            if b is None:
                return subprocess.CompletedProcess(cmd, 255, "", "Sorry but the jail 'x' does not exist")
            out = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t40\n"
                   "|  `- Journal matches:\t_SYSTEMD_UNIT=sshd.service\n`- Actions\n   |- Currently banned:\t"
                   f"{len(b)}\n   |- Total banned:\t9\n   `- Banned IP list:\t{' '.join(b)}")
        elif args[:1] == ["get"]:
            out = {"bantime": "600", "findtime": "600", "maxretry": "5",
                   "actions": "The jail sshd has the following actions:\nfirewallcmd-rich-rules"}[args[2]]
        elif args[:1] == ["set"]:
            (self.banned[args[1]].append if args[2] == "banip" else self.banned[args[1]].remove)(args[3])
        elif args == ["version"]:
            out = "1.1.0"
        return subprocess.CompletedProcess(cmd, rc, out, "")


def test_fail2ban(api, monkeypatch, tmp_path):
    f = FakeF2B()
    monkeypatch.setattr(fail2ban, "runner", f)
    monkeypatch.setattr(fail2ban, "CONF_DIR", tmp_path)
    (tmp_path / "filter.d").mkdir()
    (tmp_path / "filter.d" / "sshd.conf").write_text("")
    st = api.get("/api/fail2ban").json()
    assert st["running"] and st["jails"][0]["name"] == "sshd"
    j = st["jails"][0]
    assert j["banned"] == ["203.0.113.9"] and j["total_failed"] == 40 and j["uses_firewalld"] and j["maxretry"] == 5
    assert api.post("/api/fail2ban/jails/sshd/ban", json={"ip": "198.51.100.1", "action": "ban"}).status_code == 200
    assert "198.51.100.1" in f.banned["sshd"]
    api.post("/api/fail2ban/jails/sshd/ban", json={"ip": "203.0.113.9", "action": "unban"})
    assert "203.0.113.9" not in f.banned["sshd"]
    assert api.post("/api/fail2ban/jails/sshd/ban", json={"ip": "nope", "action": "ban"}).status_code == 400
    r = api.put("/api/fail2ban/jails/sshd", json={"enabled": "true", "maxretry": "3", "bantime": "1h", "findtime": "10m"})
    assert r.status_code == 200, r.text
    text = (tmp_path / "jail.d" / "richfd-sshd.local").read_text()
    assert "[sshd]" in text and "maxretry = 3" in text and "bantime = 1h" in text
    assert ["reload"] in f.calls
    assert api.put("/api/fail2ban/jails/sshd", json={"bantime": "forever"}).status_code == 400
    assert api.put("/api/fail2ban/jails/sshd", json={"logpath": "a\nb"}).status_code == 400
    assert api.get("/api/fail2ban/jails/sshd").json()["managed_settings"]["maxretry"] == "3"
    assert api.delete("/api/fail2ban/jails/sshd/settings").status_code == 200
    assert not (tmp_path / "jail.d" / "richfd-sshd.local").exists()
    assert api.get("/api/fail2ban/jails/bad name!").status_code in (400, 404)


def test_fail2ban_not_installed(api, monkeypatch):
    monkeypatch.setattr(fail2ban, "runner", subprocess.run)
    monkeypatch.setattr(fail2ban.shutil, "which", lambda x: None)
    st = api.get("/api/fail2ban").json()
    assert st["installed"] is False and "dnf install fail2ban" in st["hint"]


# -- DDNS -----------------------------------------------------------------------------------


def test_ddns_lifecycle(api, fake, monkeypatch):
    ips = {"home.example.org": ["198.51.100.20"]}

    def resolver(host, port, fam, typ):
        if host not in ips:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, typ, 6, "", (ip, 0)) for ip in ips[host]]

    monkeypatch.setattr(ddns, "resolver", resolver)
    rule = {"family": "", "priority": 0, "source": {"addr": "home.example.org", "mac": "", "ipset": "", "invert": False},
            "destination": None, "element": {"type": "service", "name": "ssh"}, "log": None, "audit": None,
            "action": {"type": "accept", "reject_type": "", "set": "", "limit": None}}
    r = api.post("/api/ddns", json={"hostname": "home.example.org", "rule": rule, "zone": "public"})
    assert r.status_code == 200, r.text
    entry = r.json()
    expected = 'rule family="ipv4" source address="198.51.100.20" service name="ssh" accept'
    assert entry["resolved"] == ["198.51.100.20"]
    assert fake.runtime["public"]["rules_str"] == [expected] and fake.permanent["public"]["rules_str"] == [expected]
    # IP changes: old rule replaced
    ips["home.example.org"] = ["198.51.100.21"]
    api.post(f"/api/ddns/{entry['id']}/refresh")
    assert fake.runtime["public"]["rules_str"] == [expected.replace(".20", ".21")]
    # resolution failure keeps rules
    del ips["home.example.org"]
    e = api.post(f"/api/ddns/{entry['id']}/refresh").json()
    assert "Cannot resolve" in e["last_error"] and len(fake.runtime["public"]["rules_str"]) == 1
    # someone deleted the rule by hand: refresh re-adds it, tolerant of missing ones
    ips["home.example.org"] = ["198.51.100.21"]
    fake.runtime["public"]["rules_str"].clear()
    api.post(f"/api/ddns/{entry['id']}/refresh")
    assert api.delete(f"/api/ddns/{entry['id']}").status_code == 200
    assert fake.permanent["public"]["rules_str"] == [] and api.get("/api/ddns").json() == []


def test_ddns_validation(api):
    rule = {"source": {"addr": "x"}, "action": {"type": "accept"}}
    assert api.post("/api/ddns", json={"hostname": "not a host", "rule": rule, "zone": "public"}).status_code == 400
    assert ddns.is_hostname("myhome.dyndns.org") and not ddns.is_hostname("10.0.0.1") and not ddns.is_hostname("10.0.0.0/8")


# -- backups ---------------------------------------------------------------------------------


def test_backups_files_roundtrip(api, fake, monkeypatch):
    monkeypatch.setattr(settings, "firewalld_dir", fake.fwdir)
    zfile = fake.fwdir / "zones" / "public.xml"
    zfile.write_text("<zone>original</zone>")
    b = api.post("/api/backups", json={"name": "before change"}).json()
    assert b["has_files"] and b["id"].endswith("before-change")
    zfile.write_text("<zone>broken</zone>")
    (fake.fwdir / "zones" / "extra.xml").write_text("<zone/>")
    info = api.get(f"/api/backups/{b['id']}").json()
    changes = {c["file"]: c["change"] for c in info["changes"]}
    assert changes == {"zones/public.xml": "modified", "zones/extra.xml": "removed"}
    assert api.post(f"/api/backups/{b['id']}/restore").json()["mode"] == "files"
    assert zfile.read_text() == "<zone>original</zone>" and not (fake.fwdir / "zones" / "extra.xml").exists()
    dl = api.get(f"/api/backups/{b['id']}/download")
    assert dl.status_code == 200 and tarfile.open(fileobj=io.BytesIO(dl.content)).getmember("meta.json")
    listed = api.get("/api/backups").json()
    assert listed["backups"][0]["name"] == "before change" and listed["settings"]["auto"] is True
    assert api.delete(f"/api/backups/{b['id']}").status_code == 200
    assert api.get("/api/backups/bad!id").status_code == 400


def test_backup_upload_bundle_and_tarball(api, fake, monkeypatch):
    monkeypatch.setattr(settings, "firewalld_dir", fake.fwdir)
    bundle = api.get("/api/export?format=json").json()
    bundle["zones"]["newzone"] = bundle["zones"]["public"]
    up = api.post("/api/backups/upload", files={"file": ("cfg.json", json.dumps(bundle).encode(), "application/json")}).json()
    assert up["has_files"] is False
    plan = api.get(f"/api/backups/{up['id']}").json()["plan"]
    assert {"kind": "zones", "name": "newzone", "action": "create"}.items() <= next(p for p in plan if p["name"] == "newzone").items()
    assert api.post(f"/api/backups/{up['id']}/restore").json()["mode"] == "bundle"
    assert "newzone" in fake.permanent
    # raw /etc/firewalld tarball as produced by Export -> tar.gz
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.add(fake.fwdir, arcname="firewalld")
    up = api.post("/api/backups/upload", files={"file": ("fw.tar.gz", buf.getvalue(), "application/gzip")}).json()
    assert up["has_files"] is True
    # path traversal is rejected
    evil = io.BytesIO()
    with tarfile.open(fileobj=evil, mode="w:gz") as t:
        info = tarfile.TarInfo("../../etc/passwd")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    assert api.post("/api/backups/upload", files={"file": ("e.tar.gz", evil.getvalue(), "application/gzip")}).status_code == 400


def test_auto_backup_retention(api, fake, monkeypatch):
    monkeypatch.setattr(settings, "firewalld_dir", fake.fwdir)
    api.put("/api/backups/settings", json={"auto": True, "interval_hours": 1, "keep": 2})
    backups.auto_backup_due()
    backups.auto_backup_due()  # not due again yet
    assert len([b for b in backups.list_backups() if b["source"] == "auto"]) == 1


# -- templates & feeds ------------------------------------------------------------------------


def test_cloudflare_and_tor_templates(api, fake, monkeypatch):
    fake.permanent["public"]["services"].append("http")
    r = api.post("/api/templates/preview", json={"template": "cloudflare-only", "params": {"zone": "public"}})
    assert r.status_code == 200, r.text
    steps = " | ".join(r.json()["steps"])
    assert "cloudflare-v4" in steps and "cloudflare-v6" in steps and "remove service http" in steps
    assert 'source ipset="cloudflare-v4" port port="443" protocol="tcp" accept' in steps
    r = api.post("/api/templates/preview", json={"template": "block-tor", "params": {"zone": "public"}})
    assert "torbulkexitlist" in " ".join(r.json()["steps"]) and "refreshed every 6h" in " ".join(r.json()["steps"])
    r = api.post("/api/templates/preview", json={"template": "rate-limit-ssh", "params": {"zone": "public"}})
    assert 'limit value="3/m"' in " ".join(r.json()["steps"])


def test_feed_refresh(api, fake, monkeypatch):
    stored = {}

    class IPSetObj:
        def setEntries(self, e):
            stored["perm"] = e

    orig = fake.config
    cfg = orig()
    cfg.getIPSetByName = lambda n: IPSetObj()
    fake.config = lambda: cfg
    monkeypatch.setattr(templates, "download_list", lambda url: ["192.0.2.0/24", "198.51.100.1"])
    r = api.put("/api/feeds/cloudflare-v4", json={"url": "https://www.cloudflare.com/ips-v4", "interval_hours": 24})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 2 and stored["perm"] == ["192.0.2.0/24", "198.51.100.1"]
    assert "cloudflare-v4" in api.get("/api/feeds").json()
    assert api.delete("/api/feeds/cloudflare-v4").status_code == 200
    fake.config = orig
