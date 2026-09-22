"""Translate firewalld configuration into an Ansible playbook or a firewall-cmd script.

Prototype visually, then deploy the same configuration to many servers. Output is built from
the *permanent* configuration (what survives a reload), for everything or a subset:
zones, policies, custom services, IP sets, or just a list of rich rules for one zone/policy.

Ansible output uses ``ansible.posix.firewalld`` where it has a parameter for the item
(services, ports, rich rules, sources, interfaces, masquerade, forward ports, ICMP blocks,
zone targets) and idempotent ``firewall-cmd`` commands for the rest (policies, IP sets,
custom services), each guarded by a check so re-running the playbook changes nothing.
"""

import shlex
import socket
import time

from .fw import firewall

_BUILTIN_ZONE_TARGET = "default"


def _q(s) -> str:
    return shlex.quote(str(s))


def _yaml_str(s) -> str:
    """A YAML double-quoted scalar."""
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


# -- collection ---------------------------------------------------------------------------


def collect(zones: list[str] | None = None, policies: list[str] | None = None,
            include_services: bool = True, include_ipsets: bool = True) -> dict:
    """Permanent config in richrule's view format, filtered to what was asked for."""
    zone_names = firewall.zone_names("permanent") if zones is None else zones
    policy_names = firewall.policy_names("permanent") if policies is None else policies
    data = {
        "zones": {z: firewall.zone(z, "permanent") for z in zone_names},
        "policies": {p: firewall.policy(p, "permanent") for p in policy_names},
        "services": {},
        "ipsets": {},
    }
    if include_services:
        data["services"] = {s["name"]: s for s in firewall.services() if not s.get("builtin") or s.get("modified")}
    if include_ipsets:
        data["ipsets"] = {s["name"]: s for s in firewall.ipsets("permanent")}
    return data


# -- bash -----------------------------------------------------------------------------------


def to_bash(data: dict, only_rules: list[str] | None = None, target: tuple[str, str] | None = None) -> str:
    """firewall-cmd script. Additive: it adds what is configured and never removes anything."""
    L = [
        "#!/usr/bin/env bash",
        f"# firewalld configuration exported by RichFD from {socket.gethostname()} on {time.strftime('%Y-%m-%d %H:%M')}",
        "# Additive and idempotent: existing items are skipped, nothing is removed.",
        "set -euo pipefail",
        "",
        "fwc() { firewall-cmd --permanent \"$@\"; }",
        "",
    ]
    if only_rules is not None and target:
        scope, name = target
        flag = f"--zone={_q(name)}" if scope == "zone" else f"--policy={_q(name)}"
        L.append(f"# rich rules for {scope} {name}")
        for r in only_rules:
            L.append(_bash_line((f"{flag} --query-rich-rule={_q(r)}", f"{flag} --add-rich-rule={_q(r)}")))
        L += ["", "firewall-cmd --reload"]
        return "\n".join(L) + "\n"

    for name, s in data["services"].items():
        L.append(f"# service {name}")
        L.append(f"fwc --info-service={_q(name)} >/dev/null 2>&1 || fwc --new-service={_q(name)}")
        if s.get("short"):
            L.append(f"fwc --service={_q(name)} --set-short={_q(s['short'])}")
        if s.get("description"):
            L.append(f"fwc --service={_q(name)} --set-description={_q(s['description'])}")
        sf = f"--service={_q(name)}"
        for what, val in ([("port", f"{p['port']}/{p['protocol']}") for p in s.get("ports", [])]
                          + [("protocol", _q(x)) for x in s.get("protocols", [])]
                          + [("source-port", f"{p['port']}/{p['protocol']}") for p in s.get("source_ports", [])]
                          + [("helper", _q(x)) for x in s.get("helpers", [])]
                          + [("include", _q(x)) for x in s.get("includes", [])]):
            L.append(_bash_line((f"{sf} --query-{what}={val}", f"{sf} --add-{what}={val}")))
        L.append("")

    for name, s in data["ipsets"].items():
        opts = " ".join(f"--option={_q(f'{k}={v}')}" for k, v in (s.get("options") or {}).items())
        L.append(f"# ipset {name} ({len(s['entries'])} entries)")
        L.append(f"fwc --info-ipset={_q(name)} >/dev/null 2>&1 || fwc --new-ipset={_q(name)} --type={_q(s['type'])} {opts}".rstrip())
        if s["entries"]:
            L.append('tmp=$(mktemp)')
            L.append("cat <<'EOF' >\"$tmp\"")
            L += s["entries"]
            L.append("EOF")
            L.append(f"fwc --ipset={_q(name)} --add-entries-from-file=\"$tmp\" >/dev/null 2>&1 || true")
            L.append('rm -f "$tmp"')
        L.append("")

    for name, z in data["zones"].items():
        f = f"--zone={_q(name)}"
        L.append(f"# zone {name}")
        L.append(f"fwc --info-zone={_q(name)} >/dev/null 2>&1 || fwc --new-zone={_q(name)}")
        if z.get("target") and z["target"] != _BUILTIN_ZONE_TARGET:
            L.append(f"fwc {f} --set-target={_q(z['target'])}")
        L += [_bash_line(x) for x in _items(f, z)]
        for i in z.get("interfaces", []):
            L.append(_bash_line((f"{f} --query-interface={_q(i)}", f"{f} --add-interface={_q(i)}")))
        for src in z.get("sources", []):
            L.append(_bash_line((f"{f} --query-source={_q(src)}", f"{f} --add-source={_q(src)}")))
        if z.get("icmp_block_inversion"):
            L.append(_bash_line((f"{f} --query-icmp-block-inversion", f"{f} --add-icmp-block-inversion")))
        if z.get("forward"):
            L.append(_bash_line((f"{f} --query-forward", f"{f} --add-forward")))
        L.append("")

    for name, p in data["policies"].items():
        f = f"--policy={_q(name)}"
        L.append(f"# policy {name}")
        L.append(f"fwc --info-policy={_q(name)} >/dev/null 2>&1 || fwc --new-policy={_q(name)}")
        L.append(f"fwc {f} --set-priority={p['priority']}")
        L.append(f"fwc {f} --set-target={_q(p['target'])}")
        for z in p.get("ingress_zones", []):
            L.append(_bash_line((f"{f} --query-ingress-zone={_q(z)}", f"{f} --add-ingress-zone={_q(z)}")))
        for z in p.get("egress_zones", []):
            L.append(_bash_line((f"{f} --query-egress-zone={_q(z)}", f"{f} --add-egress-zone={_q(z)}")))
        L += [_bash_line(x) for x in _items(f, p)]
        L.append("")

    L.append("firewall-cmd --reload")
    return "\n".join(L) + "\n"


def _bash_line(pair: tuple[str, str]) -> str:
    query, add = pair
    return f"fwc {query} >/dev/null 2>&1 || fwc {add} >/dev/null"


def _items(f: str, v: dict) -> list[tuple[str, str]]:
    """(query args, add args) for every item of a zone or policy; ``f`` is --zone=X / --policy=X."""
    pairs: list[tuple[str, str]] = []

    def add(what: str, val: str | None = None):
        suffix = f"={val}" if val is not None else ""
        pairs.append((f"{f} --query-{what}{suffix}", f"{f} --add-{what}{suffix}"))

    for s in v.get("services", []):
        add("service", _q(s))
    for p in v.get("ports", []):
        add("port", f"{p['port']}/{p['protocol']}")
    for pr in v.get("protocols", []):
        add("protocol", _q(pr))
    for p in v.get("source_ports", []):
        add("source-port", f"{p['port']}/{p['protocol']}")
    for i in v.get("icmp_blocks", []):
        add("icmp-block", _q(i))
    for fp in v.get("forward_ports", []):
        spec = f"port={fp['port']}:proto={fp['protocol']}"
        if fp.get("to_port"):
            spec += f":toport={fp['to_port']}"
        if fp.get("to_addr"):
            spec += f":toaddr={fp['to_addr']}"
        add("forward-port", _q(spec))
    if v.get("masquerade"):
        add("masquerade")
    for r in v.get("rich_rules", []):
        add("rich-rule", _q(r["rule"]))
    return pairs


# -- ansible ----------------------------------------------------------------------------------


def _task(name: str, module: str, args: dict, loop: list | None = None, extra: dict | None = None) -> list[str]:
    L = [f"    - name: {_yaml_str(name)}", f"      {module}:"]
    for k, v in args.items():
        if isinstance(v, bool):
            L.append(f"        {k}: {'true' if v else 'false'}")
        elif isinstance(v, int):
            L.append(f"        {k}: {v}")
        else:
            L.append(f"        {k}: {_yaml_str(v) if not str(v).startswith('{{') else _yaml_str(v)}")
    if loop is not None:
        L.append("      loop:")
        L += [f"        - {_yaml_str(x)}" for x in loop]
    for k, v in (extra or {}).items():
        L.append(f"      {k}: {v}")
    return L


def _fw_items(where: dict, v: dict) -> list[str]:
    """ansible.posix.firewalld tasks for the items of a zone (policies have no module support)."""
    base = {**where, "permanent": True, "immediate": True, "state": "enabled"}
    label = where.get("zone")
    L = []
    if v.get("services"):
        L += _task(f"{label}: services", "ansible.posix.firewalld", {**base, "service": "{{ item }}"}, v["services"])
    ports = [f"{p['port']}/{p['protocol']}" for p in v.get("ports", [])]
    if ports:
        L += _task(f"{label}: ports", "ansible.posix.firewalld", {**base, "port": "{{ item }}"}, ports)
    if v.get("protocols"):
        L += _task(f"{label}: protocols", "ansible.posix.firewalld", {**base, "protocol": "{{ item }}"}, v["protocols"])
    sports = [f"{p['port']}/{p['protocol']}" for p in v.get("source_ports", [])]
    if sports:
        L += _task(f"{label}: source ports", "ansible.posix.firewalld", {**base, "source_port": "{{ item }}"}, sports)
    if v.get("icmp_blocks"):
        L += _task(f"{label}: ICMP blocks", "ansible.posix.firewalld", {**base, "icmp_block": "{{ item }}"}, v["icmp_blocks"])
    fwd = []
    for fp in v.get("forward_ports", []):
        fwd.append(f"{fp['port']}/{fp['protocol']};{fp.get('to_port') or ''};{fp.get('to_addr') or ''}")
    if fwd:
        L += _task(f"{label}: forward ports", "ansible.posix.firewalld", {**base, "port_forward": "{{ item }}"}, fwd)
    if v.get("masquerade"):
        L += _task(f"{label}: masquerade", "ansible.posix.firewalld", {**base, "masquerade": True})
    rules = [r["rule"] for r in v.get("rich_rules", [])]
    if rules:
        L += _task(f"{label}: rich rules", "ansible.posix.firewalld", {**base, "rich_rule": "{{ item }}"}, rules)
    return L


def _cmd(name: str, check: str, cmd: str) -> list[str]:
    """Idempotent firewall-cmd task: run ``cmd`` only when ``check`` fails."""
    return [
        f"    - name: {_yaml_str(name)}",
        "      ansible.builtin.shell: |",
        f"        {check} >/dev/null 2>&1 && exit 0",
        f"        {cmd}",
        "        echo changed",
        "      register: _r",
        "      changed_when: \"'changed' in _r.stdout\"",
        "      notify: reload firewalld",
    ]


def to_ansible(data: dict, only_rules: list[str] | None = None, target: tuple[str, str] | None = None) -> str:
    L = [
        "---",
        f"# firewalld configuration exported by RichFD from {socket.gethostname()} on {time.strftime('%Y-%m-%d %H:%M')}",
        "# Requires the ansible.posix collection:  ansible-galaxy collection install ansible.posix",
        "# Additive and idempotent: existing items are left alone, nothing is removed.",
        "- name: Configure firewalld",
        "  hosts: all",
        "  become: true",
        "  tasks:",
        "    - name: firewalld is installed and running",
        "      ansible.builtin.package:",
        "        name: firewalld",
        "        state: present",
        "    - name: firewalld service",
        "      ansible.builtin.service:",
        "        name: firewalld",
        "        state: started",
        "        enabled: true",
    ]
    if only_rules is not None and target:
        scope, name = target
        if scope == "zone":
            L += _task(f"{name}: rich rules", "ansible.posix.firewalld",
                       {"zone": name, "permanent": True, "immediate": True, "state": "enabled", "rich_rule": "{{ item }}"},
                       only_rules)
        else:
            for r in only_rules:
                L += _cmd(f"policy {name}: {r[:60]}", f"firewall-cmd --permanent --policy={_q(name)} --query-rich-rule={_q(r)}",
                          f"firewall-cmd --permanent --policy={_q(name)} --add-rich-rule={_q(r)}")
        return "\n".join(L + _handlers()) + "\n"

    for name, s in data["services"].items():
        L += _cmd(f"service {name} exists", f"firewall-cmd --permanent --info-service={_q(name)}",
                  f"firewall-cmd --permanent --new-service={_q(name)}")
        for p in s.get("ports", []):
            L += _cmd(f"service {name}: port {p['port']}/{p['protocol']}",
                      f"firewall-cmd --permanent --service={_q(name)} --query-port={p['port']}/{p['protocol']}",
                      f"firewall-cmd --permanent --service={_q(name)} --add-port={p['port']}/{p['protocol']}")
        for pr in s.get("protocols", []):
            L += _cmd(f"service {name}: protocol {pr}",
                      f"firewall-cmd --permanent --service={_q(name)} --query-protocol={_q(pr)}",
                      f"firewall-cmd --permanent --service={_q(name)} --add-protocol={_q(pr)}")
    if data["services"]:
        L += ["    - name: load new services", "      ansible.builtin.meta: flush_handlers"]

    for name, s in data["ipsets"].items():
        opts = " ".join(f"--option={_q(f'{k}={v}')}" for k, v in (s.get("options") or {}).items())
        L += _cmd(f"ipset {name} exists", f"firewall-cmd --permanent --info-ipset={_q(name)}",
                  f"firewall-cmd --permanent --new-ipset={_q(name)} --type={_q(s['type'])} {opts}".rstrip())
        if s["entries"]:
            L += [
                f"    - name: {_yaml_str(f'ipset {name}: entries')}",
                "      ansible.builtin.copy:",
                f"        dest: /etc/firewalld/richfd-{name}.list",
                "        mode: \"0640\"",
                "        content: |",
                *[f"          {e}" for e in s["entries"]],
            ]
            L += [
                f"    - name: {_yaml_str(f'ipset {name}: load entries')}",
                f"      ansible.builtin.command: firewall-cmd --permanent --ipset={_q(name)} "
                f"--add-entries-from-file=/etc/firewalld/richfd-{name}.list",
                "      failed_when: false  # entries already present are reported as warnings",
                "      changed_when: false",
                "      notify: reload firewalld",
            ]

    for name, z in data["zones"].items():
        L += _cmd(f"zone {name} exists", f"firewall-cmd --permanent --info-zone={_q(name)}",
                  f"firewall-cmd --permanent --new-zone={_q(name)}")
        L += ["    - name: load new zones", "      ansible.builtin.meta: flush_handlers"]
        if z.get("target") and z["target"] != _BUILTIN_ZONE_TARGET:
            L += _task(f"{name}: target", "ansible.posix.firewalld",
                       {"zone": name, "target": z["target"], "permanent": True, "state": "present"})
        L += _fw_items({"zone": name}, z)
        for i in z.get("interfaces", []):
            L += _task(f"{name}: interface {i}", "ansible.posix.firewalld",
                       {"zone": name, "interface": i, "permanent": True, "immediate": True, "state": "enabled"})
        for src in z.get("sources", []):
            L += _task(f"{name}: source {src}", "ansible.posix.firewalld",
                       {"zone": name, "source": src, "permanent": True, "immediate": True, "state": "enabled"})
        if z.get("icmp_block_inversion"):
            L += _task(f"{name}: ICMP block inversion", "ansible.posix.firewalld",
                       {"zone": name, "icmp_block_inversion": True, "permanent": True, "immediate": True, "state": "enabled"})
        if z.get("forward"):
            L += _task(f"{name}: intra-zone forwarding", "ansible.posix.firewalld",
                       {"zone": name, "forward": True, "permanent": True, "immediate": True, "state": "enabled"})

    for name, p in data["policies"].items():
        pq = f"--policy={_q(name)}"
        L += _cmd(f"policy {name} exists", f"firewall-cmd --permanent --info-policy={_q(name)}",
                  f"firewall-cmd --permanent --new-policy={_q(name)}")
        L += _cmd(f"policy {name}: priority {p['priority']}",
                  f"test \"$(firewall-cmd --permanent {pq} --get-priority)\" = {p['priority']}",
                  f"firewall-cmd --permanent {pq} --set-priority={p['priority']}")
        L += _cmd(f"policy {name}: target {p['target']}",
                  f"test \"$(firewall-cmd --permanent {pq} --get-target)\" = {_q(p['target'])}",
                  f"firewall-cmd --permanent {pq} --set-target={_q(p['target'])}")
        for z in p.get("ingress_zones", []):
            L += _cmd(f"policy {name}: ingress {z}", f"firewall-cmd --permanent {pq} --query-ingress-zone={_q(z)}",
                      f"firewall-cmd --permanent {pq} --add-ingress-zone={_q(z)}")
        for z in p.get("egress_zones", []):
            L += _cmd(f"policy {name}: egress {z}", f"firewall-cmd --permanent {pq} --query-egress-zone={_q(z)}",
                      f"firewall-cmd --permanent {pq} --add-egress-zone={_q(z)}")
        for q, a in _items(pq, p):
            L += _cmd(f"policy {name}: {a.split('--add-', 1)[1][:60]}", f"firewall-cmd --permanent {q}",
                      f"firewall-cmd --permanent {a}")
    return "\n".join(L + _handlers()) + "\n"


def _handlers() -> list[str]:
    return [
        "  handlers:",
        "    - name: reload firewalld",
        "      ansible.builtin.command: firewall-cmd --reload",
    ]
