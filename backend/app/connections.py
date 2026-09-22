"""Live network connections (ss, and conntrack when available) for the connection tracker.

Each remote address is annotated with what the firewall thinks of it: private/public, which
zone its traffic lands in, and whether a rich rule already mentions it. Blocking is done by
the frontend through the normal change path (a drop rich rule); established flows can then
be terminated here, because conntrack keeps accepting already-established connections.
"""

import ipaddress
import re
import shutil
import subprocess

from .fw import FwError

_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FwError(f"{cmd[0]} failed: {e}", 500) from None


def _split(addr: str) -> tuple[str, str]:
    """'1.2.3.4:22' / '[fe80::1%eth0]:22' / '*:*' -> (address, port)."""
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    if "%" in host:
        host = host.split("%", 1)[0]
    return host, port


def classify(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if a.is_private:
        return "private"
    if a.is_unspecified:
        return "any"
    return "public"


def parse_ss(output: str) -> list[dict]:
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, state = parts[0], parts[1]
        local, peer = parts[4], parts[5]
        proc = " ".join(parts[6:])
        lip, lport = _split(local)
        pip, pport = _split(peer)
        m = _PROC_RE.search(proc)
        rows.append({
            "proto": proto,
            "state": state,
            "local_addr": lip,
            "local_port": lport,
            "peer_addr": pip,
            "peer_port": pport,
            "process": m.group(1) if m else "",
            "pid": int(m.group(2)) if m else None,
            "listening": state in ("LISTEN", "UNCONN") and pip in ("*", "0.0.0.0", "::", ""),
            "peer_class": classify(pip) if pip not in ("*", "0.0.0.0", "::", "") else "any",
        })
    return rows


def parse_conntrack(output: str) -> list[dict]:
    """``conntrack -L -o extended`` lines (first tuple = original direction)."""
    rows = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("conntrack"):
            continue
        parts = line.split()
        try:
            proto = parts[2]
        except IndexError:
            continue
        kv = [p.split("=", 1) for p in parts if "=" in p]
        first: dict[str, str] = {}
        second: dict[str, str] = {}
        for k, v in kv:
            (second if k in first else first).setdefault(k, v)
        state = next((p for p in parts[4:6] if p.isupper() and "=" not in p), "")
        rows.append({
            "proto": proto,
            "state": state,
            "src": first.get("src", ""),
            "dst": first.get("dst", ""),
            "sport": first.get("sport", ""),
            "dport": first.get("dport", ""),
            "reply_src": second.get("src", ""),
            "nat": bool(second) and second.get("src") != first.get("dst"),
            "assured": "[ASSURED]" in line,
            "src_class": classify(first.get("src", "")),
        })
    return rows


def connections() -> dict:
    ss = _run(["ss", "-Htunap"])
    rows = parse_ss(ss.stdout)
    listening = {(r["proto"], r["local_port"]) for r in rows if r["listening"]}
    for r in rows:
        r["direction"] = "listen" if r["listening"] else ("in" if (r["proto"], r["local_port"]) in listening else "out")
    ct_rows: list[dict] = []
    ct_error = ""
    if shutil.which("conntrack"):
        ct = _run(["conntrack", "-L", "-o", "extended"])
        if ct.returncode == 0:
            ct_rows = parse_conntrack(ct.stdout)
        else:
            ct_error = (ct.stderr or "conntrack failed").strip().splitlines()[-1]
    else:
        ct_error = "conntrack-tools is not installed (dnf install conntrack-tools) — showing sockets from ss only"
    return {"sockets": rows, "conntrack": ct_rows, "conntrack_error": ct_error,
            "processes_visible": any(r["pid"] for r in rows)}


def terminate(ip: str) -> dict:
    """Kill established connections with a peer (ss -K) and drop its conntrack entries."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise FwError(f"Invalid address: {ip}") from None
    if addr.is_loopback:
        raise FwError("Refusing to terminate loopback connections")
    results = {}
    r = _run(["ss", "-K", "dst", str(addr)])
    killed = max(0, len([l for l in r.stdout.splitlines() if l.strip()]) - 1)
    results["sockets_closed"] = killed if r.returncode == 0 else 0
    if r.returncode != 0:
        results["ss_error"] = r.stderr.strip() or "ss -K failed (needs root and kernel INET_DIAG_DESTROY)"
    if shutil.which("conntrack"):
        c1 = _run(["conntrack", "-D", "-s", str(addr)])
        c2 = _run(["conntrack", "-D", "-d", str(addr)])
        n = sum(int(m.group(1)) for c in (c1, c2) if (m := re.search(r"(\d+) flow entries", c.stderr)))
        results["conntrack_deleted"] = n
    return results
