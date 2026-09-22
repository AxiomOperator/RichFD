"""Kernel packet-log entries (firewalld log-denied and rich rule 'log') from the journal."""

import asyncio
import json
import re
import subprocess
from datetime import datetime, timezone

# firewalld's log-denied prefixes, e.g. "filter_IN_public_REJECT: ", "filter_FWD_docker_DROP: "
_PREFIX_RE = re.compile(r"(?:filter|nat|mangle)_(?P<hook>IN|FWD|OUT|INPUT|FORWARD|OUTPUT)_(?P<zone>.+?)_(?P<action>REJECT|DROP|ACCEPT|allow|deny)\b", re.I)
_POLICY_RE = re.compile(r"filter_(?P<policy>[\w.+-]+?)_(?P<action>REJECT|DROP)\b")
_KV_RE = re.compile(r"(\b[A-Z]+)=(\S*)")


def parse_message(msg: str) -> dict | None:
    """Parse one kernel log line; None if it is not a packet log."""
    idx = msg.find("IN=")
    if idx < 0 or "SRC=" not in msg:
        return None
    prefix = msg[:idx].strip().rstrip(":").strip()
    fields = dict(_KV_RE.findall(msg[idx:]))
    entry = {
        "prefix": prefix,
        "in": fields.get("IN", ""),
        "out": fields.get("OUT", ""),
        "src": fields.get("SRC", ""),
        "dst": fields.get("DST", ""),
        "proto": fields.get("PROTO", "").lower(),
        "spt": int(fields["SPT"]) if fields.get("SPT", "").isdigit() else None,
        "dpt": int(fields["DPT"]) if fields.get("DPT", "").isdigit() else None,
        "len": int(fields["LEN"]) if fields.get("LEN", "").isdigit() else None,
        "icmp_type": fields.get("TYPE", ""),
        "mac": fields.get("MAC", ""),
        "zone": "",
        "action": "",
        "kind": "logged",
    }
    if entry["proto"] == "icmpv6":
        entry["proto"] = "ipv6-icmp"
    if m := _PREFIX_RE.search(prefix):
        entry["zone"] = m.group("zone")
        entry["action"] = m.group("action").upper()
        entry["kind"] = "denied" if entry["action"] in ("REJECT", "DROP", "DENY") else "logged"
        entry["direction"] = m.group("hook").upper()[:3]
    elif m := _POLICY_RE.search(prefix):
        entry["policy"] = m.group("policy")
        entry["action"] = m.group("action")
        entry["kind"] = "denied"
    elif "INVALID" in prefix.upper():
        entry["action"] = "DROP"
        entry["kind"] = "invalid"
    return entry


def _from_journal(rec: dict) -> dict | None:
    msg = rec.get("MESSAGE", "")
    if isinstance(msg, list):  # non-UTF-8 message is exported as a byte array
        msg = bytes(msg).decode("utf-8", "replace")
    entry = parse_message(msg)
    if entry is None:
        return None
    try:
        ts = int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        entry["ts"] = datetime.fromtimestamp(ts, timezone.utc).astimezone().isoformat(timespec="seconds")
    except (TypeError, ValueError):
        entry["ts"] = ""
    entry["cursor"] = rec.get("__CURSOR", "")
    return entry


def _read(args: list[str]) -> list[dict]:
    try:
        out = subprocess.run(["journalctl", "-k", "-o", "json", "--no-pager", *args],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    entries = []
    for line in out.splitlines():
        try:
            e = _from_journal(json.loads(line))
        except json.JSONDecodeError:
            continue
        if e:
            entries.append(e)
    return entries


def recent(limit: int = 500, scan: int = 20000) -> list[dict]:
    """Most recent packet-log entries, newest first."""
    return _read(["-n", str(scan)])[-limit:][::-1]


def stats(hours: int = 24, port: int | None = None, top: int = 10, entries: list[dict] | None = None) -> dict:
    """Aggregates of denied packets for the dashboard: top sources/ports/zones and a timeline."""
    from collections import Counter
    from datetime import datetime, timedelta

    if entries is None:
        entries = _read(["--since", f"-{hours}h"])
    denied = [e for e in entries if e["kind"] in ("denied", "invalid")]
    now = datetime.now().astimezone()
    start = now - timedelta(hours=hours)
    # bucket size: 5 min for <= 6h, 15 min for <= 24h, else hourly
    minutes = 5 if hours <= 6 else 15 if hours <= 24 else 60
    nb = max(1, int(hours * 60 / minutes))
    buckets = [0] * nb
    for e in denied:
        try:
            t = datetime.fromisoformat(e["ts"])
        except (KeyError, ValueError):
            continue
        idx = int((t - start).total_seconds() // (minutes * 60))
        if 0 <= idx < nb:
            buckets[idx] += 1
    timeline = [{"t": (start + timedelta(minutes=minutes * i)).isoformat(timespec="minutes"), "count": c}
                for i, c in enumerate(buckets)]

    def port_label(e):
        return f"{e['dpt']}/{e['proto']}" if e.get("dpt") else e.get("proto") or "?"

    src = Counter(e["src"] for e in denied)
    ports = Counter(port_label(e) for e in denied)
    zones = Counter(e.get("zone") or e.get("policy") or "other" for e in denied)
    ifaces = Counter(e.get("in") or "?" for e in denied)
    result = {
        "hours": hours,
        "bucket_minutes": minutes,
        "total": len(denied),
        "unique_sources": len(src),
        "timeline": timeline,
        "top_sources": [{"src": k, "count": v, "ports": sorted({port_label(e) for e in denied if e["src"] == k})[:5]}
                        for k, v in src.most_common(top)],
        "top_ports": [{"port": k, "count": v} for k, v in ports.most_common(top)],
        "top_zones": [{"zone": k, "count": v} for k, v in zones.most_common(top)],
        "top_interfaces": [{"interface": k, "count": v} for k, v in ifaces.most_common(top)],
    }
    if port is not None:
        on_port = Counter(e["src"] for e in denied if e.get("dpt") == port)
        result["port"] = port
        result["top_sources_on_port"] = [{"src": k, "count": v} for k, v in on_port.most_common(top)]
    return result


async def stream():
    """Server-sent events: one ``data:`` line per new packet-log entry, with keep-alives."""
    proc = await asyncio.create_subprocess_exec(
        "journalctl", "-k", "-o", "json", "--no-pager", "-f", "-n", "0",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        yield "retry: 3000\n\n"
        while True:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            if not line:
                yield "event: end\ndata: {}\n\n"
                break
            try:
                e = _from_journal(json.loads(line))
            except json.JSONDecodeError:
                continue
            if e:
                yield f"data: {json.dumps(e)}\n\n"
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
