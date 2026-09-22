"""Send audit events to a webhook, syslog and/or email.

Settings live in the state directory (``notifications.json``) and are edited from the UI.
Delivery happens on a background thread so a slow endpoint never blocks a change.
"""

import json
import logging
import logging.handlers
import smtplib
import socket
import threading
import urllib.request
from email.message import EmailMessage

from . import store

_log = logging.getLogger("richrule.notify")

DEFAULTS = {
    "webhook_url": "",
    "syslog": False,
    "email_to": "",
    "email_from": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_starttls": True,
    "smtp_user": "",
    "smtp_password": "",
    # Which events: "changes" (all changes + external changes) or "all" (also logins).
    "events": "changes",
}

_syslog: logging.Logger | None = None


def get_settings() -> dict:
    return {**DEFAULTS, **store.load("notifications")}


def public_settings() -> dict:
    s = get_settings()
    s["smtp_password_set"] = bool(s.pop("smtp_password"))
    return s


def update_settings(new: dict) -> None:
    s = get_settings()
    for k in DEFAULTS:
        if k in new and not (k == "smtp_password" and new[k] is None):
            s[k] = new[k]
    store.save("notifications", s)


def summary(entry: dict) -> str:
    detail = entry.get("detail") or {}
    parts = []
    if ops := detail.get("ops"):
        parts.append("; ".join(ops) if isinstance(ops, list) else str(ops))
    for key in ("zone", "policy", "name", "target", "label", "commit"):
        if key in detail:
            parts.append(f"{key}={detail[key]}")
    if runtime := detail.get("runtime_changes"):
        parts.append("; ".join(runtime[:10]))
    if err := detail.get("error"):
        parts.append(f"error: {err}")
    status = "" if entry.get("ok", True) else " [FAILED]"
    return f"[richrule@{socket.gethostname()}] {entry['user']}: {entry['action']}{status} — {' · '.join(parts)}"[:2000]


def _wanted(entry: dict, s: dict) -> bool:
    if entry["action"] == "login":
        return s["events"] == "all" or not entry.get("ok", True)
    return True


def _send_webhook(url: str, entry: dict, text: str) -> None:
    body = json.dumps({"text": text, "event": entry, "host": socket.gethostname()}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _send_syslog(text: str) -> None:
    global _syslog
    if _syslog is None:
        _syslog = logging.getLogger("richrule.syslog")
        _syslog.propagate = False
        handler = logging.handlers.SysLogHandler(address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_AUTHPRIV)
        handler.setFormatter(logging.Formatter("richrule: %(message)s"))
        _syslog.addHandler(handler)
        _syslog.setLevel(logging.INFO)
    _syslog.info(text)


def _send_email(s: dict, entry: dict, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[richrule] {entry['action']} by {entry['user']} on {socket.gethostname()}"
    msg["From"] = s["email_from"] or f"richrule@{socket.getfqdn()}"
    msg["To"] = s["email_to"]
    msg.set_content(text + "\n\n" + json.dumps(entry, indent=2))
    with smtplib.SMTP(s["smtp_host"], int(s["smtp_port"]), timeout=15) as smtp:
        if s["smtp_starttls"]:
            smtp.starttls()
        if s["smtp_user"]:
            smtp.login(s["smtp_user"], s["smtp_password"])
        smtp.send_message(msg)


def deliver(entry: dict, s: dict | None = None) -> dict[str, str]:
    """Send one event synchronously. Returns channel -> 'ok' or error text."""
    s = s or get_settings()
    text = summary(entry)
    results: dict[str, str] = {}
    channels = []
    if s["webhook_url"]:
        channels.append(("webhook", lambda: _send_webhook(s["webhook_url"], entry, text)))
    if s["syslog"]:
        channels.append(("syslog", lambda: _send_syslog(text)))
    if s["email_to"] and s["smtp_host"]:
        channels.append(("email", lambda: _send_email(s, entry, text)))
    for name, fn in channels:
        try:
            fn()
            results[name] = "ok"
        except Exception as e:  # never let notification failures escape
            results[name] = f"{type(e).__name__}: {e}"
            _log.warning("notification via %s failed: %s", name, e)
    return results


def dispatch(entry: dict) -> None:
    s = get_settings()
    if not (s["webhook_url"] or s["syslog"] or (s["email_to"] and s["smtp_host"])):
        return
    if not _wanted(entry, s):
        return
    threading.Thread(target=deliver, args=(entry, s), daemon=True).start()
