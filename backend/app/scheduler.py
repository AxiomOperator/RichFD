"""Background jobs: DDNS re-resolution, IP-list feed refresh, automatic backups.

One daemon thread wakes every 30 seconds and runs whatever is due. Each job is isolated so a
failure in one never stops the others.
"""

import logging
import threading
import time

from . import audit, backups, ddns, store
from .fw import FwError, firewall

_log = logging.getLogger("richrule.scheduler")
_stop = threading.Event()
_thread: threading.Thread | None = None
TICK = 30


# -- IP list feeds (Cloudflare, Tor exit nodes, country blocks, ...) -------------------------


def feeds() -> dict:
    return store.load("feeds")


def register_feed(ipset: str, url: str, interval_hours: int = 24) -> None:
    data = feeds()
    data[ipset] = {**data.get(ipset, {}), "url": url, "interval_hours": interval_hours}
    store.save("feeds", data)


def remove_feed(ipset: str) -> None:
    data = feeds()
    data.pop(ipset, None)
    store.save("feeds", data)


def refresh_feed(ipset: str, user: str = "scheduler") -> dict:
    from .history import history
    from .templates import download_list

    data = feeds()
    feed = data.get(ipset)
    if not feed:
        raise FwError("No feed for this IP set", 404)
    feed["last_check"] = time.time()
    try:
        entries = download_list(feed["url"])
        with history.change(user, f"Refresh IP list {ipset} from {feed['url']}"):
            firewall.call(lambda c: c.config().getIPSetByName(ipset).setEntries(entries))
            if ipset in firewall.call(lambda c: c.getIPSets()):
                firewall.call(lambda c: c.setEntries(ipset, entries))
        feed.update(count=len(entries), last_error="", last_ok=time.time())
        audit.record(user, "refresh ip list", {"name": ipset, "count": len(entries)})
    except FwError as e:
        feed["last_error"] = e.message
    data[ipset] = feed
    store.save("feeds", data)
    return feed


def _feeds_due() -> None:
    now = time.time()
    for name, feed in feeds().items():
        if now - feed.get("last_check", 0) >= feed.get("interval_hours", 24) * 3600:
            refresh_feed(name)


# -- loop ------------------------------------------------------------------------------------


def _run_once() -> None:
    for job in (ddns.refresh_due, _feeds_due, backups.auto_backup_due):
        try:
            job()
        except Exception as e:  # keep the scheduler alive
            _log.warning("%s failed: %s", job.__name__, e)


def _loop() -> None:
    while not _stop.wait(TICK):
        _run_once()


def start() -> None:
    global _thread
    if _thread is None:
        _thread = threading.Thread(target=_loop, name="richrule-scheduler", daemon=True)
        _thread.start()


def stop() -> None:
    _stop.set()
