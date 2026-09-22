"""Configuration history: git snapshots of /etc/firewalld, and detection of outside changes.

Every change made through richrule runs inside ``history.change(user, label)``, which:

1. checks for changes made outside richrule since the last check (``firewall-cmd``,
   editing XML, another tool) — permanent ones are committed as "external change",
   runtime ones are diffed against the last known runtime state — and records them;
2. runs the change;
3. commits the resulting permanent config with the user and a description, and records
   the new runtime state as expected.

A background watcher performs step 1 periodically. Restoring a snapshot copies its files
back into /etc/firewalld and reloads firewalld.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import audit
from .config import settings
from .fw import FwError, firewall

_log = logging.getLogger("richrule.history")


class History:
    def __init__(self, fw_dir: Path | None = None, repo: Path | None = None):
        self.fw_dir = fw_dir or settings.firewalld_dir
        self.repo = repo or settings.state_dir / "history"
        self.tree = self.repo / "tree"
        self.lock = threading.RLock()
        self._runtime: dict | None = None
        self._git_ok: bool | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # (expires_at, change line) for runtime items added with a timeout: their expiry
        # is expected and must not be reported as an external change.
        self._timed: list[tuple[float, str]] = []

    # -- git plumbing ---------------------------------------------------------

    def _git(self, *args: str, check: bool = True) -> str:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.repo),
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
        r = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, env=env)
        if check and r.returncode != 0:
            raise FwError(f"git {args[0]} failed: {r.stderr.strip() or r.stdout.strip()}", 500)
        return r.stdout

    @property
    def enabled(self) -> bool:
        """Snapshots need git, a readable firewalld config dir and a writable state dir."""
        if self._git_ok is None:
            self._git_ok = self._init()
        return self._git_ok

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "firewalld_dir": str(self.fw_dir),
            "repo": str(self.repo),
            "watch_interval": settings.watch_interval,
        }

    def _init(self) -> bool:
        if not shutil.which("git"):
            _log.warning("git not installed; config history disabled")
            return False
        if not os.access(self.fw_dir, os.R_OK | os.X_OK):
            _log.warning("%s not readable; config history disabled", self.fw_dir)
            return False
        try:
            self.tree.mkdir(parents=True, exist_ok=True)
            if not (self.repo / ".git").exists():
                self._git("init", "-q")
                self._git("config", "user.name", "richrule")
                self._git("config", "user.email", "richrule@localhost")
            self._sync_in()
            if not self._git("rev-parse", "--verify", "-q", "HEAD", check=False).strip():
                self._commit("Initial snapshot", "richrule")
            return True
        except (OSError, FwError) as e:
            _log.warning("config history disabled: %s", e)
            return False

    @staticmethod
    def _mirror(src: Path, dst: Path) -> None:
        """Make dst an exact copy of src (files and directories), preserving file modes."""
        dst.mkdir(parents=True, exist_ok=True)
        src_names = {p.name for p in src.iterdir()}
        for p in dst.iterdir():
            if p.name not in src_names:
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
        for p in src.iterdir():
            target = dst / p.name
            if p.is_dir() and not p.is_symlink():
                if target.exists() and not target.is_dir():
                    target.unlink()
                History._mirror(p, target)
            elif p.is_file():
                if target.is_dir():
                    shutil.rmtree(target)
                data = p.read_bytes()
                if not target.exists() or target.read_bytes() != data:
                    target.write_bytes(data)
                    os.chmod(target, p.stat().st_mode & 0o7777)

    def _sync_in(self) -> None:
        self._mirror(self.fw_dir, self.tree)

    def _commit(self, message: str, author: str) -> str | None:
        self._git("add", "-A", ".")
        if not self._git("status", "--porcelain").strip():
            return None
        safe_author = "".join(ch for ch in author if ch.isalnum() or ch in "-_.") or "unknown"
        self._git("commit", "-q", "-m", message, "--author", f"{safe_author} <{safe_author}@richrule>")
        return self._git("rev-parse", "HEAD").strip()

    # -- runtime fingerprint -------------------------------------------------

    def _runtime_state(self) -> dict:
        def f(c):
            state = {"default_zone": c.getDefaultZone(), "panic": bool(c.queryPanicMode()), "zones": {}, "policies": {}, "ipsets": {}}
            for z in c.getZones():
                state["zones"][z] = c.getZoneSettings(z).getSettingsDict()
            for name, fn in (("policies", lambda: {p: dict(c.getPolicySettings(p).getSettingsDict()) for p in c.getPolicies()}),
                             ("ipsets", lambda: {i: sorted(str(e) for e in c.getEntries(i)) for i in c.getIPSets()})):
                try:
                    state[name] = fn()
                except Exception:
                    pass
            return json.loads(json.dumps(state, default=list))

        return firewall.call(f)

    @staticmethod
    def _diff_runtime(old: dict, new: dict) -> list[str]:
        lines = []
        for key in ("default_zone", "panic"):
            if old.get(key) != new.get(key):
                lines.append(f"{key}: {old.get(key)} → {new.get(key)}")
        for section, label in (("zones", "zone"), ("policies", "policy")):
            o, n = old.get(section, {}), new.get(section, {})
            for name in sorted(set(o) | set(n)):
                if name not in o:
                    lines.append(f"{label} {name} added")
                    continue
                if name not in n:
                    lines.append(f"{label} {name} removed")
                    continue
                for k in sorted(set(o[name]) | set(n[name])):
                    ov, nv = o[name].get(k), n[name].get(k)
                    if ov == nv:
                        continue
                    if isinstance(ov, list) and isinstance(nv, list):
                        ov_s, nv_s = [json.dumps(x) for x in ov], [json.dumps(x) for x in nv]
                        for x in nv_s:
                            if x not in ov_s:
                                lines.append(f"{label} {name}: + {k} {json.loads(x)}")
                        for x in ov_s:
                            if x not in nv_s:
                                lines.append(f"{label} {name}: - {k} {json.loads(x)}")
                    else:
                        lines.append(f"{label} {name}: {k} {ov} → {nv}")
        o, n = old.get("ipsets", {}), new.get("ipsets", {})
        for name in sorted(set(o) | set(n)):
            added = set(n.get(name, [])) - set(o.get(name, []))
            removed = set(o.get(name, [])) - set(n.get(name, []))
            if added:
                lines.append(f"ipset {name}: + {len(added)} entries ({', '.join(sorted(added)[:5])})")
            if removed:
                lines.append(f"ipset {name}: - {len(removed)} entries ({', '.join(sorted(removed)[:5])})")
        return lines

    def expect_expiry(self, zone: str, scope: str, key: str, value, seconds: int) -> None:
        label = "zone" if scope == "zone" else "policy"
        self._timed.append((time.time() + seconds + 120, f"{label} {zone}: - {key} {json.loads(json.dumps(value))}"))

    def _filter_expected(self, lines: list[str]) -> list[str]:
        now = time.time()
        self._timed = [(t, l) for t, l in self._timed if t > now]
        expected = {l for _, l in self._timed}
        return [l for l in lines if l not in expected]

    # -- detection -------------------------------------------------------------

    def check_external(self) -> dict | None:
        """Record changes made outside richrule since the last check. Returns what was found."""
        with self.lock:
            found: dict = {}
            if self.enabled:
                try:
                    self._sync_in()
                    commit = self._commit("External change (made outside richrule)", "external")
                    if commit:
                        found["commit"] = commit[:12]
                        found["files"] = self._git("show", "--name-status", "--format=", commit).split("\n")[:50]
                        found["files"] = [f for f in found["files"] if f]
                except (OSError, FwError) as e:
                    _log.warning("snapshot failed: %s", e)
            try:
                current = self._runtime_state()
            except FwError:
                current = None
            if current is not None:
                if self._runtime is not None:
                    lines = self._filter_expected(self._diff_runtime(self._runtime, current))
                    if lines:
                        found["runtime_changes"] = lines
                self._runtime = current
            if found:
                audit.record("external", "external change detected", found)
                return found
            return None

    @contextmanager
    def change(self, user: str, label: str):
        """Wrap a change made through richrule (see module docstring)."""
        with self.lock:
            self.check_external()
            try:
                yield
            finally:
                if self.enabled:
                    try:
                        self._sync_in()
                        self._commit(f"{label}", user)
                    except (OSError, FwError) as e:
                        _log.warning("snapshot after change failed: %s", e)
                try:
                    self._runtime = self._runtime_state()
                except FwError:
                    pass

    # -- browsing / restore ------------------------------------------------------

    def _require(self) -> None:
        if not self.enabled:
            raise FwError(
                f"Config history is unavailable (needs git and read access to {self.fw_dir}; run richrule as root)", 503
            )

    def log(self, limit: int = 200) -> list[dict]:
        self._require()
        out = self._git("log", f"-n{limit}", "--format=%H%x1f%an%x1f%aI%x1f%s%x1e", "--shortstat")
        # Header lines contain \x1f; the --shortstat line that follows belongs to the entry before it.
        entries = []
        for line in out.replace("\x1e", "\n").splitlines():
            line = line.strip()
            if not line:
                continue
            if "\x1f" in line:
                h, author, date, subject = line.split("\x1f", 3)
                entries.append({"id": h, "short": h[:12], "author": author, "date": date, "message": subject,
                                "stat": "", "external": author == "external"})
            elif entries:
                entries[-1]["stat"] = line
        return entries

    def _verify_id(self, commit: str) -> str:
        if not commit.isalnum() or len(commit) < 7:
            raise FwError("Invalid snapshot id", 400)
        full = self._git("rev-parse", "--verify", "-q", f"{commit}^{{commit}}", check=False).strip()
        if not full:
            raise FwError("No such snapshot", 404)
        return full

    def show(self, commit: str) -> dict:
        """The change a snapshot introduced (diff against its parent)."""
        self._require()
        full = self._verify_id(commit)
        return {"id": full, "diff": self._git("show", "--format=", "--patch", "--find-renames", full, "--", ".")}

    def diff_to_current(self, commit: str) -> dict:
        """What restoring ``commit`` would change in the current configuration."""
        self._require()
        full = self._verify_id(commit)
        with self.lock:
            self._sync_in()
            self._git("add", "-A", ".")
            diff = self._git("diff", "--cached", "-R", full, "--", ".")
            self._git("reset", "-q")
        return {"id": full, "diff": diff}

    def restore(self, commit: str, user: str) -> None:
        self._require()
        full = self._verify_id(commit)
        with self.change(user, f"Restore snapshot {full[:12]}"):
            with tempfile.TemporaryDirectory() as tmp:
                archive = subprocess.run(
                    ["git", "-C", str(self.repo), "archive", "--format=tar", full, "tree"],
                    capture_output=True, check=True,
                ).stdout
                subprocess.run(["tar", "-x", "-C", tmp], input=archive, check=True)
                src = Path(tmp) / "tree"
                src.mkdir(exist_ok=True)
                self._restore_modes(src)
                self._mirror(src, self.fw_dir)
            firewall.reload()

    def _restore_modes(self, src: Path) -> None:
        """git keeps only the exec bit; reuse current modes where files exist, else 0640/0750."""
        for p in src.rglob("*"):
            current = self.fw_dir / p.relative_to(src)
            try:
                mode = current.stat().st_mode & 0o7777
            except FileNotFoundError:
                mode = 0o750 if p.is_dir() else 0o640
            os.chmod(p, mode)

    # -- watcher -------------------------------------------------------------------

    def start(self) -> None:
        if settings.watch_interval <= 0 or self._thread:
            return
        self._thread = threading.Thread(target=self._watch, name="richrule-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _watch(self) -> None:
        # Establish the baseline without reporting it.
        with self.lock:
            if self.enabled:
                pass
            try:
                self._runtime = self._runtime_state()
            except FwError:
                pass
        while not self._stop.wait(settings.watch_interval):
            try:
                self.check_external()
            except Exception as e:
                _log.warning("external change check failed: %s", e)


history = History()
