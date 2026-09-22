"""Small JSON documents kept in the state directory (mode 0600: they may hold secrets)."""

import json
import os
import threading
from pathlib import Path

from .config import settings

_lock = threading.Lock()
# Fallback when the state directory is not writable (dev runs as a normal user).
_memory: dict[str, dict] = {}


def _path(name: str) -> Path:
    return settings.state_dir / f"{name}.json"


def load(name: str, default: dict | None = None) -> dict:
    with _lock:
        try:
            return json.loads(_path(name).read_text())
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError):
            if name in _memory:
                return json.loads(json.dumps(_memory[name]))
        return json.loads(json.dumps(_memory.get(name, default or {})))


def save(name: str, data: dict) -> None:
    with _lock:
        _memory[name] = json.loads(json.dumps(data))
        path = _path(name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except OSError:
            pass  # kept in memory only
