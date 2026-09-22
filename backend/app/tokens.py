"""API tokens that let a richrule console manage this host as an agent.

Only SHA-256 hashes are stored. Manage with ``python -m app.tokens create|list|revoke``
or from the Settings page.
"""

import hashlib
import hmac
import secrets
import sys
import time

from . import store

PREFIX = "rr_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def list_tokens() -> list[dict]:
    return [{k: v for k, v in t.items() if k != "hash"} for t in store.load("agent_tokens").get("tokens", [])]


def create(name: str) -> str:
    data = store.load("agent_tokens")
    tokens = data.setdefault("tokens", [])
    if any(t["name"] == name for t in tokens):
        raise ValueError(f"token '{name}' already exists")
    token = PREFIX + secrets.token_urlsafe(32)
    tokens.append({"name": name, "hash": _hash(token), "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "last_used": ""})
    store.save("agent_tokens", data)
    return token


def revoke(name: str) -> bool:
    data = store.load("agent_tokens")
    before = len(data.get("tokens", []))
    data["tokens"] = [t for t in data.get("tokens", []) if t["name"] != name]
    store.save("agent_tokens", data)
    return len(data["tokens"]) < before


def verify(token: str) -> str | None:
    """Return the token's name if valid."""
    if not token.startswith(PREFIX):
        return None
    h = _hash(token)
    data = store.load("agent_tokens")
    for t in data.get("tokens", []):
        if hmac.compare_digest(t["hash"], h):
            now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            if t.get("last_used", "")[:16] != now[:16]:  # throttle writes to once a minute
                t["last_used"] = now
                store.save("agent_tokens", data)
            return t["name"]
    return None


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "create":
        print(create(argv[1]))
        return 0
    if argv[:1] == ["list"]:
        for t in list_tokens():
            print(f"{t['name']}\tcreated {t['created']}\tlast used {t.get('last_used') or 'never'}")
        return 0
    if len(argv) >= 2 and argv[0] == "revoke":
        ok = revoke(argv[1])
        print("revoked" if ok else "no such token")
        return 0 if ok else 1
    print("usage: python -m app.tokens create NAME | list | revoke NAME", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
