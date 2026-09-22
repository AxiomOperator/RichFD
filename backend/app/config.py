"""Runtime settings, read from RICHRULE_* environment variables."""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"RICHRULE_{name}", default)


def _load_secret(path: Path) -> bytes:
    """Read the session signing key, creating it (mode 0600) on first run."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except OSError:
        # Not writable (e.g. dev run as a normal user): key lives for this process only.
        pass
    return key


@dataclass
class Settings:
    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("PORT", "8443")))
    allowed_group: str = field(default_factory=lambda: _env("ALLOWED_GROUP", "wheel"))
    # Members of this group may log in read-only.
    viewer_group: str = field(default_factory=lambda: _env("VIEWER_GROUP", "firewall-viewers"))
    pam_service: str = field(default_factory=lambda: _env("PAM_SERVICE", "richrule"))
    secret_file: Path = field(
        default_factory=lambda: Path(_env("SECRET_FILE", "/var/lib/richrule/secret.key"))
    )
    audit_log: Path = field(
        default_factory=lambda: Path(_env("AUDIT_LOG", "/var/log/richrule/audit.log"))
    )
    session_idle_seconds: int = field(
        default_factory=lambda: int(_env("SESSION_IDLE_SECONDS", "1800"))
    )
    safe_apply_seconds: int = field(
        default_factory=lambda: int(_env("SAFE_APPLY_SECONDS", "60"))
    )
    state_dir: Path = field(default_factory=lambda: Path(_env("STATE_DIR", "/var/lib/richrule")))
    firewalld_dir: Path = field(default_factory=lambda: Path(_env("FIREWALLD_DIR", "/etc/firewalld")))
    # Seconds between checks for changes made outside richrule (0 disables the watcher).
    watch_interval: int = field(default_factory=lambda: int(_env("WATCH_INTERVAL", "30")))
    # Optional built-in HTTPS.
    tls_cert: str = field(default_factory=lambda: _env("TLS_CERT", ""))
    tls_key: str = field(default_factory=lambda: _env("TLS_KEY", ""))
    # Set to 0 when serving plain HTTP on localhost without a TLS proxy.
    secure_cookies: bool = field(
        default_factory=lambda: _env("SECURE_COOKIES", "1" if _env("TLS_CERT", "") else "0") == "1"
    )
    static_dir: Path = field(
        default_factory=lambda: Path(
            _env("STATIC_DIR", str(Path(__file__).resolve().parents[2] / "frontend" / "dist"))
        )
    )
    # Development only: skip PAM and accept any login as this user.
    dev_user: str = field(default_factory=lambda: _env("DEV_USER", ""))

    _secret: bytes | None = None

    @property
    def secret_key(self) -> bytes:
        if self._secret is None:
            self._secret = _load_secret(self.secret_file)
        return self._secret


settings = Settings()
