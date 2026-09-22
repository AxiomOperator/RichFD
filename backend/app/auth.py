"""PAM login restricted to a group, signed session cookies, CSRF protection."""

import grp
import hmac
import os
import pwd
import secrets
import threading
import time
from collections import defaultdict, deque

import pam
from fastapi import Depends, HTTPException, Request, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import settings

COOKIE = "richrule_session"
CSRF_HEADER = "X-CSRF-Token"

_serializer: URLSafeTimedSerializer | None = None


def _signer() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(settings.secret_key, salt="richrule-session")
    return _serializer


# -- rate limiting ---------------------------------------------------------

_MAX_FAILURES = 5
_WINDOW = 300  # seconds
_failures: dict[str, deque[float]] = defaultdict(deque)
_fail_lock = threading.Lock()


def _check_rate(key: str) -> None:
    now = time.time()
    with _fail_lock:
        q = _failures[key]
        while q and q[0] < now - _WINDOW:
            q.popleft()
        if len(q) >= _MAX_FAILURES:
            raise HTTPException(429, "Too many failed logins; try again later")


def _note_failure(key: str) -> None:
    with _fail_lock:
        _failures[key].append(time.time())


# -- credentials -------------------------------------------------------------

def in_group(username: str, group_name: str) -> bool:
    try:
        user = pwd.getpwnam(username)
        group = grp.getgrnam(group_name)
    except KeyError:
        return False
    return group.gr_gid in os.getgrouplist(username, user.pw_gid)


def role_for(username: str) -> str | None:
    if in_group(username, settings.allowed_group):
        return "admin"
    if settings.viewer_group and in_group(username, settings.viewer_group):
        return "viewer"
    return None


def verify(username: str, password: str, client_ip: str) -> str:
    """Return the user's role; raise HTTPException unless the credentials are valid and authorized."""
    for key in (f"ip:{client_ip}", f"user:{username}"):
        _check_rate(key)
    if settings.dev_user:
        ok = True
    else:
        ok = pam.authenticate(username, password, service=settings.pam_service)
    if not ok:
        _note_failure(f"ip:{client_ip}")
        _note_failure(f"user:{username}")
        raise HTTPException(401, "Invalid username or password")
    if settings.dev_user:
        return os.environ.get("RICHRULE_DEV_ROLE", "admin")
    role = role_for(username)
    if role is None:
        groups = f"'{settings.allowed_group}'" + (f" or '{settings.viewer_group}'" if settings.viewer_group else "")
        raise HTTPException(403, f"User is not a member of the {groups} group")
    return role


# -- sessions ------------------------------------------------------------------

def start_session(response: Response, username: str, role: str) -> str:
    csrf = secrets.token_urlsafe(24)
    token = _signer().dumps({"u": username, "c": csrf, "r": role})
    _set_cookie(response, token)
    return csrf


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE,
        token,
        max_age=settings.session_idle_seconds,
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
        path="/",
    )


def end_session(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/")


class Session:
    def __init__(self, user: str, csrf: str, role: str = "admin", via_token: bool = False):
        self.user = user
        self.csrf = csrf
        self.role = role
        self.via_token = via_token

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def current_session(request: Request, response: Response) -> Session:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        from . import tokens

        name = tokens.verify(auth[7:].strip())
        if not name:
            raise HTTPException(401, "Invalid API token")
        # A console forwards the name of its logged-in user for the audit log.
        forwarded = request.headers.get("X-Richrule-User", "").strip()[:64]
        user = f"{forwarded}@{name}" if forwarded else f"token:{name}"
        role = request.headers.get("X-Richrule-Role", "admin")
        return Session(user, "", "viewer" if role == "viewer" else "admin", via_token=True)
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Not logged in")
    try:
        data = _signer().loads(token, max_age=settings.session_idle_seconds)
    except BadSignature:
        raise HTTPException(401, "Session expired") from None
    # Sliding idle timeout: re-issue the cookie on each authenticated request.
    _set_cookie(response, _signer().dumps(data))
    return Session(data["u"], data["c"], data.get("r", "admin"))


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
# POST endpoints that only read (analysis/validation); viewers may call them.
READ_ONLY_POSTS = ("/rich-rules/parse", "/rich-rules/render", "/tester", "/risk",
                   "/templates/preview", "/import/preview")


def require_user(request: Request, session: Session = Depends(current_session)) -> Session:
    """Authenticated user. Mutating requests need the CSRF token (cookie sessions) and the admin role."""
    if request.method not in SAFE_METHODS:
        if not session.via_token:
            sent = request.headers.get(CSRF_HEADER, "")
            if not hmac.compare_digest(sent, session.csrf):
                raise HTTPException(403, "Missing or invalid CSRF token")
        path = request.url.path
        # Suffix match so proxied calls (/api/h/<host>/tester) are covered too.
        read_only = any(path.endswith(p) for p in READ_ONLY_POSTS) or (
            path.startswith("/api/hosts/") and path.endswith("/test"))
        if not session.is_admin and not read_only and path not in ("/api/logout",):
            raise HTTPException(403, "Read-only account: changes are not allowed")
    return session
