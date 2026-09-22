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

def in_allowed_group(username: str) -> bool:
    try:
        user = pwd.getpwnam(username)
        group = grp.getgrnam(settings.allowed_group)
    except KeyError:
        return False
    return group.gr_gid in os.getgrouplist(username, user.pw_gid)


def verify(username: str, password: str, client_ip: str) -> None:
    """Raise HTTPException unless the credentials are valid and authorized."""
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
    if not settings.dev_user and not in_allowed_group(username):
        raise HTTPException(403, f"User is not a member of the '{settings.allowed_group}' group")


# -- sessions ------------------------------------------------------------------

def start_session(response: Response, username: str) -> str:
    csrf = secrets.token_urlsafe(24)
    token = _signer().dumps({"u": username, "c": csrf})
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
    def __init__(self, user: str, csrf: str):
        self.user = user
        self.csrf = csrf


def current_session(request: Request, response: Response) -> Session:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Not logged in")
    try:
        data = _signer().loads(token, max_age=settings.session_idle_seconds)
    except BadSignature:
        raise HTTPException(401, "Session expired") from None
    # Sliding idle timeout: re-issue the cookie on each authenticated request.
    _set_cookie(response, _signer().dumps(data))
    return Session(data["u"], data["c"])


def require_user(request: Request, session: Session = Depends(current_session)) -> Session:
    """Authenticated user; mutating methods must also carry the CSRF token."""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent, session.csrf):
            raise HTTPException(403, "Missing or invalid CSRF token")
    return session
