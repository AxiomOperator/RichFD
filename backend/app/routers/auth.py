from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from .. import audit
from ..auth import Session, current_session, end_session, require_user, start_session, verify
from ..config import settings

router = APIRouter(prefix="/api", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "?"
    try:
        verify(body.username, body.password, client_ip)
    except Exception:
        audit.record(body.username, "login", {"ip": client_ip}, ok=False)
        raise
    csrf = start_session(response, body.username)
    audit.record(body.username, "login", {"ip": client_ip})
    return {"user": body.username, "csrf": csrf}


@router.post("/logout")
def logout(response: Response, session: Session = Depends(require_user)):
    end_session(response)
    return {"ok": True}


@router.get("/me")
def me(session: Session = Depends(current_session)):
    return {
        "user": session.user,
        "csrf": session.csrf,
        "safe_apply_seconds": settings.safe_apply_seconds,
        "dev_mode": bool(settings.dev_user),
    }
