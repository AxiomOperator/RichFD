from fastapi import APIRouter, Depends, Query

from .. import audit
from ..auth import Session, require_user

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit")
def get_audit(limit: int = Query(200, ge=1, le=5000), session: Session = Depends(require_user)):
    return audit.tail(limit)
