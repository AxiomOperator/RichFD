from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from .. import denied, tester
from ..auth import Session, require_user

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/tester")
def run_tester(pkt: tester.Packet, session: Session = Depends(require_user)):
    """Simulate how firewalld handles a new incoming connection."""
    return tester.evaluate(pkt)


@router.get("/denied")
def denied_recent(limit: int = 500, session: Session = Depends(require_user)):
    return denied.recent(min(max(limit, 1), 5000))


@router.get("/denied/stream")
async def denied_stream(session: Session = Depends(require_user)):
    return StreamingResponse(denied.stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
