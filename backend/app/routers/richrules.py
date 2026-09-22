from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import richrule
from ..auth import Session, require_user
from ..richrule import RichRule

router = APIRouter(prefix="/api/rich-rules", tags=["rich rules"])


class RuleText(BaseModel):
    rule: str


@router.post("/parse")
def parse(body: RuleText, session: Session = Depends(require_user)):
    """Validate a rule string; returns its canonical form and structured fields."""
    try:
        parsed = richrule.parse(body.rule)
        return {"valid": True, "rule": richrule.render(parsed), "parsed": parsed.model_dump()}
    except richrule.RuleError as e:
        return {"valid": False, "error": str(e)}


@router.post("/render")
def render(body: RichRule, session: Session = Depends(require_user)):
    """Validate a structured rule and render it to a rule string."""
    try:
        return {"valid": True, "rule": richrule.render(body)}
    except richrule.RuleError as e:
        return {"valid": False, "error": str(e)}
