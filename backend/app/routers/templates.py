from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import templates
from ..auth import Session, require_user
from ..changes import changing
from ..fw import Target

router = APIRouter(prefix="/api/templates", tags=["templates"])


@router.get("")
def list_templates(session: Session = Depends(require_user)):
    return templates.TEMPLATES


class TemplateRequest(BaseModel):
    template: str
    params: dict = {}
    target: Target = "both"


@router.post("/preview")
def preview(body: TemplateRequest, session: Session = Depends(require_user)):
    plan = templates.build(body.template, body.params)
    return {"title": plan["title"], "steps": templates.describe(plan), "notes": plan["notes"],
            "ops": [o.model_dump() for s in plan["steps"] if s["kind"] == "ops" for o in s["ops"]]}


@router.post("/apply")
def apply(body: TemplateRequest, session: Session = Depends(require_user)):
    # Rebuild on the server: never trust a client-supplied plan.
    plan = templates.build(body.template, body.params)
    with changing(session, f"template: {plan['title']}", {"ops": templates.describe(plan), "target": body.target}) as d:
        d["done"] = templates.run(plan, body.target)
    return {"ok": True, "done": d["done"], "notes": plan["notes"]}
