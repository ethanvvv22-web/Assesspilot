"""HTTP service that the n8n workflow orchestrates.

Two credentials, two roles (least privilege):
  X-API-Key       - held by n8n; can run agent stages and publish an *approved* run.
  approver key    - held only by human reviewers; the only way to approve a run.
n8n can therefore never approve its own output.

Run:  uvicorn assesspilot.api:app --port 8000
"""
from __future__ import annotations

import hmac
import html
import json
import urllib.request

from fastapi import Depends, FastAPI, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from .config import load_settings
from .ingest import IngestError
from .llm import LLMError
from .pipeline import Pipeline, PipelineError

app = FastAPI(title="AssessPilot", version="0.1.0")
_pipeline: Pipeline | None = None


def pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline(load_settings())
    return _pipeline


def _eq(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def require_service_key(x_api_key: str = Header(default="")) -> None:
    expected = pipeline().s.api_key
    if expected and not _eq(x_api_key, expected):
        raise HTTPException(401, "invalid service key")


def _wrap(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except PipelineError as exc:
        raise HTTPException(409, str(exc)) from exc
    except IngestError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LLMError as exc:
        raise HTTPException(502, str(exc)) from exc


class StartReq(BaseModel):
    source: str
    ref: str | None = None
    docs: list[str] = []
    backend: str | None = None


class DraftReq(BaseModel):
    resume_url: str | None = None


svc = [Depends(require_service_key)]


@app.get("/health")
def health():
    s = pipeline().s
    return {"ok": True, "backend": s.backend, "azure_configured": s.azure_configured,
            "approver_key_configured": bool(s.approver_key)}


@app.post("/runs", dependencies=svc)
def start(req: StartReq):
    return _wrap(pipeline().start, req.source, req.ref, req.docs, req.backend)


@app.post("/runs/{run_id}/inventory", dependencies=svc)
def inventory(run_id: str):
    return _wrap(pipeline().inventory, run_id)


@app.post("/runs/{run_id}/cia", dependencies=svc)
def cia(run_id: str):
    return _wrap(pipeline().classify, run_id)


@app.post("/runs/{run_id}/controls", dependencies=svc)
def controls(run_id: str):
    return _wrap(pipeline().map_controls, run_id)


@app.post("/runs/{run_id}/verify", dependencies=svc)
def verify(run_id: str):
    return _wrap(pipeline().verify, run_id)


@app.post("/runs/{run_id}/draft", dependencies=svc)
def draft(run_id: str, req: DraftReq):
    out = _wrap(pipeline().draft, run_id, req.resume_url)
    out["review_url"] = f"/runs/{run_id}/review"
    return out


@app.post("/runs/{run_id}/publish", dependencies=svc)
def publish(run_id: str):
    # Anyone holding the service key can call this, so record the credential, not an assumed caller.
    return _wrap(pipeline().publish, run_id, actor="service-key")


@app.get("/runs/{run_id}", dependencies=svc)
def get_run(run_id: str):
    run = pipeline().store.get_run(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    arts = {k: v for k, v in run["artifacts"].items() if k not in ("snapshot", "draft_report")}
    return {**run, "artifacts": arts}


@app.get("/runs/{run_id}/audit", dependencies=svc)
def audit(run_id: str):
    return pipeline().store.audit_log(run_id)


@app.get("/audit/verify", dependencies=svc)
def audit_verify():
    return pipeline().store.verify_chain()


# ------------------------------------------------------------ human review
@app.get("/runs/{run_id}/review", response_class=HTMLResponse)
def review_page(run_id: str):
    run = pipeline().store.get_run(run_id)
    if not run or "draft_report" not in run["artifacts"]:
        raise HTTPException(404, "no draft for this run")
    md = html.escape(run["artifacts"]["draft_report"])
    decided = run["status"] != "awaiting_approval"
    form = ("<p><b>This run is already " + html.escape(run["status"]) + ".</b></p>") if decided else f"""
    <form method="post" action="/runs/{run_id}/review">
      <label>Reviewer name <input name="reviewer" required></label>
      <label>Approver key <input name="approver_key" type="password" required></label>
      <label>Comment <input name="comment" size="60"></label>
      <button name="decision" value="approve">Approve and publish</button>
      <button name="decision" value="reject">Reject</button>
    </form>"""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Review {run_id}</title>
    <style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px}}
    pre{{white-space:pre-wrap;background:#f6f6f6;padding:16px;border-radius:6px;font-size:13px}}
    form{{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:16px 0}}
    button{{padding:6px 14px}}</style></head><body>
    <h1>AssessPilot review: run {run_id}</h1>{form}<pre>{md}</pre></body></html>"""


@app.post("/runs/{run_id}/review", response_class=PlainTextResponse)
def review_submit(run_id: str, reviewer: str = Form(...), approver_key: str = Form(...),
                  decision: str = Form(...), comment: str = Form("")):
    p = pipeline()
    if not _eq(approver_key, p.s.approver_key):
        p.store.audit(run_id, f"human:{reviewer}", "approval_denied", {"reason": "bad approver key"})
        raise HTTPException(403, "invalid approver key")
    result = _wrap(p.decide, run_id, decision == "approve", reviewer, comment)
    resume = p.store.get_run(run_id)["artifacts"].get("resume_url")
    if resume:  # wake the waiting n8n execution; it will call /publish, which re-checks approval
        req = urllib.request.Request(resume, data=json.dumps({"run_id": run_id, "approved": result["approved"]}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=15).read()  # noqa: S310 - URL supplied by our own n8n
        except OSError as exc:
            return f"Decision recorded, but n8n could not be notified: {exc}"
    return f"Decision recorded: {'approved' if result['approved'] else 'rejected'} by {result['reviewer']}."
