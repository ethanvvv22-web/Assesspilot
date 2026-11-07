"""Stage-by-stage pipeline shared by the HTTP API (called from n8n) and the CLI.

    ingest -> inventory -> cia -> controls -> verify -> draft -> [human decision] -> publish

State lives in SQLite; every stage writes an audit entry with input/output hashes.
Publishing is the only step that changes anything outside AssessPilot and it is
refused unless a human approval is recorded for the run.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .agents import Agents
from .config import Settings
from .evidence import evidence_stats, verify_cia, verify_inventory, verify_mapping
from .ingest import Snapshot, ingest
from .llm import AzureLLM
from .report import render
from .schemas import CIAClassification, ControlMapping, Inventory
from .store import Store, _canon, sha256

ORDER = ["ingested", "inventoried", "classified", "mapped", "verified", "awaiting_approval",
         "approved", "rejected", "published"]


class PipelineError(RuntimeError):
    pass


def _h(obj) -> str:
    return sha256(_canon(obj))[:16]


class Pipeline:
    def __init__(self, settings: Settings, store: Store | None = None):
        self.s = settings
        self.store = store or Store(settings.data_dir / "assesspilot.db")

    # ---------------------------------------------------------------- helpers
    def _run(self, run_id: str) -> dict:
        run = self.store.get_run(run_id)
        if not run:
            raise PipelineError(f"unknown run {run_id}")
        return run

    def _require(self, run: dict, *keys: str) -> None:
        missing = [k for k in keys if k not in run["artifacts"]]
        if missing:
            raise PipelineError(f"run {run['run_id']} is missing stage output: {', '.join(missing)}")

    def _agents(self, run: dict) -> tuple[Agents, AzureLLM | None]:
        llm = AzureLLM(self.s) if run["backend"] == "azure" else None
        return Agents(run["backend"], llm), llm

    def _usage(self, run_id: str, stage: str, llm: AzureLLM | None, seconds: float) -> dict:
        u = {"seconds": round(seconds, 2)}
        if llm:
            u.update(llm.usage.as_dict())
        timing = self._run(run_id)["artifacts"].get("timing", {})
        timing[stage] = u
        self.store.put_artifact(run_id, "timing", timing)
        return u

    # ----------------------------------------------------------------- stages
    def start(self, source: str, ref: str | None = None, docs: list[str] | None = None,
              backend: str | None = None, actor: str = "n8n") -> dict:
        backend = backend or self.s.backend
        t0 = time.perf_counter()
        snap = ingest(source, self.s, ref=ref, docs=docs)
        run_id = self.store.new_run(source, backend)
        self.store.put_artifact(run_id, "snapshot", snap.to_dict())
        self.store.audit(run_id, actor, "ingest", {
            "source": source, "revision": snap.revision, "backend": backend, "files": len(snap.files),
            "snapshot_sha256": snap.digest(), "redactions": len(snap.filter_report.redactions),
            "injections": snap.filter_report.injections})
        self._usage(run_id, "ingest", None, time.perf_counter() - t0)
        return {"run_id": run_id, "files": len(snap.files), "revision": snap.revision,
                "backend": backend, "design_docs": snap.design_docs,
                "redactions": len(snap.filter_report.redactions),
                "injections": len(snap.filter_report.injections)}

    def _snap(self, run: dict) -> Snapshot:
        self._require(run, "snapshot")
        return Snapshot.from_dict(run["artifacts"]["snapshot"])

    def inventory(self, run_id: str, actor: str = "inventory-agent") -> dict:
        run = self._run(run_id)
        snap = self._snap(run)
        agents, llm = self._agents(run)
        t0 = time.perf_counter()
        inv = agents.inventory(snap.safe)
        out = inv.model_dump()
        self.store.put_artifact(run_id, "inventory", out, status="inventoried")
        self.store.audit(run_id, actor, "inventory", {"items": len(inv.items), "output_sha": _h(out),
                                                      "usage": self._usage(run_id, "inventory", llm, time.perf_counter() - t0)})
        return out

    def classify(self, run_id: str, actor: str = "cia-agent") -> dict:
        run = self._run(run_id)
        self._require(run, "inventory")
        snap = self._snap(run)
        agents, llm = self._agents(run)
        t0 = time.perf_counter()
        cia = agents.cia(Inventory.model_validate(run["artifacts"]["inventory"]), snap.safe, snap.design_docs)
        out = cia.model_dump()
        self.store.put_artifact(run_id, "cia", out, status="classified")
        self.store.audit(run_id, actor, "classify", {
            "levels": {k: out[k]["level"] for k in ("confidentiality", "integrity", "availability")},
            "output_sha": _h(out), "usage": self._usage(run_id, "cia", llm, time.perf_counter() - t0)})
        return out

    def map_controls(self, run_id: str, actor: str = "control-agent") -> dict:
        run = self._run(run_id)
        self._require(run, "inventory", "cia")
        snap = self._snap(run)
        agents, llm = self._agents(run)
        t0 = time.perf_counter()
        mapping, unknown = agents.controls(Inventory.model_validate(run["artifacts"]["inventory"]),
                                           CIAClassification.model_validate(run["artifacts"]["cia"]), snap.safe)
        out = mapping.model_dump()
        self.store.put_artifact(run_id, "mapping", out, status="mapped")
        self.store.put_artifact(run_id, "unknown_controls", sorted(set(unknown)))
        self.store.audit(run_id, actor, "map_controls", {
            "findings": len(mapping.findings), "unknown_control_ids_removed": sorted(set(unknown)),
            "output_sha": _h(out), "usage": self._usage(run_id, "controls", llm, time.perf_counter() - t0)})
        return out

    def verify(self, run_id: str, actor: str = "evidence-verifier") -> dict:
        run = self._run(run_id)
        self._require(run, "inventory", "cia", "mapping")
        safe = self._snap(run).safe
        inv = verify_inventory(Inventory.model_validate(run["artifacts"]["inventory"]), safe)
        cia = verify_cia(CIAClassification.model_validate(run["artifacts"]["cia"]), safe)
        mapping = verify_mapping(ControlMapping.model_validate(run["artifacts"]["mapping"]), safe)
        stats = evidence_stats(mapping, cia)
        self.store.put_artifact(run_id, "inventory", inv.model_dump())
        self.store.put_artifact(run_id, "cia", cia.model_dump())
        self.store.put_artifact(run_id, "mapping", mapping.model_dump())
        self.store.put_artifact(run_id, "evidence", stats, status="verified")
        self.store.audit(run_id, actor, "verify_evidence", stats)
        return stats

    def draft(self, run_id: str, resume_url: str | None = None, actor: str = "n8n") -> dict:
        run = self._run(run_id)
        self._require(run, "inventory", "cia", "mapping", "evidence")
        md = self._render(run, decision=None)
        self.store.put_artifact(run_id, "draft_report", md, status="awaiting_approval")
        if resume_url:
            self.store.put_artifact(run_id, "resume_url", resume_url)
        self.store.audit(run_id, actor, "draft", {"report_sha": _h(md)})
        return {"run_id": run_id, "status": "awaiting_approval", "report_markdown": md,
                "evidence": run["artifacts"]["evidence"]}

    def _render(self, run: dict, decision: dict | None) -> str:
        a = run["artifacts"]
        snap = a["snapshot"]
        meta = {"revision": snap["revision"], "files": len(snap["files"]), "design_docs": snap["design_docs"],
                "evidence": a.get("evidence", {}), "unknown_controls": a.get("unknown_controls", []),
                "guardrails": {"redactions": snap.get("redactions", []), "injections": snap.get("injections", [])}}
        return render(run, Inventory.model_validate(a["inventory"]), CIAClassification.model_validate(a["cia"]),
                      ControlMapping.model_validate(a["mapping"]), meta, decision)

    # ------------------------------------------------------- human-in-the-loop
    def decide(self, run_id: str, approved: bool, reviewer: str, comment: str = "") -> dict:
        run = self._run(run_id)
        if run["status"] != "awaiting_approval":
            raise PipelineError(f"run {run_id} is '{run['status']}', not awaiting approval")
        if not reviewer.strip():
            raise PipelineError("a named reviewer is required")
        decision = {"approved": bool(approved), "reviewer": reviewer.strip(), "comment": comment,
                    "ts": time.time(), "draft_sha": _h(run["artifacts"]["draft_report"])}
        self.store.put_artifact(run_id, "decision", decision, status="approved" if approved else "rejected")
        self.store.audit(run_id, f"human:{decision['reviewer']}", "approve" if approved else "reject", decision)
        return decision

    def publish(self, run_id: str, actor: str = "n8n") -> dict:
        """The only externally visible change. Refused without a recorded human approval."""
        run = self._run(run_id)
        decision = run["artifacts"].get("decision")
        if run["status"] != "approved" or not decision or not decision.get("approved"):
            self.store.audit(run_id, actor, "publish_refused", {"status": run["status"]})
            raise PipelineError("publishing requires a recorded human approval")
        md = self._render(run, decision)
        out_dir = self.s.data_dir / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{run_id}.md"
        path.write_text(md, encoding="utf-8")
        (out_dir / f"{run_id}.json").write_text(json.dumps({k: run["artifacts"][k] for k in
                                                           ("inventory", "cia", "mapping", "evidence", "decision")},
                                                          indent=2), encoding="utf-8")
        result = {"report_path": str(path)}
        # Posting to GitLab is outward-facing (and the repo may belong to someone else), so it is opt-in.
        if run["source"].startswith("gitlab:") and self.s.gitlab_publish_issues and self.s.gitlab_publish_token:
            try:
                result["gitlab_issue"] = self._open_gitlab_issue(run["source"].removeprefix("gitlab:"), md)
            except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
                # The local report is still published; the failed external step is recorded, not hidden.
                result["gitlab_issue_error"] = str(exc)[:300]
        self.store.put_artifact(run_id, "published", result, status="published")
        self.store.audit(run_id, actor, "publish", {**result, "report_sha": _h(md)})
        return result

    def _open_gitlab_issue(self, project: str, md: str) -> str:
        pid = urllib.parse.quote(project, safe="")
        data = urllib.parse.urlencode({"title": "AssessPilot security assessment (approved)",
                                       "description": md[:900_000], "labels": "security,assessment"}).encode()
        req = urllib.request.Request(f"{self.s.gitlab_url}/api/v4/projects/{pid}/issues", data=data, method="POST")
        req.add_header("PRIVATE-TOKEN", self.s.gitlab_publish_token)
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return json.loads(resp.read())["web_url"]

    # ------------------------------------------------------------- shortcuts
    def run_to_draft(self, source: str, ref: str | None = None, docs: list[str] | None = None,
                     backend: str | None = None, actor: str = "cli") -> dict:
        info = self.start(source, ref, docs, backend, actor)
        rid = info["run_id"]
        self.inventory(rid)
        self.classify(rid)
        self.map_controls(rid)
        self.verify(rid)
        return {**info, **self.draft(rid, actor=actor)}

    def report_path(self, run_id: str) -> Path:
        return self.s.data_dir / "reports" / f"{run_id}.md"
