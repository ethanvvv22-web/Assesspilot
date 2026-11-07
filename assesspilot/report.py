"""Render the draft / approved assessment as Markdown."""
from __future__ import annotations

import datetime as dt

from .guardrails import control_catalog, control_title, framework_of
from .schemas import CIAClassification, ControlMapping, Evidence, Inventory

STATUS_ORDER = {"gap": 0, "needs_review": 1, "implemented": 2}
STATUS_LABEL = {"gap": "Gaps", "needs_review": "Needs reviewer judgement", "implemented": "Controls in place"}


def _ev(e: Evidence) -> str:
    q = e.quote.replace("`", "'")
    loc = f"{e.file}:{e.line_start}" + (f"-{e.line_end}" if e.line_end != e.line_start else "")
    return f"`{loc}` — `{q}`"


def render(run: dict, inv: Inventory, cia: CIAClassification, mapping: ControlMapping,
           meta: dict, decision: dict | None = None) -> str:
    status = "APPROVED" if decision and decision.get("approved") else "DRAFT — NOT APPROVED"
    out = [f"# Security assessment: {run['source']}", "",
           f"| | |\n|---|---|\n| Status | **{status}** |\n| Revision | `{meta.get('revision', '?')}` |"
           f"\n| Run | `{run['run_id']}` |\n| Backend | {run['backend']} |"
           f"\n| Generated | {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} |"]
    if decision:
        out.append(f"| Reviewer | {decision.get('reviewer')} ({'approved' if decision.get('approved') else 'rejected'}) |")
        if decision.get("comment"):
            out.append(f"| Reviewer comment | {decision['comment']} |")
    out += ["", "> Drafted by AI agents. Every finding below cites code that was checked "
            "automatically; conclusions still require a qualified reviewer.", ""]

    out += ["## 1. System overview", "", inv.summary, ""]
    cats: dict[str, list[str]] = {}
    for it in inv.items:
        cats.setdefault(it.category, []).append(it.name)
    out += [f"- **{c.replace('_', ' ')}**: {', '.join(n)}" for c, n in cats.items()] + [""]

    out += ["## 2. CIA classification", "", "| Dimension | Level | Rationale | Evidence |", "|---|---|---|---|"]
    for name, r in (("Confidentiality", cia.confidentiality), ("Integrity", cia.integrity),
                    ("Availability", cia.availability)):
        evs = "<br>".join(_ev(e) for e in r.evidence if e.verified) or "_no verified evidence_"
        level = f"**{r.level}**" if r.supported else f"**Unverified** (proposed: {r.level})"
        out.append(f"| {name} | {level} | {r.rationale} | {evs} |")
    out.append("")

    supported = sorted([f for f in mapping.findings if f.supported], key=lambda f: STATUS_ORDER[f.status])
    out += ["## 3. Findings", ""]
    n = 0
    for st in ("gap", "needs_review", "implemented"):
        group = [f for f in supported if f.status == st]
        if not group:
            continue
        out += [f"### {STATUS_LABEL[st]} ({len(group)})", ""]
        for f in group:
            n += 1
            ctrls = "; ".join(f"{framework_of(c)} {c} ({control_title(c)})" for c in f.controls)
            out += [f"**{n}. {f.title}**", "", f"- Controls: {ctrls}", f"- {f.description}"]
            if f.recommendation and st != "implemented":
                out.append(f"- Recommendation: {f.recommendation}")
            out += [f"- Evidence: {_ev(e)}" for e in f.evidence if e.verified] + [""]

    out += ["## 4. Control coverage", "", "| Framework | Gap | Needs review | Implemented | Not evidenced |",
            "|---|---|---|---|---|"]
    for fw, ctrls in control_catalog().items():
        status_of: dict[str, set[str]] = {}
        for f in supported:
            for c in f.controls:
                status_of.setdefault(c, set()).add(f.status)
        cnt = {"gap": 0, "needs_review": 0, "implemented": 0, "none": 0}
        for cid in ctrls:
            s = status_of.get(cid)
            key = "none" if not s else min(s, key=STATUS_ORDER.get)  # worst status wins
            cnt[key] += 1
        out.append(f"| {fw} | {cnt['gap']} | {cnt['needs_review']} | {cnt['implemented']} | {cnt['none']} |")
    out.append("")

    rejected = [f for f in mapping.findings if not f.supported]
    g = meta.get("guardrails", {})
    out += ["## 5. Quality and guardrail log", "",
            f"- Files analysed: {meta.get('files', '?')}; design documents: {', '.join(meta.get('design_docs', [])) or 'none'}",
            f"- Citations verified: {meta.get('evidence', {}).get('verified', 0)}/{meta.get('evidence', {}).get('citations', 0)}",
            f"- Findings dropped for unverifiable evidence: {len(rejected)}",
            f"- CIA levels without verified evidence: {meta.get('evidence', {}).get('unverified_cia_levels', 0)}",
            f"- Control claims discarded because nothing was cited: {', '.join(mapping.dropped_uncited) or 'none'}",
            f"- Unknown control IDs removed: {', '.join(meta.get('unknown_controls', [])) or 'none'}",
            f"- Secrets redacted before analysis: {len(g.get('redactions', []))}",
            f"- Prompt-injection lines neutralised: {len(g.get('injections', []))}"]
    for inj in g.get("injections", [])[:10]:
        out.append(f"  - `{inj['file']}:{inj['line']}`")
    if rejected:
        out += ["", "<details><summary>Dropped findings</summary>", ""]
        for f in rejected:
            reasons = "; ".join(f"{e.file}:{e.line_start} {e.reason}" for e in f.evidence)
            out.append(f"- {f.title} ({', '.join(f.controls)}): {reasons}")
        out += ["", "</details>"]
    return "\n".join(out) + "\n"
