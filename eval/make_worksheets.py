"""Build the human labelling material from the latest evaluation runs.

    python eval/make_worksheets.py dvpwa simply-vulnerable-notes ...

For each pilot this writes:
  eval/worksheets/<pilot>.md   what the rule baseline and Azure said per control, with citations
  eval/labels/<pilot>.yaml     blank label file covering every control

The label file starts blank so the person judges each control against the code; the tool output
is a pointer to where to look, not the answer. Files a person has already verified are never
overwritten.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from assesspilot.guardrails import control_catalog  # noqa: E402

EVAL = ROOT / "eval"
DIMS = ("confidentiality", "integrity", "availability")
RUNS = 3


def latest_runs(db: sqlite3.Connection, source: str, backend: str) -> list[dict]:
    rows = db.execute("SELECT artifacts FROM runs WHERE source LIKE ? AND backend=? AND status='awaiting_approval' "
                      "ORDER BY created DESC LIMIT ?", (f"%{source}%", backend, RUNS)).fetchall()
    return [json.loads(r[0]) for r in rows]


def per_control(run: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in run["mapping"]["findings"]:
        if f.get("supported", True):
            for c in f["controls"]:
                out.setdefault(c, f)
    return out


def describe(runs: list[dict], cid: str) -> list[str]:
    statuses, cite, why = [], None, ""
    for run in runs:
        f = per_control(run).get(cid)
        statuses.append(f["status"] if f else "not_evidenced")
        if f and not cite:
            good = [e for e in f["evidence"] if e.get("verified")]
            cite = good[0] if good else None
            why = f["title"]
    lines = [" / ".join(statuses) or "(no runs)"]
    if cite:
        lines.append(f"`{cite['file']}:{cite['line_start']}` `{cite['quote'][:120].replace('`', chr(39))}` ({why[:80]})")
    return lines


def write_label(name: str) -> str:
    path = EVAL / "labels" / f"{name}.yaml"
    if path.exists():
        current = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if current.get("status") == "verified" or current.get("labeled_by"):
            return f"kept {path.name} (already labelled by a person)"
    lines = [f"pilot: {name}", "status: draft             # set to verified when every line is done",
             "labeled_by: null", "cia:", *[f"  {d}: TODO" for d in DIMS], "controls:"]
    for fw, ctrls in control_catalog().items():
        lines.append(f"  # ---- {fw} ----")
        lines += [f'  "{cid}": TODO   # {title}' for cid, title in ctrls.items()]
    lines += ["manual_minutes: null", "review_minutes: null", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return f"wrote {path.name}"


def main(names: list[str]) -> int:
    pilots = {p["name"]: p for p in yaml.safe_load((EVAL / "pilots.yaml").read_text(encoding="utf-8"))["pilots"]}
    db = sqlite3.connect(EVAL / "results" / "data" / "assesspilot.db")
    (EVAL / "worksheets").mkdir(exist_ok=True)
    for name in names:
        src = pilots[name]["source"]
        src = src.removeprefix("gitlab:").removeprefix("https://github.com/")
        rules, azure = latest_runs(db, src, "heuristic"), latest_runs(db, src, "azure")
        ref = pilots[name].get("ref", "")
        out = [f"# Labelling worksheet: {name}", "",
               f"Source: `{pilots[name]['source']}` at `{ref}`", "",
               "Use this to find where to look, then decide from the code yourself. The tools are often wrong.", "",
               f"Each cell lists one status per run (rules: {len(rules)} runs, Azure: {len(azure)} runs).", "",
               "## CIA", "", "| Dimension | Rules | Azure |", "|---|---|---|"]
        for d in DIMS:
            levels = [" / ".join(r["cia"][d]["level"] if r["cia"][d].get("supported", True) else "Unverified" for r in rs)
                      for rs in (rules, azure)]
            out.append(f"| {d} | {levels[0]} | {levels[1]} |")
        for fw, ctrls in control_catalog().items():
            out += ["", f"## {fw}", ""]
            for cid, title in ctrls.items():
                r, a = describe(rules, cid), describe(azure, cid)
                out += [f"**{cid}**: {title}", "", f"- Rules: {r[0]}"] + [f"  - {x}" for x in r[1:]]
                out += [f"- Azure: {a[0]}"] + [f"  - {x}" for x in a[1:]] + [""]
        (EVAL / "worksheets" / f"{name}.md").write_text("\n".join(out), encoding="utf-8")
        print(name, "| rules runs", len(rules), "| azure runs", len(azure), "|", write_label(name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
