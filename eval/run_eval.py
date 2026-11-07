"""Evaluate AssessPilot on the pilot repositories.

    python eval/run_eval.py                         # heuristic backend, 3 runs per pilot
    python eval/run_eval.py --backends heuristic azure --runs 3
    python eval/run_eval.py --pilots sample_app pygoat
    python eval/run_eval.py --draft-labels pygoat   # write a DRAFT label file for a human to correct

Metrics (written to eval/results/results.json and results.md):
  accuracy      CIA level accuracy; per-control status accuracy; gap precision/recall
                -- only against label files with `status: verified`
  consistency   CIA agreement across repeated runs; mean pairwise Jaccard of (control, status) sets
  alignment     share of model-proposed control IDs that exist in the catalog;
                share of citations that verify against the code; share of findings supported
  effort        wall-clock seconds and tokens per assessment; minutes saved
                = manual_minutes - review_minutes (from the label file, measured by a person)
"""
from __future__ import annotations

import argparse
import itertools
import json
import statistics as st
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from assesspilot.config import load_settings  # noqa: E402
from assesspilot.ingest import IngestError  # noqa: E402
from assesspilot.llm import LLMError  # noqa: E402
from assesspilot.pipeline import Pipeline  # noqa: E402

EVAL = ROOT / "eval"
WORST = {"gap": 0, "needs_review": 1, "implemented": 2}
DIMS = ("confidentiality", "integrity", "availability")


def predicted_status(mapping: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in mapping["findings"]:
        if not f.get("supported", True):
            continue
        for c in f["controls"]:
            if c not in out or WORST[f["status"]] < WORST[out[c]]:
                out[c] = f["status"]
    return out


def jaccard(a: set, b: set) -> float:
    return 1.0 if not a and not b else len(a & b) / len(a | b)


def run_once(pipe: Pipeline, pilot: dict, backend: str) -> dict:
    t0 = time.perf_counter()
    docs = [str(ROOT / d) for d in pilot.get("docs", [])]
    src = pilot["source"] if ("://" in pilot["source"] or pilot["source"].startswith("gitlab:")) else str(ROOT / pilot["source"])
    out = pipe.run_to_draft(src, pilot.get("ref"), docs, backend, actor="eval")
    art = pipe.store.get_run(out["run_id"])["artifacts"]
    tokens = sum(v.get("prompt_tokens", 0) + v.get("completion_tokens", 0) for v in art["timing"].values())
    n_ids = sum(len(f["controls"]) for f in art["mapping"]["findings"]) + len(art.get("unknown_controls", []))
    return {
        "run_id": out["run_id"], "seconds": round(time.perf_counter() - t0, 1), "tokens": tokens,
        "files": out["files"], "cia": {d: art["cia"][d]["level"] if art["cia"][d].get("supported", True) else "Unverified" for d in DIMS},
        "status": predicted_status(art["mapping"]), "evidence": art["evidence"],
        "valid_control_id_rate": round(1 - len(art.get("unknown_controls", [])) / n_ids, 3) if n_ids else None,
        "uncited": len(art["mapping"].get("dropped_uncited", [])),
    }


def score_pilot(runs: list[dict], label: dict | None) -> dict:
    res: dict = {
        "runs": len(runs),
        "seconds_mean": round(st.mean(r["seconds"] for r in runs), 1),
        "tokens_mean": round(st.mean(r["tokens"] for r in runs)),
        "files": runs[0]["files"],
        "citation_verified_rate": round(st.mean(r["evidence"]["verified_rate"] or 0 for r in runs), 3),
        "supported_finding_rate": round(st.mean(
            (r["evidence"]["supported_findings"] / r["evidence"]["findings"]) if r["evidence"]["findings"] else 1
            for r in runs), 3),
        "valid_control_id_rate": round(st.mean(r["valid_control_id_rate"] or 1 for r in runs), 3),
        "cia_predicted": runs[0]["cia"],
        "uncited_claims_mean": round(st.mean(r["uncited"] for r in runs), 1),
    }
    # consistency across repeated runs
    res["cia_agreement"] = round(st.mean(len({r["cia"][d] for r in runs}) == 1 for d in DIMS), 3)
    sets = [set(r["status"].items()) for r in runs]
    pairs = list(itertools.combinations(sets, 2))
    res["finding_jaccard"] = round(st.mean(jaccard(a, b) for a, b in pairs), 3) if pairs else None

    if label and label.get("status") == "verified":
        cia_hits = [r["cia"][d] == label["cia"][d] for r in runs for d in DIMS if label.get("cia", {}).get(d)]
        res["cia_accuracy"] = round(st.mean(cia_hits), 3) if cia_hits else None
        ctrl = {str(k): v for k, v in (label.get("controls") or {}).items()}
        acc, tp, fp, fn = [], 0, 0, 0
        misses: dict[str, str] = {}
        for r in runs:
            for cid, want in ctrl.items():
                got = r["status"].get(cid, "not_evidenced")
                acc.append(got == want)
                if got != want:
                    misses[cid] = f"expected {want}, got {got}"
                tp += got == "gap" and want == "gap"
                fp += got == "gap" and want != "gap"
                fn += got != "gap" and want == "gap"
        res["control_status_accuracy"] = round(st.mean(acc), 3) if acc else None
        res["gap_precision"] = round(tp / (tp + fp), 3) if tp + fp else None
        res["gap_recall"] = round(tp / (tp + fn), 3) if tp + fn else None
        res["labelled_controls"] = len(ctrl)
        res["misses"] = misses
        if label.get("manual_minutes") is not None and label.get("review_minutes") is not None:
            res["minutes_saved"] = label["manual_minutes"] - label["review_minutes"]
            res["effort_reduction"] = round(1 - label["review_minutes"] / label["manual_minutes"], 3)
    else:
        res["accuracy_note"] = "no verified labels; accuracy not computed"
    return res


def write_draft_labels(name: str, run: dict) -> Path:
    path = EVAL / "labels" / f"{name}.yaml"
    if path.exists():
        raise SystemExit(f"{path} exists; refusing to overwrite human labels")
    doc = {"pilot": name, "status": "draft", "labeled_by": None,
           "cia": run["cia"], "controls": dict(sorted(run["status"].items())),
           "manual_minutes": None, "review_minutes": None}
    header = ("# DRAFT generated from one AssessPilot run. A person must check every line against the code,\n"
              "# fix wrong statuses, add missed controls, then set status: verified and labeled_by.\n")
    path.write_text(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def to_markdown(results: dict) -> str:
    cols = [("runs", "Runs"), ("files", "Files"), ("seconds_mean", "Sec/run"), ("tokens_mean", "Tokens/run"),
            ("cia_accuracy", "CIA acc."), ("control_status_accuracy", "Control acc."),
            ("gap_precision", "Gap P"), ("gap_recall", "Gap R"), ("cia_agreement", "CIA agree"),
            ("finding_jaccard", "Finding Jaccard"), ("citation_verified_rate", "Citations OK"),
            ("valid_control_id_rate", "Valid IDs"), ("effort_reduction", "Effort saved")]
    lines = ["| Backend | Pilot | " + " | ".join(c[1] for c in cols) + " |",
             "|---|---|" + "---|" * len(cols)]
    for backend, pilots in results["results"].items():
        for name, r in pilots.items():
            cells = ["-" if r.get(k) is None else str(r.get(k)) for k, _ in cols]
            lines.append(f"| {backend} | {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backends", nargs="+", default=["heuristic"], choices=["heuristic", "azure"])
    ap.add_argument("--pilots", nargs="*")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--draft-labels", metavar="PILOT")
    args = ap.parse_args()

    pilots = yaml.safe_load((EVAL / "pilots.yaml").read_text(encoding="utf-8"))["pilots"]
    if args.pilots:
        pilots = [p for p in pilots if p["name"] in args.pilots]
    settings = load_settings(data_dir=EVAL / "results" / "data")
    pipe = Pipeline(settings)

    if args.draft_labels:
        pilot = next(p for p in pilots if p["name"] == args.draft_labels)
        print("wrote", write_draft_labels(pilot["name"], run_once(pipe, pilot, args.backends[0])))
        return 0

    results: dict = {"generated": time.strftime("%Y-%m-%d %H:%M"), "runs_per_pilot": args.runs, "results": {}}
    for backend in args.backends:
        if backend == "azure" and not settings.azure_configured:
            print("skipping azure: AZURE_OPENAI_* not set")
            continue
        results["results"][backend] = {}
        for pilot in pilots:
            label_path = EVAL / "labels" / f"{pilot['name']}.yaml"
            label = yaml.safe_load(label_path.read_text(encoding="utf-8")) if label_path.exists() else None
            runs = []
            for i in range(args.runs):
                print(f"[{backend}] {pilot['name']} run {i + 1}/{args.runs} ...", flush=True)
                try:
                    runs.append(run_once(pipe, pilot, backend))
                except (LLMError, IngestError) as exc:  # keep what we have; a failed run is reported, not hidden
                    print(f"  run failed: {str(exc)[:300]}", flush=True)
                    results.setdefault("failed_runs", []).append(
                        {"backend": backend, "pilot": pilot["name"], "run": i + 1, "error": str(exc)[:300]})
            if runs:
                results["results"][backend][pilot["name"]] = score_pilot(runs, label)
            save(results)  # save after every pilot so an interruption loses little

    print(to_markdown(results))
    return 0


def save(results: dict) -> None:
    out = EVAL / "results"
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out / "results.md").write_text(to_markdown(results), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
