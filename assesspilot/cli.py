"""Command line entry point (no n8n needed).

    python -m assesspilot.cli assess examples/sample_app --docs examples/design.md
    python -m assesspilot.cli assess https://github.com/adeyosemanputra/pygoat.git --backend azure
    python -m assesspilot.cli audit
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import load_settings
from .ingest import IngestError
from .llm import LLMError
from .pipeline import Pipeline


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="assesspilot")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="draft an assessment, then ask a human to approve it")
    a.add_argument("source", help="local directory, git URL, or gitlab:group/project")
    a.add_argument("--ref", help="branch, tag or commit")
    a.add_argument("--docs", nargs="*", default=[], help="extra design documents")
    a.add_argument("--backend", choices=["azure", "heuristic"])
    a.add_argument("--reviewer", help="name of the human reviewer (asked interactively if missing)")
    a.add_argument("--draft-only", action="store_true", help="stop after the draft; do not publish")
    sub.add_parser("audit", help="verify the integrity of the audit chain")
    args = ap.parse_args(argv)

    p = Pipeline(load_settings())
    if args.cmd == "audit":
        print(json.dumps(p.store.verify_chain(), indent=2))
        return 0

    try:
        out = p.run_to_draft(args.source, args.ref, args.docs, args.backend)
    except (IngestError, LLMError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    rid = out["run_id"]
    draft_path = p.s.data_dir / "reports" / f"{rid}.draft.md"
    draft_path.parent.mkdir(parents=True, exist_ok=True)
    draft_path.write_text(out["report_markdown"], encoding="utf-8")
    ev = out["evidence"]
    print(f"run {rid}: {out['files']} files, backend={out['backend']}, "
          f"findings {ev['supported_findings']}/{ev['findings']} supported, "
          f"citations verified {ev['verified']}/{ev['citations']}")
    print(f"draft: {draft_path}")
    if args.draft_only:
        return 0

    if not sys.stdin.isatty() and not args.reviewer:
        print("not interactive and no --reviewer given; leaving run awaiting approval")
        return 0
    reviewer = args.reviewer or input("Reviewer name: ").strip()
    answer = input(f"{reviewer}, approve and publish run {rid}? [y/N] ").strip().lower()
    p.decide(rid, answer == "y", reviewer)
    if answer == "y":
        print("published:", p.publish(rid)["report_path"])
    else:
        print("rejected; nothing published")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
