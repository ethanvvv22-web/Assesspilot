"""Check every citation the agents produce against the actual repository snapshot.

A citation is accepted only if:
  1. the file exists in the snapshot,
  2. the line range is inside the file,
  3. the quoted text appears (whitespace-normalised) in those lines, with a
     tolerance of +/- LINE_TOLERANCE lines for off-by-one model errors.

A finding with no verified evidence is marked unsupported and is kept out of
the main report (it is listed separately so the reviewer can see what was dropped).
"""
from __future__ import annotations

import re

from .schemas import CIAClassification, ControlMapping, Evidence, Inventory

LINE_TOLERANCE = 2
_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip().lower()


def verify_one(ev: Evidence, safe_files: dict[str, str]) -> Evidence:
    text = safe_files.get(ev.file)
    if text is None:
        # Models sometimes add "./" or a leading slash.
        alt = ev.file.lstrip("./").lstrip("/")
        text = safe_files.get(alt)
        if text is not None:
            ev.file = alt
    if text is None:
        ev.verified, ev.reason = False, "file not in snapshot"
        return ev
    lines = text.splitlines()
    if ev.line_end < ev.line_start:
        ev.line_start, ev.line_end = ev.line_end, ev.line_start
    if ev.line_start > len(lines):
        ev.verified, ev.reason = False, f"line {ev.line_start} beyond end of file ({len(lines)} lines)"
        return ev
    quote = _norm(ev.quote.strip(" .…").replace("...", " "))
    if not quote:
        ev.verified, ev.reason = False, "empty quote"
        return ev
    lo = max(0, ev.line_start - 1 - LINE_TOLERANCE)
    hi = min(len(lines), ev.line_end + LINE_TOLERANCE)
    window = _norm(" ".join(lines[lo:hi]))
    if quote in window:
        ev.verified, ev.reason = True, "quote found at cited lines"
        # Snap the line range to where the quote really is, when it is a single line.
        for i in range(lo, hi):
            if quote in _norm(lines[i]):
                ev.line_start = ev.line_end = i + 1
                break
        return ev
    ev.verified, ev.reason = False, "quote not found at cited lines"
    return ev


def verify_inventory(inv: Inventory, safe: dict[str, str]) -> Inventory:
    for item in inv.items:
        item.evidence = [verify_one(e, safe) for e in item.evidence]
    return inv


def verify_cia(cia: CIAClassification, safe: dict[str, str]) -> CIAClassification:
    for rating in (cia.confidentiality, cia.integrity, cia.availability):
        rating.evidence = [verify_one(e, safe) for e in rating.evidence]
        rating.supported = any(e.verified for e in rating.evidence)
    return cia


def verify_mapping(mapping: ControlMapping, safe: dict[str, str]) -> ControlMapping:
    for f in mapping.findings:
        f.evidence = [verify_one(e, safe) for e in f.evidence]
        f.supported = any(e.verified for e in f.evidence)
    return mapping


def evidence_stats(mapping: ControlMapping, cia: CIAClassification | None = None) -> dict:
    evs = [e for f in mapping.findings for e in f.evidence]
    if cia:
        evs += [e for r in (cia.confidentiality, cia.integrity, cia.availability) for e in r.evidence]
    n = len(evs)
    ok = sum(e.verified for e in evs)
    ratings = (cia.confidentiality, cia.integrity, cia.availability) if cia else ()
    return {
        "unverified_cia_levels": sum(not r.supported for r in ratings),
        "citations": n,
        "verified": ok,
        "verified_rate": round(ok / n, 3) if n else None,
        "findings": len(mapping.findings),
        "supported_findings": sum(f.supported for f in mapping.findings),
    }
