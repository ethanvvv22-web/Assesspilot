"""Input and output filtering.

Input side (before anything reaches a model):
  * secrets are redacted line-by-line, so line numbers stay stable for evidence;
  * lines that look like prompt-injection attempts are neutralised and recorded.

Output side (before anything reaches a report):
  * control IDs must exist in the curated catalog;
  * any secret-looking string in model output is redacted again.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

REDACTION_MARK = "[REDACTED:{kind}]"

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("azure_conn_string", re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    # key = "value" style assignments in any language / config format
    ("credential", re.compile(
        r"""(?ix)
        (?P<key>(?:[\w-]*\.)*[\w-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)[\w-]*)
        (?P<sep>\s*[:=]\s*|\s*=>\s*)
        (?P<q>["'])(?P<val>[^"'\s]{6,})(?P=q)
        """)),
]

_INJECTION_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|rules|prompts?)",
        r"disregard (?:all |the )?(?:previous|prior|above)",
        r"you are now (?:a|an|the)\b",
        r"(?:reveal|print|show) (?:your|the) (?:system )?prompt",
        r"<\|im_start\|>|<\|system\|>|\[INST\]",
        r"(?:rate|classify|mark) (?:everything|all (?:findings|controls)?) as (?:low|implemented|compliant)",
        r"do not report (?:any|this)",
    )
]


@dataclass
class FilterReport:
    redactions: list[dict] = field(default_factory=list)
    injections: list[dict] = field(default_factory=list)


def _redact_line(line: str) -> tuple[str, list[str]]:
    kinds: list[str] = []
    for kind, pattern in _SECRET_PATTERNS:
        if kind == "credential":
            def repl(m: re.Match[str]) -> str:
                val = m.group("val")
                if val.startswith("[REDACTED") or val.startswith("${") or val.lower() in {"changeme", "example"}:
                    return m.group(0)
                kinds.append(kind)
                return f'{m.group("key")}{m.group("sep")}{m.group("q")}{REDACTION_MARK.format(kind=kind)}{m.group("q")}'
            line = pattern.sub(repl, line)
        elif pattern.search(line):
            kinds.append(kind)
            line = pattern.sub(REDACTION_MARK.format(kind=kind), line)
    return line, kinds


def filter_input(path: str, text: str, report: FilterReport) -> str:
    """Return a copy of `text` that is safe to send to a model. Line count is preserved."""
    out = []
    for no, line in enumerate(text.splitlines(), start=1):
        line, kinds = _redact_line(line)
        for k in kinds:
            report.redactions.append({"file": path, "line": no, "kind": k})
        if any(p.search(line) for p in _INJECTION_PATTERNS):
            report.injections.append({"file": path, "line": no, "text": line.strip()[:200]})
            line = "[REMOVED BY ASSESSPILOT: possible prompt injection]"
        out.append(line)
    return "\n".join(out)


def redact_text(text: str) -> str:
    """Output-side DLP: redact secrets in anything the model produced."""
    return "\n".join(_redact_line(l)[0] for l in text.splitlines()) if text else text


@lru_cache(maxsize=1)
def control_catalog() -> dict[str, dict[str, str]]:
    path = Path(__file__).with_name("controls.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def all_control_ids() -> set[str]:
    return {cid for fw in control_catalog().values() for cid in fw}


def control_title(cid: str) -> str:
    for fw in control_catalog().values():
        if cid in fw:
            return fw[cid]
    return ""


def framework_of(cid: str) -> str:
    for name, fw in control_catalog().items():
        if cid in fw:
            return name
    return "unknown"


def normalize_control_id(raw: str) -> str:
    """Accept common spellings: 'A.8.28', 'ISO 27001 8.28', 'v5.3.4', 'MEASURE-2.7'."""
    s = re.split(r"\s*:\s+", raw.strip(), maxsplit=1)[0]  # models often echo "8.28: Secure coding"
    s = re.sub(r"(?i)^(iso(?:/iec)?\s*27001(?::2022)?\s*)", "", s)
    s = re.sub(r"(?i)^(asvs\s*)", "", s)
    s = re.sub(r"(?i)^(nist\s*ai\s*rmf\s*)", "", s)
    s = re.sub(r"^A\.", "", s)
    m = re.match(r"(?i)^(govern|map|measure|manage)[\s-]*(\d+\.\d+)$", s)
    if m:
        return f"{m.group(1).upper()} {m.group(2)}"
    if re.match(r"(?i)^v\d", s):
        return "V" + s[1:]
    return s


def validate_control_ids(ids: list[str]) -> tuple[list[str], list[str]]:
    """Split into (known, unknown) after normalisation."""
    known_set = all_control_ids()
    known, unknown = [], []
    for raw in ids:
        cid = normalize_control_id(raw)
        (known if cid in known_set else unknown).append(cid)
    return list(dict.fromkeys(known)), unknown
