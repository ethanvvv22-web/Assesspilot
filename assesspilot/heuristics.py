"""Deterministic baseline: the same three agent outputs, produced by rules only.

Used (a) when no Azure OpenAI deployment is configured, so the whole workflow
runs offline, and (b) as the baseline the LLM agents are compared against in
eval/run_eval.py. Every rule cites the exact line it matched.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from .schemas import (CIAClassification, CIARating, ControlMapping, Evidence, Finding,
                      Inventory, InventoryItem)

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs",
            ".rs", ".html", ".htm", ".jinja", ".j2", ".vue", ".sql", ".sh", ".ps1"}
CONFIG_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json", ".xml", ".properties", ".env"}
LANG = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
        ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".rb": "Ruby",
        ".php": "PHP", ".cs": "C#", ".rs": "Rust"}
MAX_EVIDENCE = 4


def _ext(path: str) -> str:
    p = PurePosixPath(path)
    return ".env" if p.name.startswith(".env") else p.suffix.lower()


def _is_code(path: str) -> bool:
    return _ext(path) in CODE_EXT or _ext(path) in CONFIG_EXT or PurePosixPath(path).name == "Dockerfile"


def _is_test(path: str) -> bool:
    low = path.lower()
    return "/test" in f"/{low}" or "spec." in low or "_test." in low


def _ev(path: str, no: int, line: str) -> Evidence:
    return Evidence(file=path, line_start=no, line_end=no, quote=line.strip()[:200])


def _scan(safe: dict[str, str], pattern: re.Pattern[str], *, code_only: bool = True,
          skip_tests: bool = True, limit: int = MAX_EVIDENCE, files: list[str] | None = None) -> list[Evidence]:
    out: list[Evidence] = []
    for path in files or sorted(safe):
        if code_only and not _is_code(path):
            continue
        if skip_tests and _is_test(path):
            continue
        for no, line in enumerate(safe[path].splitlines(), start=1):
            if len(line) > 400 or "[REMOVED BY ASSESSPILOT" in line:
                continue
            if pattern.search(line):
                out.append(_ev(path, no, line))
                if len(out) >= limit:
                    return out
    return out


# =============================================================== inventory
_INV_RULES: list[tuple[str, str, str]] = [
    # category, name, regex
    ("framework", "Flask", r"^\s*(from|import)\s+flask\b|^flask\b"),
    ("framework", "Django", r"^\s*(from|import)\s+django\b|^django\b"),
    ("framework", "FastAPI", r"^\s*(from|import)\s+fastapi\b|^fastapi\b"),
    ("framework", "aiohttp", r"^\s*(from|import)\s+aiohttp\b|^aiohttp\b"),
    ("framework", "Express", r"""require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]"""),
    ("framework", "Spring", r"org\.springframework"),
    ("framework", "Angular", r"""from\s+['"]@angular/core['"]"""),
    ("framework", "React", r"""from\s+['"]react['"]"""),
    ("datastore", "SQLite", r"\bsqlite3?\b"),
    ("datastore", "PostgreSQL", r"\bpsycopg2?\b|\bpostgres(?:ql)?://|\basyncpg\b"),
    ("datastore", "MySQL", r"\bpymysql\b|\bmysql(?:\+\w+)?://|\bmysql2?\b"),
    ("datastore", "MongoDB", r"\bpymongo\b|\bmongoose\b|mongodb://"),
    ("datastore", "Redis", r"\bredis\b"),
    ("datastore", "SQLAlchemy ORM", r"\bsqlalchemy\b"),
    ("datastore", "Sequelize ORM", r"\bsequelize\b"),
    ("auth", "JWT", r"\bjwt\b|jsonwebtoken"),
    ("auth", "Session-based login", r"flask_login|django\.contrib\.auth|express-session|\bsession\[\s*['\"]user"),
    ("auth", "OAuth / OIDC", r"\boauth2?\b|openid"),
    ("auth", "Password hashing", r"\bbcrypt\b|\bargon2\b|\bpbkdf2\b|\bscrypt\b|generate_password_hash"),
    ("external_service", "Outbound HTTP calls", r"\brequests\.(get|post|put|delete)\(|\baxios\b|\bhttpx\.|urllib\.request|\bfetch\("),
    ("ai_component", "LLM / ML library", r"\bopenai\b|\banthropic\b|\blangchain\b|\btransformers\b|AzureOpenAI|\btorch\b"),
    ("deployment", "Container image", r"(?-i:^FROM\s+[\w./:@-]+(\s+AS\s+\w+)?\s*$)"),
    ("deployment", "CI pipeline", r"^\s*(stages|jobs|pipeline)\s*:"),
]

_DATA_TYPES: list[tuple[str, str]] = [
    ("credentials", r"\bpassword(_hash)?\b\s*[:=]|\bpassword\s*=\s*(db\.)?Column|\bpassword\b\s*:\s*\w"),
    ("personal data (PII)", r"\b(email|phone(_number)?|first_?name|last_?name|address|date_of_birth|dob|ssn|personnummer)\b\s*[:=]"),
    ("payment data", r"\b(card_?number|credit_?card|cvv|iban|payment|wallet|balance)\b\s*[:=]"),
    ("health data", r"\b(diagnosis|medical|patient|health_record)\b\s*[:=]"),
]

_ENTRY = re.compile(r"@(app|bp|blueprint|router|api|routes)\.(route|get|post|put|delete|patch)\b|"
                    r"\bapp\.(get|post|put|delete|patch)\(\s*['\"]|@(Get|Post|Put|Delete|Request)Mapping|"
                    r"\bpath\(\s*['\"]|\badd_(get|post|route)\(")


def inventory(safe: dict[str, str]) -> Inventory:
    items: list[InventoryItem] = []
    lang_files = Counter(LANG[_ext(p)] for p in safe if _ext(p) in LANG)
    for lang, _ in lang_files.most_common(4):
        path = next(p for p in sorted(safe) if LANG.get(_ext(p)) == lang)
        lines = safe[path].splitlines()
        no = next((i for i, l in enumerate(lines, 1) if l.strip()), None)
        evs = [_ev(path, no, lines[no - 1])] if no else []
        items.append(InventoryItem(category="language", name=lang, evidence=evs))

    for cat, name, rx in _INV_RULES:
        code_only = cat != "framework"  # requirements.txt / package.json carry framework hints
        evs = _scan(safe, re.compile(rx, re.I | re.M), code_only=code_only, skip_tests=True, limit=2)
        evs = [e for e in evs if _ext(e.file) not in {".md", ".rst"}]
        if evs:
            items.append(InventoryItem(category=cat, name=name, evidence=evs))

    for name, rx in _DATA_TYPES:
        evs = _scan(safe, re.compile(rx, re.I), limit=2)
        if evs:
            items.append(InventoryItem(category="data_type", name=name, evidence=evs))

    entries = _scan(safe, _ENTRY, limit=50)
    if entries:
        items.append(InventoryItem(category="entry_point",
                                   name=f"{len(entries)}{'+' if len(entries) == 50 else ''} HTTP endpoints",
                                   evidence=entries[:3]))
    names = ", ".join(sorted({i.name for i in items if i.category in ("framework", "datastore")})) or "unknown stack"
    return Inventory(summary=f"Rule-based inventory of {len(safe)} files ({names}).", items=items)


# ===================================================================== CIA
_AVAIL_HIGH = re.compile(r"24/7|99\.9|business[- ]critical|mission[- ]critical|safety[- ]critical|\bSLA\b|"
                         r"high availability|must not (be )?(down|unavailable)", re.I)
_ADMIN = re.compile(r"\badmin\b|is_superuser|is_staff|role\s*==\s*['\"]admin", re.I)
_WRITE = re.compile(r"\b(INSERT|UPDATE|DELETE)\b|\.save\(\)|\.commit\(\)|\.create\(|methods=\[[^\]]*POST", re.I)


def cia(inv: Inventory, safe: dict[str, str], design_docs: list[str]) -> CIAClassification:
    by_cat: dict[str, list[InventoryItem]] = {}
    for it in inv.items:
        by_cat.setdefault(it.category, []).append(it)
    dtypes = {i.name: i for i in by_cat.get("data_type", [])}
    auth = by_cat.get("auth", [])
    stores = by_cat.get("datastore", [])

    def ev_of(*its: InventoryItem | None) -> list[Evidence]:
        return [e.model_copy() for it in its if it for e in it.evidence[:1]]

    # Confidentiality
    sensitive = [dtypes.get(k) for k in ("payment data", "health data") if k in dtypes]
    if sensitive or ("credentials" in dtypes and "personal data (PII)" in dtypes):
        lvl = "High"
        src = sensitive or [dtypes["credentials"], dtypes["personal data (PII)"]]
        why = "Stores " + " and ".join(i.name for i in src) + "; disclosure would harm users directly."
    elif dtypes or auth:
        lvl, src = "Medium", list(dtypes.values())[:2] or auth[:1]
        why = "Processes " + ", ".join(i.name for i in src) + " but no payment or health data was found."
    else:
        lvl, src, why = "Low", [], "No personal, credential or payment data was found in the code."
    c = CIARating(level=lvl, rationale=why, evidence=ev_of(*src))

    # Integrity
    admin_ev = _scan(safe, _ADMIN, limit=1)
    write_ev = _scan(safe, _WRITE, limit=1)
    if "payment data" in dtypes or (stores and admin_ev):
        lvl = "High"
        why = ("Handles payment data; unauthorised changes have financial impact." if "payment data" in dtypes
               else "Persistent data store with privileged/admin functions; tampering affects all users.")
        evs = ev_of(dtypes.get("payment data")) or admin_ev
    elif stores and write_ev:
        lvl, why, evs = "Medium", "Application writes to a persistent data store.", write_ev
    else:
        lvl, why, evs = "Low", "No persistent writes found.", []
    i = CIARating(level=lvl, rationale=why, evidence=evs + ev_of(stores[0] if stores else None))

    # Availability
    doc_ev = _scan(safe, _AVAIL_HIGH, code_only=False, skip_tests=True, limit=1,
                   files=design_docs or None)
    if doc_ev:
        lvl, why, evs = "High", "Design documentation states availability requirements.", doc_ev
    elif "entry_point" in by_cat:
        lvl, why = "Medium", "Network-facing service; downtime blocks its users but no SLA is documented."
        evs = ev_of(by_cat["entry_point"][0])
    else:
        lvl, why, evs = "Low", "No network-facing entry points or availability requirements found.", []
    a = CIARating(level=lvl, rationale=why, evidence=evs)
    return CIAClassification(confidentiality=c, integrity=i, availability=a)


# ================================================================ controls
@dataclass(frozen=True)
class Rule:
    title: str
    status: str
    controls: tuple[str, ...]
    pattern: str
    description: str
    recommendation: str = ""
    code_only: bool = True


RULES: list[Rule] = [
    Rule("Hard-coded secret in source", "gap", ("V6.4.1", "5.17", "8.24"),
         r"\[REDACTED:(credential|aws_access_key|private_key|azure_conn_string|gitlab_token|jwt)\]",
         "A credential is committed to the repository (value redacted before analysis).",
         "Move the secret to a secrets manager or environment variable and rotate it."),
    Rule("SQL query built from strings", "gap", ("V5.3.4", "8.28"),
         r"""(execute|executemany|raw|query)\(\s*f["']|(execute|query)\(\s*["'][^"']*["']\s*(%|\+|\.format\()|"""
         r"""["'](SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(\+|%)\s*\w|`(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{""",
         "SQL is assembled with string formatting, which allows SQL injection.",
         "Use parameterised queries or the ORM's query builder."),
    Rule("Parameterised queries / ORM in use", "implemented", ("V5.3.4",),
         r"""execute\(\s*["'][^"']*(\?|%s|:\w+)[^"']*["']\s*,|\.objects\.(filter|get)\(|session\.query\(|\.filter_by\(""",
         "Database access uses bound parameters or an ORM."),
    Rule("Debug mode enabled", "gap", ("V14.3.2", "8.9"),
         r"\bdebug\s*=\s*True\b|^\s*DEBUG\s*=\s*True\b|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*1",
         "Framework debug mode is switched on in code or configuration.",
         "Disable debug mode outside local development; drive it from environment config."),
    Rule("Weak hash used for passwords or integrity", "gap", ("V2.4.1", "V6.2.2", "8.24"),
         r"hashlib\.(md5|sha1)\(|\bmd5\(|createHash\(\s*['\"](md5|sha1)['\"]|MessageDigest\.getInstance\(\s*\"(MD5|SHA-1)\"",
         "MD5/SHA-1 is used; these are unsuitable for password storage and broken for collision resistance.",
         "Store passwords with Argon2id, bcrypt or PBKDF2; use SHA-256+ elsewhere."),
    Rule("Adaptive password hashing in use", "implemented", ("V2.4.1", "8.5"),
         r"\bbcrypt\.|\bargon2\b|\bpbkdf2|generate_password_hash\(|make_password\(|PasswordHasher\(",
         "Passwords are hashed with an adaptive, salted algorithm."),
    Rule("OS command built from input", "gap", ("V5.3.8", "8.28"),
         r"os\.system\(|os\.popen\(|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\(",
         "A shell is invoked in a way that allows command injection if any argument is user-controlled.",
         "Pass arguments as a list without shell=True and validate inputs against an allow list."),
    Rule("Unsafe deserialisation or eval", "gap", ("V5.5.3", "8.28"),
         r"pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|(?<![\w.])eval\(|(?<![\w.])exec\(|marshal\.loads\(|ObjectInputStream\(",
         "Untrusted data may reach a deserialiser or code evaluator.",
         "Use safe formats (JSON, yaml.safe_load) and never eval user-supplied data."),
    Rule("TLS certificate validation disabled", "gap", ("V9.2.1", "8.20", "8.24"),
         r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE|InsecureSkipVerify\s*:\s*true",
         "Outbound TLS connections do not validate certificates.",
         "Keep certificate validation on; pin a CA bundle if needed."),
    Rule("Security-relevant logging present", "implemented", ("8.15", "V7.1.3"),
         r"logging\.getLogger\(|\blogger\.(info|warning|error)\(|\bwinston\b|LoggerFactory\.getLogger",
         "The application has structured logging that can record security events."),
    Rule("Credentials written to logs", "gap", ("V7.1.1", "8.12"),
         r"(log(ger)?\.\w+|print|console\.log)\([^)]*\b(password|passwd|token|secret)\b",
         "A log or print statement includes a credential-named value.",
         "Never log credentials; mask sensitive fields in log formatters."),
    Rule("Server-side access control checks", "implemented", ("V4.1.1", "5.15"),
         r"@login_required|@permission_required|@requires_auth|Depends\(\s*get_current_\w*user|@PreAuthorize|"
         r"@jwt_required|isAuthenticated\(|@user_passes_test",
         "Endpoints are protected by server-side authentication/authorisation checks."),
    Rule("Privileged functions without role check", "needs_review", ("8.2", "V4.1.1"),
         r"""@\w+\.route\(\s*['"]/admin""",
         "Admin routes exist; confirm each enforces a role check on the server.",
         "Add an explicit role/permission check to every admin endpoint."),
    Rule("CORS allows any origin", "gap", ("V14.5.3", "8.20"),
         r"""allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|CORS\(\s*app\s*\)|origin\s*:\s*["']\*["']|\bcors\(\s*\)""",
         "Cross-origin requests are accepted from any origin.",
         "Restrict CORS to an explicit allow list of trusted origins."),
    Rule("Session cookie without Secure/HttpOnly", "gap", ("V3.4.1", "V3.4.2"),
         r"SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|(secure|httponly|httpOnly)\s*[:=]\s*(False|false)",
         "Session cookies are configured without the Secure or HttpOnly attribute.",
         "Set Secure, HttpOnly and SameSite on session cookies."),
    Rule("Output rendered without escaping", "gap", ("V5.3.3", "8.28"),
         r"\|\s*safe\b|mark_safe\(|render_template_string\(|\.innerHTML\s*=|dangerouslySetInnerHTML|bypassSecurityTrust\w+\(|Markup\(",
         "User-influenced content may be rendered without context-aware escaping (XSS).",
         "Rely on template auto-escaping; sanitise HTML with an allow-list sanitiser if it must be rendered."),
    Rule("File path built from request data", "gap", ("V12.3.1", "8.28"),
         r"(open|send_file|send_from_directory|res\.sendFile|readFile(Sync)?)\([^)]*(request\.|req\.(params|query|body))",
         "Filesystem paths include request data, which allows path traversal.",
         "Map user input to server-side identifiers; never use client file names directly."),
    Rule("Dependency or security scanning in CI", "implemented", ("8.8", "8.25"),
         r"\b(dependabot|safety check|pip-audit|npm audit|snyk|bandit|semgrep|trivy|gitleaks)\b|SAST|Dependency-Scanning",
         "The pipeline runs automated dependency or security scanning.", code_only=True),
    Rule("AI / LLM component present", "needs_review", ("MAP 1.1", "MEASURE 2.7", "MANAGE 4.1"),
         r"\bopenai\b|\banthropic\b|AzureOpenAI|\blangchain\b|\bChatCompletion\b",
         "The system integrates an AI model; its intended use, security testing and monitoring must be documented.",
         "Document intended use and limits, add prompt-injection tests, and monitor model behaviour in production."),
    Rule("Personal data processed", "needs_review", ("5.34",),
         r"\b(email|phone(_number)?|date_of_birth|dob|ssn|personnummer|address)\b\s*[:=]\s*\w",
         "The data model contains personal data; confirm lawful basis, minimisation and retention.",
         "Record the PII in a data inventory and define retention and access rules.", code_only=True),
]


def controls(safe: dict[str, str]) -> ControlMapping:
    findings: list[Finding] = []
    for r in RULES:
        evs = _scan(safe, re.compile(r.pattern, re.I | re.M), code_only=r.code_only)
        evs = [e for e in evs if _ext(e.file) not in {".md", ".rst", ".txt"}]
        if not evs:
            continue
        findings.append(Finding(title=r.title, status=r.status, controls=list(r.controls),
                                description=r.description, recommendation=r.recommendation,
                                evidence=evs))
    return ControlMapping(findings=findings)
