"""Collect a read-only snapshot of a repository plus design documents.

Supported sources:
  * a local directory               ->  D:/code/myrepo
  * any git URL (cloned, read-only) ->  https://github.com/org/repo.git
  * a GitLab project via the API    ->  gitlab:group/project

Least privilege: the GitLab token is checked before use and refused if it has
any write scope. Ingestion never pushes, commits or opens anything.
"""
from __future__ import annotations

import hashlib
import http.client
import io
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .guardrails import FilterReport, filter_input

TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs",
    ".html", ".htm", ".jinja", ".j2", ".vue", ".sql", ".sh", ".ps1",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json", ".xml", ".properties", ".env",
    ".md", ".rst", ".txt",
}
TEXT_NAMES = {"Dockerfile", "docker-compose.yml", "Makefile", "requirements.txt", "Pipfile",
              "package.json", "pom.xml", "build.gradle", ".gitlab-ci.yml", "Procfile"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv",
             "env", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "coverage", ".idea",
             "static/vendor", "migrations"}
SKIP_SUFFIXES = (".min.js", ".lock", "package-lock.json", ".map")

# Files that usually carry security-relevant decisions are read first.
PRIORITY_HINTS = ("auth", "login", "user", "account", "password", "session", "security", "config",
                  "settings", "route", "view", "api", "controller", "model", "db", "database",
                  "crypto", "token", "admin", "upload", "docker", "ci", "requirements", "package",
                  "readme", "design", "architecture", "threat", "app", "main", "server")

ALLOWED_GITLAB_SCOPES = {"read_repository", "read_api"}
GITLAB_ATTEMPTS = 3
MAX_ARCHIVE_BYTES = 300_000_000


class IngestError(RuntimeError):
    pass


@dataclass
class Snapshot:
    source: str
    revision: str
    files: dict[str, str]          # original text (kept server-side only)
    safe: dict[str, str]           # filtered text, the only view models ever see
    design_docs: list[str]
    filter_report: FilterReport = field(default_factory=FilterReport)

    def digest(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.files):
            h.update(p.encode())
            h.update(self.files[p].encode("utf-8", "replace"))
        return h.hexdigest()

    def to_dict(self) -> dict:
        return {
            "source": self.source, "revision": self.revision, "files": self.files,
            "safe": self.safe, "design_docs": self.design_docs,
            "redactions": self.filter_report.redactions,
            "injections": self.filter_report.injections,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        return cls(d["source"], d["revision"], d["files"], d["safe"], d["design_docs"],
                   FilterReport(d.get("redactions", []), d.get("injections", [])))


def _is_text_candidate(rel: str) -> bool:
    p = Path(rel)
    if any(part in SKIP_DIRS for part in p.parts[:-1]):
        return False
    if rel.endswith(SKIP_SUFFIXES):
        return False
    return p.suffix.lower() in TEXT_EXT or p.name in TEXT_NAMES


def _priority(rel: str) -> tuple[int, int, str]:
    low = rel.lower()
    hits = sum(h in low for h in PRIORITY_HINTS)
    is_test = int("test" in low)
    return (-hits + is_test * 2, low.count("/"), low)


def _select(paths: list[str], settings: Settings) -> list[str]:
    cands = [p for p in paths if _is_text_candidate(p)]
    return sorted(cands, key=_priority)[: settings.max_files]


def _decode(raw: bytes) -> str | None:
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------- sources
def _from_directory(root: Path, settings: Settings) -> tuple[dict[str, str], str]:
    rels = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    files: dict[str, str] = {}
    for rel in _select(rels, settings):
        fp = root / rel
        if fp.stat().st_size > settings.max_file_bytes:
            continue
        text = _decode(fp.read_bytes())
        if text is not None:
            files[rel] = text
    rev = "working-tree"
    try:
        rev = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                             text=True, check=True, timeout=20).stdout.strip() or rev
    except (OSError, subprocess.SubprocessError):
        pass
    return files, rev


def _clone(url: str, ref: str | None, settings: Settings) -> Path:
    slug = hashlib.sha1(f"{url}@{ref}".encode()).hexdigest()[:12]
    dest = settings.data_dir / "repos" / slug
    if (dest / ".git").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)

    def git(*args: str) -> None:
        r = subprocess.run(["git", "-C", str(dest), *args], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise IngestError(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")

    git("init", "-q")
    git("remote", "add", "origin", url)
    git("fetch", "-q", "--depth", "1", "origin", ref or "HEAD")
    git("checkout", "-q", "FETCH_HEAD")
    return dest


def _gitlab_get(settings: Settings, path: str, raw: bool = False):
    req = urllib.request.Request(f"{settings.gitlab_url}/api/v4{path}")
    if settings.gitlab_token:
        req.add_header("PRIVATE-TOKEN", settings.gitlab_token)
    for attempt in range(GITLAB_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https base URL
                body = resp.read()
            return body if raw else json.loads(body)
        except urllib.error.HTTPError as exc:  # client errors will not fix themselves
            if (exc.code != 429 and exc.code < 500) or attempt == GITLAB_ATTEMPTS - 1:
                raise
            if exc.code == 429:
                time.sleep(min(int(exc.headers.get("Retry-After", 20) or 20), 90))
                continue
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
            if attempt == GITLAB_ATTEMPTS - 1:
                raise IngestError(f"GitLab request failed after {GITLAB_ATTEMPTS} attempts: {exc}") from exc
        time.sleep(2 ** attempt)


def check_gitlab_token_scopes(settings: Settings) -> list[str]:
    """Refuse tokens that could change anything. Returns the token's scopes."""
    if not settings.gitlab_token:
        return []
    info = _gitlab_get(settings, "/personal_access_tokens/self")
    scopes = set(info.get("scopes", []))
    bad = {s for s in scopes if not s.startswith("read_")}  # allow list: anything else could change something
    if bad:
        raise IngestError(f"GitLab token has non-read scopes {sorted(bad)}; use a read_repository + read_api token")
    if not scopes & ALLOWED_GITLAB_SCOPES:
        raise IngestError(f"GitLab token scopes {sorted(scopes)} do not allow reading repositories")
    return sorted(scopes)


def _from_gitlab(project: str, ref: str | None, settings: Settings) -> tuple[dict[str, str], str]:
    try:
        return _read_gitlab(project, ref, settings)
    except urllib.error.HTTPError as exc:
        hint = {401: "token rejected", 403: "token lacks access", 404: "project or ref not found (or private)"}
        raise IngestError(f"GitLab returned {exc.code} for {project}: {hint.get(exc.code, exc.reason)}") from exc
    except urllib.error.URLError as exc:
        raise IngestError(f"cannot reach GitLab at {settings.gitlab_url}: {exc.reason}") from exc


def _read_gitlab(project: str, ref: str | None, settings: Settings) -> tuple[dict[str, str], str]:
    check_gitlab_token_scopes(settings)
    pid = urllib.parse.quote(project, safe="")
    meta = _gitlab_get(settings, f"/projects/{pid}")
    ref = ref or meta.get("default_branch", "main")
    commit = _gitlab_get(settings, f"/projects/{pid}/repository/commits/{urllib.parse.quote(ref, safe='')}")
    sha = commit["id"]
    return _files_from_archive(_gitlab_archive(pid, sha, settings), settings), sha


def _gitlab_archive(pid: str, sha: str, settings: Settings) -> bytes:
    """One request for the whole tree, cached by commit: one request per file hits rate limits."""
    cache = settings.data_dir / "gitlab_cache" / f"{sha}.zip"
    if cache.is_file():
        return cache.read_bytes()
    raw = _gitlab_get(settings, f"/projects/{pid}/repository/archive.zip?sha={sha}", raw=True)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise IngestError(f"repository archive is too large ({len(raw)} bytes)")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(raw)
    return raw


def _files_from_archive(raw: bytes, settings: Settings) -> dict[str, str]:
    """Read selected files straight from the zip in memory; nothing is ever extracted to disk."""
    files: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        members = {}
        for info in zf.infolist():
            if info.is_dir() or "/" not in info.filename:
                continue
            members[info.filename.split("/", 1)[1]] = info  # drop GitLab's top-level <project>-<sha>/ folder
        for rel in _select(list(members), settings):
            info = members[rel]
            if info.file_size <= settings.max_file_bytes and (text := _decode(zf.read(info))) is not None:
                files[rel] = text
    return files


# --------------------------------------------------------------------- entry
def ingest(source: str, settings: Settings, ref: str | None = None,
           docs: list[str] | None = None) -> Snapshot:
    if source.startswith("gitlab:"):
        files, rev = _from_gitlab(source.removeprefix("gitlab:"), ref, settings)
    elif source.startswith(("http://", "https://", "git@")):
        files, rev = _from_directory(_clone(source, ref, settings), settings)
    else:
        root = Path(source)
        if not root.is_dir():
            raise IngestError(f"not a directory: {source}")
        files, rev = _from_directory(root, settings)

    design_docs = [p for p in files if p.lower().endswith((".md", ".rst", ".txt"))
                   and any(k in p.lower() for k in ("design", "architecture", "threat", "security", "docs/"))]
    for extra in docs or []:
        ep = Path(extra)
        if not ep.is_file():
            raise IngestError(f"design document not found: {extra}")
        rel = f"_design/{ep.name}"
        files[rel] = ep.read_text(encoding="utf-8", errors="replace")
        design_docs.append(rel)

    if not files:
        raise IngestError("no readable source files found")

    report = FilterReport()
    safe = {p: filter_input(p, t, report) for p, t in files.items()}
    return Snapshot(source, rev, files, safe, design_docs, report)
