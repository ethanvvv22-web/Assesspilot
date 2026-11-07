"""Runtime settings, read from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    backend: str                  # "azure" or "heuristic"
    azure_endpoint: str
    azure_key: str
    azure_deployment: str
    azure_api_version: str
    data_dir: Path
    gitlab_url: str
    gitlab_token: str             # read-only token used for ingestion
    gitlab_publish_token: str     # separate token, only used after human approval
    gitlab_publish_issues: bool   # opt-in: also post approved reports as GitLab issues
    api_key: str                  # key n8n uses to call the service
    approver_key: str             # key only human reviewers hold
    max_files: int
    max_file_bytes: int

    @property
    def azure_configured(self) -> bool:
        # A key is optional: without one, Entra ID (az login) is used.
        return bool(self.azure_endpoint and self.azure_deployment)


def normalize_endpoint(url: str) -> str:
    """Accept a Foundry *project* endpoint and reduce it to the resource endpoint.

    https://x.services.ai.azure.com/api/projects/p  ->  https://x.services.ai.azure.com/
    """
    url = url.strip()
    if "<" in url or not url:
        return ""
    for suffix in ("/api/projects/", "/openai/"):
        if suffix in url:
            url = url.split(suffix, 1)[0]
    return url.rstrip("/") + "/"


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from .env (project root) without overriding real env vars."""
    path = Path(__file__).resolve().parents[1] / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def load_settings(**overrides) -> Settings:
    _load_dotenv()
    env = os.environ
    endpoint = normalize_endpoint(env.get("AZURE_OPENAI_ENDPOINT") or env.get("AZURE_AI_PROJECT_ENDPOINT", ""))
    key = env.get("AZURE_OPENAI_API_KEY", "")
    deployment = env.get("AZURE_OPENAI_DEPLOYMENT", "")
    default_backend = "azure" if (endpoint and deployment) else "heuristic"
    values = dict(
        backend=env.get("ASSESSPILOT_BACKEND", default_backend),
        azure_endpoint=endpoint,
        azure_key=key,
        azure_deployment=deployment,
        azure_api_version=env.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        data_dir=Path(env.get("ASSESSPILOT_DATA_DIR", "./data")),
        gitlab_url=env.get("GITLAB_URL", "https://gitlab.com").rstrip("/"),
        gitlab_token=env.get("GITLAB_READ_TOKEN", ""),
        gitlab_publish_token=env.get("GITLAB_PUBLISH_TOKEN", ""),
        gitlab_publish_issues=env.get("GITLAB_PUBLISH_ISSUES", "false").strip().lower() == "true",
        api_key=env.get("ASSESSPILOT_API_KEY", ""),
        approver_key=env.get("ASSESSPILOT_APPROVER_KEY", ""),
        max_files=int(env.get("ASSESSPILOT_MAX_FILES", "400")),
        max_file_bytes=int(env.get("ASSESSPILOT_MAX_FILE_BYTES", "200000")),
    )
    values.update(overrides)
    if isinstance(values["data_dir"], str):
        values["data_dir"] = Path(values["data_dir"])
    return Settings(**values)
