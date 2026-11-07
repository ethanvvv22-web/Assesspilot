"""Azure OpenAI client wrapper with JSON-only outputs and schema-validated retries."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from pydantic import BaseModel, ValidationError

from .config import Settings


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    retries: int = 0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AzureLLM:
    settings: Settings
    usage: Usage = field(default_factory=Usage)
    _client: object = None
    _supports_temperature: bool = True

    def _get_client(self):
        if self._client is None:
            if not self.settings.azure_configured:
                raise LLMError("Azure OpenAI is not configured (AZURE_OPENAI_ENDPOINT / _API_KEY / _DEPLOYMENT)")
            from openai import AzureOpenAI
            auth: dict = {"api_key": self.settings.azure_key}
            if not self.settings.azure_key:  # keyless: Entra ID via az login / managed identity
                try:
                    from azure.identity import DefaultAzureCredential, get_bearer_token_provider
                except ImportError as exc:
                    raise LLMError("No AZURE_OPENAI_API_KEY set. Either add the key to .env, or "
                                   "`pip install azure-identity` and run `az login`.") from exc
                auth = {"azure_ad_token_provider": get_bearer_token_provider(
                    DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default")}
            self._client = AzureOpenAI(azure_endpoint=self.settings.azure_endpoint,
                                       api_version=self.settings.azure_api_version,
                                       timeout=180, max_retries=3, **auth)
        return self._client

    def _chat(self, messages: list[dict]) -> str:
        client = self._get_client()
        kwargs = dict(model=self.settings.azure_deployment, messages=messages,
                      response_format={"type": "json_object"})
        if self._supports_temperature:
            kwargs.update(temperature=0, seed=7)
        t0 = time.perf_counter()
        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as exc:  # reasoning models reject temperature/seed
            if self._supports_temperature and "temperature" in str(exc).lower():
                self._supports_temperature = False
                return self._chat(messages)
            raise LLMError(f"Azure OpenAI call failed: {exc}") from exc
        self.usage.calls += 1
        self.usage.seconds += time.perf_counter() - t0
        if resp.usage:
            self.usage.prompt_tokens += resp.usage.prompt_tokens or 0
            self.usage.completion_tokens += resp.usage.completion_tokens or 0
        return resp.choices[0].message.content or ""

    def structured(self, system: str, user: str, schema: type[BaseModel], max_attempts: int = 2) -> BaseModel:
        """Ask for JSON matching `schema`; on parse/validation error, retry once with the error."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last_err = ""
        for attempt in range(max_attempts):
            raw = self._chat(messages)
            try:
                return schema.model_validate(json.loads(raw))
            except (json.JSONDecodeError, ValidationError) as exc:
                last_err = str(exc)[:1500]
                self.usage.retries += 1
                messages += [{"role": "assistant", "content": raw[:4000]},
                             {"role": "user", "content": "Your output did not match the required JSON schema:\n"
                                                         f"{last_err}\nReturn only the corrected JSON object."}]
        raise LLMError(f"model output failed schema validation after {max_attempts} attempts: {last_err}")
