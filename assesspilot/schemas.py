"""Structured outputs every agent must return. Anything that does not parse is rejected."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

MAX_QUOTE_CHARS = 400
Level = Literal["Low", "Medium", "High"]
Status = Literal["implemented", "gap", "needs_review"]


class Evidence(BaseModel):
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    quote: str = Field(min_length=1)
    # Filled in by evidence.verify(), never by the model.
    verified: bool = False
    reason: str = ""

    @field_validator("quote")
    @classmethod
    def _shorten_long_quote(cls, v: str) -> str:
        # An overlong quote should not sink a whole run; the start is still checked against the code.
        return v[:MAX_QUOTE_CHARS]


class InventoryItem(BaseModel):
    category: Literal["language", "framework", "datastore", "auth", "data_type",
                      "external_service", "ai_component", "entry_point", "deployment"]
    name: str
    evidence: list[Evidence] = Field(default_factory=list)


class Inventory(BaseModel):
    summary: str
    items: list[InventoryItem]


class CIARating(BaseModel):
    level: Level
    rationale: str
    evidence: list[Evidence] = Field(default_factory=list)
    # Set by the verifier: False means no citation checked out, so the level is only a proposal.
    supported: bool = True


class CIAClassification(BaseModel):
    confidentiality: CIARating
    integrity: CIARating
    availability: CIARating


class Finding(BaseModel):
    title: str
    status: Status
    controls: list[str] = Field(min_length=1)
    description: str
    recommendation: str = ""
    evidence: list[Evidence] = Field(min_length=1)
    # Set by the pipeline after verification.
    supported: bool = True


class ControlMapping(BaseModel):
    findings: list[Finding]
    # Controls where the model claimed a status but cited nothing; the claim is discarded.
    dropped_uncited: list[str] = Field(default_factory=list)


class ControlAssessment(BaseModel):
    """The model's verdict on exactly one control."""
    control: str
    status: Literal["implemented", "gap", "needs_review", "not_evidenced"]
    title: str = ""
    description: str = ""
    recommendation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)


class ControlAssessments(BaseModel):
    assessments: list[ControlAssessment]
