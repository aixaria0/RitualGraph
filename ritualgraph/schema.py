from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Score = Annotated[float, Field(ge=0.0, le=1.0)]
Delta = Annotated[float, Field(ge=-1.0, le=1.0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceStatus(StrEnum):
    ESTABLISHED = "established_attack_class"
    PLAUSIBLE = "plausible_mechanism"
    HYPOTHESIS = "research_hypothesis"
    SYMBOLIC = "symbolic_construct"


class Metric(StrEnum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    PROVENANCE = "provenance"
    FIDELITY = "fidelity"
    ATTACK_SURFACE = "attack_surface"


class MetricState(StrictModel):
    confidentiality: Score = 1.0
    integrity: Score = 1.0
    availability: Score = 1.0
    provenance: Score = 1.0
    fidelity: Score = 1.0
    attack_surface: Score = 0.0


class MetricDelta(StrictModel):
    confidentiality: Delta = 0.0
    integrity: Delta = 0.0
    availability: Delta = 0.0
    provenance: Delta = 0.0
    fidelity: Delta = 0.0
    attack_surface: Delta = 0.0


class Asset(StrictModel):
    id: str = Field(pattern=r"^A-[A-Z0-9_-]+$")
    name: str
    kind: str
    trust_boundary: str
    criticality: Literal["low", "medium", "high", "critical"]
    baseline: MetricState = Field(default_factory=MetricState)


class Taxonomy(StrictModel):
    stride: list[Literal["S", "T", "R", "I", "D", "E"]] = Field(default_factory=list)
    ciap: list[Literal["Confidentiality", "Integrity", "Availability", "Provenance"]] = Field(default_factory=list)
    nist_aml: list[Literal["evasion", "poisoning", "privacy", "misuse", "other"]] = Field(default_factory=list)


class Evidence(StrictModel):
    kind: Literal["standard", "paper", "experiment", "incident", "internal", "hypothesis"]
    reference: str
    confidence: Score


class Threat(StrictModel):
    id: str = Field(pattern=r"^T-[A-Z0-9_-]+$")
    name: str
    source: str
    target: str
    preconditions: list[str] = Field(default_factory=list)
    effects: MetricDelta
    taxonomy: Taxonomy
    evidence_status: EvidenceStatus
    evidence: list[Evidence] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def hypothesis_requires_hypothesis_evidence(self) -> "Threat":
        if self.evidence_status == EvidenceStatus.HYPOTHESIS:
            if self.evidence and not any(e.kind in {"hypothesis", "experiment", "paper"} for e in self.evidence):
                raise ValueError("research hypotheses require hypothesis, experiment, or paper evidence")
        return self


class Control(StrictModel):
    id: str = Field(pattern=r"^C-[A-Z0-9_-]+$")
    name: str
    mitigates: list[str]
    effectiveness: Score
    metric_coverage: dict[Metric, Score] = Field(default_factory=dict)
    verification: list[str] = Field(default_factory=list)


class Invariant(StrictModel):
    id: str = Field(pattern=r"^INV-[A-Z0-9_-]+$")
    name: str
    asset: str
    metric: Metric
    operator: Literal[">=", "<="]
    threshold: Score
    rationale: str


class ThreatModel(StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    name: str
    version: str
    description: str
    assets: list[Asset]
    threats: list[Threat]
    controls: list[Control]
    invariants: list[Invariant]
