from __future__ import annotations

from dataclasses import dataclass

from .schema import Invariant, MetricState


@dataclass(frozen=True)
class InvariantResult:
    invariant_id: str
    passed: bool
    actual: float
    operator: str
    threshold: float


def evaluate_invariant(inv: Invariant, state: MetricState) -> InvariantResult:
    actual = float(getattr(state, inv.metric.value))
    passed = actual >= inv.threshold if inv.operator == ">=" else actual <= inv.threshold
    return InvariantResult(inv.id, passed, actual, inv.operator, inv.threshold)
