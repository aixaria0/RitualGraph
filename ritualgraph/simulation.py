from __future__ import annotations

from dataclasses import dataclass
from math import prod

from .compiler import CompiledGraph
from .invariants import InvariantResult, evaluate_invariant
from .schema import Metric, MetricState


class SimulationError(ValueError):
    pass


@dataclass(frozen=True)
class AppliedThreat:
    threat_id: str
    target: str
    controls: tuple[str, ...]


@dataclass(frozen=True)
class SimulationResult:
    states: dict[str, MetricState]
    applied: tuple[AppliedThreat, ...]
    invariants: tuple[InvariantResult, ...]

    @property
    def passed(self) -> bool:
        return all(i.passed for i in self.invariants)


def _combined_reduction(graph: CompiledGraph, threat_id: str, metric: Metric, active: set[str]) -> float:
    factors = []
    for control in graph.model.controls:
        if control.id in active and threat_id in control.mitigates:
            coverage = float(control.metric_coverage.get(metric, 0.0))
            factors.append(1.0 - float(control.effectiveness) * coverage)
    return 1.0 - prod(factors) if factors else 0.0


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def simulate(graph: CompiledGraph, threat_ids: list[str], active_controls: list[str] | None = None) -> SimulationResult:
    active_controls = active_controls or []
    threat_map = {t.id: t for t in graph.model.threats}
    control_ids = {c.id for c in graph.model.controls}

    unknown_t = sorted(set(threat_ids) - set(threat_map))
    unknown_c = sorted(set(active_controls) - control_ids)
    if unknown_t:
        raise SimulationError(f"unknown threats: {', '.join(unknown_t)}")
    if unknown_c:
        raise SimulationError(f"unknown controls: {', '.join(unknown_c)}")

    states = {a.id: a.baseline.model_copy(deep=True) for a in graph.model.assets}
    selected = set(threat_ids)
    active = set(active_controls)
    applied: list[AppliedThreat] = []

    order_index = {asset: i for i, asset in enumerate(graph.topological_assets)}
    ordered_threats = sorted(
        (t for t in graph.model.threats if t.id in selected),
        key=lambda t: (order_index[t.target], t.id),
    )

    for threat in ordered_threats:
        state = states[threat.target]
        data = state.model_dump()
        effect = threat.effects.model_dump()
        used_controls: list[str] = []

        for metric in Metric:
            delta = float(effect[metric.value])
            reduction = _combined_reduction(graph, threat.id, metric, active)
            if reduction > 0:
                used_controls.extend(
                    c.id for c in graph.model.controls
                    if c.id in active and threat.id in c.mitigates and c.metric_coverage.get(metric, 0) > 0
                )
            data[metric.value] = _clamp(float(data[metric.value]) + delta * (1.0 - reduction))

        states[threat.target] = MetricState.model_validate(data)
        applied.append(AppliedThreat(threat.id, threat.target, tuple(sorted(set(used_controls)))))

    inv_results = tuple(
        evaluate_invariant(inv, states[inv.asset]) for inv in graph.model.invariants
    )
    return SimulationResult(states, tuple(applied), inv_results)
