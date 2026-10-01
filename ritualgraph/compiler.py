from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict, deque

from .schema import ThreatModel


class CompileError(ValueError):
    pass


@dataclass(frozen=True)
class CompiledGraph:
    model: ThreatModel
    adjacency: dict[str, tuple[str, ...]]
    topological_assets: tuple[str, ...]
    threats_by_target: dict[str, tuple[str, ...]]


def _unique(items, kind: str) -> None:
    ids = [item.id for item in items]
    dupes = sorted({x for x in ids if ids.count(x) > 1})
    if dupes:
        raise CompileError(f"duplicate {kind} ids: {', '.join(dupes)}")


def compile_model(model: ThreatModel) -> CompiledGraph:
    _unique(model.assets, "asset")
    _unique(model.threats, "threat")
    _unique(model.controls, "control")
    _unique(model.invariants, "invariant")

    assets = {a.id for a in model.assets}
    threats = {t.id for t in model.threats}
    controls = {c.id for c in model.controls}

    for t in model.threats:
        if t.source not in assets or t.target not in assets:
            raise CompileError(f"{t.id} references unknown asset edge {t.source} -> {t.target}")
        missing = sorted(set(t.controls) - controls)
        if missing:
            raise CompileError(f"{t.id} references unknown controls: {', '.join(missing)}")

    for c in model.controls:
        missing = sorted(set(c.mitigates) - threats)
        if missing:
            raise CompileError(f"{c.id} mitigates unknown threats: {', '.join(missing)}")

    for inv in model.invariants:
        if inv.asset not in assets:
            raise CompileError(f"{inv.id} references unknown asset {inv.asset}")

    adjacency_sets: dict[str, set[str]] = defaultdict(set)
    indegree = {a: 0 for a in assets}
    for t in model.threats:
        if t.target not in adjacency_sets[t.source]:
            adjacency_sets[t.source].add(t.target)
            indegree[t.target] += 1

    q = deque(sorted(a for a, d in indegree.items() if d == 0))
    order: list[str] = []
    while q:
        node = q.popleft()
        order.append(node)
        for nxt in sorted(adjacency_sets[node]):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                q.append(nxt)

    if len(order) != len(assets):
        raise CompileError("asset transition graph contains a cycle; v0.1 executes DAGs only")

    by_target: dict[str, list[str]] = defaultdict(list)
    for t in model.threats:
        by_target[t.target].append(t.id)

    return CompiledGraph(
        model=model,
        adjacency={k: tuple(sorted(v)) for k, v in adjacency_sets.items()},
        topological_assets=tuple(order),
        threats_by_target={k: tuple(v) for k, v in by_target.items()},
    )
