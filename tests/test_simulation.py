import json
from pathlib import Path

from ritualgraph.compiler import compile_model
from ritualgraph.schema import ThreatModel
from ritualgraph.simulation import simulate


def graph():
    model = ThreatModel.model_validate(json.loads(Path("models/molecular_pipeline.json").read_text()))
    return compile_model(model)


def test_poisoning_breaks_provenance_without_control():
    result = simulate(graph(), ["T-POISON"])
    checks = {i.invariant_id: i for i in result.invariants}
    assert not checks["INV-DATA-PROV"].passed
    assert not result.passed


def test_provenance_control_preserves_invariant():
    result = simulate(graph(), ["T-POISON"], ["C-PROVENANCE"])
    checks = {i.invariant_id: i for i in result.invariants}
    assert checks["INV-DATA-PROV"].passed
    assert result.passed


def test_full_chain_fails_without_controls_and_passes_with_controls():
    threats = ["T-POISON", "T-SUPPLY", "T-INJECTION", "T-DECISION-DRIFT"]
    no_controls = simulate(graph(), threats)
    assert not no_controls.passed

    controls = ["C-PROVENANCE", "C-SIGNATURE", "C-TOOL-GATE", "C-INDEPENDENT-VERIFY"]
    defended = simulate(graph(), threats, controls)
    assert defended.passed


def test_hypothesis_is_executable_but_explicitly_typed():
    g = graph()
    threat = next(t for t in g.model.threats if t.id == "T-THERMAL-HYP")
    assert threat.evidence_status.value == "research_hypothesis"
    result = simulate(g, [threat.id], ["C-TELEMETRY"])
    assert result.passed
