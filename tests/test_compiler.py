import json
from pathlib import Path

import pytest

from ritualgraph.compiler import CompileError, compile_model
from ritualgraph.schema import ThreatModel


def load_reference():
    return ThreatModel.model_validate(json.loads(Path("models/molecular_pipeline.json").read_text()))


def test_reference_model_compiles_to_dag():
    graph = compile_model(load_reference())
    assert graph.topological_assets[0] == "A-EXT"
    assert graph.topological_assets[-1] == "A-DECISION"
    assert "A-AGENT" in graph.adjacency["A-MODEL"]


def test_unknown_control_is_rejected():
    model = load_reference()
    model.threats[0].controls.append("C-DOES-NOT-EXIST")
    with pytest.raises(CompileError, match="unknown controls"):
        compile_model(model)


def test_cycle_is_rejected():
    model = load_reference()
    model.threats[4].source = "A-DECISION"
    model.threats[4].target = "A-DATA"
    with pytest.raises(CompileError, match="cycle"):
        compile_model(model)
