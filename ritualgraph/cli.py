from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from .compiler import CompileError, compile_model
from .io import load_model
from .simulation import SimulationError, simulate

app = typer.Typer(help="Compile and execute RitualGraph threat models.")


@app.command()
def validate(model: Path) -> None:
    """Validate schema and graph references."""
    try:
        compiled = compile_model(load_model(model))
    except (ValidationError, CompileError, ValueError) as exc:
        typer.echo(f"INVALID: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo(f"VALID: {compiled.model.name} ({len(compiled.model.assets)} assets, {len(compiled.model.threats)} threats)")


@app.command()
def compile(model: Path) -> None:
    """Emit a deterministic compiled graph summary."""
    graph = compile_model(load_model(model))
    payload = {
        "name": graph.model.name,
        "version": graph.model.version,
        "topological_assets": graph.topological_assets,
        "adjacency": graph.adjacency,
        "threats_by_target": graph.threats_by_target,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command()
def run(
    model: Path,
    threat: list[str] = typer.Option([], "--threat", "-t"),
    control: list[str] = typer.Option([], "--control", "-c"),
) -> None:
    """Execute selected perturbations and fail if an invariant breaks."""
    try:
        graph = compile_model(load_model(model))
        result = simulate(graph, threat, control)
    except (ValidationError, CompileError, SimulationError, ValueError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(2)

    payload = {
        "passed": result.passed,
        "applied": [a.__dict__ for a in result.applied],
        "invariants": [i.__dict__ for i in result.invariants],
        "states": {k: v.model_dump() for k, v in result.states.items()},
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if not result.passed:
        raise typer.Exit(3)


if __name__ == "__main__":
    app()
