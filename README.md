# RitualGraph

**Executable threat modeling for AI systems.**

RitualGraph turns threat specifications into typed security graphs that can be validated, simulated, and enforced in CI. Instead of treating a threat model as a document that goes stale, RitualGraph treats it as an executable contract.

```text
Artifact --Fracture--> Artifact'
   ^                       |
   |                       v
 evidence              invariants
   |                       |
   +---- controls <--------+
```

## What exists in v0.1

- strict Pydantic threat-model schema
- STRIDE + CIAP + NIST AML taxonomy fields
- explicit epistemic status (`established`, `plausible`, `hypothesis`, `symbolic`)
- referential-integrity compiler
- DAG validation and deterministic execution order
- normalized security-state simulation
- composable controls with per-metric coverage
- invariant engine with CI-friendly exit codes
- vendor-neutral molecular-AI reference model
- pytest suite and GitHub Actions verification

## The core idea

Most threat models answer: **what could go wrong?**

RitualGraph adds three harder questions:

1. **What state changes if it does?**
2. **Which invariant proves the system is no longer acceptable?**
3. **Can the control be executed in simulation and demonstrated to preserve that invariant?**

That makes the model useful to architecture review, red teaming, CI/CD, and assurance engineering rather than only documentation.

## Install

```bash
pip install -e '.[dev]'
```

## Validate and compile

```bash
ritualgraph validate models/molecular_pipeline.json
ritualgraph compile models/molecular_pipeline.json
```

## Execute an unsafe scenario

```bash
ritualgraph run models/molecular_pipeline.json \
  --threat T-POISON
```

The command exits with status `3` because data provenance falls below its invariant. That behavior is intentional: a broken security invariant is a failed build condition.

Now activate the provenance control:

```bash
ritualgraph run models/molecular_pipeline.json \
  --threat T-POISON \
  --control C-PROVENANCE
```

The same perturbation now remains inside the declared security envelope.

## Epistemic honesty

RitualGraph refuses to flatten established attack classes and speculative mechanisms into one bucket. Every threat declares an `evidence_status`. Research hypotheses are executable for experiments, but remain hypotheses until evidence changes their status. See [docs/epistemic-model.md](docs/epistemic-model.md).

## Reference architecture

```text
External Sources
      |  poisoning
      v
Curated Corpus
      |  artifact substitution
      v
Foundation Model
      |  indirect injection
      v
Discovery Agent
      |  decision drift
      v
Scientific Decision
```

The reference model is deliberately vendor-neutral. It demonstrates the engine; it does not claim to describe any company's deployed infrastructure.

## Project roles

- **Aix** — Project Lead
- **Architect** — Systems Architecture & Engineering

## Status

`v0.1` is the semantic kernel. Next layers are evidence adapters, temporal propagation, scanner ingestion, attestation/telemetry adapters, and graph visualization.

Apache-2.0.
