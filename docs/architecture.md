# Architecture

RitualGraph compiles a declarative threat model into an executable directed acyclic graph. The v0.1 runtime is intentionally small: deterministic inputs, deterministic state transitions, explicit controls, and explicit invariants.

## Core mapping

| RitualGraph | Meaning |
|---|---|
| Artifact | typed system state / asset |
| Ritual | ordinary transformation or control |
| Fracture | adversarial state transition |
| Trigger | precondition for a transition |
| Shadow | perturbation applied to security state |
| Invariant | property that must remain true |
| Evidence | epistemic support for a threat claim |

The runtime does **not** execute arbitrary expressions from model files. Invariants are typed comparisons over normalized metrics. This is deliberate: threat specifications are data, not executable code.

## Pipeline

```text
JSON model
   |
   v
Pydantic schema validation
   |
   v
referential-integrity compiler
   |
   v
DAG + deterministic order
   |
   v
perturbation simulation
   |            \
   v             v
metric states   evidence metadata
   |
   v
invariant engine
   |
   +--> PASS (release may continue)
   `--> FAIL (CI exit code 3)
```

## Metric semantics

All metrics are normalized to `[0, 1]`. Higher is better for confidentiality, integrity, availability, provenance, and fidelity. Lower is better for attack surface. Threat effects are deltas. Controls reduce the magnitude of a delta; they do not magically restore state.

The v0.1 model is not a probabilistic risk calculator. Likelihood, uncertainty distributions, temporal propagation, and Bayesian evidence fusion belong in later versions once the deterministic semantics are stable.
