# Epistemic model

RitualGraph treats *what we know about a threat* as part of the threat model. A mechanism cannot be promoted from speculation to fact by putting it next to established attack classes.

`evidence_status` is mandatory and has four values:

- `established_attack_class` — recognized attack class with strong external support.
- `plausible_mechanism` — technically plausible scenario that may be architecture-specific.
- `research_hypothesis` — requires controlled validation before any production claim.
- `symbolic_construct` — useful for reasoning or simulation but not asserted as an empirical mechanism.

Evidence records carry a kind, reference, and confidence. Confidence is not probability of compromise; it expresses confidence that the cited evidence supports the modeled mechanism.

## Why this matters

The threat engine must be able to execute a hypothesis without laundering it into a fact. This lets experimental ideas live beside standardized AML classes while preserving scientific honesty.

The reference model maps recognized adversarial-ML concepts to NIST AI 100-2e2025 categories where appropriate. Project-specific constructs remain separately typed.
