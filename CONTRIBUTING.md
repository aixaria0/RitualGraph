# Contributing

RitualGraph treats threat models as executable security contracts.

A change is mergeable when:

1. schema changes are explicit and backward-compatibility impact is documented;
2. compiler semantics remain deterministic;
3. new threat claims include an epistemic status and evidence reference;
4. controls identify what they mitigate and how they are verified;
5. new behavior has tests;
6. broken invariants fail closed.

Do not solve a failing test by weakening an invariant without an architectural reason documented in the pull request.
