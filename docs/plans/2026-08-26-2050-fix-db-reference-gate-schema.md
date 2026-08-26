# Align the database reference-gate schema

## Implementation

1. Define the exact gate-field set once in the shared reference contract and consume it from both
   the config loader and database challenge parser.
2. Update the canonical reservation fixture to the same closed, production-shaped schema and
   configured 262,144-token envelope.
3. Add a missing-field rejection case for the new bound receipt root.
4. Reproduce reservation success against a disposable copy of the authoritative database with all
   provider calls stubbed.
5. Run focused/full tests, Ruff, publication/privacy and documentation checks, simplify, and review.
6. Commit, push, open a public PR, monitor checks, and merge only when green.

## Review outcome

The simplify review removed a per-load mutable copy of the frozen field set and consolidated the
schema-version literal into the same shared contract. Reuse, quality, and efficiency re-review found
no remaining actionable issue after those changes.

## Acceptance criteria

- Current canonical schema-v5 reference configs pass `_reference_challenge`.
- The config loader and database parser consume one frozen gate-field definition.
- Removing any new gate field fails with a schema error.
- The authoritative database remains unreserved during development and review.
- Existing USD, one-shot, provider, privacy, and execution-scope checks are unchanged.
- All repository checks pass.

## Test commands

```text
uv run pytest tests/test_db.py tests/test_reference_orchestrator.py -q
uv run pytest -q
uv run ruff check .
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
python <compound-engineering-skill>/scripts/validate-doc-claims.py docs/solutions/best-practices/fail-closed-research-control-plane.md
```

## Stop conditions

Stop on canonical identity drift, approval/challenge drift, budget or slot mutation, privacy failure,
provider contact, or any need to relax a field requirement. Do not execute U8 from this branch.
