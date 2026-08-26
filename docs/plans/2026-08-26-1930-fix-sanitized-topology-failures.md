# Emit closed topology failure codes

## Implementation

1. Define the exact allowed failure-code set at the topology boundary.
2. Emit a fixed network code from the HEAD client without retaining the underlying exception.
3. Preserve only an allowed code and numeric artifact ordinal; map all other exceptions to
   `unknown_failure`.
4. Add focused privacy and closed-code regression tests.
5. Run full tests, Ruff, publication/privacy and documentation checks, simplify, and review.
6. Commit, push, open a public PR, monitor checks, and merge only when green.

## Acceptance criteria

- A signed-query sentinel cannot appear in the exception or traceback.
- Arbitrary exception messages cannot cross the topology boundary.
- Known policy failures remain distinguishable without target details.
- No request body is read and no provider or budget state is changed.
- All repository checks pass.

## Test commands

```text
uv run pytest tests/test_reference_transport.py -q
uv run pytest -q
uv run ruff check .
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
python <compound-engineering-skill>/scripts/validate-doc-claims.py docs/solutions/best-practices/fail-closed-research-control-plane.md
```

## Stop conditions

Stop on privacy leakage, open-ended error content, any body transfer, reservation, Modal contact, or
need to weaken the signed-CDN authority. Do not execute U8 from this branch.
