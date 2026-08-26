# Restore validated provider environment lineage

## Implementation

1. Add `provider_environment` to the closed result returned after complete provider-receipt
   reproduction.
2. Consume that flat field in capability construction and fresh deterministic preflight.
3. Update exact validator-result and capability-construction regression tests.
4. Repeat the metadata-only topology observation after deterministic preflight and before any
   reservation; test the exact ordering.
5. Run focused and full tests, lint, publication/privacy checks, simplification, and report-only
   review.
6. Record the durable lesson, commit, push, open a public PR, monitor required checks, and merge only
   when green.

## Acceptance criteria

- No consumer indexes `validated_result["billing"]`.
- Capability construction does not trust a raw provider receipt for the environment identity.
- Complete receipt reproduction and byte-digest checks remain unchanged.
- The exact pre-contact failure is covered by a focused test.
- The final topology receipt is created after slow local hashing and before the reservation.
- No reservation, provider contact, weight transfer, or Modal spend occurs during the fix.
- All repository checks pass and the tracked tree remains target-neutral.

## Test commands

```text
uv run pytest tests/test_provider_evidence.py tests/test_reference_orchestrator.py tests/test_reference_modal_adapter.py -q
uv run pytest -q
uv run ruff check .
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
python <compound-engineering-skill>/scripts/validate-doc-claims.py docs/solutions/best-practices/fail-closed-research-control-plane.md
```

## Stop conditions

Stop on receipt drift, clean-tree drift, privacy findings, a paid reservation, provider contact, or
any need to weaken the controlling authorities. U8 execution remains unavailable from this branch.
