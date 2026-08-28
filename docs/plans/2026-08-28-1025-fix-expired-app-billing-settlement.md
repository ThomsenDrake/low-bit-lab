---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Settle replacement billing after app-list retention expires
date: 2026-08-28
requirements: docs/plans/2026-08-28-1025-brainstorm-expired-app-billing-settlement.md
---

# Implementation plan: settle replacement billing after app-list retention expires

## Scope

Add a zero-spend billing-only evidence variant for the already consumed replacement action. This
plan authorizes read-only capture and local settlement only; it authorizes no Modal execution,
retry, replacement, weights, U9, conversion, training, or promotion.

## Work

1. Add a closed billing-app identity schema that states only its authoritative billing source and
   the observed absence from the provider's recent-app listing.
2. Refactor capture to keep the existing listed-app path, but defer unique identity selection to the
   complete billing report when the listing returns no eligible app.
3. Require one nonempty billing identity in fallback mode and preserve in-memory privacy filtering.
4. Validate both evidence variants and keep the existing transactional failed-state settlement.
5. Test legacy compatibility, fallback success, multiple identities, empty rows, command count,
   exact cost, and non-fabrication of lifecycle claims.
6. Simplify, review, run full verification, compound the durable retention-window lesson, and ship
   a public PR after checks pass.

## Verification

```text
uv run pytest tests/test_reference_replacement_settlement.py tests/test_reference_orchestrator.py tests/test_db.py -q
uv run ruff check src tests
uv run pytest -q
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
git diff --check
```

## Stop condition

Any ambiguous identity, incomplete report, or lineage mismatch remains audit-blocked. Settlement
must record the authoritative cost as a failed action and must not claim a reference baseline.

