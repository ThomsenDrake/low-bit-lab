---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Settle the consumed replacement from app-attributed billing
date: 2026-08-27
requirements: docs/plans/2026-08-27-1455-brainstorm-replacement-billing-settlement.md
---

# Implementation plan: settle the consumed replacement from app-attributed billing

## Scope

Implement the zero-spend read-only evidence and local settlement path for the already consumed
replacement U8 action. This plan authorizes no execution, retry, replacement, weights, or U9.

## Work

1. Add closed canonical contracts for sanitized stopped-app evidence, filtered billing rows, and a
   replacement settlement receipt.
2. Add a read-only capture command that validates merged clean lineage, the unique audit-blocked
   replacement, approved workspace identity, complete-hour coverage, app identity, and cost rows.
3. Add one transactional database consumer that validates every evidence byte and atomically binds
   app identity, actual cost, settlement digest, reservation, execution scope, environment scope,
   entitlement, and the exact eligible run-state transition.
4. Add a local-only settlement command and update status/runbook output.
5. Test privacy filtering, completeness delay, lineage mismatch, replay, zero/nonzero cost, and
   over-cap failure.
6. Simplify, independently review, run full verification, compound the durable lesson, and ship a
   public PR after checks pass.

## Verification

```text
uv run ruff check src tests
uv run pytest tests/test_reference_replacement_settlement.py tests/test_reference_orchestrator.py tests/test_db.py -q
uv run pytest -q
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
git diff --check
```

## Stop condition

Do not capture before the complete action window and billing delay have elapsed. Absent, incomplete,
or ambiguous evidence must remain audit-blocked. Exact authoritative over-cap evidence must be
recorded atomically as a terminal budget failure and must never become successful or reusable
authority.
