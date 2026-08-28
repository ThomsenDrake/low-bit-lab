---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Normalize the pinned Modal billing UTC serialization
date: 2026-08-28
requirements: docs/plans/2026-08-28-1040-brainstorm-modal-billing-utc-serialization.md
---

# Implementation plan: normalize the pinned Modal billing UTC serialization

## Scope

Add a provider-specific timestamp parser at the billing-report boundary. This plan authorizes
zero-spend code, tests, documentation, and read-only billing capture only.

## Work

1. Add a narrow parser that accepts explicit UTC or exact offset-free second-resolution Modal
   billing timestamps and canonicalizes both to aware UTC.
2. Use it only for authoritative billing interval rows; keep all other timestamps on the strict
   general parser.
3. Lock accepted and rejected forms in focused tests, including the observed provider form.
4. Simplify, independently review, run full verification, compound the durable serialization
   lesson, and ship a public PR after checks pass.

## Verification

```text
uv run pytest tests/test_reference_orchestrator.py tests/test_reference_replacement_settlement.py -q
uv run ruff check src tests
uv run pytest -q
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
git diff --check
```

## Stop condition

Any timestamp outside the two exact UTC forms remains invalid. No paid provider action is
authorized.

