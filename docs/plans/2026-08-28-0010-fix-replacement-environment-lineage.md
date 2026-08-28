---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Bind replacement billing environment to validated capability evidence
date: 2026-08-28
requirements: docs/plans/2026-08-28-0010-brainstorm-replacement-environment-lineage.md
---

# Implementation plan: bind replacement billing environment to validated capability evidence

## Scope

Repair the zero-spend read-only replacement billing capture. This plan authorizes no Modal
execution, retry, replacement, weights, U9, conversion, training, or promotion.

## Work

1. Reproduce the failure with a config fixture containing only the public environment-scope digest.
2. Validate the ignored canonical bootstrap request and reproduce its bound provider-capability
   receipt.
3. Use the receipt's provider environment transiently for the app and billing queries while keeping
   the scope digest as the durable authority binding.
4. Recompute the exact standing packet from config and request bytes and compare it with the packet
   persisted when the consumed reservation was created.
5. Assert the exact capability-receipt and image-recipe hashes used by the validation call and prove
   local lineage drift cannot reach authentication or Modal CLI reads.
6. Simplify, review, run full verification, compound the durable boundary convention, and ship a
   public PR after checks pass.

## Verification

```text
uv run pytest tests/test_reference_orchestrator.py::test_replacement_capture_filters_private_workspace_rows -q
uv run pytest tests/test_reference_orchestrator.py tests/test_reference_replacement_settlement.py -q
uv run ruff check src tests
uv run pytest -q
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
git diff --check
```

## Stop condition

Any missing or drifted local authority remains a pre-contact failure. Provider reads remain limited
to the already authorized app listing and complete billing report; no remote function may run.
