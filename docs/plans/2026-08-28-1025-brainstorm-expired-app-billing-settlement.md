---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Expired app-list billing settlement requirements
date: 2026-08-28
---

# Requirements brainstorm: expired app-list billing settlement

## Problem

The complete authoritative billing report contains one uniquely attributed replacement app and a
nonzero actual cost, but the provider's recent-app listing no longer returns the stopped app after
its retention window. The existing settlement schema requires lifecycle fields that can no longer
be observed and must not be invented.

## Requirements

- Preserve the exact submitted request packet, consumed reservation, workspace, environment scope,
  billing authority, complete query window, and pre/post authentication bindings.
- Prefer the existing stopped-app evidence when exactly one eligible app is still listed.
- When no eligible app is listed, accept only nonempty, closed-schema billing rows with the fixed
  target-neutral description, validated environment, one unique app identity, exact interval, and
  exact summed cost.
- Record only the factual state that the recent-app listing did not return the app and that identity
  came from the authoritative filtered billing report.
- Never infer that no task ran, that the app was stopped, or that the reference baseline succeeded.
- Reject multiple listed apps, multiple billing identities, zero matching billing rows in fallback
  mode, private rows, type drift, lineage drift, or authentication drift.
- Perform no provider execution, retry, weight transfer, scheduling, storage, or destructive work.

## Acceptance

- The captured USD 0.00293476 cost can be represented without fabricated lifecycle fields.
- Both legacy stopped-app and billing-only evidence validate under closed schemas.
- Billing-only settlement remains a terminal failed reference action and restores no authority.
- Focused/full tests, Ruff, publication/privacy checks, and independent review pass.

