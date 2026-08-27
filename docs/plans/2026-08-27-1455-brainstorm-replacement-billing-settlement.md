---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Replacement U8 billing settlement requirements
date: 2026-08-27
---

# Requirements brainstorm: replacement U8 billing settlement

## Problem

The sole replacement U8 action is audit-blocked after Modal created and stopped an app but rejected
the oversized function before a call identity was persisted. The stopped app later reports zero
currently running tasks; that observation is not lifetime task evidence. The existing settlement
CLI handles only the earlier authentication-before-identity case and cannot bind this app-attributed
attempt.

## Requirements

- Preserve the consumed replacement entitlement and forbid any retry or second replacement.
- Select exactly one audit-blocked replacement reservation with the expected sanitized failure.
- Re-authenticate the approved workspace immediately before and after read-only evidence capture.
- Capture a unique stopped app identity reporting zero currently running tasks from the approved
  provider environment, without treating that field as lifetime task evidence.
- Capture a complete-hour billing report covering the full 2,700-second action window plus the
  frozen 3,600-second completeness delay.
- Persist only target-neutral, sanitized app and billing rows; never persist other workspace data.
- Bind reservation, execution scope, entitlement, workspace identity, provider-environment scope,
  billing authority, app evidence, exact sanitized report bytes, and actual cost in one
  compare-and-set settlement.
- Record nonzero authoritative cost exactly; cost over USD 4.00 is a terminal budget failure.
- Perform no provider execution, weight transfer, retry, scheduling, storage, or cleanup.

## Acceptance

- Incomplete, mismatched, ambiguous, noncanonical, or stale evidence leaves the reservation
  `audit_blocked`.
- Exact complete evidence settles once and is replay-safe.
- Focused/full tests, Ruff, publication/privacy checks, doc validation, and independent review pass.
