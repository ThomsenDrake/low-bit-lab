---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Implement autonomous no-weight provider-smoke campaign authority
date: 2026-08-24
status: approved
requirements_source: docs/plans/2026-08-24-2025-brainstorm-autonomous-provider-smoke-campaign.md
---

# Goal

Replace per-action approval artifacts with one mechanically enforced campaign authority while
preserving exact action lineage, cumulative USD 4.00 enforcement, and fail-closed settlement.

# Settled decisions

- session-settled: use one reusable campaign authority (user-directed; rejected per-action hash
  approval because the operator delegated this bounded campaign).
- session-settled: enforce one USD 4.00 cumulative lifetime ceiling (user-approved; rejected
  independent per-run budgets because they can exceed the campaign ceiling).
- session-settled: retain exact one-shot action contracts (user-approved; rejected unbound standing
  execution because regenerated code must remain traceable).
- session-settled: no weights, payloads, secrets, mounts, volumes, schedules, destructive cleanup,
  target activation, or U8 (user-directed; rejected broader research authority).

# Technical design

Freeze standing statement SHA-256
`d1d49e39a244b9308d77ae19e538c88cfa468bb271eb7d13d7b043362e77361a` in tracked code. An ignored
closed authority artifact carries the exact grant and envelope. Every action contract binds its
canonical digest while remaining unique to the current clean lineage and short validity window.

SQLite remains the cumulative-cost source of truth. Active and audit-blocked attempts commit their
requested amount; settled or failed attempts commit authoritative actual cost. A new reservation
requires sufficient remaining balance and no active smoke. Prelaunch failures use a separate
evidence transition binding a stopped app with zero tasks and containers before settlement.

# Implementation units

## U1 — Amend controlling contracts

Update `PLAN.md`, `BUDGET.md`, and `docs/runbooks/modal-jobs.md` for campaign authority without
changing public zero defaults or target/U8 boundaries.

## U2 — Add closed campaign authority

Update `src/lowbit_lab/provider_smoke.py` so live contracts and execution require the fixed campaign
artifact instead of per-action approval. Cover statement hashing, schema closure, forbidden flags,
artifact drift, contract binding, dirty lineage, and replay in `tests/test_provider_smoke.py`.

## U3 — Enforce cumulative balance transactionally

Update `src/lowbit_lab/db.py` and `tests/test_db.py`. Use requested values for active/unknown states
and authoritative actual values for settled/failed states. Reject overlap and insufficient balance.

## U4 — Add prelaunch audit recovery

Add a closed local evidence transition and CLI that binds stopped app identity, zero tasks and
containers, timestamps, report hash, and reservation lineage. It may move only a matching
`audit_blocked` row without a call identity into `settlement_pending`.

## U5 — Verify and ship

Run focused/full tests, Ruff, lock, diff, publication/privacy scan, simplification, five-lens review,
and compound capture. Fix clear findings, commit, push, refresh PR #2, and monitor CI.

# Test commands

```text
uv run pytest -q tests/test_provider_smoke.py tests/test_db.py
uv run pytest -q
uv run ruff check .
uv lock --check
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
```

# Stop conditions

Stop on unknown billing, overlap, insufficient confirmed balance, authority or lineage drift,
privacy findings, resource drift, any weight/payload surface, U8, or weakened PLAN.md controls. No
paid action runs until the first attempt is authoritatively settled.
