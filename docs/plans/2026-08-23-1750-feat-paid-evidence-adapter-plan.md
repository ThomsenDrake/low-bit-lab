---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-brainstorm
execution: code
title: Implement the paid-evidence adapter boundary
date: 2026-08-23
status: approved-for-zero-spend-implementation
requirements_source: docs/plans/2026-08-23-1749-brainstorm-paid-evidence-adapter-plan.md
---

# Goal

Implement the approved, target-neutral paid-evidence adapter boundary for one no-weight provider
smoke test without invoking Modal, reserving credits, or transferring weights. Stop when an exact
smoke command and approval sentence can be generated and verified locally.

# Settled decisions

- session-settled: public defaults remain target-neutral, submission-disabled, and USD 0.
- session-settled: U8 and weight transfer remain unauthorized.
- session-settled: the ignored local ledger ceiling is not current-action authority.
- session-settled: the adapter exists only behind an approval-plus-reservation capability.
- session-settled: this implementation may generate but must not run the first paid command.
- session-settled: the first paid command is a provider smoke test only; it cannot load a model or
  clear memory-fit, cold-load, quality, throughput, soak, kernel, or useful-context gates.

# Implementation units

## U1 — Amend the controlling public contract

Update `PLAN.md`, `BUDGET.md`, and the Modal runbook to permit one audited provider adapter while
keeping every public default at zero and execution unauthorized. Document that the amendment
changes representability, not execution authority.

Acceptance:

- The public scaffold remains target-neutral.
- No positive personal budget is committed.
- U8, weights, scheduling, retries, and destructive cleanup remain forbidden.

## U2 — Define a closed paid-action contract

Add a frozen value object and validator that bind action kind, canonical config/challenge/scope,
reviewed commit, control-plane hash, provider environment, resource envelope, formula approval,
ledger digest, exact per-action maximum, expiry, and approval statement digest.

Acceptance:

- Unknown fields, cap drift, expiry, lineage drift, or wording drift fail closed.
- The contract cannot derive a positive cap from the total ledger.
- The contract states that weights and U8 are unauthorized.

## U3 — Add the audited provider adapter

Replace the declarative-only Modal module with one narrowly scoped no-weight smoke adapter. Its
public call accepts only a one-shot execution capability created after approval consumption and
budget reservation. The remote function returns only bounded runtime/GPU observations and accepts
no model identifier, path, URL, token, repository, or user payload. Keep retries, schedules,
secrets, mounts, volumes, uploads, and cleanup absent.

Acceptance:

- Static scanning permits the provider primitive only in the audited module.
- Direct calls without the capability fail before importing or contacting Modal.
- Tests monkeypatch the provider boundary and assert zero network/provider calls.
- Tests prove model/weight inputs are not part of the adapter schema or function signature.

## U4 — Add the command gate and handoff

Add a CLI with `plan`, `verify`, and `execute`. `plan` and `verify` are read-only. `execute` requires
an ignored approval artifact, atomically consumes the approval and reserves the exact cap, creates
the one-shot capability, and only then calls the adapter. The implementation work runs only the
first two commands.

Acceptance:

- The local handoff contains the exact command, scope hash, maximum authorized cost, and exact
  approval wording.
- Before the later approval, `paid_action_ready` remains false.
- No command executed during this plan may enter the `execute` branch.

## U5 — Test and document failure containment

Add focused tests for schema closure, expiry, replay, stale commit, control-plane drift, cap drift,
reservation atomicity, direct adapter bypass, and provider-call non-occurrence. Update runbooks and
compound durable lessons.

Acceptance:

- `uv run ruff check .`
- focused paid-boundary tests pass
- `uv run pytest -q`
- publication/privacy scan passes
- database totals remain requested/reserved/actual USD 0

# Stop conditions

Stop immediately on any Modal API contact, nonzero reservation, weight access, credential request,
private-data risk, unknown provider behavior, U8 authorization, or conflict with the frozen budget
ledger. Do not run the generated paid command.

# Review lenses

1. reproducibility and lineage;
2. Modal-credit safety and unknown-state containment;
3. Windows/WSL2 and RTX 5080 compatibility;
4. security, credentials, and public target neutrality;
5. support for the research loop without conflating configured and useful 256K context.
