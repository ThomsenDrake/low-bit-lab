---
title: Enforce the additional U8 pre-provider forfeit and one replacement
type: feat
date: 2026-08-30
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
---

# Goal

Represent the failed additional U8 command truthfully as a zero-spend pre-provider forfeit and
provide one fail-closed replacement entitlement bound to the corrected request and unchanged lab
limits.

# Authority and invariants

- Amendment base: `59882a3fae30fb73e00af9ae3be1ae2e51ed7654`.
- Failed request: `eb70d52416d67aae5f050778b42a72d070ffac6f572387aa3aee657714c0ec6e`.
- Corrected preflight parent request:
  `c8453ddec2a1ed058ce5fce038d18ebb66c0a8d71d1e03caf5b21a09786b0474`.
- The paid child request is regenerated after merge because reviewed-commit lineage is an input; its
  exact bytes are stored irreversibly at claim time.
- Prior authoritative Modal spend: USD 0.00564445.
- Replacement caps: USD 4.00 incremental and USD 4.00564445 cumulative.
- The original grant and failed command remain immutable historical lineage.
- Claim is irreversible; reservation release cannot recreate authority.
- Provider submission, weights, retries, fallback, mounts, volumes, schedules, and private data
  remain prohibited except for the one later gated replacement action expressly authorized here.

# Work units

## U1 - Immutable amendment and forfeit artifacts

- Add closed builders and validators for the exact ignored human statement, amendment authority,
  and pre-provider forfeit receipt.
- Bind their hashes to the base commit, failed/corrected request hashes, original additional
  authority, prior settlement receipt, prior spend, and unchanged resource/budget envelope.
- Reject byte drift, unknown keys, contradictory provider-contact/reservation/spend fields, and
  any request mismatch.

## U2 - One-use database entitlement

- Advance the SQLite schema with a singleton replacement-entitlement table and immutable forfeit
  lineage.
- Materialize it only through explicit validated amendment activation; do not mint it merely by
  opening an old database.
- Support `available -> claimed -> consumed` and terminal `claimed` audit-blocking. Never permit a
  transition back to `available`.
- Require a matching claimed entitlement when reserving the replacement action and consume it at
  the existing provider-boundary transition.

## U3 - Orchestration and status

- Add a local activation command that writes/validates the receipt and atomically records the
  forfeit plus replacement entitlement without reservation or provider contact.
- Require the exact corrected request and entitlement lineage in prepare/execute paths.
- Claim immediately before the mutable reservation boundary after all deterministic gates and WSL
  parity pass; retain the claim on every subsequent failure.
- Expose explicit forfeit and entitlement state in JSON status output.

## U4 - Verification and simplification

- Add focused tests for authority validation, schema/migration, activation idempotency, one-use
  claim, reservation binding, release non-restoration, and orchestrator failure paths.
- Remove duplicated state checks and keep transition logic small and explicit.
- Run focused tests, the full suite, Ruff, whitespace validation, and publication/privacy scans.

## U5 - Independent review, compound, and shipping

- Perform report-only review for lineage, Modal-credit containment, RTX 5080/WSL compatibility,
  privacy, and research-loop support; fix clear high-confidence findings.
- Record only durable phase-boundary and one-shot-entitlement lessons in `docs/solutions/`.
- Commit, push, open a public PR, monitor required checks, and merge only when green.

## U6 - Final gated replacement action

- Synchronize the exact merged commit into the isolated WSL checkout and re-run focused/full
  verification plus local preflight.
- Activate the amendment, verify the corrected request hash, then execute exactly one replacement
  action only if every unchanged gate passes.
- Treat every submitted, failed, timed-out, ambiguous, or post-claim pre-provider outcome as
  terminal with no replacement or retry; reconcile authoritative billing when applicable.

# Acceptance criteria

- The failed request is recorded exactly once as a zero-spend pre-provider forfeit without a fake
  reservation or provider identity.
- The corrected preflight has one and only one replacement entitlement, and the regenerated paid
  child request is bound exactly once when that entitlement is claimed.
- No generic additional grant path can bypass the amendment or reuse a claimed entitlement.
- Focused and full tests, lint, whitespace, and publication/privacy scans pass.
- Independent review has no unresolved high-confidence finding.
- The public PR is merged before any replacement execution.
- If the paid boundary is reached, its resource and budget envelope is unchanged and its terminal
  outcome is recorded without retry.
- Configured context remains 262,144 tokens; proven-useful context remains unset unless the actual
  evaluation establishes it.

# Test commands

```text
uv run pytest tests/test_reference_authority.py tests/test_db.py tests/test_reference_orchestrator.py tests/test_reference_modal_adapter.py
uv run pytest
uv run ruff check .
git diff --check
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
```

# Stop conditions

Stop before provider contact on lineage, receipt, request, parity, clean-tree, privacy, provenance,
runtime, environment, resource-envelope, watchdog, or budget failure. After entitlement claim,
stop terminally on every failure and do not restore, retry, replace, or submit another action.
