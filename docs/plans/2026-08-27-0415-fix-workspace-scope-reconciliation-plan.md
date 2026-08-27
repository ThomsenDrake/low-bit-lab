---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
title: Implement one-time workspace-scope reconciliation
date: 2026-08-27
requirements: docs/plans/2026-08-27-0415-brainstorm-workspace-scope-reconciliation.md
---

# Implement one-time workspace-scope reconciliation

## Outcome

Add one closed authority and database transition that preserve the historical logical workspace
scope while binding it to the separately authenticated provider workspace identity. Use the mapping
only for the existing exact-zero settlement and its single replacement action.

## Key technical decisions

- KTD1 (`user-approved`): retain the original scope as immutable lineage and add a separate identity
  field. Rejected: changing the historical config or treating the digests as equal. Reason: experiment
  lineage must describe what was originally authorized.
- KTD2 (`user-approved`): freeze a separate ignored authority whose exact content hash is tracked.
  Rejected: accepting a caller-supplied mapping at runtime. Reason: only the approved pair is valid.
- KTD3 (`user-approved`): revalidate the provider-local profile at billing capture and final paid
  consumption. Rejected: trusting an earlier authentication receipt. Reason: profile state can drift.
- KTD4 (`user-approved`): preserve one-shot and budget boundaries exactly. Rejected: restoring the
  original slot or creating a retry counter. Reason: settlement and retry authority are distinct.

## Implementation units

### U1. Immutable reconciliation authority

Create a closed builder, materializer, and validator for an ignored authority artifact. Validate the
exact approved statement bytes and frozen authority digest. Derive original reservation, execution
scope, billing authority, and logical scope from existing immutable local lineage; derive the
authenticated identity only from the official provider-local profile. Persist neither display names
nor credential values.

**Acceptance:** missing or altered statement, reversed mapping, changed base, different reservation,
or future workspace identity fails before database or provider mutation.

### U2. Distinct authentication and billing identities

Bump local binding and receipt schemas so `original_workspace_scope_sha256` and
`authenticated_workspace_identity_sha256` are always distinct named fields. Bind the reconciliation
authority digest into authentication receipts and exact-zero billing evidence. Remove every equality
assumption between original logical scope and authenticated identity.

**Acceptance:** tests reject field substitution, equality shortcuts, stale receipts, wrong profile,
and unbound evidence bytes.

### U3. Schema migration and atomic settlement

Bump the database schema. Add immutable mapping lineage to the pre-identity settlement and
replacement entitlement tables. Preserve every prior budget-ledger cell through recognized-schema
migration. In the settlement transaction, revalidate exact authority, auth receipts, billing authority,
report bytes, original config scope, authenticated identity, reservation, execution scope, and mapping
before settling USD 0 and minting one entitlement.

**Acceptance:** disposable v12/v13 migrations preserve all rows and reject unknown or missing ledgers;
transaction rollback leaves the original reservation audit-blocked and creates no entitlement.

### U4. Replacement boundary and operator workflow

Carry both identities and the reconciliation digest through replacement preparation and the final
adapter capability. Immediately before entitlement consumption, reproduce SDK identity, official
endpoint, empty override headers, provider profile, authenticated identity, auth receipt bytes, and
mapping authority. Keep the original resource and budget envelope unchanged.

**Acceptance:** any drift stops before entitlement consumption; successful local preparation contacts
no paid provider primitive.

### U5. Documentation, simplification, review, and shipping

Update the recovery runbook, budget explanation, report-only review, and durable solution note.
Simplify recently changed code, run independent reproducibility/migration/security reviews, fix clear
findings, and run focused/full tests, Ruff, diff validation, and publication/privacy scanning. Commit,
push, open a public target-neutral PR, monitor CI, and merge only after required checks pass.

**Acceptance:** clean merged main reproduces every deterministic gate. Browser testing is explicitly
skipped because the change has no browser surface.

## Verification commands

```powershell
.venv\Scripts\python.exe -m pytest -q tests/test_reference_authority.py tests/test_reference_settlement.py tests/test_reference_orchestrator.py tests/test_reference_modal_adapter.py tests/test_db.py
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check src tests
git diff --check
.venv\Scripts\python.exe -m lowbit_lab.publication --manifest configs/local/publication.yaml
```

## Live stop conditions

- Stop before billing capture if the official endpoint, profile transport, authenticated identity,
  authority bytes, original scope, reservation, execution scope, or billing authority differs.
- Stop before settlement unless exact complete-window evidence is canonical USD 0.
- Stop before replacement unless the original is settled, exactly one entitlement is available, the
  tree is clean merged main, and every existing deterministic paid gate passes.
- Any submitted, failed, timed-out, or ambiguous replacement consumes the one-shot authority and
  remains audit-blocked pending authoritative billing settlement.
