# Phase 1 Workspace-Scope Reconciliation Review

Date: 2026-08-27

Scope: one-time mapping of the preserved configured workspace scope to the authenticated Modal
workspace identity, bound to merged parent `fe73bdee00c3cbe59587f4f677168865908bdafd`

Mode: report-only review followed by high-confidence fixes

## Verdict

Ready for public review after full verification. The change adds no provider action, retry, budget,
weight transfer, target activation, or promotion authority. It does not rewrite the original
experiment config or represent the configured scope and authenticated identity as equal.

## Review lenses

### Reproducibility and experiment lineage

The original workspace-scope digest, authenticated workspace-identity digest, exact reconciliation
authority, reservation, execution scope, billing authority, exact billing-report bytes, settlement,
and replacement entitlement are distinct immutable inputs. The SQLite transaction inserts the
mapping, settlement, and single entitlement atomically. Migration accepts only frozen v13 schema
fingerprints and rejects decision-bearing recovery rows in the source schema.

### Modal-credit safety and failure containment

Reconciliation is zero-spend and read-only. Billing capture and entitlement consumption require a
clean local `main` exactly matching local `origin/main`. Authentication evidence expires after five
minutes. A settlement is possible only for the existing exact empty billing report, and the
replacement retains the existing one-A100-80GB, one-container, one-spawn, 2,700-second, zero-retry,
USD 4.00 incremental boundary. Submitted or ambiguous replacement state remains audit-blocked.

### Local RTX 5080 compatibility

The change performs no local inference, conversion, quantization, driver update, or GPU claim. The
local RTX 5080 remains a control-plane/runtime-validation environment; the remote A100-80GB
reference envelope is unchanged.

### Security and private-data handling

The active workspace probe authenticates only the selected Modal profile and emits only a SHA-256
digest; it does not enumerate other profiles or reveal the workspace display value. Endpoint and
override-header validation occur in the same isolated process as each read-only Modal CLI request.
The paid adapter checks the active workspace identity from the exact cached SDK configuration
immediately before entitlement consumption. Credentials, profile names, private paths, targets, and
signed query values remain absent from tracked artifacts and sanitized evidence.

### Research-loop support

The explicit reconciliation closes the pre-identity settlement gap without fabricating identity or
erasing historical scope. It permits the already-authorized one-time replacement only after exact
USD 0 evidence settles the existing attempt. The evaluation envelope remains configured at 262,144
tokens; useful 262,144-token behavior remains unproven until empirical evaluation succeeds.

## Findings and disposition

- Fixed: the first approach would have used a profile-list command, which can contact every locally
  configured profile. The implementation now authenticates only the active profile and hashes its
  returned workspace value before output.
- Fixed: endpoint validation and read-only billing capture originally occurred in separate
  processes. One isolated process now loads and validates the configuration before invoking the
  CLI request.
- Fixed: the replacement gate originally trusted a preceding authentication receipt without
  checking the paid SDK session. The adapter now reproduces the active identity from its cached SDK
  configuration immediately before atomic entitlement consumption.
- Fixed: authentication receipts had no freshness limit. They now expire after 300 seconds and are
  revalidated at settlement and replacement boundaries.
- Fixed: an empty but structurally unknown v13 database could migrate. The migration now requires an
  exact supported recovery-table DDL fingerprint even when no rows exist.
- Fixed: mutable feature branches could reach evidence and settlement commands. These commands now
  require clean merged `main` matching `origin/main`.
- Accepted residual: the provider dollar ceiling remains locally enforced rather than a
  provider-enforced hard cap. The existing one-shot and audit-blocked ambiguity rules contain but
  cannot eliminate provider-managed execution or billing risk.

## Required verification

```text
uv run ruff check src tests
uv run pytest tests/test_reference_authority.py tests/test_reference_settlement.py tests/test_reference_orchestrator.py tests/test_reference_modal_adapter.py tests/test_db.py -q
uv run pytest -q
git diff --check
```
