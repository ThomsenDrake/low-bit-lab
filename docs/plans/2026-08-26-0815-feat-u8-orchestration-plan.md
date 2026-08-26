# Implement the U8 orchestration boundary

## Controlling authority

This implementation is bounded by the human-approved signed-CDN transport amendment tied to
merge commit `a96d5949f2826438b0f219b1dd8633c8bd42f8c1`.  It changes no public default and grants no
additional provider action.

## Work

1. Add a pure builder that reconstructs the canonical U8 bootstrap request from validated ignored
   local artifacts and the current clean merged commit.  Accept only query-free immutable origins,
   exact sizes, and SHA-256 values already present in the public-metadata provenance chain.
2. Add a target-neutral orchestration CLI with fixed repository-relative paths:
   - `prepare` regenerates and validates ignored request/capability evidence without touching the
     results database or constructing a provider client; local import is limited to reproducing
     the already-audited pinned SDK fingerprint;
   - `execute` repeats preparation, requires the exact prepared request digest as confirmation,
     atomically registers/attaches a short-lived derived standing-authority approval and reserves
     USD 4.00, then calls the existing single adapter boundary exactly once.
3. Derive identifiers and approval bytes from canonical lineage plus fresh nonces.  Persist only
   sanitized hashes and closed audit records.  Never serialize target metadata into tracked files
   or command output.
4. Add focused unit and integration tests for request construction, fixed paths, preparation
   purity, confirmation mismatch, database reservation, adapter handoff, and fail-closed behavior.
5. Run simplification, independent review, full tests, lint, documentation checks, and publication
   privacy scans.  Fix clear findings and record only durable lessons.
6. Commit, push, open a public PR, monitor checks, and merge only after the required checks pass.
   Regenerate all ignored evidence from merged `main` before any provider contact.

## Acceptance criteria

- `prepare` exits successfully with JSON containing only action kind, request digest, execution
  scope digest, configured-context status, and `provider_contacted: false`.
- `prepare` leaves the database unchanged and performs no provider-client construction, reservation,
  provider contact, or network body transfer.
- `execute` is unavailable unless the current request digest is explicitly confirmed and every
  deterministic paid gate passes from current bytes.
- A successful local mocked handoff creates exactly one USD 4.00 reservation and one capability;
  a failed gate calls neither the adapter nor Modal.
- The adapter remains the only code containing the U8 `remote.spawn` primitive.
- Focused and full tests, Ruff, documentation validation, and publication/privacy scans pass.
- Tracked files remain target-neutral and all target-specific generated evidence remains ignored.
- No Modal submission occurs during implementation, review, CI, or merged-main regeneration.

## Test commands

```text
uv run pytest -q tests/test_reference_orchestrator.py tests/test_reference_bootstrap.py tests/test_reference_modal_adapter.py tests/test_db.py
uv run pytest -q
uv run ruff check .
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
python <compound-engineering-skill>/scripts/validate-doc-claims.py docs/solutions/best-practices/fail-closed-research-control-plane.md
```

## Stop conditions

Stop before provider import on any unknown lineage, provenance, privacy, budget, environment,
topology, watchdog, source, or authority state.  A reservation that reaches submission-pending or
an ambiguous provider boundary is never released or retried.
