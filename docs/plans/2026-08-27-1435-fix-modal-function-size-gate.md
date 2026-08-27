# Implementation plan: fail closed on Modal function size

## Scope

Add a zero-spend local gate for Modal's 64 KiB serialized-function ceiling. This plan does not
authorize a provider action, retry, new entitlement, weight transfer, or U9.

## Work

1. Split raw remote-callable construction from provider-cap validation.
2. Freeze the exact 65,536-byte ceiling and reject larger serialized bytes while cleaning all
   registered-by-value modules.
3. Run serialization before the local budget reservation and bind those exact cached bytes to the
   pinned Modal SDK's actual hydration object.
4. Clear serialization policy if boundary persistence or deadline admission fails.
5. Add focused boundary, cleanup, and current-graph regression tests.
6. Run Simplify, report-only Review, full verification, and Compound documentation.
7. Commit, push, open a public PR, monitor required checks, and merge only when green.

## Acceptance criteria

- Oversize detection occurs before reservation creation and `_mark_submission_pending`; it writes
  only a reservation-free terminal audit attempt.
- The production execution graph currently fails locally with a fixed sanitized error.
- Payloads of exactly 65,536 bytes remain admissible and 65,537-byte payloads fail.
- No provider call is made and no Modal cost is incurred by this implementation work.
- Configured context remains 262,144 tokens and proven-useful context remains unknown.

## Verification

```text
uv run ruff check src tests
uv run pytest tests/test_reference_modal_adapter.py -q
uv run pytest -q
uv run python -m lowbit_lab.publication --root . --manifest configs/local/publication.yaml
git diff --check
```
