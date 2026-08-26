# Stabilize installed-runtime evidence before U8

## Goal

Make the isolated WSL probes observational with respect to the hash-bound package tree, restore the
approved receipt without destructive cleanup, and regenerate the merged-main U8 preparation packet.

## Implementation

1. Add explicit Python `-B` to every probe command because isolated mode ignores Python
   environment variables.
2. Apply the closed flags and environment to native probes and WSL `env -i`.
3. Extend focused tests to assert the flag for inventory and CUDA/framework probes.
4. Preserve both runtime receipt identities: verify canonical semantic content, then bind the exact
   persisted receipt bytes used by the config and dependent evidence.
5. Move only cache files created after the approved receipt into an ignored, timestamped quarantine.
   Validate source and destination remain inside `artifacts/local/runtime/` before moving.
6. Verify the original receipt twice, then run focused/full tests, lint, diff checks, publication and
   privacy scans.
7. Simplify and independently review the branch; fix high-confidence findings.
8. Commit, push, open and merge the PR after checks pass. On merged main, regenerate U8 `prepare`.

## Acceptance criteria

- Both probe subprocesses run with bytecode writes disabled.
- Existing isolation variables and `-I` remain intact.
- No cache path or machine-specific path enters tracked artifacts.
- The original runtime receipt SHA-256 verifies twice after reversible quarantine.
- `uv run pytest tests/test_runtime.py tests/test_reference_orchestrator.py`
- `uv run pytest`
- `uv run ruff check .`
- `git diff --check`
- Publication/privacy and documentation-claim scans report zero findings.
- `uv run --extra remote lowbit-reference-u8 --root . prepare` succeeds on merged main without
  creating the results database or contacting Modal.

## Stop conditions

Stop before quarantine if any post-receipt file is not a regular `.pyc` below `__pycache__`, before
provider contact if any deterministic gate fails, and before U8 if the request or execution scope
cannot be reproduced exactly.
