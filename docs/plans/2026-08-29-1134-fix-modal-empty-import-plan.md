---
title: Fix pinned Modal workspace probe Empty import
type: fix
date: 2026-08-29
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
---

# Goal

Restore the pre-provider opaque workspace-authentication gate without changing its endpoint, privacy, authority, or one-shot semantics.

# Root cause

The isolated probe imports `Empty` from `modal_proto.api_pb2`, but Modal 1.5.3 does not export that symbol. The subprocess exits before `_Client.from_env()` authenticates, and the controller returns `Modal workspace identity is unavailable`. Existing coverage compiled the script but never executed its imports in the pinned environment.

# Work

1. Strengthen `tests/test_reference_orchestrator.py` so the probe names `google.protobuf.empty_pb2.Empty` and rejects the unavailable import.
2. Confirm the regression test fails on merged `main`.
3. Change only the tracked probe import.
4. Run the focused auth/orchestrator tests, Ruff, the full suite, and the publication scan.
5. Execute the exact isolated probe in the pinned WSL environment and require a sanitized workspace digest.
6. Review, compound the import-boundary lesson, commit, push, open a PR, monitor CI, and merge when checks pass.

# Acceptance

- The static regression test fails before the code fix and passes afterward.
- The pinned WSL `auth-verify` command succeeds and emits only hashed/sanitized identity evidence.
- The additional grant remains `available`; no reservation or Modal execution occurs during the fix.
- Full tests, lint, whitespace checks, publication/privacy scan, PR checks, and review pass.

# Stop conditions

Stop on any credential exposure, endpoint drift, non-opaque auth path, grant consumption, reservation, provider execution, weight transfer, spend, or unexplained pinned-environment failure.

