---
title: Modal workspace probe import regression - requirements brainstorm
type: brainstorm
date: 2026-08-29
artifact_contract: ce-requirements/v1
---

# Requirements

- Preserve opaque provider authentication: lab code must not read, copy, log, or persist credential values.
- Use the pinned Modal client's authenticated `_Client.from_env()` path and the official endpoint check.
- Construct the workspace lookup request from the protobuf package that exists in the pinned isolated environment.
- Exercise the exact isolated probe subprocess in a regression test; compiling the script alone is insufficient.
- Fail before reservation, provider execution, weight transfer, or spend on any import, endpoint, identity, or transport error.
- Preserve the active WSL ownership marker and the available additional grant while the deterministic defect is repaired.
- Ship through a clean public PR, CI, and merge before the WSL gate is rerun.

