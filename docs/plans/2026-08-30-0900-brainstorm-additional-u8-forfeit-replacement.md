---
title: Additional U8 pre-provider forfeit and replacement - requirements brainstorm
type: brainstorm
date: 2026-08-30
artifact_contract: ce-requirements/v1
---

# Requirements

- Preserve merged commit `59882a3fae30fb73e00af9ae3be1ae2e51ed7654` as the amendment base.
- Immutably record failed request SHA-256
  `eb70d52416d67aae5f050778b42a72d070ffac6f572387aa3aee657714c0ec6e` as a
  consumed pre-provider forfeit with zero incremental spend, no reservation, no provider
  submission, and no weight transfer.
- Preserve corrected zero-spend preflight request SHA-256
  `c8453ddec2a1ed058ce5fce038d18ebb66c0a8d71d1e03caf5b21a09786b0474` as
  immutable parent evidence, then separately bind the post-merge paid request at claim time.
- Preserve the original additional authority and database lineage instead of rewriting history or
  pretending the failed command had a reservation.
- Mint exactly one mechanically enforced replacement entitlement only after validating the exact
  human amendment, the immutable forfeit receipt, the original grant, and prior settled spend.
- Make the replacement entitlement non-reusable: once the final paid boundary is claimed, every
  failure path remains terminal and no release operation may restore it.
- Require all existing deterministic, privacy, provenance, runtime, provider-environment,
  resource, watchdog, WSL parity, and cumulative-budget gates before the final paid boundary.
- Preserve one A100-80GB GPU, one container, one spawn, 2,700 seconds, zero retries, no fallback,
  USD 4.00 incremental, and USD 4.00564445 cumulative caps.
- Preserve target-neutral tracked files; keep human authority and generated receipts in ignored
  local paths.
- Add focused regression coverage for schema migration, immutable lineage, one-use claiming,
  reservation/release behavior, request binding, status, and provider-contact failure handling.
- Do not initiate Modal execution, reserve credits, or transfer weights until the amendment is
  reviewed, merged, synchronized into WSL, and every unchanged gate passes.
