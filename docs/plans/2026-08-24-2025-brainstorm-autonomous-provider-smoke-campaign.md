---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Autonomous no-weight provider-smoke campaign requirements
date: 2026-08-24
---

# Problem

Per-action human approval protects paid execution but creates avoidable approval churn after the
operator explicitly delegates a tightly bounded campaign. The lab needs reusable authority that
remains narrower than target activation and cannot broaden through regenerated hashes.

# Requirements

- R1. Freeze the exact standing-authority statement by SHA-256 and require an ignored, closed
  campaign-authority artifact matching it.
- R2. Keep public defaults at USD 0. The ignored campaign authority permits only no-weight provider
  smokes within a cumulative lifetime USD 4.00 cap.
- R3. Each action reserves no more than confirmed unspent balance and binds exact clean lineage,
  environment, resources, ledger bytes, and billing authority.
- R4. Permit at most one A100-80GB GPU, one container, 2700 seconds, zero retries, and no overlap.
- R5. Continue to forbid weights, model identifiers, user payloads, private data, secrets, mounts,
  volumes, schedules, uploads, target activation, destructive cleanup, and U8.
- R6. Submitted or ambiguous attempts retain their reservation until authoritative billing settles
  them. Settled actual cost determines reusable balance.
- R7. Support auditable recovery of a stopped provider app that launched zero tasks and containers
  before a function-call identity existed, without inventing such an identity.
- R8. All CLIs emit bounded JSON and fail closed on unknown fields, lineage drift, dirty trees,
  insufficient balance, active reservations, stale billing, or unknown provider state.
- R9. A provider smoke proves neither useful 256K context nor model or kernel support.
- R10. Add focused migration, authority, replay, balance, recovery, and CLI tests plus full review.

# Out of scope

- Model weights, target configuration, inference, conversion, evaluation, or U8.
- Increasing the USD 4.00 lifetime cap.
- Scheduling or unattended recurring execution.

# Success

One human grant enables lineage-bound no-weight smokes only while authoritative billing proves
sufficient unspent balance. No per-action approval remains, and ambiguous state still blocks reuse.
