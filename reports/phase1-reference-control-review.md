# Phase 1 U1–U7 report-only review

Date: 2026-08-23

Scope: the target-neutral public control plane for U1–U7. U8 submission remains absent and unauthorized.

## Reproducibility and experiment lineage

- Inventory, provenance, runtime receipt, evaluation lock, reviewed commit, resource specification, scorer, and executor runtime are digest-bound.
- The SQLite schema records immutable config identity, attempts, source hashes, hardware/runtime metadata, reservations, metrics, artifacts, and sanitized failures.
- Approval challenges are recomputed from canonical config rather than accepted as caller-provided identity.

## Remote-credit safety and failure containment

- The remote wrapper is declarative and contains no provider app, submit, or remote-call primitive.
- The only reference envelope is fixed at one A100 80 GB GPU, 8 CPU cores, 96 GiB memory, 90 GiB ephemeral disk, 2,700 seconds, no startup override, and zero retries.
- The local reservation and failure threshold is exactly USD 4.00; it is not described as a
  provider-enforced cap. Challenge consumption and reservation creation are atomic. Unknown submitted
  work remains audit-blocked, and authoritative cost above the reservation is durably recorded as a
  terminal budget failure.
- Provider concurrency, residual-risk acceptance, billing scope, formula, memory fit, cold-path time,
  evaluation authority, and human approval are independent fail-closed gates.
- One-container and one-GPU environment limits reduce overlap but do not bound provider-managed crash
  rescheduling or cumulative dollar spend. A submitted execution scope can never be retried.

## Local RTX 5080 compatibility

- The installed WSL environment receipt proves framework discovery, CUDA build metadata, driver visibility, compute capability observation, and device memory observation.
- It does not claim full-model inference, low-bit kernel support, or useful long-context operation. Those remain later empirical gates.
- Full-weight local execution is deferred when host memory does not satisfy the declared fit requirement.

## Security and private-data handling

- Config schemas are closed, credential-like fields are rejected, persisted failures are redacted and bounded, and privacy checks cover keys and string values.
- Target-specific source data, evidence, receipts, approval packets, databases, and artifacts remain under ignored local paths.
- Public tracked configuration and documentation remain target-neutral.

## Research-loop support

- U1–U3 establish immutable source and runtime lineage without transferring weights.
- U4 defines the six-family deterministic reference interface and distinguishes configured context from proven usefulness.
- U5–U7 provide a dry-run-only reference contract, approval challenge, exact local reservation ledger,
  provider observation/billing contracts, evidence gates, and a manual runbook.
- Candidate promotion and threshold compilation are mechanically blocked; U8 is required before any paid reference execution can exist.

## Findings fixed during review

- Bound challenges to canonical config and lineage inputs.
- Replaced provider-safety booleans with hashed evidence references.
- Made reservation settlement and stale reconciliation race-safe.
- Kept submitted unknown-cost reservations audit-blocked.
- Bound scorer/runtime executor identity and metric domains in the evaluation harness.
- Bound memory and timing evidence to the evaluation lock, context, and formula method.
- Rejected malformed YAML through an auditable failed attempt and expanded privacy redaction.
- Kept numeric threshold authority unavailable rather than accepting self-authored thresholds.
- Replaced the unavailable provider-dollar-cap prerequisite with an explicitly weaker, versioned
  concurrency contract bound to the approved amendment.
- Added transactional schema migration, immutable execution-scope consumption, nullable pending
  provider cost, and durable delayed/over-cap settlement behavior.
- Versioned the amended config and preview contract explicitly, made no-submit scanning recursive and
  syntax-aware, and rejected non-string digest claims at the database boundary.
- Bound settlement to the approved billing authority, authoritative report identity, completeness
  delay, and owner-checked renewable leases.

## Remaining blockers by design

- Source, evaluation, inventory, and installed-runtime authority can be cross-verified without
  transferring weight shards.
- The resource-accounting formula remains pending human review.
- The stored provider screenshot is historical and cannot satisfy the 15-minute approval freshness
  gate. A fresh local observation receipt and regenerated packet are required.
- Billing authority can describe attribution and completeness, but no pre-submission value can prove
  actual provider cost. Unknown post-submission billing remains audit-blocked.
- No conservative memory-fit evidence, cold-path-time evidence, residual-risk approval, or U8
  approval exists.
- No model weights have been downloaded or transferred, and no remote job has been submitted.

## Evidence-remediation addendum

- Evaluation fixtures are resolved by immutable fixture ID, not by family alias.
- Windows delegates executable hashing to the isolated WSL inventory probe only when Windows cannot
  resolve the Linux symlink; the probe must first attest that the resolved executable remains under
  the expected repository root.
- Provider-managed crash rescheduling is not bounded by `retries: 0`. The approved amendment accepts
  that residual risk only through a later exact-packet approval; concurrency limits are never treated
  as proof of one billable attempt.
