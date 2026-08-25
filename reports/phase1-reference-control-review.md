# Phase 1 reference control review

Date: 2026-08-25

Scope: autonomous authority, cumulative budget, conservative evidence generation, and local Modal reference preview through U12. The paid U8 adapter and execution were not reached because the evidence gates remain unproven.

## Review outcomes

- Reproducibility and lineage: fixed raw authority-byte drift, duplicate JSON keys, stale direct-database authority acceptance, unbound architecture metadata, and semantic-only evidence reproduction. Method and evidence artifacts now reproduce from exact hashed inputs.
- Modal-credit safety and containment: fixed the one-shot boundary so `reserved -> submission_pending` and slot consumption occur atomically. Expired provider-contact state becomes `audit_blocked`; schema migration backfills historical contact and fails closed on ambiguity. The ledger preserves settled smoke cost USD 0.00270969 and permits at most one USD 4.00 reference reservation.
- Local RTX compatibility: no local full-weight claim was added. Local preview remains model-free and reports hardware metadata only. The A100 reference envelope uses one GPU, a 2,700-second timeout, zero retries, and 512 GiB ephemeral disk.
- Security and private data: authority read errors are sanitized, paths are repository-confined, publication scanning remains clean, and target-specific evidence stays ignored-local.
- Research loop support: configured 262,144-token context remains distinct from proven usefulness. Hybrid memory accounting includes full-attention KV plus linear-attention recurrent and convolution state, but lacks authorized runtime-overhead, allocator-reserve, and usable-memory bounds. Cold-path stage bounds and a resolved image identity are also absent, so U8 remains unreachable.

## Verification

- Full tests: 410 passed, 2 skipped.
- Ruff: passed.
- Publication/privacy scan: 321 tracked sources, no findings.
- Local Modal dry run: completed with actual cost USD 0 and no weight transfer; submission remained false.

## Terminal blocker

The known batch-one 262,144-token memory floor is 75,163,362,784 bytes before runtime overhead and allocator reserve. No independently authorized finite receipts exist for the remaining memory or cold-path terms, and no resolved provider image identity exists. The control plane therefore emits `proven: false` and stops before provider import, reservation consumption, or U8 execution.
