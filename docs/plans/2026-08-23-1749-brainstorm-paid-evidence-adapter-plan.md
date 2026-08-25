---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
product_contract_source: ce-brainstorm
title: Paid-evidence adapter boundary
date: 2026-08-23
status: approved-scope
---

# Goal Capsule

Prepare a target-neutral, disabled-by-default Modal adapter and exact paid-action contract for one
no-weight provider smoke test so the lab can stop at a mechanically enforced execution boundary.
This change may make that paid command representable, but it must not execute it, reserve credits,
transfer weights, or authorize U8.

# Product Contract

## Requirements

- R1: Public defaults remain target-unconfigured, submission-disabled, and USD 0.
- R2: A provider execution primitive may exist only in one audited adapter module and may be
  reached only through a closed CLI gate.
- R3: Planning and verification are read-only. Preparing an approval packet may write only ignored
  local evidence and SQLite audit state with USD 0 requested, reserved, and actual cost.
- R4: The first paid-action contract binds the reviewed commit, control-plane digest, canonical
  config, challenge, reference execution scope, provider environment, resource envelope, formula
  receipt, total ledger, per-action cap, and a short expiry.
- R5: Total ledger ceiling and current-action cap remain separate. Public code cannot infer a
  positive action cap from the total ledger.
- R6: Execution requires a fresh ignored human approval matching exact wording, atomic reservation
  of the full action cap, and a one-shot capability consumed in the same transaction.
- R7: Direct adapter imports cannot bypass the capability check. Tests must replace the provider
  call before the boundary and must never contact Modal.
- R8: Unknown submission state is audit-blocked and retains its reservation. A never-submitted
  failure may release only under the existing compare-and-set rules.
- R9: No retries, schedules, secrets, volumes, mounts, destructive cleanup, or implicit uploads.
- R10: U8, weight transfer, model loading, kernel claims, and promotion remain unauthorized.
- R10a: The remote smoke function may return only bounded provider/runtime/GPU observations. It
  cannot access model identifiers, model files, repositories, tokens, or user payloads.
- R11: The generated handoff reports the exact command, scope hash, maximum cost, and approval
  wording, while still reporting `paid_action_ready:false` until the approval artifact exists.
- R12: 262,144 configured tokens remain distinct from useful 262,144-token evidence.

## Success criteria

- The adapter cannot be invoked by dry-run, plan, verify, import, or tests.
- Focused tests prove approval mismatch, expiry, replay, cap drift, config drift, direct-call bypass,
  missing reservation, and unknown provider state all fail closed.
- Full tests, lint, publication scan, and a report-only five-lens review pass.
- The final local packet names an exact command but the command is not run.
- The command authorizes only the no-weight provider smoke test; it cannot clear model memory-fit,
  cold-load, quality, throughput, soak, kernel, or useful-context gates.
- Database accounting remains requested USD 0, reserved USD 0, actual USD 0.

## Out of scope

- Modal execution or credit reservation.
- Weight download, upload, mount, or transfer.
- Creating provider credentials or secrets.
- U8 authorization or execution.
- Changing promotion thresholds or claiming useful 256K context.

## Human-attested scope

The user replied `Approved` immediately after the zero-spend handoff identified the next action as
a controlling amendment for a disabled provider adapter and paid-evidence action contract. That
attestation authorizes this bounded preparation only; it is not the later execution approval.
