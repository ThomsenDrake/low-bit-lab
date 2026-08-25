---
title: Fail-closed boundaries for a research control plane
date: 2026-08-21
last_updated: 2026-08-24
category: best-practices
module: experiment-control-plane
problem_type: best_practice
component: infrastructure
severity: high
applies_when:
  - "A local research agent can later authorize paid or destructive work"
  - "Experiment results must remain reproducible across uncommitted runs"
tags: [budget-safety, experiment-lineage, immutable-config, sqlite, local-first]
---

# Fail-closed boundaries for a research control plane

## Context

A prose budget and a config hash are not sufficient authority controls. A policy file can drift while remaining syntactically valid, an experiment identifier can be reused for different canonical bytes, and failures before run creation can disappear from the system of record.

## Guidance

Encode frozen values independently in code, then require the machine-readable policy to match them exactly. Bind each immutable experiment ID to one canonical config digest in SQLite; reruns may reuse only the same digest. Create an attempt audit before fallible validation and link it to a run only after identity, source hashes, privacy, and budget gates pass.

Runtime lineage must describe the executing tree even before the first commit. Record both dirty state and a deterministic digest over the control-plane sources, lockfile, policy, and entrypoints. Keep configured capabilities separate from demonstrated results: a context length, GPU name, or package install is not proof of useful long-context operation.

Bind every decision-bearing local artifact into activation authority, including the runtime
selection input. A retry must not reuse completed evidence unless the implementation binds the
full preceding evidence chain. Until that chain exists, rerunning all bounded local gates is the
safer and simpler contract.

Apply the same closed URL policy to the lock, every redirect, and the final response. Reject
credentials, query strings, fragments, and non-default ports. Scan Git path names as well as blob
and commit content before publication, because a private identifier can leak through either
surface. Persist only bounded, sanitized HTTP facts; raw server-controlled headers do not belong
in durable evidence.

Framework readiness should verify the exact Python and direct framework versions from the runtime
lock. It still does not prove model inference or kernel compatibility. A scheduled controller needs
an additional installed-environment receipt because version agreement alone does not attest every
installed byte.

Paid execution needs a second boundary beyond authorization: atomically reserve worst-case cost from resource count and timeout before submission, settle actual cost at terminal state, and block overlap. A plan-only wrapper should contain no provider SDK or submit call until that transaction exists.

Treat digest-shaped values as claims, not verified lineage. Recompute approval challenges from the canonical config, verify every authority path against its declared hash, and cross-bind evidence to the inventory, runtime receipt, evaluation lock, reviewed commit, and resource envelope. Provider-safety flags must point to hashed evidence; a self-asserted boolean is not an independent gate.

A digest proves that exact bytes were used; it does not prove who authored or approved them. Treat a human statement as attested input, freeze the accepted statement digest independently in code, and keep the accepted action classes closed. Regenerating a plan or readiness packet under that standing authority must never broaden the allowlist.

Keep the total project ledger distinct from the cap for the next action. The ledger answers how much the lab may ever spend; the action cap answers whether this specific invocation may spend anything. A zero-spend controller must require the action cap to remain zero even when an ignored local ledger has a positive total ceiling.

Readiness evidence is not paid authority. A handoff may report that only paid-boundary evidence remains, but it must leave the execution command, paid action cap, and approval wording unavailable until an exact provider action contract exists. Otherwise generated prose can become a self-authorizing execution surface.

For immutable evidence, validate the exact bytes after persistence rather than trusting the object held in memory before the write. Hash the complete decision-bearing packet, including state, blockers, lineage, authority, budget, and safety fields. Canonical semantic equality and raw-byte digest equality are separate checks and both matter.

Use compare-and-set state changes inside `BEGIN IMMEDIATE` transactions for reservation settlement and stale-run reconciliation. Reserve the exact worst-case cap, consume approval and reserve cost atomically, and move unknown submitted work to an audit-blocked state rather than releasing its reservation. Avoid SQLite `executescript` inside an explicit migration transaction because its implicit commit behavior can defeat the intended atomic boundary.

Apply the same transaction rule to controller leases. Reconcile expired active cycles inside the acquisition transaction, then create the next generation under a uniqueness fence. Read-only status and verification commands must open SQLite in read-only mode so missing evidence cannot be created as a side effect.

Evidence formulas must be versioned and hashed. Memory and cold-path timing evidence should name the method digest and bind the exact evaluation context; otherwise a valid-looking report can be replayed against a larger context or a different accounting method. Promotion-threshold compilation remains a separate authority step and should be mechanically unavailable until implemented and approved.

Formula approval must be bound at every consumer, including direct preview, challenge derivation, persisted config gates, and execution-scope hashing. Enforcing it only in a higher-level controller leaves lower-level entrypoints able to construct a different decision surface.

Cross-platform receipts must verify in the environment that owns the executable. Windows cannot
reliably resolve a Linux virtual-environment symlink stored on a mounted filesystem. In that case,
run an isolated WSL probe against the exact repository-relative interpreter, require the probe to
prove its resolved executable stays below the expected repository root, and use the digest computed
by that probe. Do not weaken the check to a path-string comparison or silently skip executable
lineage.

Provider retry configuration and provider crash recovery are separate controls. A declared retry
count of zero does not bound provider-managed container rescheduling. Prefer a provider-enforced
dollar cap when one exists. When it does not, treat observed one-container/one-GPU concurrency as a
strictly weaker control: bind it to a fresh receipt and a separately approved residual-risk
amendment, never describe it as a cumulative cost cap, and keep unknown billing audit-blocked.

When a human deliberately overrides observation freshness, encode that decision as a separate
closed artifact rather than mutating the original receipt. Bind the stale receipt, screenshot,
environment identities, every controlling plan, explicit drift-risk acceptance, and the human
statement digest. Emit a distinct authority mode so downstream reports cannot confuse accepted
human trust with fresh mechanical observation. The override should clear only the gate it names.
Freeze the approved statement digest independently in code; comparing two caller-controlled files
to each other does not establish human authority.

Make the reference execution scope a canonical digest over source revision, weight inventory,
evaluation lock, formula authority, resource envelope, and every controlling plan. A released
never-submitted reservation may retry only with a fresh observation, packet, challenge, and
approval. Any submitted-or-later state consumes the scope permanently. Settlement must match the
challenge-bound billing authority and report identity, wait for the declared completeness delay,
and preserve authoritative over-limit cost as a durable terminal failure.

A provider-only smoke probe should not reuse a model/reference reservation schema whose scope
requires weight inventory and evaluation lineage. Give the probe a separate target-neutral action
contract and reservation state, but calculate committed cost across both ledgers in the same
transaction. Bind the exact resource envelope, environment, reviewed commit, control-plane hash,
local ledger bytes, approval expiry, and fixed human wording. The adapter should accept one
capability object and no model, path, URL, token, repository, or user payload.

Persist an explicit `submission_pending` state before importing the provider SDK. Immediately after
`spawn`, store the real provider call identity before waiting for results. A failure before that
identity is known and a failure after it is known are both audit-blocking; neither may release or
replay the scope. This separates provider contact from provider completion without inventing a job
identity during an ambiguous start.

Arm every mutable local authority before hashing the paid-action contract. Flipping an authorization
flag after approval changes the ledger digest and invalidates the scope. Treat timezone spellings as
semantic instants at validation boundaries: `Z` and `+00:00` are equivalent UTC representations even
though their strings differ. Exercise the actual CLI failure path before paid use; a fail-closed
validator is incomplete if its error reporter raises a second exception and hides the gate result.

Bind provider resource defaults as carefully as explicit limits. Modal's default ephemeral disk is
512 GiB and its API rejects smaller explicit requests, so a locally plausible 90 GiB request can
create a stopped app record without launching a task. Encode the provider minimum in the hashed
resource envelope, test it locally, and treat any app created before a call identity is persisted as
audit-blocked until delayed billing evidence resolves the attempt. A stopped app with zero tasks and
zero containers is strong execution evidence, but it is not a substitute for the declared billing
authority when settling reserved cost.

Standing paid authority should be a campaign capability, not an invitation to skip per-action
lineage. Freeze the exact human grant digest and a closed campaign envelope in code, then bind that
authority into short-lived action contracts. Account active or ambiguous attempts at requested
cost, settled or failed attempts at authoritative actual cost, and permit reuse only when the full
next safe reservation fits confirmed remaining lifetime balance. Validate the approved campaign
plan's exact bytes during both contract generation and execution; a constant that merely repeats a
historical digest does not prove the plan is still present. For prelaunch provider rejection, bind a
stopped app identity and zero task/container evidence separately; do not relabel an app ID as a
function-call ID merely to satisfy settlement plumbing.

## Why This Matters

These invariants make silent policy drift, config mutation, preflight failure loss, and concurrent overspend observable or impossible. They also let later agents resume from durable state without inheriting hidden judgment from an earlier session.

## When to Apply

- Before enabling any cloud submission path.
- When experiment configs or results become shared durable state.
- When a scheduled controller can act without a human in the loop.

## Examples

- `src/lowbit_lab/constants.py` freezes zero-spend defaults independently of editable policy files.
- `src/lowbit_lab/db.py` binds experiment IDs to config digests and stores pre-validation attempts.
- `src/lowbit_lab/db.py` atomically consumes approval challenges, reserves exact worst-case cost, and settles reservations with compare-and-set transitions.
- `src/lowbit_lab/reference_contract.py` derives the immutable one-shot reference execution scope.
- `src/lowbit_lab/controller.py` enforces the closed zero-spend action allowlist and immutable cycle fencing.
- `src/lowbit_lab/handoff.py` emits a complete readiness packet without synthesizing paid authority.
- `src/lowbit_lab/runtime.py` records dirty state plus a deterministic control-plane digest.
- `src/lowbit_lab/activation.py` binds decision artifacts and reruns all bounded gates.
- `src/lowbit_lab/publication.py` scans Git paths and contents before public publication.
- `src/lowbit_lab/reference_gates.py` verifies method-bound memory and timing evidence without enabling submission.
- `src/lowbit_lab/provider_smoke.py` binds one ignored campaign authority, the approved plan bytes,
  and the exact local cap before the audited adapter can be imported.
- `src/lowbit_lab/modal_adapter.py` persists provider-call identity immediately after spawn and
  accepts no model input or remote payload.

## Related

- `PLAN.md`
- `reports/phase0-review.md`
