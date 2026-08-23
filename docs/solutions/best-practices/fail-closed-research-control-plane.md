---
title: Fail-closed boundaries for a research control plane
date: 2026-08-21
last_updated: 2026-08-23
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

Use compare-and-set state changes inside `BEGIN IMMEDIATE` transactions for reservation settlement and stale-run reconciliation. Reserve the exact worst-case cap, consume approval and reserve cost atomically, and move unknown submitted work to an audit-blocked state rather than releasing its reservation. Avoid SQLite `executescript` inside an explicit migration transaction because its implicit commit behavior can defeat the intended atomic boundary.

Evidence formulas must be versioned and hashed. Memory and cold-path timing evidence should name the method digest and bind the exact evaluation context; otherwise a valid-looking report can be replayed against a larger context or a different accounting method. Promotion-threshold compilation remains a separate authority step and should be mechanically unavailable until implemented and approved.

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
- `src/lowbit_lab/runtime.py` records dirty state plus a deterministic control-plane digest.
- `src/lowbit_lab/activation.py` binds decision artifacts and reruns all bounded gates.
- `src/lowbit_lab/publication.py` scans Git paths and contents before public publication.
- `src/lowbit_lab/reference_gates.py` verifies method-bound memory and timing evidence without enabling submission.

## Related

- `PLAN.md`
- `reports/phase0-review.md`
