---
title: Fail-closed boundaries for a research control plane
date: 2026-08-21
last_updated: 2026-08-21
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

## Why This Matters

These invariants make silent policy drift, config mutation, preflight failure loss, and concurrent overspend observable or impossible. They also let later agents resume from durable state without inheriting hidden judgment from an earlier session.

## When to Apply

- Before enabling any cloud submission path.
- When experiment configs or results become shared durable state.
- When a scheduled controller can act without a human in the loop.

## Examples

- `src/lowbit_lab/constants.py` freezes zero-spend defaults independently of editable policy files.
- `src/lowbit_lab/db.py` binds experiment IDs to config digests and stores pre-validation attempts.
- `src/lowbit_lab/runtime.py` records dirty state plus a deterministic control-plane digest.
- `src/lowbit_lab/activation.py` binds decision artifacts and reruns all bounded gates.
- `src/lowbit_lab/publication.py` scans Git paths and contents before public publication.

## Related

- `PLAN.md`
- `reports/phase0-review.md`
