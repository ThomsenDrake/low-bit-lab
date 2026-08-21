---
title: Fail-closed boundaries for a research control plane
date: 2026-08-21
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

## Related

- `PLAN.md`
- `reports/phase0-review.md`
