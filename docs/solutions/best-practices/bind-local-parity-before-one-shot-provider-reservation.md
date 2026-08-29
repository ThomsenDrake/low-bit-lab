---
title: Bind local parity before a one-shot provider reservation
date: 2026-08-29
category: best-practices
module: provider-control-plane
problem_type: architecture_pattern
component: infrastructure
severity: high
tags: [wsl, serialization, lineage, budget-safety, one-shot-authority]
---

# Bind local parity before a one-shot provider reservation

## Context

A provider callable may be locally serializable yet still differ between preparations, checkout
locations, or SDK hydration. Reserving money before proving the exact WSL state and payload turns a
deterministic local defect into budget ambiguity.

## Guidance

Require the paid entrypoint to name both the ext4 execution root and the durable checkout. Prepare
the exact provider graph twice before reservation and require identical serialized bytes. Bind that
payload to an immutable parity receipt covering the reviewed commit, tracked tree, database,
authority, request, runtime, evaluation, provenance, authenticated workspace digest, and pinned SDK.

Carry the parity-receipt digest, one-shot authority digest, and freshly authenticated workspace
digest in the reservation-specific capability. Revalidate the parity bytes against the exact graph
again inside the sole provider adapter. A deterministic failure may release only a still-reserved
action; after the durable provider-boundary transition, uncertainty remains audit-blocked and the
grant is never restored.

A normal submitted provider action may have both an app identity and a call identity. Preserve both
in the ledger, then attribute billing only when all matching rows name exactly one of those durable
identities. Prefer neither identity by assumption: select the one the authoritative rows prove and
reject mixed or unrelated identities.

When an ext4 WSL checkout owns paid state, returning only its SQLite database is incomplete. Before
archiving the ownership marker, copy the content-addressed parity generation and the closed,
hash-verified request, execution, manifest, authentication, billing, and settlement evidence needed
by downstream audit and proposal compilation. A collision or missing artifact leaves WSL ownership
active; the mirror remains recovery evidence and is not destructively cleaned.

Keep post-baseline governance separate. Successful settlement may unlock a proposal compiler, but
the proposal must not authorize its own numeric thresholds or candidate execution. Record configured
context independently from empirically proven-useful context.

## Applicability

Use this pattern for any single-use, locally budgeted provider action whose executable graph is
serialized before remote hydration and whose durable state moves between operating environments.
