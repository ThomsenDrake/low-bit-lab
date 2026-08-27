---
title: Preflight provider serialization before one-shot consumption
date: 2026-08-27
category: best-practices
module: provider-control-plane
problem_type: best_practice
component: infrastructure
severity: high
applies_when:
  - "A remote provider serializes a function only after app or image creation"
  - "An action has one-shot authority or a strict local cost reservation"
tags: [modal, serialization, budget-safety, one-shot-authority, wsl, drvfs]
---

# Preflight provider serialization before one-shot consumption

## Context

Provider SDKs can defer function-size validation until app hydration. By then an image may already be
built and one-shot authority may already be consumed, even though no function task can launch. A
large by-value Python closure is especially vulnerable because cloudpickle includes referenced
modules and globals that are not obvious from the entrypoint's source.

Large runtime trees introduce a separate local hazard on Windows: byte-for-byte hashing through
WSL's `/mnt/c` DrvFS path can remain blocked in `p9_client_rpc` for tens of minutes even when the
same tree hashes quickly through native Windows APIs.

## Guidance

Use the provider's pinned production serializer locally and enforce the provider's exact byte limit
before creating the budget reservation, submission-pending, entitlement consumption, app creation,
or image construction. Bind the accepted bytes to the actual SDK hydration object; merely hashing
preflight bytes while hydration serializes again does not establish lineage. Clear temporary
by-value module registration immediately after freezing the bytes and on every rejection. Audit the
failure with a received-to-failed attempt that has no run link; do not create or lock a budget
reservation merely to record the rejection.

Keep the raw serializer separately testable. This permits round-trip and byte-size regression tests
even while the production wrapper intentionally rejects the current graph. Test the exact boundary:
the maximum byte count passes and one byte more fails.

When a complete runtime receipt must be reproduced under WSL, prefer an isolated ext4-backed
checkout over `/mnt/c`. Clone the exact public commit, copy only ignored local authority and pinned
runtime artifacts, verify `HEAD == origin/main`, reproduce all hashes and ledger state, and retain the
Windows checkout as durable state. Do not use the mirror to weaken path, runtime, privacy, or clean-
tree checks.

## Applicability

This pattern prevents deterministic provider rejections from consuming scarce authority. It does
not make an oversized execution graph deployable; the graph must still be reduced under the frozen
limit before a future provider action can be authorized.
