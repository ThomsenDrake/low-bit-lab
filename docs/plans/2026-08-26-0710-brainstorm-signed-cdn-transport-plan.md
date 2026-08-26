---
title: Signed CDN Transport Amendment - Plan
type: feat
date: 2026-08-26
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
product_contract_source: ce-brainstorm
execution: code
---

# Signed CDN Transport Amendment - Plan

## Goal Capsule

- **Objective:** The one-shot reference workflow can retrieve exact immutable public artifacts through provider-generated signed redirects without exposing redirect credentials or broadening network authority.
- **Means:** Add a mechanically bound, fail-closed exception for signed redirect targets while retaining the existing origin, lineage, privacy, deadline, hash, and budget gates.
- **Authority:** The signed-CDN amendment statement with SHA-256 `3843da6c982c09c0975d95060b685c6a0506ca6c4be9c4d05c2e18fd77da1223`, bound to merged commit `a96d5949f2826438b0f219b1dd8633c8bd42f8c1`.
- **Stop conditions:** Stop before provider submission on any authority, source, privacy, URL, DNS, peer, size, hash, timeout, or budget deviation. A submitted or ambiguous U8 attempt consumes the one-shot slot.

---

## Product Contract

### Summary

Permit provider-generated query parameters only after a query-free immutable public origin redirects to a frozen, path-scoped public delivery endpoint. Keep signed values transient and keep all evidence sanitized.

### Problem Frame

The current executor rejects every query string. Public immutable artifact origins can redirect to provider delivery endpoints that require transient signed query parameters, so the authorized reference action cannot start even though its immutable inventory and privacy gates pass.

### Requirements

**Authority and scope**

- R1. The amendment must be bound to its exact statement bytes, parent authority chain, and merged commit before U8 can be submitted.
- R2. The tracked repository must remain target-neutral, and target-specific inputs must remain ignored local artifacts.
- R3. The amendment must not add an action, retry, fallback, reservation, budget, credential, mount, volume, schedule, persistent store, destructive cleanup, training, conversion, promotion, or threshold approval.

**Transport boundary**

- R4. Every declared artifact origin must remain HTTPS-only, query-free, fragment-free, revision-pinned, host-approved, and bound to exact size and SHA-256.
- R5. A redirect may carry a query only when the destination matches a frozen host and path policy in reviewed code and is also in the request's approved host set.
- R6. Each redirect target must reject user information, fragments, nonstandard ports, unapproved hosts, non-global resolution, and connected-peer drift, with at most five redirects.
- R7. The direct transport must disable ambient proxies and must send no cookies, caller headers, credentials, or authorization material.
- R8. A signed query may exist only in transient remote request-processing memory: the received redirect location, its parsed validated representation, and the immediate outbound request target. It must never appear in logs, errors, receipts, manifests, database rows, persisted artifacts, returned evidence, or a later artifact request.

**Integrity and execution**

- R9. Downloaded bytes must match the inventory entry's declared length and SHA-256 before any artifact becomes usable.
- R10. Any redirect, identity, size, hash, timeout, privacy, or provenance deviation must stop fail-closed without retry.
- R11. The existing one-shot U8 envelope remains one A100-80GB, one concurrent container, one spawn, 2,700 seconds, USD 4.00 incremental, and USD 4.00270969 cumulative including settled smoke spend.
- R12. Configured 262,144-token context must remain distinct from empirically proven-useful context.

### Key Decisions

- **Path-scoped closed allowlist:** Permit query-bearing redirects only through exact provider delivery hosts and path prefixes reviewed in code. (session-settled: user-directed — chosen over rejecting all query strings: immutable public artifacts require provider-generated signed redirects.) Governs R5, R6, R8.
- **No redirect credential persistence:** Treat the complete query as ephemeral bearer-like material. (session-settled: user-directed — chosen over recording redirect URLs for diagnostics: persistence would violate the privacy boundary.) Governs R7, R8.
- **Existing one-shot authority remains controlling:** The amendment changes transport only. (session-settled: user-directed — chosen over issuing a new provider action: the existing U8 slot and caps remain unchanged.) Governs R1, R3, R10, R11.

### Acceptance Examples

- AE1. Covers R4, R5, R6. Given a query-free approved origin that redirects to a frozen delivery path with a query, the executor validates every hop and performs the final GET.
- AE2. Covers R5, R6, R10. Given a query-bearing origin or a query-bearing redirect to any non-frozen host or path, the executor stops before connecting to that target.
- AE3. Covers R7, R8. Given a signed redirect containing a synthetic query sentinel assembled at test runtime, neither successful nor failed serialized evidence contains the complete sentinel.
- AE4. Covers R9, R10. Given incorrect content length, excess bytes, truncated bytes, or a hash mismatch, the artifact is never passed to the loader and no retry occurs.

### Scope Boundaries

#### Deferred to Follow-Up Work

- U9 numeric threshold compilation remains proposal-only after a successful, settled reference result.

#### Outside This Product's Identity

- Generic authenticated downloads, wildcard CDN policies, caller-defined headers, reusable signed URLs, local weight transfer, and any candidate conversion or training.

### Success Criteria

- The exact approved authority is mechanically required by the paid path.
- Focused and full tests, lint, and publication/privacy scans pass.
- A public PR contains no target identity or transient signed query value.
- The first paid action cannot run until the amendment is merged and all existing gates pass from merged `main`.

### Sources

- `PLAN.md`
- `docs/solutions/best-practices/fail-closed-research-control-plane.md`
- Hugging Face Hub documentation, "Downloading models" (explicit HTTPS delivery-host inventory and redirect behavior).
- Python 3.12 `http.client` documentation (request target includes the supplied URL selector).
