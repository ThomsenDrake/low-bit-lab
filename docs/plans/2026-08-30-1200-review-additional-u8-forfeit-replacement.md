---
title: Additional U8 pre-provider forfeit and replacement review
type: review
date: 2026-08-30
---

# Verdict

The amendment is eligible to ship once the final full-suite, publication, and CI checks pass.
No Modal action is eligible from the feature branch. The one replacement remains gated on the
exact merged commit, WSL parity, a clean tree, authenticated provider environment, and all
unchanged privacy, provenance, resource, watchdog, and budget checks.

# Review lenses

## Reproducibility and lineage

- The failed request, corrected zero-spend preflight, exact human statement, amendment authority,
  and zero-spend forfeit receipt are immutable parents.
- The post-merge paid request must differ because reviewed-commit and control-plane hashes are
  request inputs. Its exact request and selected WSL parity hashes are irreversibly captured when
  the sole child entitlement is claimed, then rechecked at reservation and provider contact.
- Database migration fingerprints the complete v15 source shape before adding the empty v16
  activation slot. Unknown authority-bearing shapes stop without DDL.

## Modal-credit safety and failure containment

- Activation creates no reservation and contacts no provider.
- Claim is one-way. A released reservation does not restore the child entitlement, and provider
  contact atomically consumes both parent grant and child entitlement.
- The resource envelope remains one A100-80GB, one container, one spawn, 2,700 seconds, no retry,
  USD 4.00 incremental, and USD 4.00564445 cumulative.
- Provider-side rescheduling and billing overage cannot be eliminated by local controls; ambiguous
  outcomes remain audit-blocked and cannot authorize another action.

## Local RTX 5080 and WSL compatibility

- Paid execution remains WSL/Linux-only and preserves the existing local hardware/runtime gates.
- No driver, OS, BIOS, or global configuration change is introduced.
- The durable Windows checkout receives hash-verified request, parity, database, and terminal
  evidence before WSL ownership can be archived.

## Security and private-data handling

- Tracked artifacts remain target-neutral; exact authority and generated evidence remain ignored.
- No secret, mount, volume, persistence, schedule, local weight transfer, or private payload path
  is added.
- Immutable authority columns, request bytes, parity evidence, workspace identity, and billing
  lineage are checked fail-closed at their mutable boundaries.

## Research-loop support

- Status exposes the historical pre-provider forfeit independently from the child entitlement.
- Configured context remains 262,144 tokens. Proven-useful context remains unset until successful
  evaluation evidence establishes it.
- U9 remains proposal-only; conversion, training, promotion, and numeric-threshold approval remain
  unauthorized.

# Findings resolved

- Removed a generic parent-grant reservation bypass.
- Removed destructive pre-fingerprint normalization of an unexpected authority table.
- Bound the claimed paid request and selected WSL parity at the provider boundary.
- Required downstream provider transitions to observe both parent and child consumption.
- Made pre-provider WSL return preserve the exact claimed request and parity generation.
- Added an explicit historical-forfeit status object and focused regression coverage.

# Residual risks

- Modal limits are local rather than provider-enforced dollar or execution caps.
- A durable ignored request-path collision stops return fail-closed and requires evidence-preserving
  diagnosis; it never overwrites existing bytes.
- The paid path still requires final real WSL and provider evidence after merge.
