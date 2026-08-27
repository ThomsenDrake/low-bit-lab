---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Workspace-scope reconciliation requirements
date: 2026-08-27
---

# Workspace-scope reconciliation requirements

## Problem

The audit-blocked reference attempt preserves an opaque workspace scope selected before provider
authentication. The authenticated provider-local profile proves a different workspace identity.
The control plane correctly refuses to equate them, but the approved recovery cannot proceed even
though the human has authorized exactly one immutable mapping between those two existing identities.

## Requirements

- R1. Preserve the original configured workspace scope and original experiment config byte-for-byte.
- R2. Record the approved original-to-authenticated mapping as a separate immutable ignored authority.
- R3. Bind the authority to the exact human statement, merged implementation base, original
  reservation, original execution scope, billing authority, and the single replacement action.
- R4. Represent the original configured scope and authenticated workspace identity as distinct fields
  in every binding, authentication receipt, billing receipt, settlement row, and replacement gate.
- R5. Accept exactly the approved mapping. Unknown, reversed, missing, future, or additional mappings
  must fail closed.
- R6. Revalidate the official provider endpoint, empty override headers, isolated provider-local
  profile, and authenticated workspace identity immediately before billing capture and entitlement
  consumption.
- R7. The exact unfiltered complete-window USD 0 billing requirement remains unchanged. Nonzero,
  incomplete, mismatched, or ambiguous evidence remains audit-blocked.
- R8. Settlement must atomically bind the mapping, exact report bytes, original reservation and scope,
  billing authority, authenticated identity, and one replacement entitlement.
- R9. The original U8 slot remains consumed. Exactly one replacement exists and has no reset, retry,
  fallback GPU, or second-replacement path.
- R10. The existing one-GPU, one-container, one-spawn, 2,700-second, zero-retry, USD 4.00 incremental,
  and USD 4.00270969 cumulative limits remain unchanged.
- R11. Public tracked files remain target-neutral and contain no workspace display value, credential,
  private path, provider report, or other private data. Exact mapping values remain ignored local
  evidence; tracked code may freeze only their content digests.
- R12. Configured 262,144-token context remains distinct from empirically proven-useful context.
- R13. No billing settlement, reservation, or provider execution may occur until reviewed code is
  merged and all deterministic gates reproduce from clean main.

## Non-goals

- Rewriting historical config or declaring the two scope digests equivalent.
- General workspace aliases or a reusable mapping registry.
- Additional provider actions, retries, conversion, training, promotion, U9 execution, or threshold
  approval.

## Acceptance

- Exact mapping validation succeeds only for the approved ignored authority and authenticated profile.
- Historical configuration and original slot remain unchanged after settlement.
- Schema migration preserves every existing ledger cell and fails closed on unknown shapes.
- Focused and full tests, lint, diff validation, publication/privacy scan, and independent review pass.
- Live evidence remains untouched until the implementation PR is merged.
