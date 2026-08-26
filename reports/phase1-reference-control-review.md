# Phase 1 reference control review

Date: 2026-08-25

Scope: bootstrap authority and the staged U8 reference control plane through U21. U8 was not
submitted because the immutable public source transport fails the approved redirect policy.

## Review outcomes

- Reproducibility and lineage: the adapter now rejects caller-selected database paths, provider
  environments, execution identities, evaluation locks, request bytes, and image-lock bytes. It
  derives them from freshly reproduced config, provider-capability, and repository evidence.
- Modal-credit safety and containment: one slot is consumed before provider import; one spawn is
  statically enforced; provider image/app identity precedes spawn; call identity follows it; all
  post-boundary ambiguity retains the reservation. Audit-block persistence failure is no longer
  swallowed. The cumulative cap remains USD 4.00270969, including settled smoke cost USD
  0.00270969 and at most USD 4.00 incremental U8 authority.
- Local RTX 5080 compatibility: local control-plane tests pass in the isolated environment, but no
  local full-weight fit or kernel claim is made. The provider envelope remains one A100-80GB, one
  container, 2,700 seconds maximum, zero configured/application retries, and no fallback.
- Security and private data: source inclusion, secrets, mounts, volumes, schedules, user payloads,
  and local weight transfer are structurally absent. The serialized function bytes are hash-bound,
  and serialization policy is cleared on all exits. Target-specific artifacts remain ignored-local.
- Research loop support: the six locked evaluation families and full context ladder feed one staged
  receipt. The local validator binds receipt-to-manifest bytes and persists sanitized evidence
  before settlement pending. Configured context is 262,144 tokens; proven-useful context remains
  unset until a successful empirical run.

## Verification

- Full tests: 509 passed, 2 skipped.
- Ruff: passed.
- Focused paid-boundary tests: 118 passed.
- Modal SDK inspection and fake-provider flow: passed without provider contact.
- U8 actual spend: USD 0. Total settled lab Modal spend remains USD 0.00270969.

## Terminal blocker

A metadata-only HEAD request read zero body bytes and observed an approved query-free immutable
source URL redirecting to a public CDN URL with a query string. The U19 policy rejects query and
fragment components at every redirect boundary. U8 therefore stops before reservation consumption,
provider import, or weight transfer. Proceed only with a compliant immutable query-free origin or a
later human-approved transport amendment; do not weaken the policy locally.
