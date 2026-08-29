---
title: Fix additional U8 preflight action reproduction
type: fix
date: 2026-08-29
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
---

# Goal

Make the contact-free preflight reproduce the request action named by validated request bytes while
leaving authority consumption and provider submission semantics unchanged.

# Root cause

`validate_reference_preflight` inferred the additional action from fully consumed additional
authority fields. The first pre-reservation validation cannot contain those fields, so it rebuilt an
additional request as the original U8 request and failed provenance reproduction.

# Work

1. Add a regression that exercises original and additional validated request actions while the
   capability has no reservation-time authority fields.
2. Parse and validate request bytes before selecting the reproduction and preview paths.
3. Reject any action outside the two closed request actions.
4. Run focused and full tests, Ruff, whitespace validation, and publication/privacy scanning.
5. Simplify, independently review, record the durable phase-ordering lesson, and ship through a
   public PR with green CI.

# Acceptance

- Both request actions select their matching reproduction and preview paths.
- Unknown actions fail before reservation or provider contact.
- Hybrid and partial authority generations remain rejected.
- Full verification and independent review pass.
- No remote execution, reservation, weights, or additional spend occurs.

# Stop conditions

Stop on authority ambiguity, credential exposure, privacy drift, budget mutation, provider
execution, weight activity, or any inability to preserve the consumed one-shot state.

