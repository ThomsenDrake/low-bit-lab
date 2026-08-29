---
title: Additional U8 preflight action identity - requirements brainstorm
type: brainstorm
date: 2026-08-29
artifact_contract: ce-requirements/v1
---

# Requirements

- Preserve the distinction between an unreserved additional-action capability and a consumed
  additional authority generation.
- Select the deterministic request reproduction path from validated immutable request bytes, not
  from reservation-time authority fields that cannot exist before reservation.
- Reject unknown request actions before any mutable budget or provider boundary.
- Preserve the existing hybrid and partial authority-generation rejection.
- Add regression coverage for both the original and additional request actions with no provider
  contact.
- Do not retry the consumed one-shot provider action or create any new paid entitlement.

