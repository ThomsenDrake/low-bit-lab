# Requirements brainstorm: Modal serialized-function size gate

## Problem

The one-shot reference action built its remote image, then Modal rejected registration because the
serialized function was 259,658 bytes while the provider limit is 65,536 bytes. The control plane
used a 16 MiB local ceiling, so an impossible payload crossed the entitlement-consumption boundary.

## Requirements

- Freeze the observed provider limit at 65,536 bytes in tracked, target-neutral code.
- Serialize with the same Modal serializer used during hydration before consuming any authority or
  recording submission pending.
- Reject an oversized function locally before provider contact or reservation creation, clear
  temporary cloudpickle registration state, and leave entitlements untouched.
- Reuse the exact preflight bytes for hydration; do not serialize a different callable after the
  paid boundary.
- Clear temporary serialization policy on every failure path.
- Preserve the existing one-shot, budget, privacy, no-weight, no-retry, and configured-versus-proven
  context rules.
- Do not authorize or perform another provider action.

## Acceptance

- The current execution graph is deterministically rejected before local reservation creation and
  `_mark_submission_pending`.
- A synthetic payload at 65,536 bytes is accepted; 65,537 bytes is rejected.
- Focused and full tests, Ruff, publication/privacy scanning, and diff validation pass.
- The provider failure and DrvFS workaround are captured as reusable target-neutral learning.
