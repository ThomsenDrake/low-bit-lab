# Expose validated provider SDK lineage

## Implementation

1. Add `sdk_version` to the closed result returned after complete provider-receipt reproduction.
2. Consume that flat validated field when building the reference bootstrap request.
3. Update the exact validator-result test and verify merged-main preparation end to end.
4. Run focused/full tests, lint, publication/privacy, simplification, and independent review.

## Acceptance criteria

- The request SDK version comes from the same validated receipt snapshot.
- Receipt drift continues to fail closed.
- `prepare` remains zero-spend and provider-contact-free.
- All repository checks pass.

## Stop conditions

Stop on receipt, SDK, lineage, privacy, clean-tree, or budget drift. Do not execute U8 from this
unmerged branch.
