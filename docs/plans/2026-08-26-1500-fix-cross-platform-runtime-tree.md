# Hash long runtime paths consistently

## Implementation

1. Add a narrow Windows extended-length path adapter for filesystem inspection and content reads.
2. Keep logical repository-relative path derivation separate from the I/O path.
3. Add pure formatting coverage plus a Windows integration test above the legacy path limit.
4. Run focused/full tests, lint, publication/privacy, simplification, and independent review.
5. Merge, regenerate the ignored receipt through the reviewed evidence CLI, then reproduce it from
   Windows and WSL before any paid action.

## Acceptance criteria

- Long regular files contribute to file count, byte total, and tree digest on Windows.
- Symlinks and path escapes remain fail-closed.
- Existing Linux behavior and serialized receipt schema are unchanged.
- All checks pass and preparation remains zero-spend.

## Stop conditions

Stop on incomplete enumeration, symlink ambiguity, path escape, receipt mismatch, clean-tree drift,
privacy failure, or any provider/budget state change.
