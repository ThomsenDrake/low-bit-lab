# Bind persisted and canonical evaluation-lock identities

## Implementation

1. Read the evaluation-lock file once during config refresh; semantically validate that snapshot and
   compare its raw SHA-256 with the approved config.
2. Extend the downstream authority preview to verify the same raw bytes while retaining the semantic
   digest for inventory provenance.
3. Build the closed Modal capability from canonical bytes derived from the validated local file.
4. At fresh paid preflight, require the current raw file hash to match config and its canonical form
   to match the capability and request lineage.
5. Add regression tests for pretty/noncanonical local JSON, canonical transport bytes, raw drift,
   canonical drift, and unchanged 262,144 configuration.
6. Run focused/full tests, lint, publication/privacy and documentation checks; simplify and perform
   independent report-only review before merging.

## Acceptance criteria

- Persisted-file and canonical semantic digests remain explicit and cannot substitute for each other.
- Every comparison uses one read snapshot.
- `prepare` passes only after merged-main regeneration and leaves the results DB untouched.
- No Modal SDK execution primitive, reservation, body transfer, or weight transfer occurs in prepare.
- Full tests, Ruff, diff check, publication/privacy scan, and documentation validation pass.

## Stop conditions

Stop on evaluation schema, fixture, raw-byte, canonical-byte, configured-context, lineage, privacy,
budget, or clean-tree drift. Do not execute U8 until the merged-main packet reproduces exactly.
