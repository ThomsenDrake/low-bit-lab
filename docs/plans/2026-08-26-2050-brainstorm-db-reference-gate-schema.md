# Database reference-gate schema — requirements brainstorm

## Problem

The validated schema-v5 reference config gained reproducibility bindings for memory methods,
cold-path methods, architecture metadata, image-build identity, and a bound receipt root. The
database's independent challenge parser still requires the older seven-field gate object, so the
atomic reservation stops locally with `reference config schema is invalid`.

## Requirements

- Make the database challenge parser require the exact current closed gate-field set.
- Preserve canonical config identity, challenge derivation, execution-scope hashing, privacy scans,
  budget caps, and atomic rollback.
- Reject missing, extra, or renamed reproducibility bindings.
- Keep nullability semantics under the validated config parser; do not invent empirical evidence.
- Add database-level regression coverage using the current full schema.
- Do not reserve the authoritative ledger, contact Modal, transfer weights, or change thresholds.

## Success state

The same canonical schema-v5 config accepted by the reference-config validator is accepted by the
database challenge parser, and schema drift still fails before any authoritative reservation.
