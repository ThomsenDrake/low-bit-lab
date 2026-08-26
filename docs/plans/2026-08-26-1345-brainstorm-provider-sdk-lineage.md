# Provider SDK lineage — requirements brainstorm

## Problem

The provider-capability validator reproduces and validates the complete ignored receipt, including
the Modal SDK version, but its closed summary omits that version. Bootstrap request construction
then tries to read the discarded nested receipt shape and stops with `KeyError` before contact.

## Requirements

- Expose only the already-validated SDK version from the validator's closed summary.
- Build request lineage exclusively from the validator result, not a second receipt read.
- Preserve offline-only inspection and all existing provider, budget, and privacy gates.
- Stop before reservation, provider contact, or weight transfer on receipt or SDK drift.

## Success state

Merged-main preparation can include the validated SDK version without weakening receipt validation
or contacting Modal.
