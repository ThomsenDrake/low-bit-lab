# Provider environment lineage — requirements brainstorm

## Problem

The provider-capability validator reproduces and validates the complete ignored receipt, including
the provider environment identity, but its closed summary omits that identity. Fresh U8 preflight
then tries to read the discarded nested receipt shape and stops before reservation or provider
contact.

## Requirements

- Expose only the already-validated provider environment from the validator's closed summary.
- Make both capability construction and fresh preflight consume that flat validated field.
- Do not let either consumer reread an unvalidated nested billing value as authority.
- Preserve every existing lineage, privacy, topology, runtime, budget, and one-shot gate.
- Keep preparation and regression verification local, zero-spend, and weight-free.
- Record a regression test for the exact closed-summary contract that failed.
- Refresh the metadata-only transport observation after slow deterministic preflight and immediately
  before reservation, so its 15-minute freshness bound cannot expire during runtime hashing.

## Success state

Fresh U8 preflight derives the provider environment from the reproduced receipt, while receipt drift
continues to stop before reservation or Modal contact.
