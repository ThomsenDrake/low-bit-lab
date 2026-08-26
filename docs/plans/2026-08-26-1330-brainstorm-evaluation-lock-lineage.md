# Evaluation-lock lineage — requirements brainstorm

## Problem

The approved config and evidence bind the exact persisted evaluation-lock bytes, while the remote
execution contract must carry canonical evaluation-lock bytes. Merged-main preparation compared the
semantic canonical digest to the raw persisted digest, and the capability attempted to transmit the
noncanonical local file. Both identities are valid but serve different boundaries.

## Requirements

- Verify the local evaluation lock semantically with its complete fixture set.
- Bind the approved config to the exact persisted evaluation-lock bytes from the same read snapshot.
- Bind the bootstrap request and remote contract to canonical evaluation-lock bytes.
- Reproduce canonical bytes from the verified local snapshot; never accept caller-supplied lock bytes.
- Recheck both raw and canonical identities immediately before the paid boundary.
- Preserve the configured 262,144-token envelope and keep proven usefulness unknown.
- Stop before reservation or provider contact on either identity mismatch.

## Success state

Merged-main `prepare` accepts the approved raw file, emits a request bound to the verified canonical
lock, and performs no provider contact, reservation, or weight transfer.
