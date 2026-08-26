# Stable runtime receipt — requirements brainstorm

## Problem

The installed-environment receipt hashes the complete isolated `site-packages` tree. The
read-only framework probe imports packages and allows CPython to create additional `__pycache__`
files, so the probe mutates the tree that it subsequently verifies. Merged-main U8 preparation
therefore fails even though the locked interpreter, distributions, CUDA runtime, driver, GPU, and
all non-cache package files are unchanged.

## Requirements

- Preserve the existing runtime receipt and its SHA-256 as the approved identity.
- Prevent every isolated inventory/framework probe from writing bytecode caches.
- Keep isolated execution, user-site suppression, deterministic hashing, bounded output, and
  sanitized failures unchanged.
- Do not exclude package files from the receipt or weaken tree verification.
- Recover the prior tree only by moving post-receipt cache files to an ignored local quarantine;
  do not delete or overwrite them.
- Prove that every quarantined file is a regular `.pyc` below an `__pycache__` directory and is
  newer than the receipt. Stop on any other changed file.
- Add focused tests for both probe paths and all platform command forms.
- Perform no provider contact, reservation, body transfer, or weight transfer while repairing the
  evidence gate.

## Success state

Two consecutive observations reproduce the original receipt digest, merged-main U8 `prepare`
passes, and the generated request remains zero-spend preparation only.
