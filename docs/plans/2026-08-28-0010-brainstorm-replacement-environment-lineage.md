---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Replacement billing environment lineage requirements
date: 2026-08-28
---

# Requirements brainstorm: replacement billing environment lineage

## Problem

The read-only replacement billing capture assumed that tracked, target-neutral configuration
contained a plaintext provider environment. It intentionally contains only the immutable
environment-scope digest, so capture failed before authentication or provider contact.

## Requirements

- Keep the plaintext provider environment out of tracked configuration and durable public output.
- Resolve it transiently only from the ignored provider-capability receipt already trusted by the
  paid boundary.
- Validate the canonical bootstrap request and use its exact provider-receipt and image-recipe
  hashes to reproduce the capability receipt before any provider read.
- Recompute the consumed reservation's standing packet from the exact request and config bytes and
  reject any mismatch with its persisted approval-challenge packet before provider contact.
- Preserve the tracked environment-scope digest for billing-authority and settlement lineage.
- Fail closed before provider contact on missing, malformed, or drifted request or capability
  evidence.
- Add a regression test whose config omits the nonexistent plaintext field.
- Perform no provider execution, retry, weight transfer, scheduling, storage, or destructive work.

## Acceptance

- The focused regression test proves capture no longer reads plaintext environment from config.
- Exact capability and image-recipe hashes are passed to receipt validation.
- Coordinated drift of ignored request and capability evidence cannot escape the persisted packet
  binding or reach provider authentication.
- Focused/full tests, Ruff, publication/privacy checks, and diff checks pass.
