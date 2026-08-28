---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
execution: code
title: Modal billing UTC serialization requirements
date: 2026-08-28
---

# Requirements brainstorm: Modal billing UTC serialization

## Problem

The pinned official Modal client returns UTC billing intervals, but its JSON formatter deliberately
removes the UTC offset when no timezone override is supplied. The general lab timestamp validator
correctly rejects offset-free timestamps, so the authoritative billing capture fails before it can
persist sanitized evidence.

## Requirements

- Keep the general UTC parser strict; do not accept naive timestamps anywhere else.
- Normalize only the exact offset-free second-resolution ISO form emitted by the pinned Modal
  billing JSON command, whose installed official API implementation declares result timestamps UTC.
- Continue to accept explicit UTC billing timestamps and reject non-UTC offsets, spaces, dates,
  missing seconds, malformed values, and non-string values.
- Persist the normalized timestamp with an explicit UTC offset.
- Preserve every identity, lineage, privacy, completeness, budget, and no-retry gate.
- Perform no provider execution, weight transfer, scheduling, storage, or destructive work.

## Acceptance

- The observed `2026-08-27T14:00:00` hourly bucket normalizes to
  `2026-08-27T14:00:00+00:00` only in billing capture.
- General UTC validation remains unchanged.
- Focused/full tests, Ruff, publication/privacy checks, simplification, and review pass.

