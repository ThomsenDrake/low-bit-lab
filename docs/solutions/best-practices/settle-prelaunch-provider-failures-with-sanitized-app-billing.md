---
title: Settle prelaunch provider failures with sanitized app billing
date: 2026-08-27
category: best-practices
module: provider-control-plane
problem_type: best_practice
component: infrastructure
severity: high
applies_when:
  - "A provider creates an app but rejects the function before issuing a call identity"
  - "A one-shot reservation must be settled without authorizing a retry"
tags: [billing, modal, privacy, settlement, app-identity, audit]
---

# Settle prelaunch provider failures with sanitized app billing

## Context

A provider can build an image and create a stopped app before a client persists a call identity.
The stopped app may report zero currently running tasks, but that is not evidence that no task ever
ran. Image preparation may still incur cost. Leaving the worst-case reservation audit-blocked
forever is safe but prevents authoritative lifetime-cost accounting.

## Guidance

Do not invent a call ID or copy the app ID into a call-ID field. Bind a unique stopped app created
inside the consumed action window and record the provider field accurately as currently running
tasks. Do not reinterpret it as a lifetime count. Query complete-hour billing only after the
declared completeness delay. Authenticate the approved workspace before and after both read-only
calls.

Provider workspace reports may contain unrelated private descriptions and costs. Filter them in
memory and persist only a closed canonical app record plus rows whose object ID matches the selected
target-neutral app. Reject another row carrying the same action description under a different app
ID as ambiguous. Bind the exact sanitized bytes, their lengths and hashes, the billing authority,
reservation, execution scope, consumed entitlement, workspace identity, and provider-environment
scope in one receipt.

Reject provider type drift before canonicalization. In particular, do not stringify numeric costs
or resource identifiers, and remember that Python booleans compare equal to integers. Closed JSON
contracts must require exact integer types for versions, counts, sizes, and delays before comparing
their values.

Validate that receipt again inside the same `BEGIN IMMEDIATE` transaction that records app identity,
actual cost, settlement digest, and an exact compare-and-set terminal run transition. A within-cap
result is still a failed action, not a successful experiment. An over-cap result must be durably
recorded before raising a budget failure. Neither result restores one-shot authority.

Mocks at this boundary must preserve the production call signature, including keyword-only root or
authority arguments. A permissive one-argument mock can hide an integration failure that occurs
before authentication and all provider reads.

Keep plaintext provider identifiers out of tracked target-neutral configuration. When a read-only
billing query needs an environment name, resolve it transiently from the ignored provider-capability
receipt after reproducing that receipt from the canonical bootstrap request's exact capability and
image-recipe hashes. Continue to persist only the environment-scope digest. Tests must omit the
nonexistent plaintext config field so this boundary cannot silently regress.

An ignored request cannot be its own historical authority. Before using its capability receipt for
post-failure provider attribution, recompute the standing packet from the exact request hash,
canonical config hash, and frozen authority hashes, then compare it with the packet persisted when
the consumed reservation was created. This reuses pre-submission lineage to reject coordinated
ignored-evidence drift without retroactively rewriting the experiment config.

Track read-only provider contact separately from paid execution contact. A failed app or billing
query must still report that the provider read boundary was attempted, while keeping paid execution
contact false. Lock the exact read-only command sequence and invocation count in tests so an added
retry, broadened query, or missing environment selector cannot hide behind response-only mocks.

Provider lifecycle listings and billing reports can have different retention windows. When the
recent-app listing no longer returns an eligible app, use a separate closed evidence variant rather
than populating lifecycle fields from assumptions. The fallback may bind identity only when the
complete authoritative billing report contains at least one matching row and exactly one valid app
ID across all matching rows. Record that the recent listing did not return the app and that billing
was the identity source; do not record created, stopped, task-count, or state fields. Reject empty
matching rows, multiple app IDs, malformed IDs, timestamp type drift, or any report inconsistency
before persisting evidence. Keep the action terminally failed even after its exact cost is settled.

Provider machine-readable output may intentionally serialize a UTC value without its offset. Bind
any exception to the pinned client and the exact command boundary: the official Modal billing API
returns UTC intervals, while its JSON formatter removes UTC `tzinfo` when no timezone override is
requested. Normalize only the exact offset-free `YYYY-MM-DDTHH:MM:SS` billing form at that boundary,
persist an explicit `+00:00`, and keep the general timestamp validator strict. Reject dates, missing
seconds, spaces, non-UTC offsets, malformed strings, and non-string values.

## Applicability

This pattern resolves accounting after prelaunch provider rejection. It does not prove the function
ran, does not create baseline metrics, and does not authorize retry, conversion, training, or
promotion.
