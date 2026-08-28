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

## Applicability

This pattern resolves accounting after prelaunch provider rejection. It does not prove the function
ran, does not create baseline metrics, and does not authorize retry, conversion, training, or
promotion.
