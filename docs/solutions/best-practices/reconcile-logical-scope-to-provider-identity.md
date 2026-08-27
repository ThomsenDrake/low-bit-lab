---
title: Reconcile logical scope to provider identity without rewriting lineage
date: 2026-08-27
category: best-practices
module: experiment-control-plane
problem_type: architecture_pattern
component: infrastructure
severity: high
applies_when:
  - "A provider action was recorded before the provider issued a concrete workspace identity"
  - "A logical configured scope must be mapped to authenticated provider billing evidence"
tags: [audit-lineage, authentication, billing, modal, sqlite, one-shot-authority]
---

# Reconcile logical scope to provider identity without rewriting lineage

## Context

A configured workspace scope and an authenticated provider workspace identity are different facts.
Treating their digests as equal, or rewriting the original experiment config after authentication,
destroys the history needed to explain a pre-identity failure and any later replacement entitlement.

## Guidance

Record a separate immutable reconciliation authority that names both digests and explicitly requires
them to differ. Bind that authority to the original reservation and execution scope, then insert the
mapping, exact billing-evidence identity, settlement, and one-time replacement entitlement in one
database transaction. Revalidate the authority and authentication receipt inside the transaction;
validation only at CLI entry is insufficient.

Validate migration shape even when a decision-bearing table is empty. Row-count checks cannot prove
that an empty legacy schema has the expected constraints, so freeze and compare the supported DDL
fingerprints before adding authority-bearing tables.

Provider identity checks should authenticate only the active profile. A profile-list operation may
contact unrelated configured workspaces. Load the active provider configuration once in an isolated
process, validate the official endpoint and absence of override headers, authenticate that profile,
hash the returned workspace value before output, and emit only the digest. For a paid boundary,
repeat the identity check from the same cached SDK configuration that will perform the action.

Require clean merged `main` for evidence capture and entitlement consumption, and make
authentication receipts short-lived. These checks ensure the evidence names the reviewed code and
the provider session that is actually about to consume authority.

Keep configured capability distinct from proof: preserving a 262,144-token evaluation envelope does
not establish that the model uses that context effectively.

## Applicability

Use this pattern for one-time recovery from a pre-identity provider failure. It is not a general
workspace-alias mechanism and must not accept future identities, reset consumed authority, or create
an open-ended retry path.
