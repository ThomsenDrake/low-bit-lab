---
artifact_contract: ce-unified-plan/v1
artifact_readiness: requirements-only
product_contract_source: ce-brainstorm
title: Phase 0 foundation requirements
date: 2026-08-21
source: PLAN.md
---

# Phase 0 foundation requirements

## Goal capsule

Create a public, target-neutral research control plane that can prove what ran, why it was authorized, what it cost, and what it produced before weights or cloud compute enter a project.

## Required outcomes

- A complete repository skeleton with durable authority, plans, solutions, configs, source, remote-job boundary, evaluation, results, artifacts, and reports.
- A reproducible Python environment for Windows 11 and WSL2 control-plane use.
- Immutable experiment definitions and a SQLite system of record for lineage, states, cost, measurements, artifacts, and failures.
- Weight-free local and remote dry runs that exercise control logic while mechanically preventing spend.
- Hash-based manifests and placeholder contracts for coding, structured tool use, retrieval, throughput, memory, and soak behavior.
- Safe manual setup and controller runbooks; scheduling is documented but disabled.

## Success criteria

- Focused tests pass in the locked environment.
- Both dry runs emit JSON, record USD 0, download nothing, upload nothing, and submit nothing.
- The next action is an explicit target-specific planning gate.
- Configured capacity is never conflated with empirically useful capacity.

## Boundaries

- `PLAN.md` controls; target status and zero-spend policy are frozen.
- No system changes, external uploads, opaque conversion code, fabricated artifacts, kernel claims, destructive defaults, or broad authority.
- No personal hardware inventory, private paths, credentials, or selected target belong in the public scaffold.

## Key decisions

- Keep the repository and SQLite as durable shared state so research runs remain auditable.
- Enforce authority in code and closed schemas because spend and destructive actions must fail closed.
- Use small JSON-emitting CLIs so each boundary can be tested independently.
- Prepare but do not activate remote execution or scheduling; manual validation is a prerequisite.

## Out of scope

Target selection, baselines, weights, conversion, training, kernel claims, cloud assets, promotion thresholds, and promotion decisions.

