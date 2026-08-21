---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-brainstorm
execution: code
title: Phase 0 control-plane foundation
date: 2026-08-21
source: PLAN.md
---

# Phase 0 control-plane foundation

## Goal capsule

Build the public, local-first, zero-spend control plane and prepare a gated Phase 1 planning action without selecting a target.

## Requirements

- Preserve `PLAN.md` authority boundaries and zero-spend defaults.
- Pin the Python environment and lock dependencies.
- Store canonical config identity, source hashes, runtime and hardware metadata, cost, metrics, artifacts, transitions, and failures in SQLite.
- Validate closed YAML configs and immutable configured-target lineage.
- Run a complete weight-free local dry run.
- Produce a plan-only remote workflow with budget, timeout, checkpoint, cleanup, privacy, and explicit stop controls.
- Generate SHA-256 manifests.
- Provide placeholder interfaces for every evaluation family.
- Document safe Windows 11 and WSL2 verification and a scheduling-disabled controller.

## Implementation units

1. Project and authority documents: `pyproject.toml`, lockfile, ignore rules, control documents, README, and license.
2. Config and budget guards: `src/lowbit_lab/config.py`, `src/lowbit_lab/budget.py`, and `configs/`.
3. Results and local runner: database, runtime capture, runner, and results directory.
4. Remote plan and manifests: wrapper, planner, manifest generator, and artifacts directory.
5. Evaluation contracts: registry and fixtures.
6. Runbooks, focused tests, report-only review, simplification, and compound note.

## Acceptance criteria

- Invalid keys, mutable revisions, positive spend, unsafe paths, submission requests, and source drift fail before execution.
- Valid local and remote dry runs create completed rows with zero cost, no weights, no upload, and no submission.
- Manifests contain repository-relative paths, hashes, runtime lineage, and unconfigured target state.
- Scheduling and destructive operations stay absent or disabled.
- A public-content scan finds no selected target, personal inventory, private path, credential, or personal budget.

## Verification commands

```powershell
uv sync --frozen --extra dev
uv run pytest -q
uv run ruff check .
uv run lowbit-dry-run --config configs/example-local-dry-run.yaml --db results/verification.sqlite
uv run lowbit-modal-plan --config configs/example-modal-dry-run.yaml --db results/verification.sqlite --dry-run
uv run lowbit-manifest --root . --config configs/example-local-dry-run.yaml --output artifacts/scaffold-source-manifest.json pyproject.toml PLAN.md SPEC.md BUDGET.md
```

## Phase 1 gate

The next authorized action is to draft a target-specific Phase 1 plan. It must pin provenance and immutable revisions, document license and privacy constraints, define local compatibility checks and evaluation thresholds, and propose any budget. It authorizes no download or remote execution by itself.
