# Low-Bit Lab Controlling Plan

## Mission

Build a reusable, local-first control plane for reproducible low-bit research. This repository is scaffolding: it deliberately selects no research target, makes no performance claim, and authorizes no paid compute.

## Frozen public-scaffold constraints

- The target remains `unconfigured` until a human approves a target-specific plan.
- Cloud spend, every phase cap, and the single-job cap remain USD 0.
- Cloud submission, cloud upload, scheduling, weight download, conversion, training, and destructive cleanup remain disabled by default.
- Credentials, private code, personal data, and work data must never enter configs, results, artifacts, logs, or remote services.
- Host, driver, firmware, BIOS, and global system changes are outside agent authority.
- Configured capability and empirically proven usefulness are distinct states.
- Artifact lineage uses immutable revisions and SHA-256 hashes.
- Unknown states and unknown failure modes stop execution.

Changing a frozen constraint requires an explicit human-approved plan, matching policy and code changes, focused tests, and a review before execution.

The approved no-weight provider-smoke amendment, plan SHA-256
`dd08a09dbdbd6e88f53a50de932fc15f933ee71d41a21f0f16ad28b68b402d61`, permits
one audited Modal adapter to be represented in code. It does not authorize executing the adapter,
reserving money, transferring weights, or U8. The adapter accepts no model identifier or payload,
and remains unreachable until a fresh ignored approval is atomically consumed with an exact local
USD 4.00 reservation. Representation is not execution authority.

## Repository contract

The durable repository contains:

- control documents: `AGENTS.md`, `SPEC.md`, `BUDGET.md`, and this plan;
- Compound Engineering artifacts in `docs/plans/` and durable lessons in `docs/solutions/`;
- immutable experiment inputs in `configs/`;
- composable Python CLIs in `src/lowbit_lab/`;
- a non-submitting remote-job wrapper in `modal/`;
- evaluation contracts and fixtures in `eval/`;
- generated results, artifacts, and reports in their named directories.

## Phase 0: public foundation

Phase 0 delivers:

1. A pinned Python environment and lock file.
2. A SQLite schema for configuration, source hashes, runtime, local hardware metadata, cost, metrics, artifacts, state transitions, and failures.
3. A closed, canonical experiment-config schema.
4. A local dry run that records a complete zero-spend experiment without weights.
5. A remote-job dry run that validates budget, wall-clock, checkpoint, cleanup, privacy, and stop conditions without submitting.
6. SHA-256 artifact manifests.
7. Evaluation interfaces and placeholder fixtures for coding, tool-call validity, retrieval, throughput, memory, and soak tests.
8. Windows 11 and WSL2 setup instructions.
9. A manually invoked research-controller runbook; scheduling stays disabled.

## Target-activation gate

The next authorized action is documentation-only: create a target-specific Phase 1 plan in a separate change. It must define an immutable source identifier and revision, license and provenance, tokenizer lineage when applicable, local runtime compatibility, hardware observations, an evaluation contract, and a budget proposal. No target fetch or cloud action is authorized by this scaffold.

Only after explicit human approval may a configured experiment be added. A configured target must use an immutable lowercase revision hash. Any tokenizer file must be repository-relative and carry a SHA-256 hash.

## Research loop

Each attempt follows `received -> linked | failed`. A linked run follows explicit transitions:

`created -> validated -> running -> completed | failed`

A failed validation never becomes a run. Every attempt is audited. Promotion requires declared metrics and thresholds in the approved target-specific plan; this generic scaffold defines no promotion threshold.

## Stop conditions

Stop immediately on a budget violation, source-hash mismatch, privacy violation, checkpoint failure, wall-clock limit, invalid transition, missing provenance, or unknown failure mode. Destructive cleanup remains opt-in and limited to explicitly marked ephemeral paths.

## Phase 0 acceptance

- Focused tests pass in the locked environment.
- Local and remote dry runs complete with weights unloaded, uploads disabled, submissions false, and recorded cost USD 0.
- A generated manifest verifies source hashes and records target status as unconfigured.
- Public files contain no credentials, private paths, personal hardware inventory, personal budget, or selected target.
