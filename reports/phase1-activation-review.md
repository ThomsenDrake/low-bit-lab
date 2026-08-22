## Code Review Results

**Scope:** Phase 1 activation foundation on `codex/phase1-activation-clean`
**Intent:** Prove a zero-cost local WSL/CUDA activation path while keeping public state target-neutral
**Mode:** markdown local-apply

**Reviewers:** reproducibility, credit safety, local GPU compatibility, security, testing,
maintainability, reliability, and research-loop completeness.

### Applied

| # | File | Fix | Reviewer |
|---|------|-----|----------|
| 1 | `evaluation.py`, `evaluation_lock.py` (+tests) | Made candidate authority factory-only and verified its canonical identity at use | security, correctness |
| 2 | `publication.py` (+tests) | Scanned tracked and outgoing Git paths as well as contents; bounded Git subprocesses | security, reliability |
| 3 | `runtime.py`, `runtime_artifacts.py` (+tests) | Closed runtime URLs across lock, redirects, and final response; fixed artifact-root containment | security |
| 4 | `activation.py`, `config.py`, `db.py` (+tests) | Bound runtime-decision authority, disabled unsafe evidence reuse, bounded fixtures, and atomically linked activation attempts to runs | reproducibility, correctness |
| 5 | `runtime_probe.py` (+tests) | Required closed probe evidence and exact locked Python/framework versions | local compatibility, security |
| 6 | `provenance.py` (+tests) | Stopped persisting raw untrusted cache-validator headers | private-data handling |

Validation: 187 tests pass; Ruff passes; publication scan reports no findings across 280
sources; the hardened eight-gate local activation completed with requested and actual cloud
cost both `0`.

Committed status: pending isolated review commit. The authority and concurrency contract changes
need diff review even though the tests are green.

### Requirements Completeness

- Met: immutable config and authority hashes, SQLite lineage, zero-budget gate, bounded local
  runtime artifacts, WSL CUDA observation, metadata-only provenance, pending evaluation lock,
  publication guard, and terminal activation record.
- Met: configured context remains distinct from runtime initialization and usefulness proof.
- Met: Modal submission, scheduling, uploads, weight downloads, and destructive cleanup remain
  disabled.
- Not authorized: candidate execution, full-weight baseline execution, conversion, or threshold
  promotion.

### Learnings & Past Solutions

- Known pattern: `docs/solutions/best-practices/fail-closed-research-control-plane.md`.

### Agent-Native Gaps

- A future controller should return the attempt identifier on every failed CLI response.
- Activation preview validates authority hashes but does not execute the runtime, provenance, or
  evaluation gates. This is intentional; consumers must not interpret preview as readiness.

### Coverage

- Reproducibility and lineage: exact runtime artifacts, authority files, fixture bytes, gate
  evidence, state transitions, and zero-cost metrics are persisted.
- Modal-credit safety: no provider SDK or submission path is reachable; atomic reservation and
  actual-cost settlement are still required before that boundary can change.
- Local GPU compatibility: WSL CUDA allocation, deterministic arithmetic, and synchronization
  passed. Framework readiness does not prove target inference or kernel compatibility.
- Security and privacy: public paths and content are scanned; ambient proxies and credentials are
  excluded from artifact fetches; raw response validators are not persisted.
- Research loop: retries create new runs and rerun every local gate. Promotion remains blocked by
  the pending evaluation lock.
- Residual risk: installed package versions are checked against the runtime lock, but a future
  long-lived controller should add a receipt over the installed environment tree before scheduling.
- Testing gap: hard process termination before run linkage is not yet covered by a process-level
  integration test; atomic run linkage removes the orphan-run window, but an abandoned `received`
  attempt can still require operator reconciliation.

### Actionable Findings

No remaining finding authorizes candidate, cloud, or weight activity. Before scheduling, add an
installed-environment receipt and process-level termination reconciliation test.

---

> **Verdict:** Ready for the Phase 1 stop point
>
> **Reasoning:** The local activation evidence is terminal, reproducible, target-neutral in public
> state, and zero-cost. Candidate and paid paths remain mechanically blocked.
>
> **Actionable:** Obtain separate human approval for a threshold-authority and full-weight baseline
> plan before any model-weight download or candidate execution.
