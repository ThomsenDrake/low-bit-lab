# Codex research controller

Scheduling status: **disabled**. Do not create a scheduled task until one manual cycle has been run and reviewed after Phases 0 and 1 pass.

## Manual cycle

1. Read `PLAN.md`, `BUDGET.md`, `AGENTS.md`, the latest decision report, active experiment config, and relevant `docs/solutions/` notes.
2. Query SQLite. If a job is `running`, inspect/collect it only; do not launch another.
3. If none is running, select exactly one config already authorized by phase, policy, spend balance, and prerequisites.
4. Validate config/source hashes, runtime, privacy, phase cap, total ceiling, timeout, checkpoint, cleanup, and explicit submission state.
5. Execute one local task, or—only in a later authorized phase—one bounded Modal task.
6. Persist terminal status, actual cost, metrics, artifact hashes, and failure reason. Write one decision report.
7. Stop on a failed gate, cap, config/source mutation, unknown failure, missing checkpoint, or private-data risk.

## Future six-hour cadence

After manual approval, a local project task may invoke the same manual cycle every six hours in the main checkout. It must use an overlap lock, never mutate the locked evaluation suite or ledger, and never infer authority from elapsed time. The schedule definition remains intentionally absent in Phase 0.

## State machine

Attempts use `received -> linked|failed`. Runs use `created -> validated -> running -> completed|failed`. Terminal states do not transition. A new attempt receives a new run ID and retains the prior failure.
