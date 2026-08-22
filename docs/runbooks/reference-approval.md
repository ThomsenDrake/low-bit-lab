# Reference approval runbook

This runbook prepares a reviewable Phase 1 reference packet. It cannot submit a remote job.

## Safe preview

1. Keep target-specific configuration and evidence under ignored `configs/local/`, `eval/local/`,
   `artifacts/local/`, `results/local/`, and `reports/local/` paths.
2. Verify the approved implementation-plan SHA-256 before editing local authority files.
3. Populate the immutable source inventory from anonymous metadata only. Do not transfer shard
   bodies.
4. Re-observe the installed WSL environment immediately before previewing. A package, executable,
   package-tree, CUDA, driver, or runtime-lock mismatch stops the run.
5. Keep the evaluation lock pending: configured context is not proven useful context, and no
   candidate execution is authorized.
6. Run the non-submitting preview:

   ```powershell
   uv run lowbit-modal-plan --config configs/local/reference.yaml `
     --db results/local/reference.sqlite
   ```

The JSON result must show `submit:false`, `weights_transferred:false`, `actual_cost_usd:"0"`, and
every unresolved blocker. Previewing never creates or consumes an execution approval.

## Evidence required before a future execution request

- Exact inventory, provenance, installed-runtime, evaluation, reviewed-commit, and control-plane
  identities.
- A separately reviewed formula authority. Numeric promotion thresholds remain absent.
- Hashed provider evidence proving the USD 4.00 workspace cap, attributable billing scope and
  completeness delay, and at most one billable attempt.
- Hashed memory-fit evidence whose method matches the formula authority and stays within the fixed
  A100-80GB envelope.
- Hashed cold-path evidence covering positive transfer, verification, load, evaluation, and safety
  margin durations inside 2,700 seconds.
- A clean reviewed tree and a short-lived approval artifact matching the canonical challenge,
  reviewed commit, USD 4.00 cap, and expiry.

## Hard stop

U8 remains unauthorized. This repository contains no `modal.App`, remote function, deploy, spawn,
or submit entrypoint. Do not add one, authenticate, transfer weights, reserve money, or register an
approval until a human separately approves the exact U7 packet and reviewed commit. Unknown billing
after any future submission must become `audit_blocked`; it must never release reusable budget.
