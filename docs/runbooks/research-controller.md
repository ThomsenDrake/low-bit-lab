# Codex research controller

Scheduling status: **disabled**. Do not create a scheduled task until one manual cycle has been run and reviewed after Phases 0 and 1 pass.

The `lowbit-controller` CLI is the only autonomous readiness entry point. It exposes exactly
`status`, `prepare`, and `verify`. None of those operations imports a provider SDK, submits work,
reserves a nonzero budget, transfers weights, creates approval, or enables scheduling.

## Zero-spend readiness cycle

Create ignored local receipts from `configs/controller-authority.example.json` and
`configs/formula-approval.example.json`, replacing only their documented hashes and local formula
path. Repository hashes prove that expected bytes and scope match; they do not cryptographically
authenticate the approving human. The fixed action allowlist is the mechanical authority boundary,
and future paid execution requires a separate authenticated approval.

The standing-authority statement preimage is exactly:

`Treat this message as human approval for those bounded plans without requesting approval for each regenerated SHA-256.`

The formula-approval statement preimage is exactly `Approved`. Verify the frozen digests with:

```powershell
uv run python -c "import hashlib; print(hashlib.sha256('Treat this message as human approval for those bounded plans without requesting approval for each regenerated SHA-256.'.encode()).hexdigest())"
uv run python -c "import hashlib; print(hashlib.sha256('Approved'.encode()).hexdigest())"
```

In the standing receipt, the statement digest, action lists, scope, origin label, schema, and plan
path are fixed. Regenerate only `controlling_plan_sha256` from the tracked plan. In the formula
receipt, every field is fixed except `formula_authority_path`, which must name the approved ignored
artifact whose SHA-256 is the frozen `approved_formula_sha256`. The receipt file's own SHA-256 must
also be recorded in the ignored reference configuration.

```powershell
uv run lowbit-controller status `
  --root . `
  --config configs/local/reference.yaml `
  --authority configs/local/controller-authority.json `
  --formula-approval reports/local/formula-approval.json

uv run lowbit-controller prepare `
  --root . `
  --config configs/local/reference.yaml `
  --db results/local/controller.sqlite `
  --authority configs/local/controller-authority.json `
  --formula-approval reports/local/formula-approval.json `
  --output-dir reports/local/controller

uv run lowbit-controller verify `
  --root . `
  --config configs/local/reference.yaml `
  --db results/local/controller.sqlite `
  --authority configs/local/controller-authority.json `
  --formula-approval reports/local/formula-approval.json
```

`status` and `verify` are read-only. `prepare` alone creates a controller cycle. It writes one
immutable per-cycle handoff and then commits its relative path and SHA-256 through an owner,
generation, context, authority, and lease compare-and-set. Readers trust only the artifact referenced
by the committed SQLite row; an interrupted stale writer cannot replace it.

The terminal state is `paid_decision_required`, not execution readiness. The handoff reads the total
ceiling from the validated ignored local ledger and separates it from a USD 0 current-action cap and a null proposed cap. It also
reports `command_available:false` because `PLAN.md` forbids a provider execution primitive. The next
plan must allocate the paid evidence action and authorize a disabled-by-default adapter before an
executable paid command can exist.

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

## Phase 1 local activation

The activation entry point is `lowbit-activate`. It is preview-only unless `--apply` is
present. Preview reads and validates the ignored local authority bundle, reports repository-relative
authority paths and hashes, lists the exact gate order and stop conditions, and reports both the
runtime and metadata byte caps. It does not initialize SQLite, call a runtime adapter, install
anything, or open a network connection.

```powershell
uv run lowbit-activate `
  --root . `
  --config configs/local/phase1-activation.yaml `
  --db results/local/phase1-activation.sqlite `
  --publication-manifest configs/local/publication.yaml `
  --approved-plan docs/plans/local/phase1-approved.md `
  --runtime-decision configs/local/phase1-runtime-decision.json `
  --runtime-lock configs/local/phase1-runtime-lock.json `
  --metadata-policy configs/local/phase1-metadata-policy.json `
  --evaluation-lock eval/local/phase1-evaluation-lock.json
```

Review the JSON before any apply invocation. `--apply` authorizes only the local adapters already
supplied to the activation pipeline; an absent adapter fails closed. It does not authorize weight
downloads, uploads, cloud submission, scheduling, destructive cleanup, global installation, or
nonzero spend. Runtime, provenance, and evaluation adapters are dependency-injected so tests and
controllers can use deterministic implementations without hidden network or installation behavior.

The durable order is publication, configuration/authority, zero budget, runtime decision, verified
local runtime, runtime probe, provenance, and evaluation lock. Publication, configuration, and
budget failures close the attempt before any run is linked. Once linked, every child gate and its
parent must become `completed` or `failed`; a failure marks all unvisited children failed without
calling later adapters. A pending evaluation lock may complete activation, but records
`promotion_authorized:false` and does not authorize candidate execution.

Each session owns a lease and heartbeat. At startup, expired nonterminal activation sessions and
their child gates are reconciled to `failed` with the sanitized interruption reason. Retrying always
creates a new run ID and reruns publication, configuration, budget, and preceding local guards.
Only completed downstream evidence with identical input and authority bindings may be referenced;
binding drift invalidates dependent evidence for that activation lineage.
