# Reference approval runbook

This runbook prepares a reviewable Phase 1 reference packet. It cannot submit a remote job.

## Safe preview

1. Keep target-specific configuration and evidence under ignored `configs/local/`, `eval/local/`,
   `artifacts/local/`, `results/local/`, and `reports/local/` paths.
2. Verify the original approved-plan, provider-constraint amendment, and provider-observation
   trust-override plan SHA-256 values before editing local authority files. The budget authority
   remains bound to the original plan.
3. Populate the immutable source inventory from anonymous metadata only. Do not transfer shard
   bodies.
4. Re-observe the installed WSL environment immediately before previewing. A package, executable,
   package-tree, CUDA, driver, or runtime-lock mismatch stops the run.
5. By default, capture the isolated provider environment immediately before approval. The receipt
   must bind a local screenshot, one-container and one-GPU limits, zero active resources, the stable
   constraint contract, and privacy-safe workspace/environment digests. It expires after 15 minutes
   for approval and after 30 minutes for a future submission check. The separately approved trust
   override may instead bind the historical receipt and screenshot with explicit acceptance of
   staleness and configuration-drift risk. Never re-date the receipt or describe this path as fresh.
6. Keep the evaluation lock pending: configured context is not proven useful context, and no
   candidate execution is authorized.
7. Run the non-submitting preview:

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
- A stable provider-constraint contract plus either a fresh observation receipt or the exact hashed
  human trust override. Preview output must distinguish `fresh_observation` from
  `human_trust_override`. Neither mode is a dollar cap or bounds provider-managed rescheduling.
- A separately hashed billing-authority contract defining the environment-scoped attribution method,
  authoritative report identity, and completeness delay.
- Hashed memory-fit evidence whose method matches the formula authority and stays within the fixed
  A100-80GB envelope.
- Hashed cold-path evidence covering positive transfer, verification, load, evaluation, and safety
  margin durations inside 2,700 seconds.
- A clean reviewed tree and a short-lived approval artifact matching the canonical challenge,
  reviewed commit, all three plan authorities, every provider evidence identity including any trust
  override, the exact cap from the ignored local ledger, explicit residual-risk acceptance, and expiry.

## No-weight provider-smoke handoff

After the reviewed tree is clean, validate the ignored standing campaign authority and generate a
short-lived action contract from local lineage. Save only the nested `contract` object. Contract
generation does not contact Modal:

```powershell
$issued = (Get-Date).ToUniversalTime()
$expires = $issued.AddMinutes(30)
$packet = uv run lowbit-paid-smoke contract --root . `
  --config configs/local/reference.yaml `
  --ledger configs/local/reference-budget.json `
  --authority configs/local/provider-smoke-campaign-authority.json `
  --issued-at $issued.ToString("o") --expires-at $expires.ToString("o") |
  ConvertFrom-Json
$contractJson = $packet.contract | ConvertTo-Json -Depth 20 -Compress
[System.IO.File]::WriteAllText(
  "$PWD\configs\local\provider-smoke-contract.json",
  $contractJson,
  (New-Object System.Text.UTF8Encoding($false))
)
```

The approved adapter implementation can then be inspected without contacting Modal:

```powershell
uv run lowbit-paid-smoke plan --contract configs/local/provider-smoke-contract.json
uv run lowbit-paid-smoke verify --contract configs/local/provider-smoke-contract.json `
  --authority configs/local/provider-smoke-campaign-authority.json
```

Both commands are read-only. The handoff reports the exact later `execute` command, action scope,
campaign-authority digest, maximum reservation, and expiry. Execution needs no regenerated human
approval, but remains blocked unless authoritative settled cost leaves enough campaign balance and
no active or audit-blocked reservation exists. The local ceiling is not provider-enforced.

After any future paid action, the reservation stays in `settlement_pending` until a canonical,
authoritative billing receipt covers the contract's complete billing-delay window. Place that
ignored receipt at `reports/local/provider-smoke-billing.json`, then settle locally without provider
contact:

```powershell
uv run lowbit-paid-smoke settle --root . `
  --db results/local/reference.sqlite `
  --report reports/local/provider-smoke-billing.json `
  --reservation-id <exact-reservation-id>
```

If Modal creates a stopped app but launches zero tasks and zero containers before a call identity
exists, first record the closed evidence at
`reports/local/provider-smoke-prelaunch-audit.json`. The JSON object must contain exactly:
`schema_version` 1, `kind` `provider_smoke_prelaunch_audit`, the reservation, action-contract, and
execution-scope identities, `provider_app_id`, `provider_environment`, stopped app state, zero task
and container counts, provider-created and provider-stopped timestamps, and the SHA-256 of the
read-only provider report. Then run:

```powershell
uv run lowbit-paid-smoke audit-prelaunch --root . `
  --db results/local/reference.sqlite `
  --evidence reports/local/provider-smoke-prelaunch-audit.json `
  --reservation-id <exact-reservation-id>
```

This transition never contacts Modal and does not invent a function-call identity; billing
settlement binds the app ID.

## Bootstrap-authorized U8 boundary

The separately approved bootstrap amendment permits one U8 action to establish provider image,
usable-memory, allocator/runtime-overhead, and cold-path evidence progressively inside that same
execution. It does not permit a retry or second action. The adapter must derive its database,
provider environment, execution identity, evaluation lock, fixtures, request, and image recipe from
freshly reproduced local authority. It persists `submission_pending` before provider import,
provider image/app identity before the sole spawn, call identity immediately after spawn, and the
validated receipt/manifest before settlement pending.

The current immutable source transport is a pre-submit stop. A metadata-only HEAD request read zero
body bytes and observed that an approved query-free source URL redirects to a final public CDN URL
with a query string. The approved source policy rejects query strings at every redirect boundary.
Do not reserve U8, import Modal, or transfer weights until either a compliant immutable query-free
origin is proven or a later human-approved transport amendment changes that exact rule.

The paid adapter must be invoked from the isolated WSL/Linux environment. Native Windows lacks the
SIGALRM watchdog used to cover the complete 2,700-second provider section, including image build.
The adapter checks this before consuming U8 authority and fails closed on unsupported hosts.

Unknown billing or provider state after any future submission must become `audit_blocked`; it must
never release reusable budget. Provider authentication is not broader authority. U9 remains
proposal-only, and candidate conversion, training, numeric-threshold approval, and promotion remain
unauthorized.
