# Reference approval runbook

This runbook prepares a reviewable Phase 1 reference packet. Public defaults cannot submit a remote
job; the final section describes the separately authorized, mechanically gated one-shot boundary.

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

The signed-CDN transport amendment keeps every immutable origin query-free and permits a query only
after a redirect to one of the exact host/path pairs frozen in code. The direct client revalidates
HTTPS, host, canonical path, DNS results, and connected peer at every hop; sends only the fixed
`Accept-Encoding: identity` header; and never returns or persists redirect query material. Five
redirects is the hard maximum. Every artifact remains unusable until its declared byte length and
SHA-256 match.

From a clean merged-main checkout, regenerate the ignored request without initializing the paid
database, reserving budget, constructing a provider client, contacting a provider, or transferring
artifact bodies. It does import the pinned local SDK to reproduce its audited source fingerprint:

```bash
uv run lowbit-reference-u8 --root . prepare
```

The JSON output reports the request digest, execution-scope digest, configured context, and the
still-null proven-useful context. The one paid command must run from the repository-isolated WSL
environment and confirm that exact freshly regenerated request digest:

```bash
uv run --extra remote lowbit-reference-u8 --root . execute \
  --confirm-request-sha256 <exact-prepare-request-sha256>
```

`execute` regenerates the request again, requires digest equality, performs the HEAD-only topology
observation with ambient proxies absent, reproduces every deterministic gate, and only then creates
the USD 4.00 local reservation. It is not a general execution command: the closed standing
authority, one-shot slot, cumulative ledger, fixed resource envelope, and exact local lineage are
all required. Any failure after potential provider contact reports the contact state as unknown.

The resulting ignored evidence must be less than 15 minutes old, bind the exact request and
transport authority hashes, record zero body bytes, and explicitly state that it does not prove the
Modal worker's regional route. A stale or mismatched observation stops before reservation or Modal
import. A remote route outside the frozen policy remains an accepted fail-closed one-shot risk, not
permission to expand the allowlist.

The paid adapter must be invoked from the isolated WSL/Linux environment. Native Windows lacks the
SIGALRM watchdog used to cover the complete 2,700-second provider section, including image build.
The adapter checks this before consuming U8 authority and fails closed on unsupported hosts.

Unknown billing or provider state after any future submission must become `audit_blocked`; it must
never release reusable budget. Provider authentication is not broader authority. U9 remains
proposal-only, and candidate conversion, training, numeric-threshold approval, and promotion remain
unauthorized.

## Recover an authentication failure before provider identity

Use this path only when the reservation is `audit_blocked` with the exact sanitized AuthError class
and every provider identity field is absent. Never invent an app, job, image, or call identity.

1. From the isolated WSL environment, verify Modal authentication using the read-only recovery
   command. Durable evidence contains only a workspace-scope digest, never credential material or a
   workspace display name.
2. Capture an explicit unfiltered workspace billing interval composed only of complete UTC hours.
   It must cover the original consumed boundary through the latest durable boundary plus 2,700
   seconds and be acquired only after the billing-completeness delay.
3. Inspect status and settle locally. Settlement must not import the remote adapter. Exact WSL CLI
   bytes `[]` followed by LF are the only accepted report; incomplete, filtered, mismatched,
   nonzero, or ambiguous evidence
   leaves the reservation audit-blocked.
4. Confirm the original slot remains consumed and exactly one replacement entitlement is available.
   Regenerate every normal U8 gate from merged main before replacement execution.

The replacement is consumed atomically immediately before provider contact. Every failure after
that boundary consumes it permanently. There is no second replacement and no retry. Configured
context remains 262,144 tokens; proven-useful context remains unknown until validated remote
evaluation evidence demonstrates usefulness.

Run the recovery only from the repository-isolated WSL environment, with proxy, custom-TLS,
Python-import, and Modal-auth override variables absent. Materialize the ignored authority, bind and
verify the provider-local workspace, capture complete hourly evidence, then settle locally:

```bash
uv run --extra remote lowbit-reference-u8 --root . recovery-authority
uv run --extra remote lowbit-reference-u8 --root . auth-bind
uv run --extra remote lowbit-reference-u8 --root . auth-verify
uv run --extra remote lowbit-reference-u8 --root . billing-capture \
  --query-start <complete-hour-UTC-start> --query-end <complete-hour-UTC-end>
uv run --extra remote lowbit-reference-u8 --root . settle-preidentity-zero
uv run --extra remote lowbit-reference-u8 --root . status
uv run --extra remote lowbit-reference-u8 --root . prepare-replacement
```

The final command reports a fresh request SHA-256 without reserving or contacting Modal. Only when
every output is successful and status reports one available replacement may the single paid action
run, once:

```bash
uv run --extra remote lowbit-reference-u8 --root . execute-replacement \
  --confirm-request-sha256 <exact-prepare-replacement-request-sha256>
```
