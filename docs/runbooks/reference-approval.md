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

1. From clean merged `main` in the isolated WSL environment, materialize the one-time reconciliation
   authority and verify Modal authentication. The original configured workspace scope remains
   historical lineage; the separately authenticated workspace identity is never treated as equal.
   Durable evidence contains only their digests, never credential material or a display name.
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
uv run --extra remote lowbit-reference-u8 --root . reconciliation-authority
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

### App-attributed replacement settlement

Use this path only for the single consumed replacement reservation when its sanitized failure is
`provider boundary uncertainty: InvalidError`, it has no call identity, and the provider exposes one
unique stopped app created inside the action window and reporting zero currently running tasks.
That field is not lifetime task evidence. This path is read-only at Modal and does not restore the
entitlement or authorize another action.

Choose complete UTC-hour boundaries such that the start is no later than entitlement consumption,
the end covers the latest durable boundary plus 2,700 seconds, and capture occurs at least 3,600
seconds after the end. Then run from the exact merged clean WSL checkout:

```text
uv run --extra remote lowbit-reference-u8 --root . billing-capture-replacement \
  --query-start <YYYY-MM-DDTHH:00:00Z> \
  --query-end <YYYY-MM-DDTHH:00:00Z>
uv run --extra remote lowbit-reference-u8 --root . settle-replacement
uv run --extra remote lowbit-reference-u8 --root . status
```

The capture persists only the selected target-neutral app identity, its current running-task count,
the approved provider-environment digest, and its filtered billing rows; other workspace
descriptions and costs are discarded in memory. Any ambiguity, incomplete interval,
workspace drift, noncanonical bytes, attribution mismatch, or over-cap cost stays terminal and must
not produce a retry.

## WSL state ownership for the additional one-shot action

The additional action may run only from an ext4-backed WSL2 mirror. The Windows checkout remains
the durable state owner before and after the action, but it must not be prepared or imported again
while WSL owns an unsettled attempt. Credentials and weights are never part of this transfer.

First synchronize the reviewed, merged, clean `main` checkout and the already-audited ignored local
inputs into the ext4 mirror without copying credential files or weight bodies. Then, from that exact
mirror, transfer only the SQLite state. Use the Windows checkout's WSL mount path as
`<durable-root>`; do not record a personal path in tracked documentation:

```text
uv run --extra remote lowbit-reference-u8 --root . wsl-transfer-begin \
  --durable-root <durable-root>
```

This command writes an immutable ownership marker under the ignored Windows `reports/local/`
directory before importing the database. It snapshots any prior mirror database, validates both
SQLite snapshots, and compares their SHA-256 hashes. If the first import is interrupted before any
parity receipt exists, rerunning the same command for the same mirror resumes that import without
deleting or rewriting the marker. Once parity exists, the active marker rejects another transfer
and rejects preparation in the Windows checkout.

The additional paid command must reproduce Modal's exact serialized hydration payload twice and
write an immutable, generation-specific parity receipt before creating a reservation. The receipt binds the marker,
merged HEAD, tracked tree, SQLite hash and integrity, authority, config, request, provider-auth,
runtime, evaluation, provenance, pinned SDK, and serialized-payload identities. Native Windows,
`/mnt/c`, a non-ext4 mirror, a different mirror path, a dirty or unmerged checkout, changed database,
stale authentication, or any byte mismatch stops before reservation. If a deterministic pre-boundary
failure releases its reservation at zero cost, a later parity generation is allowed only while the
grant remains available and every intervening reservation is durably released with no provider
identity, submission timestamp, or actual cost. Earlier receipts and the original import hash remain
immutable. A parity receipt is evidence
of configured 262,144-token context only; it does not prove useful context.

After the ignored authority and request have been regenerated from clean merged `main`, the only
paid entrypoint is:

```text
uv run --extra remote lowbit-reference-u8 --root . execute-additional \
  --durable-root <durable-root> \
  --confirm-request-sha256 <prepare-additional-request-sha256>
```

`--durable-root` is mandatory. The command authenticates the active provider-local profile without
reading credential values, constructs the exact lazy provider graph twice, records WSL parity, and
only then creates the USD 4.00 local reservation. It passes the additional authority, reservation,
fresh workspace-identity digest, and parity receipt into the sole provider boundary. There is no
retry or fallback command. Do not run this command as a dry-run: it is the one authorized paid
action and consumes the action at `submission_pending`.

If the process stops after the one-shot boundary, leave the marker active. Do not copy the Windows
database back into WSL, start another preparation, or reconstruct state from partial output. Resume
billing reconciliation against the exact mirror named by the marker. Only after that WSL database
reports a terminal settled-success or settled-failure state may it return to Windows:

```text
uv run --extra remote lowbit-reference-u8 --root . billing-capture-additional \
  --query-start <YYYY-MM-DDTHH:00:00Z> \
  --query-end <YYYY-MM-DDTHH:00:00Z>
uv run --extra remote lowbit-reference-u8 --root . settle-additional
uv run --extra remote lowbit-reference-u8 --root . status
```

The capture uses fresh opaque workspace-auth receipts before and after its read-only billing query.
It emits exactly one closed attribution mode: durable call, durable app, billing-only app, or exact
workspace-zero preidentity. Ambiguous identities, incomplete windows, noncanonical workspace-zero
bytes, or workspace drift fail closed and leave settlement blocked.

Only after local settlement reports a terminal state may the state return command run:

```text
uv run --extra remote lowbit-reference-u8 --root . wsl-transfer-return \
  --durable-root <durable-root>
```

Return creates a recoverable Windows database backup, atomically replaces the durable database,
verifies source and destination hashes and integrity, writes an immutable return receipt, and moves
the active marker into ignored transfer history. A missing or mismatched parity receipt, a
nonterminal state, or a hash failure leaves the marker active. The state-transfer commands do not
contact Modal, reserve budget, transfer credentials, or transfer model weights; billing capture is
read-only provider contact and stores only sanitized evidence.

After an authoritatively settled successful baseline, and only then, the zero-spend U9 compiler is:

```text
uv run lowbit-reference-u8 --root . compile-u9-proposal
```

The output remains an ignored, immutable proposal with threshold approval and candidate execution
both false. Unsupported single-sample numeric thresholds remain unset. Configured 262,144-token
context is reported separately from empirically proven-useful context.
