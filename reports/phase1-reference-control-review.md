# Phase 1 Signed-CDN Transport Review

## U8 orchestration addendum

- **Reproducibility and lineage:** the ignored request is regenerated from the validated inventory,
  provenance manifest, evaluation lock, runtime lock and receipt, image recipe, provider capability,
  and current clean commit. The paid adapter independently reproduces the request and requires byte
  equality before consuming U8. No target-specific value is added to tracked files.
- **Modal-credit safety and containment:** `prepare` cannot initialize the results database,
  construct a provider client, or contact Modal; it imports the pinned local SDK only to reproduce
  its audited fingerprint. `execute` requires the exact fresh request digest, WSL/Linux watchdog support, a
  fresh HEAD-only topology receipt, deterministic adapter preflight, and an atomic USD 4.00
  reservation. The existing adapter remains the only U8 spawn path, with one GPU/container/spawn,
  2,700 seconds, and zero retries. Ambiguous execute failures report provider contact as unknown.
- **Local RTX compatibility:** orchestration makes no local inference or kernel-support claim. It
  uses the repository-isolated WSL runtime only as a control environment and changes no driver, OS,
  firmware, BIOS, or global setting.
- **Security and private data:** request and topology evidence remain ignored. Origins are immutable
  and query-free; signed redirect values remain transient. CLI output contains only hashes, context
  state, and sanitized status. Publication scanning remains mandatory before merge.
- **Research-loop support:** the command closes the missing transition from merged deterministic
  evidence to the already-audited one-shot adapter. Configured context remains 262,144 tokens;
  proven-useful context remains unknown until remote evaluation evidence succeeds.

Clear finding fixed: the first producer validated source entries, but the paid consumer did not
independently reconstruct them. The adapter now reproduces the complete request from local authority
and rejects byte drift. No promotion threshold or public zero-spend default changed.

Independent review found and fixed two additional high-confidence issues. Immutable origins are now
reconstructed from a recomputed provenance-manifest identity whose repository and revision must
match the validated weight inventory; request data cannot add a new origin host. Standing approval,
attempt creation, approval consumption, and cost reservation now share one immediate transaction,
so a pre-reservation crash or failed gate cannot strand partial approval state. The CLI also reports
known pre-Modal failures as `false` and reserves `unknown` for durable submission-boundary ambiguity.

Merged-main preparation then exposed a stale derived provenance digest in the ignored config. The
refresh path now reproduces provenance, inventory, runtime, and evaluation authority, but permits
only derived provenance/inventory hashes and current commit/control-plane identity to advance. It
rejects any change to the approved source revision, tensor total, evaluation lock, configured
context, or installed-runtime receipt.

Date: 2026-08-26

Scope: signed-CDN amendment implementation against merged parent `a96d5949f2826438b0f219b1dd8633c8bd42f8c1`

Mode: report-only review followed by mechanical high-confidence fixes

## Verdict

Ready for public review after the recorded verification commands pass. The amendment changes only
redirect transport; it does not add an action, retry, provider resource, budget, or promotion
authority.

## Review lenses

### Reproducibility and experiment lineage

The exact amendment statement, canonical child authority, parent authority, parent merge, bootstrap
request, and topology observation are independently bound. The topology evidence records the exact
request digest and the number of inventory artifacts observed. It contains no URL or query value.

### Modal-credit safety and failure containment

The existing one-shot, one-GPU, one-container, 2,700-second, zero-retry, USD 4.00 incremental
boundary is unchanged. Authority and fresh topology validation occur in the deterministic paid gate.
Any submitted or ambiguous action remains one-shot and audit-blocked pending authoritative billing.

### Local RTX 5080 compatibility

This amendment changes direct HTTPS transport only. It makes no local kernel, quantization, driver,
or model-fit claim. Local hardware readiness and remote reference execution remain separate gates.

### Security and private-data handling

Origins remain query-free. Query-bearing redirects require an exact frozen host/path pair plus the
request's closed host list. URL role, canonical path, DNS results, connected peer, redirect count,
and proxy absence are fail-closed. Signed values are forwarded only in request memory and are absent
from receipts, evidence, CLI output, and sanitized tracebacks. No credential, cookie, caller header,
secret, mount, volume, or private payload is introduced.

### Research-loop support

Every immutable artifact is HEAD-observed locally, then later transferred once and held unusable
until declared length and SHA-256 verification succeeds. The evaluation lock and 262,144-token
configured envelope are unchanged. Proven-useful context remains unknown until empirical evaluation
completes; the transport preflight cannot promote that state.

## Findings and disposition

- Fixed: the first draft duplicated redirect/DNS/peer validation between GET and HEAD paths. Both
  now use one provider-neutral walker.
- Fixed: failed HEAD requests could retain signed query values in chained exceptions. Failures now
  cross the boundary as fixed messages without a cause, with a runtime-assembled sentinel test.
- Fixed: sampling only the first inventory artifact could allow later redirect drift to consume the
  one-shot action. The observer now covers the complete declared inventory and binds the count.
- Fixed: connection cleanup was success-path-only in the first draft. HEAD connections now close in
  `finally`.
- Accepted residual: local HEAD routing can differ from remote regional GET routing. Evidence states
  `remote_route_fidelity_proven: false`; remote enforcement remains fail-closed and one-shot.
- Accepted residual: provider route or billing behavior can change after the freshness check. The
  amendment does not claim a provider-enforced dollar cap or eliminate crash-rescheduling risk.

## Required verification

```text
python -m pytest tests/test_reference_authority.py tests/test_reference_bootstrap.py -q
python -m pytest tests/test_reference_execution.py tests/test_reference_backend.py tests/test_reference_transport.py -q
python -m pytest tests/test_reference_modal_adapter.py tests/test_modal_job.py -q
python -m pytest -q
python -m ruff check .
```

## 2026-08-26 runtime-receipt stabilization review

The merged-main U8 preparer exposed probe-created bytecode drift and a raw-versus-canonical receipt
digest mismatch. The repair preserves the approved complete-tree receipt: 909 post-receipt files
were mechanically proven to be `.pyc` files below `__pycache__` and moved to ignored quarantine;
nothing was deleted or overwritten.

- Reproducibility: all native and WSL inventory/framework probe command forms now share explicit
  `-I -B -c` flags. Semantic receipt verification and exact persisted-byte hashing use one snapshot.
- Modal safety: the repair performs no provider import, reservation, contact, body transfer, or
  weight transfer. Existing one-shot and USD limits are unchanged.
- Local RTX 5080: the locked Python, distributions, CUDA build, driver observation, device
  capability, and GPU memory remain unchanged and the original tree receipt reproduces.
- Security/privacy: quarantine stays ignored; no paths, cache contents, target details, or local
  hardware evidence enter tracked artifacts.
- Research loop: merged-main preparation can now bind the exact approved runtime receipt without
  converting generated cache drift into a new experiment identity.

Independent review found and fixed three issues: environment-only bytecode suppression was ignored
under isolated Python, receipt parsing and hashing initially used two snapshots, and the downstream
preview gate compared a canonical digest with an exact-byte digest. Focused tests cover the native
and WSL command shapes and noncanonical-but-valid persisted receipt bytes.

## 2026-08-26 evaluation-lock lineage review

The merged-main preparer next exposed a second persisted-versus-canonical identity boundary. The
ignored config intentionally binds the exact evaluation-lock file bytes, while inventory provenance
and the closed remote capability bind the validated canonical representation.

- Reproducibility and lineage: each exact-file/canonical comparison derives both identities from one
  snapshot. Subsequent paid-boundary reproduction intentionally rereads and revalidates current
  authority, binding exact-file SHA-256 to config and canonical SHA-256 to inventory and remote
  request lineage.
- Modal safety and containment: canonicalization occurs before provider contact; no reservation,
  SDK execution primitive, or artifact transfer is part of this repair.
- Local RTX 5080 compatibility: runtime, CUDA, hardware, and memory gates are untouched.
- Security and private-data handling: only the approved ignored evaluation lock is read. Canonical
  bytes enter the already closed capability; target data remains untracked and no signed URL is
  logged or persisted.
- Research-loop support: the configured 262,144-token envelope is preserved. Proven-useful context
  remains unknown pending empirical U8 evidence.

Independent simplify review found no unnecessary work or reusable exact-contract helper. Quality
review found one ambiguous local hash name; local variables now explicitly distinguish file-byte
and canonical identities while retaining the approved serialized schema keys.

## 2026-08-26 provider SDK lineage review

Merged-main preparation then found that the validated provider-capability summary omitted the SDK
version required by the bootstrap request. The receipt validator already reproduced and validated
that field, but the consumer incorrectly assumed the original nested receipt shape.

- Reproducibility and lineage: the closed validator projection now carries the already-validated SDK
  version; request construction performs no independent receipt or SDK read.
- Modal safety and containment: provider inspection remains offline and local. No reservation,
  provider contact, or artifact transfer is added.
- Local RTX 5080 compatibility: no runtime, CUDA, hardware, or memory behavior changes.
- Security and private-data handling: the projection adds one public package-version string and does
  not broaden the receipt, target, credential, or signed-query surface.
- Research-loop support: deterministic bootstrap request construction can proceed while configured
  context remains 262,144 tokens and proven-useful context remains unknown.

Simplify review found the narrow projection to be the smallest safe change. Independent review and
the exact-result test verify the consumer receives only validated summary data.

## 2026-08-26 cross-platform runtime-tree review

Native WSL verification exposed four deeply nested public Torch license files that Windows found
but treated as non-files beyond its legacy path limit. The earlier Windows receipt contained 22,255
files; the complete tree contains 22,259.

- Reproducibility and lineage: Windows tree traversal now uses extended-length paths for enumeration,
  metadata, resolution, and content hashing while retaining platform-neutral relative-path identity.
- Modal safety and containment: the fix is wholly local and precedes reservation or provider contact.
- Local RTX 5080 compatibility: interpreter, distributions, executable digest, CUDA build, driver,
  device capability, and memory observations already matched across Windows and WSL.
- Security and private-data handling: all symlinks and Windows reparse points fail closed, and every
  resolved file must remain beneath the resolved package root before its bytes are read.
- Research-loop support: the ignored receipt will be regenerated only after merged code includes all
  runtime files; configured 262,144 context remains distinct from unproven useful context.

Independent review found and fixed a lexical-confinement regression and a per-file root-resolution
cost. Windows tests cover both a file beyond 260 characters and a junction escape.
