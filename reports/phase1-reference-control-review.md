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
