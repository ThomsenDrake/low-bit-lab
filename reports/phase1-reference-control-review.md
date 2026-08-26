# Phase 1 Signed-CDN Transport Review

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
