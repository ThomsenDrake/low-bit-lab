# Phase 1 Replacement Billing Settlement Review

Date: 2026-08-27

Mode: report-only review followed by high-confidence fixes

## Verdict

Ready for public review as a zero-spend reconciliation path. It cannot execute Modal work, restore
the consumed entitlement, or authorize a retry. Live capture remains time-gated by the provider's
complete-hour billing window and 3,600-second delay.

## Review lenses

### Reproducibility and experiment lineage

The canonical receipt binds the replacement reservation, execution scope, consumed entitlement,
authenticated workspace identity, provider-environment scope, billing authority and method,
stopped app evidence, exact sanitized report bytes, interval, cost, and distinct pre/post
authentication receipts. The database revalidates every byte and the exact source run state inside
one immediate transaction.

### Modal-credit safety and failure containment

Capture invokes only authenticated app-list and billing-report reads. Settlement records the failed
action as terminal and never returns entitlement authority. Authoritative cost at or below USD 4.00
replaces the reservation in committed-cost accounting; cost above USD 4.00 is recorded before a
terminal budget-failure exception.

### Local RTX 5080 compatibility

The change is control-plane-only and modifies no CUDA, Torch, driver, kernel, allocator, or model
behavior. Provider evidence capture remains in the isolated WSL environment.

### Security and private-data handling

Provider app and billing responses are filtered in memory. Persisted evidence contains only the
target-neutral reference app identity and its own resource-cost rows. Unrelated descriptions,
environment rows, and costs are not stored. Workspace identity remains a digest; credentials are
never read into project code or artifacts.

### Research-loop support

The audit-blocked replacement can become a fully costed terminal failure without inventing a call
identity or relabeling an app ID. This clears accounting ambiguity but does not produce baseline
metrics. Configured context remains 262,144 tokens and proven-useful context remains unknown.

## Findings and disposition

- Fixed: status previously omitted the consumed replacement reservation and falsely reported no
  provider contact.
- Fixed: billing rows with the reference description but a different app ID now fail as ambiguous.
- Fixed: pre/post workspace authentication receipts must be distinct.
- Fixed: the app evidence now records `running_tasks` and makes no lifetime-task claim.
- Fixed: the settlement receipt binds the provider-environment digest through config, authority,
  capture, and transactional validation.
- Fixed: only the exact `created -> failed` compare-and-set may record the run transition.
- Fixed: exact integer fields reject boolean and floating-point substitutions.
- Fixed: provider billing costs and resource names must already be nonempty strings; capture never
  coerces unknown provider schema into valid evidence.
- Fixed: nested authentication validation is translated into the replacement settlement error
  contract before it crosses the database boundary.
- Fixed: local evidence reads are bounded before JSON parsing and before the write transaction.
- Accepted blocker: live billing capture cannot occur until the full provider completeness window.
- Accepted terminal state: the only replacement was consumed; no retry or second replacement exists.
