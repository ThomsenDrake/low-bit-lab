---
title: Preserve parent preflight truth while binding one regenerated paid child
date: 2026-08-30
applies_to: one-shot provider actions
---

# Durable convention

When an approved action fails before reservation or provider contact, record the failed request as
an immutable zero-spend forfeit. Do not manufacture a reservation, provider identity, or billing
event. A replacement requires a separate, explicitly activated singleton entitlement.

If the paid request includes the reviewed commit or control-plane hash, implementation and merge
necessarily change its bytes. Preserve the approved corrected preflight as parent evidence and
bind the regenerated child request independently. The irreversible claim must store the exact
child request hash, execution scope, and selected WSL parity hash. Reservation and provider-contact
transitions must recheck those bindings atomically.

# State-machine rules

- Opening or migrating a database creates only an empty activation slot.
- Activation validates exact authority and immutable forfeit bytes, then creates one `available`
  entitlement.
- Claim changes `available -> claimed` and is never reversible.
- Reservation may associate the claimed entitlement with one reservation, but release does not
  clear the claim or recreate authority.
- Provider contact consumes the parent grant and child entitlement in the same transaction.
- Downstream provider-identity and submission transitions require both records to be consumed for
  the same reservation, scope, and authentication receipt.

# Migration and return lessons

Fingerprint the complete deployed source schema before any DDL. An unexpected authority-bearing
table is unknown state even when empty; never delete it as normalization.

Returning only SQLite from WSL is incomplete. Before archiving the ownership marker, copy and
verify the exact claimed request, the selected content-addressed parity generation, applicable
terminal evidence, and the database snapshot. Store the selected parity digest in the claim so
multiple pre-claim parity generations cannot make crash recovery ambiguous.

# Testing minimum

Cover generic-parent bypass, unclaimed reservation, double claim, release non-restoration,
request/parity drift at provider contact, atomic rollback, child consumption, unknown-schema
rejection without DDL, and pre-provider WSL return with multiple parity generations.
