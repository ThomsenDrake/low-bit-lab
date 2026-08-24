# Modal boundary

`job_wrapper.py` remains plan-only. `reference_job.py` exposes the reviewed A100-80GB resource
declaration as data. The Modal SDK is version-locked in the `remote` dependency group.

One audited provider primitive exists in `src/lowbit_lab/modal_adapter.py`. It is a no-input,
network-blocked GPU/runtime smoke and cannot load or name a model. Direct calls fail before the Modal
import unless SQLite already contains the exact one-shot `submission_pending` reservation. The
`lowbit-paid-smoke plan` and `verify` commands are read-only; `execute` is the only route to the
adapter and requires a matching ignored approval, explicit scope confirmation, and atomic USD 4.00
reservation. No command in the zero-spend preparation run invokes `execute`.

A successful observation transitions to `settlement_pending`; it does not release or settle budget.
Local settlement requires an authoritative canonical billing receipt bound to the provider call,
billing authority, report identity, and complete delay window. Unknown or mismatched billing fails
closed.

The zero-spend readiness controller remains local-only. The separate smoke handoff describes a
future paid action but never makes it ready or approved.

Reference previews require exact local plan, inventory, runtime, evaluation, and budget identities.
They record `submit:false`, zero requested/actual cost, no uploads, no mounts, no volumes, no secrets,
and all unresolved execution blockers. The smoke cannot clear model memory-fit, cold-path, quality,
throughput, soak, kernel, promotion, or useful-context gates. U8 remains separately unauthorized.
