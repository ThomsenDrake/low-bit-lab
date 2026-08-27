# Phase 1 Modal Serialized-Function Cap Review

Date: 2026-08-27

Mode: report-only review followed by high-confidence fixes

## Verdict

Ready for public review as a zero-spend safety repair. The current execution graph is intentionally
blocked before one-shot consumption because its serialized function exceeds Modal's 65,536-byte
limit. This change does not authorize or perform another provider action.

## Review lenses

### Reproducibility and experiment lineage

The guard uses Modal's own pinned serializer and binds the exact accepted bytes to the SDK
`FunctionInfo` object used during hydration. The provider-observed 259,658-byte failure and current
260,033-byte graph remain testable through the unchecked builder, while the production entrypoint
applies the frozen provider ceiling. Serialization failure writes a terminal, run-free attempt for
auditability but cannot lock a budget reservation.

### Modal-credit safety and failure containment

The size check now occurs before the USD 4 local reservation, read-only SDK identity verification,
submission-pending, entitlement consumption, app creation, image construction, or function
registration. Registered cloudpickle-by-value modules are cleared immediately after the exact bytes
are frozen, including on oversize or serialization failure. Exactly 65,536 bytes remains admissible;
65,537 bytes fails closed.

### Local RTX 5080 compatibility

The repair changes no local CUDA, Torch, driver, allocator, or model behavior. An ext4-backed WSL
execution checkout reproduced the same runtime receipt without the DrvFS `p9_client_rpc` stalls seen
while hashing the 22,259-file environment from `/mnt/c`.

### Security and private-data handling

The tracked change contains no target, workspace display value, credential, local private path, or
provider log payload. It does not enable source mounts or broaden remote source transfer. Publication
scanning remains mandatory.

### Research-loop support

Future paid authority cannot be consumed by a function the provider will reject deterministically.
The larger architectural task—reducing the audited by-value execution graph below 64 KiB—remains
explicit and must be completed before any later provider action could pass this gate. Configured
context remains 262,144 tokens; proven-useful context remains unknown.

## Findings and disposition

- Fixed: the prior local ceiling was 16 MiB, while the provider rejected functions above 64 KiB.
- Fixed: serialization occurred after one-shot consumption and app/image creation.
- Fixed after independent review: an intermediate implementation serialized after reservation and
  tried to fail an already-linked attempt through a received-only transition. Serialization now
  happens before either object exists; a separate received-to-failed audit row has no run link.
- Fixed after independent review: an intermediate implementation hashed preflight bytes but allowed
  Modal hydration to serialize again. The accepted bytes are now injected into the actual pinned SDK
  `FunctionInfo` hydration path and tested against later serializer drift.
- Fixed: temporary serialization policy is cleared immediately after byte freezing and on every
  serialization or cap failure.
- Fixed after re-review: the first pre-reservation design left no record of its failed production
  attempt. The graph-preflight wrapper now records a real SQLite terminal attempt without creating a
  run or reservation.
- Accepted blocker: the audited execution graph remains 259,658 bytes and cannot be submitted under
  the provider limit. No retry or replacement is authorized.
- Accepted blocker: authoritative billing for the consumed failed action is unavailable until the
  complete action window plus provider completeness delay has elapsed.
