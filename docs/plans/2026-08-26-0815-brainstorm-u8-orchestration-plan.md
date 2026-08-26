# Requirements brainstorm: U8 orchestration boundary

## Problem

The reviewed U8 adapter accepts an already-reserved capability, but merged `main` has no
production command that can construct that capability from ignored local evidence.  The gap must
be closed without adding a second provider path or moving target-specific data into Git.

## Requirements

- Provide one target-neutral CLI whose live path is the sole caller of `submit_reference`.
- Reproduce the canonical bootstrap request from hash-verified, ignored local inputs.
- Bind the exact merged commit, control-plane digest, runtime receipt, immutable inventory,
  evaluation lock, image recipe, provider capability, billing authority, publication manifest,
  and the complete source-artifact inventory.
- Derive approval from the closed standing-authority chain; do not require a new human statement,
  plan hash, challenge, contract, or execution-scope approval.
- Register the challenge, attach the derived approval, and reserve the full USD 4.00 action cap in
  one explicit preparation sequence before constructing the adapter capability.
- Revalidate all deterministic gates immediately before the adapter consumes the one U8 slot.
- Keep request, capability, database, topology, and execution evidence under ignored local paths.
- Never persist signed redirect URLs or query values.  Source origins remain query-free.
- Expose a zero-spend `prepare` operation and an explicit `execute` operation.  Preparation must
  never import Modal, reserve money, consume U8, contact a provider, or download artifact bodies.
- Offline inspection of the pinned Modal SDK is allowed, but preparation must never construct a
  client, authenticate, initialize an app, or contact the provider.
- `execute` must fail closed outside WSL/Linux, on a dirty tree, stale or incomplete evidence,
  source/hash drift, privacy findings, topology drift, an active/ambiguous reservation, or a spent
  authority slot.
- Preserve one GPU, one container, one spawn, 2,700 seconds, zero retries, USD 4.00 incremental,
  and USD 4.00270969 cumulative limits.
- Return concise JSON only.  Never return target identifiers, URLs, local absolute paths, headers,
  credentials, signed queries, or private evidence contents.
- Keep configured 262,144-token context distinct from empirically proven-useful context.
- Add focused tests that prove preparation is side-effect free, reservation is atomic, capability
  fields are freshly derived, live confirmation is exact, Modal cannot be reached on failed gates,
  and public scans remain target-neutral.

## Non-requirements

- No new remote function, retry, provider, GPU, mount, volume, secret, schedule, storage, cleanup,
  conversion, training, candidate evaluation, promotion, or U9 threshold approval.
- No attempt to make the local USD cap provider-enforced.
- No settlement inference from local timing or application output.
