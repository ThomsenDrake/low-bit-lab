# Add a safe runtime-receipt generator

## Requirements

- Expose the existing complete environment observation through a small JSON-output CLI.
- Confine lock and output paths to the repository.
- Write canonical, deterministic pretty JSON atomically.
- Refuse overwrite by default and require an explicit `--replace` flag.
- Report only digest and aggregate tree counts; never emit local paths or hardware details.
- Perform no provider contact, reservation, weight transfer, or destructive cleanup.

## Acceptance criteria

- A merged-main command regenerates the ignored receipt reproducibly.
- Existing evidence cannot be replaced accidentally.
- Focused/full tests, lint, publication/privacy, simplification, and review pass.
