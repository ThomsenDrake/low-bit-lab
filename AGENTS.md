# Agent Instructions

Read `PLAN.md` in full before acting. Read relevant `docs/solutions/` notes before future planning.

## Authority

- Preserve the unconfigured target and zero-spend defaults unless a human explicitly approves a new controlling plan.
- Do not submit remote jobs, upload data, download weights, enable scheduling, or perform destructive cleanup.
- Do not modify operating systems, drivers, firmware, BIOS, or global configuration.
- Never store credentials, private code, personal data, work data, or machine-specific private paths in durable artifacts.
- Stop on unknown state, unknown failure mode, provenance failure, privacy risk, or budget failure.

## Engineering conventions

- Prefer composable CLIs with JSON output.
- Pin dependencies and hash inputs and artifacts.
- Use closed schemas and explicit state transitions.
- Record failed validation attempts.
- Keep configured capability separate from proven usefulness.
- Keep generated databases and large artifacts out of Git.
- Make authority enforceable in code and tests, not only prose.

## Workflow

Use Brainstorm, Plan, Work, Simplify, Review, and Compound. Store implementation-ready plans in `docs/plans/` and reusable lessons in `docs/solutions/`. Scheduling remains disabled until a human has manually tested and approved the controller.

