# Low-Bit Lab

A target-neutral, local-first control plane for reproducible low-bit research.

The scaffold records experiment lineage in SQLite, validates immutable configs, generates SHA-256 artifact manifests, and exposes local and remote dry-run CLIs. Paid execution, uploads, scheduling, weights, and destructive cleanup are disabled. The checked-in budget is frozen at USD 0.

## Quick verification

Install [uv](https://docs.astral.sh/uv/), then run:

```powershell
uv sync --frozen --extra dev
uv run pytest -q
uv run lowbit-db init --db results/results.sqlite
uv run lowbit-dry-run --config configs/example-local-dry-run.yaml
uv run lowbit-modal-plan --config configs/example-modal-dry-run.yaml --dry-run
```

The last command only produces and records a plan. There is no submission path in the scaffold.

See `PLAN.md` for authority boundaries, `SPEC.md` for contracts, and `docs/runbooks/local-setup.md` for Windows 11 and WSL2 guidance.

## Before target-specific work

Write and approve a target-specific Phase 1 plan. It must pin provenance, an immutable revision, evaluation criteria, local compatibility, privacy handling, and any proposed budget. Do not place private data or credentials in this repository.

## License

MIT
