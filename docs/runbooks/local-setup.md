# Local setup and verification

The control plane supports Windows 11 PowerShell and WSL2 Ubuntu. It does not require a GPU, model weights, system-wide Python, driver changes, or administrator access.

## Windows 11

1. Install `uv` using its documented per-user method.
2. From the repository root, run:

```powershell
uv sync --frozen --extra dev
uv run pytest -q
uv run lowbit-db --db results/results.sqlite
uv run lowbit-dry-run --config configs/example-local-dry-run.yaml --db results/results.sqlite
uv run lowbit-modal-plan --config configs/example-modal-dry-run.yaml --db results/results.sqlite --dry-run
```

## WSL2 Ubuntu

Keep the checkout in the Linux filesystem for compute-heavy future work. For scaffold verification, enter the repository directory and run:

```bash
uv sync --frozen --extra dev
uv run pytest -q
uv run lowbit-dry-run --config configs/example-local-dry-run.yaml --db results/wsl-verification.sqlite
uv run lowbit-modal-plan --config configs/example-modal-dry-run.yaml --db results/wsl-verification.sqlite --dry-run
```

## Expected evidence

- Tests pass.
- Both CLIs emit JSON with `ok: true`.
- The remote plan reports `submit: false`, `cloud_upload: false`, and budget USD 0.
- SQLite records completed runs, hardware metadata, transitions, metrics, and zero actual cost.

Do not add a target, download weights, install a compute runtime, or change drivers as part of this scaffold check. Those actions require an approved target-specific plan.
