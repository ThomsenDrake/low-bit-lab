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

## Publication guard

Keep target identifiers, immutable revisions, target-specific hardware evidence, promotion
thresholds, and reports in the ignored local directories listed in `.gitignore`. Use an ignored manifest such as
`configs/local/publication.yaml` to name the public remote and the exact values that must never enter
Git:

```yaml
schema_version: 1
public_remote: origin
private_values:
  - kind: target_identifier
    value: replace-with-the-local-value
```

Allowed `kind` values are `target_identifier`, `target_revision`, `hardware_evidence`,
`promotion_threshold`, `private_path`, and `other_sensitive`. Add every sensitive local value to the
manifest; the manifest itself must remain ignored. Before publication, run:

```powershell
uv run python -m lowbit_lab.publication --manifest configs/local/publication.yaml
```

The command emits JSON and exits nonzero if it finds a protected value, a private Windows or WSL
path, a GPU UUID, or a credential-shaped value in tracked content or outgoing Git history. It also
fails closed when the configured public remote has no unambiguous tracking base. Findings report
only categories and source classes; matched values and raw object content are never printed.

Do not add a target, download weights, install a compute runtime, or change drivers as part of this scaffold check. Those actions require an approved target-specific plan.

## Runtime decision, lock preview, and probe

Runtime activation starts with `decide_baseline_runtime`, a read-only comparison of explicit
architecture-support declarations and measured VRAM, RAM, disk, runtime-buffer, and KV-cache
envelopes. Its result is only `selected`, `deferred`, or `rejected`; even `selected` always reports
`inference_compatibility_proven: false`. A framework package or visible GPU is not runtime proof.

[`configs/runtime-lock.example.json`](../../configs/runtime-lock.example.json) documents the closed,
target-neutral schema. Its `.invalid` URLs and illustrative byte identities make it a schema example,
not activation authority. Prepare an authoritative lock only in ignored `configs/local/`, replacing
every example entry with the immutable HTTPS URL, exact byte size, and lowercase SHA-256 for:

- one bootstrap executable;
- one managed CPython 3.12 artifact; and
- every direct and transitive wheel from a complete binary-only resolution.

The lock must keep `resolution.status` at `complete`, `binary_only` at `true`, and
`apply_index_access` at `false`. `parse_runtime_lock` rejects unknown fields, incomplete resolution,
duplicates, sdists or compile requests, unsafe paths, and cap drift. `preview_runtime_lock` then
returns the exact planned byte total without reading the artifact directory, contacting a server, or
installing anything. Fetch and offline environment creation remain separate, explicitly authorized
apply operations; this repository does not run them during preview.

Before any offline apply, store each already-obtained artifact at
`artifacts/local/runtime/<sha256>/<filename>`. `verify_local_artifact_set` checks repository
confinement, file type, exact size, SHA-256, artifact count, and aggregate bytes. It performs no
extraction or installation and stops on the first missing or drifted artifact.

`run_wsl_cuda_probe` accepts only a repository-local managed-Python path and a verified lock hash.
It uses one isolated, bounded subprocess (maximum 60 seconds and 64 KiB JSON output) and refuses
root execution. Evidence records separate `observed`, `missing`, `failed`, or `unknown` states for
WSL, Python 3.12, required packages, driver, GPU, CUDA build and availability, device capability,
small allocation, deterministic arithmetic, and synchronization. Raw stderr, exception messages,
GPU names, UUIDs, usernames, and paths are discarded. Only every check being `observed` proves the
bounded framework path; target support and inference compatibility remain explicitly false.
