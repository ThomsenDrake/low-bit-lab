# Scaffold Specification

## Control plane

- Python 3.12 with dependencies pinned by `uv.lock`.
- Small CLIs emit JSON and return nonzero on failure.
- SQLite is the durable local record for attempts, runs, state transitions, metrics, artifacts, costs, runtime metadata, source hashes, and local hardware observations.
- Experiment configs use a closed YAML schema and canonical JSON hashing.
- Repository inputs and generated manifests use SHA-256.

## Target state

The public examples use `target.status: unconfigured` and null target details. A configured target requires a nonempty identifier, immutable lowercase revision hash, license, and optional tokenizer path plus hash. Configuration does not imply weights are present or any capability is proven.

## Safety state

- `weights_required` is false.
- `privacy.allow_cloud_upload` is false.
- `modal.submit` is false.
- The checked-in budget guard accepts only zero requested cost.
- The remote wrapper requires `--dry-run` and contains no submit call.
- Experiment configs and result databases are confined to repository subdirectories.

## Evaluation interface

The initial families are coding, tool-call validity, long-context retrieval, throughput, memory, and soak testing. Fixtures are interface placeholders, not benchmark results. `configured_tokens` and `useful_proven` are stored separately.

## Activation contract

Target download, conversion, training, paid compute, cloud upload, or scheduling requires a separately approved plan and reviewed code change. Prose alone cannot activate those operations.

