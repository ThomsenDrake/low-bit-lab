from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lowbit_lab.config import load_experiment_config, verify_sources
from lowbit_lab.jsonio import emit
from lowbit_lab.provenance import WeightInventory
from lowbit_lab.runtime import runtime_metadata


class ManifestError(ValueError):
    pass


def build_manifest(root: Path, paths: list[Path], lineage: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    entries: list[dict[str, Any]] = []
    for requested in sorted(paths, key=lambda value: value.as_posix()):
        candidate = (
            (root / requested).resolve() if not requested.is_absolute() else requested.resolve()
        )
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise ManifestError(f"manifest input must be a file under root: {requested}")
        relative = candidate.relative_to(root).as_posix()
        digest = hashlib.sha256()
        size = 0
        with candidate.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        entries.append({"path": relative, "sha256": digest.hexdigest(), "size_bytes": size})
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "hash_algorithm": "sha256",
        "lineage": lineage,
        "files": entries,
    }


def build_reference_manifest(
    root: Path, paths: list[Path], inventory: WeightInventory
) -> dict[str, Any]:
    bindings = inventory.bindings
    lineage = {
        "weight_inventory_sha256": inventory.sha256,
        "source_identifier": inventory.source_identifier,
        "source_revision": inventory.source_revision,
        "source_index_sha256": bindings.source_index_sha256,
        "provenance_manifest_sha256": bindings.provenance_manifest_sha256,
        "tokenizer_sha256": bindings.tokenizer_sha256,
        "runtime_lock_sha256": bindings.runtime_lock_sha256,
        "evaluation_lock_sha256": bindings.evaluation_lock_sha256,
        "weight_body_transfer": False,
    }
    return build_manifest(root, paths, lineage)


def write_manifest(
    root: Path, output: Path, paths: list[Path], experiment_config: Path
) -> dict[str, Any]:
    root = root.resolve()
    destination = (root / output).resolve() if not output.is_absolute() else output.resolve()
    if not destination.is_relative_to(root):
        raise ManifestError("output must remain under root")
    config_path = (
        (root / experiment_config).resolve()
        if not experiment_config.is_absolute()
        else experiment_config.resolve()
    )
    if not config_path.is_relative_to(root):
        raise ManifestError("experiment config must remain under root")
    config = load_experiment_config(config_path)
    lineage = {
        "experiment_config_sha256": config.sha256,
        "target_status": config.target_status,
        "target_identifier": config.target_identifier,
        "target_revision": config.target_revision,
        "target_license": config.target_license,
        "tokenizer_path": config.tokenizer_path,
        "tokenizer_sha256": config.tokenizer_sha256,
        "source_hashes": verify_sources(config, root),
        "runtime": runtime_metadata(root, config.runtime_name, config.runtime_revision),
        "true_bits_per_weight": None,
        "kv_cache_format": None,
        "training_config_sha256": None,
        "evaluation_report_sha256": None,
        "scaffold_disclaimer": "no target artifact, weights, training, or evaluation proof",
    }
    manifest = build_manifest(root, paths, lineage)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"ok": True, "output": destination.relative_to(root).as_posix(), "manifest": manifest}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("paths", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        emit(write_manifest(args.root, args.output, args.paths, args.config))
    except Exception as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
