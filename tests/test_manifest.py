import hashlib
import shutil
from pathlib import Path

from lowbit_lab.manifest import build_manifest, build_reference_manifest, write_manifest
from lowbit_lab.provenance import parse_weight_inventory

ROOT = Path(__file__).parents[1]


def test_manifest_hashes_files_and_writes_inside_root(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("traceable\n", encoding="utf-8")
    lineage = {"experiment_config_sha256": "a" * 64}
    manifest = build_manifest(tmp_path, [Path("source.txt")], lineage)
    assert manifest["files"][0]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["lineage"] == lineage


def test_write_manifest_includes_config_lineage(tmp_path: Path) -> None:
    (tmp_path / "configs").mkdir()
    shutil.copy2(ROOT / "PLAN.md", tmp_path / "PLAN.md")
    shutil.copy2(
        ROOT / "configs/example-local-dry-run.yaml",
        tmp_path / "configs/example-local-dry-run.yaml",
    )
    payload = write_manifest(
        tmp_path,
        Path("artifacts/manifest.json"),
        [Path("PLAN.md")],
        Path("configs/example-local-dry-run.yaml"),
    )
    assert payload["manifest"]["lineage"]["target_status"] == "unconfigured"
    assert payload["manifest"]["lineage"]["target_identifier"] is None
    assert (tmp_path / "artifacts/manifest.json").is_file()


def test_reference_manifest_binds_inventory_and_all_authority_identities(
    tmp_path: Path,
) -> None:
    shard = "model-00001-of-00001.safetensors"
    index_bytes = ('{"metadata":{"total_size":90},"weight_map":{"layer":"' + shard + '"}}').encode()
    index_sha256 = hashlib.sha256(index_bytes).hexdigest()
    raw = {
        "schema_version": 1,
        "source": {"identifier": "org/example-model", "revision": "1" * 40},
        "bindings": {
            "provenance_manifest_sha256": "2" * 64,
            "tokenizer_sha256": "3" * 64,
            "runtime_lock_sha256": "4" * 64,
            "evaluation_lock_sha256": "5" * 64,
            "source_index_sha256": index_sha256,
        },
        "limits": {
            "max_shards": 2,
            "per_shard_bytes": 100,
            "aggregate_bytes": 100,
        },
        "index": {
            "path": "model.safetensors.index.json",
            "sha256": index_sha256,
            "tensor_bytes": 90,
        },
        "shards": [
            {
                "path": shard,
                "size_bytes": 100,
                "lfs_sha256": "6" * 64,
                "content_sha256": "6" * 64,
            }
        ],
        "aggregate_bytes": 100,
    }
    inventory = parse_weight_inventory(
        raw,
        source_index_bytes=index_bytes,
        source_shards={shard: (100, "6" * 64)},
    )
    source = tmp_path / "protocol.json"
    source.write_text("{}\n", encoding="utf-8")

    manifest = build_reference_manifest(tmp_path, [Path("protocol.json")], inventory)

    assert manifest["lineage"] == {
        "weight_inventory_sha256": inventory.sha256,
        "source_identifier": "org/example-model",
        "source_revision": "1" * 40,
        "source_index_sha256": index_sha256,
        "provenance_manifest_sha256": "2" * 64,
        "tokenizer_sha256": "3" * 64,
        "runtime_lock_sha256": "4" * 64,
        "evaluation_lock_sha256": "5" * 64,
        "weight_body_transfer": False,
    }
