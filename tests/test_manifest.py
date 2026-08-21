import hashlib
import shutil
from pathlib import Path

from lowbit_lab.manifest import build_manifest, write_manifest

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
