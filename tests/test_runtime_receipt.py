from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import lowbit_lab.runtime_receipt as runtime_receipt
import lowbit_lab.safe_files as safe_files


def _observe(*, root: Path, lock: object) -> dict[str, object]:
    assert root.is_absolute()
    assert lock is not None
    return {
        "schema_version": 1,
        "package_tree": {"file_count": 2, "size_bytes": 3, "sha256": "a" * 64},
    }


def test_generator_is_atomic_deterministic_and_replace_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "lock.json"
    lock_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(runtime_receipt, "load_runtime_lock", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(runtime_receipt, "observe_installed_environment", _observe)
    output = Path("artifacts/local/receipt.json")

    result = runtime_receipt.generate_runtime_receipt(
        root=tmp_path, runtime_lock_path=Path("lock.json"), output_path=output
    )
    content = (tmp_path / output).read_bytes()

    expected = json.dumps(_observe(root=tmp_path, lock=object()), indent=2, sort_keys=True) + "\n"
    assert content == expected.encode()
    assert result == {
        "file_count": 2,
        "ok": True,
        "provider_contacted": False,
        "receipt_sha256": hashlib.sha256(content).hexdigest(),
        "replaced": False,
        "size_bytes": 3,
        "weights_transferred": False,
    }
    with pytest.raises(runtime_receipt.RuntimeReceiptError, match="already exists"):
        runtime_receipt.generate_runtime_receipt(
            root=tmp_path, runtime_lock_path=lock_path, output_path=output
        )
    replaced = runtime_receipt.generate_runtime_receipt(
        root=tmp_path, runtime_lock_path=lock_path, output_path=output, replace=True
    )
    assert replaced["replaced"] is True


def test_generator_rejects_paths_outside_repository(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-receipt.json"
    with pytest.raises(runtime_receipt.RuntimeReceiptError, match="outside the repository"):
        runtime_receipt.generate_runtime_receipt(
            root=tmp_path,
            runtime_lock_path=Path("lock.json"),
            output_path=outside,
        )


def test_generator_rejects_output_symlink_without_touching_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"preserve")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("file symlink creation is not available")
    monkeypatch.setattr(runtime_receipt, "load_runtime_lock", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(runtime_receipt, "observe_installed_environment", _observe)

    with pytest.raises(runtime_receipt.RuntimeReceiptError, match="filesystem alias"):
        runtime_receipt.generate_runtime_receipt(
            root=tmp_path,
            runtime_lock_path=Path("lock.json"),
            output_path=Path("alias.json"),
            replace=True,
        )
    assert target.read_bytes() == b"preserve"


def test_generator_does_not_overwrite_destination_created_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "lock.json"
    lock_path.write_text("{}", encoding="utf-8")
    output = tmp_path / "receipt.json"
    monkeypatch.setattr(runtime_receipt, "load_runtime_lock", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(runtime_receipt, "observe_installed_environment", _observe)
    real_link = safe_files.os.link

    def racing_link(source: Path, destination: Path) -> None:
        destination.write_bytes(b"racer")
        real_link(source, destination)

    monkeypatch.setattr(safe_files.os, "link", racing_link)
    with pytest.raises(runtime_receipt.RuntimeReceiptError, match="already exists"):
        runtime_receipt.generate_runtime_receipt(
            root=tmp_path, runtime_lock_path=lock_path, output_path=output
        )
    assert output.read_bytes() == b"racer"
