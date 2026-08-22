from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from lowbit_lab.runtime import (
    RuntimeContractError,
    decide_baseline_runtime,
    hardware_metadata,
    load_runtime_lock,
    parse_runtime_lock,
    preview_runtime_lock,
    verify_local_artifact_set,
)
from lowbit_lab.runtime_probe import PROBE_SCRIPT, run_wsl_cuda_probe

SHA_A = hashlib.sha256(b"uv").hexdigest()
SHA_B = hashlib.sha256(b"python").hexdigest()
SHA_C = hashlib.sha256(b"wheel").hexdigest()


def _lock(root: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "runtime_id": "generic-cuda-runtime",
        "python_version": "3.12.11",
        "artifact_root": "artifacts/local/runtime",
        "resolution": {
            "status": "complete",
            "binary_only": True,
            "apply_index_access": False,
            "allowed_hosts": ["example.invalid"],
        },
        "per_artifact_cap_bytes": 10,
        "aggregate_cap_bytes": 30,
        "artifacts": [
            {
                "role": "uv_bootstrap",
                "name": "uv",
                "version": "0.12.5",
                "url": "https://example.invalid/uv.bin",
                "filename": "uv.bin",
                "size_bytes": 2,
                "sha256": SHA_A,
                "binary_format": "standalone_binary",
                "direct": True,
            },
            {
                "role": "managed_cpython",
                "name": "cpython",
                "version": "3.12.11",
                "url": "https://example.invalid/python.tar.zst",
                "filename": "python.tar.zst",
                "size_bytes": 6,
                "sha256": SHA_B,
                "binary_format": "binary_archive",
                "direct": True,
            },
            {
                "role": "python_distribution",
                "name": "example-dependency",
                "version": "1.0.0",
                "url": "https://example.invalid/example.whl",
                "filename": "example.whl",
                "size_bytes": 5,
                "sha256": SHA_C,
                "binary_format": "wheel",
                "direct": True,
            },
        ],
    }


def test_runtime_decision_selects_only_declared_supported_fitting_runtime() -> None:
    decision = decide_baseline_runtime(
        declarations=[
            {
                "runtime_id": "generic-runtime",
                "architecture_support": "declared",
                "maintained_binary_available": True,
                "license_and_provenance_verified": True,
                "required_vram_bytes": 8,
                "required_ram_bytes": 10,
                "required_disk_bytes": 12,
                "runtime_buffer_bytes": 2,
                "kv_cache_bytes": 3,
            }
        ],
        measured={
            "vram_bytes": 13,
            "ram_bytes": 15,
            "disk_bytes": 17,
            "runtime_buffer_bytes": 2,
            "kv_cache_bytes": 3,
        },
    )
    assert decision == {
        "status": "selected",
        "runtime_id": "generic-runtime",
        "reason_codes": ["DECLARED_SUPPORTED_BINARY_FITS"],
        "inference_compatibility_proven": False,
    }


@pytest.mark.parametrize(
    ("field", "value", "status", "reason"),
    [
        ("architecture_support", "unknown", "deferred", "ARCHITECTURE_SUPPORT_UNRESOLVED"),
        ("maintained_binary_available", False, "rejected", "NO_MAINTAINED_BINARY"),
        ("license_and_provenance_verified", False, "deferred", "PROVENANCE_UNRESOLVED"),
        ("required_vram_bytes", 14, "rejected", "RESOURCE_ENVELOPE_EXCEEDED"),
    ],
)
def test_runtime_decision_defers_or_rejects(
    field: str, value: object, status: str, reason: str
) -> None:
    declaration = {
        "runtime_id": "generic-runtime",
        "architecture_support": "declared",
        "maintained_binary_available": True,
        "license_and_provenance_verified": True,
        "required_vram_bytes": 8,
        "required_ram_bytes": 10,
        "required_disk_bytes": 12,
        "runtime_buffer_bytes": 2,
        "kv_cache_bytes": 3,
    }
    declaration[field] = value
    result = decide_baseline_runtime(
        declarations=[declaration],
        measured={
            "vram_bytes": 13,
            "ram_bytes": 15,
            "disk_bytes": 17,
            "runtime_buffer_bytes": 2,
            "kv_cache_bytes": 3,
        },
    )
    assert result["status"] == status
    assert reason in result["reason_codes"]
    assert result["inference_compatibility_proven"] is False


def test_lock_preview_accounts_for_exact_bytes_without_filesystem_reads(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    preview = preview_runtime_lock(lock)
    assert preview["planned_bytes"] == 13
    assert preview["artifact_count"] == 3
    assert preview["all_artifacts_resolved"] is True
    assert preview["network_performed"] is False
    assert preview["installation_performed"] is False


def test_tracked_example_is_a_valid_target_neutral_schema() -> None:
    root = Path(__file__).resolve().parents[1]
    lock = load_runtime_lock(Path("configs/runtime-lock.example.json"), root=root)
    assert preview_runtime_lock(lock)["planned_bytes"] == 23
    assert all("example.invalid" in artifact.url for artifact in lock.artifacts)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda raw: raw.update({"extra": True}), "unknown keys"),
        (lambda raw: raw["artifacts"].append(dict(raw["artifacts"][0])), "duplicate"),
        (lambda raw: raw["artifacts"][2].update({"binary_format": "sdist"}), "binary"),
        (lambda raw: raw["artifacts"][2].update({"filename": "pkg.tar.gz"}), "wheels"),
        (lambda raw: raw["artifacts"][2].update({"binary_format": "binary_archive"}), "wheels"),
        (lambda raw: raw["artifacts"][2].update({"direct": False}), "direct wheel"),
        (lambda raw: raw["artifacts"][2].update({"build_required": True}), "unknown keys"),
        (lambda raw: raw["artifacts"][1].update({"sha256": "0" * 64}), "resolved"),
        (lambda raw: raw.update({"artifact_root": "../outside"}), "repository-relative"),
        (lambda raw: raw.update({"artifact_root": "artifacts/runtime"}), "artifacts/local/runtime"),
        (
            lambda raw: raw.update({"artifact_root": "artifacts/local/runtimeevil"}),
            "artifacts/local/runtime",
        ),
        (lambda raw: raw["artifacts"][0].update({"url": "https://example.invalid/a?x=1"}), "HTTPS"),
        (
            lambda raw: raw["artifacts"][0].update(
                {"url": "https://example.invalid:8443/a"}
            ),
            "HTTPS",
        ),
        (lambda raw: raw.update({"aggregate_cap_bytes": 12}), "aggregate"),
        (lambda raw: raw["resolution"].update({"status": "partial"}), "complete"),
    ],
)
def test_runtime_lock_rejects_invalid_or_unresolved_content(
    tmp_path: Path, mutation: object, match: str
) -> None:
    raw = _lock(tmp_path)
    mutation(raw)
    with pytest.raises(RuntimeContractError, match=match):
        parse_runtime_lock(raw, root=tmp_path)


def test_verified_local_set_checks_size_and_hash(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    artifact_root = tmp_path / "artifacts/local/runtime"
    for data, digest, filename in (
        (b"uv", SHA_A, "uv.bin"),
        (b"python", SHA_B, "python.tar.zst"),
        (b"wheel", SHA_C, "example.whl"),
    ):
        path = artifact_root / digest / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    verified = verify_local_artifact_set(lock, root=tmp_path)
    assert verified["verified_bytes"] == 13
    assert verified["complete"] is True
    (artifact_root / SHA_C / "example.whl").write_bytes(b"bad")
    with pytest.raises(RuntimeContractError, match="size mismatch"):
        verify_local_artifact_set(lock, root=tmp_path)


@pytest.mark.parametrize("missing_index", [0, 1, 2])
def test_verified_local_set_distinguishes_missing_artifact_roles(
    tmp_path: Path, missing_index: int
) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    artifact_root = tmp_path / "artifacts/local/runtime"
    data_by_digest = {SHA_A: b"uv", SHA_B: b"python", SHA_C: b"wheel"}
    for index, artifact in enumerate(lock.artifacts):
        if index == missing_index:
            continue
        path = artifact_root / artifact.sha256 / artifact.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data_by_digest[artifact.sha256])
    with pytest.raises(
        RuntimeContractError, match=f"missing: {lock.artifacts[missing_index].role}"
    ):
        verify_local_artifact_set(lock, root=tmp_path)


def _probe_payload(**overrides: object) -> dict[str, object]:
    fields = {
        name: {"state": "observed"}
        for name in (
            "os",
            "python",
            "packages",
            "driver",
            "gpu",
            "cuda_build",
            "cuda_availability",
            "device_capability",
            "small_allocation",
            "deterministic_operation",
            "synchronization",
        )
    }
    fields["python"]["version"] = "3.12.11"
    fields["os"]["version"] = "WSL2"
    fields["packages"]["versions"] = {"torch": "2.13.0", "transformers": "5.15.1"}
    fields["driver"]["version"] = "13030"
    fields["gpu"]["bytes"] = 16_000_000_000
    fields["cuda_build"]["version"] = "13.0"
    fields["device_capability"]["value"] = [9, 0]
    fields["small_allocation"]["bytes"] = 1024
    fields.update(overrides)
    return {"schema_version": 1, "checks": fields}


def test_embedded_probe_script_compiles() -> None:
    compile(PROBE_SCRIPT, "<runtime-probe>", "exec")


def test_probe_success_is_framework_only_and_sanitized(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args[0], 0, json.dumps(_probe_payload()), "secret stderr"
        )

    result = run_wsl_cuda_probe(
        python_path=python, root=tmp_path, lock_sha256="a" * 64, runner=runner
    )
    assert result["status"] == "observed"
    assert result["framework_readiness_proven"] is True
    assert result["target_support_proven"] is False
    assert "secret" not in json.dumps(result)


def test_probe_rejects_versions_that_do_not_match_runtime_lock(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    result = run_wsl_cuda_probe(
        python_path=python,
        root=tmp_path,
        lock_sha256="a" * 64,
        expected_python_version="3.12.12",
        expected_package_versions={"torch": "2.13.0", "transformers": "5.15.1"},
        runner=lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, json.dumps(_probe_payload()), ""
        ),
    )
    assert result["status"] == "unknown"
    assert result["reason_code"] == "PYTHON_LOCK_MISMATCH"


@pytest.mark.parametrize(
    "failed_check",
    [
        "cuda_availability",
        "device_capability",
        "small_allocation",
        "deterministic_operation",
        "synchronization",
    ],
)
def test_probe_fails_each_cuda_stage(tmp_path: Path, failed_check: str) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    payload = _probe_payload()
    payload["checks"][failed_check] = {"state": "failed", "reason_code": "PROBE_FAILED"}
    result = run_wsl_cuda_probe(
        python_path=python,
        root=tmp_path,
        lock_sha256="a" * 64,
        runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, json.dumps(payload), ""),
    )
    assert result["status"] == "failed"
    assert result["framework_readiness_proven"] is False


def test_probe_timeout_is_sanitized_unknown(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args[0], 5, output="C:/Users/private", stderr="GPU-secret")

    result = run_wsl_cuda_probe(
        python_path=python, root=tmp_path, lock_sha256="a" * 64, runner=timeout
    )
    assert result["status"] == "unknown"
    assert result["reason_code"] == "PROBE_TIMEOUT"
    assert "private" not in json.dumps(result)


def test_probe_missing_package_does_not_pass(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    payload = _probe_payload()
    payload["checks"]["packages"] = {
        "state": "missing",
        "reason_code": "PACKAGE_MISSING",
        "missing": ["torch"],
    }
    result = run_wsl_cuda_probe(
        python_path=python,
        root=tmp_path,
        lock_sha256="a" * 64,
        runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, json.dumps(payload), ""),
    )
    assert result["status"] == "missing"
    assert result["framework_readiness_proven"] is False
    assert result["checks"]["packages"]["missing"] == ["torch"]


def test_hardware_metadata_does_not_request_or_persist_gpu_uuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, "Generic GPU, 16384, 600.00", "")

    monkeypatch.setattr("lowbit_lab.runtime.shutil.which", lambda _: "nvidia-smi")
    monkeypatch.setattr("lowbit_lab.runtime.subprocess.run", run)
    metadata = hardware_metadata()

    assert all("uuid" not in argument.lower() for argument in captured)
    assert "GPU-" not in json.dumps(metadata)
