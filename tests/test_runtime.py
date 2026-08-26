from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lowbit_lab.runtime import (
    RuntimeContractError,
    _tree_receipt,
    _windows_extended_path_text,
    build_installed_environment_receipt,
    decide_baseline_runtime,
    hardware_metadata,
    load_runtime_lock,
    parse_runtime_lock,
    preview_runtime_lock,
    verify_current_installed_environment,
    verify_installed_environment_receipt,
    verify_local_artifact_set,
)
from lowbit_lab.runtime_probe import (
    ENVIRONMENT_INVENTORY_SCRIPT,
    PROBE_PYTHON_FLAGS,
    PROBE_SCRIPT,
    WSL_PROBE_ENV,
    _isolated_python_command,
    _wsl_isolated_python_command,
    run_environment_inventory_probe,
    run_wsl_cuda_probe,
)

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


def test_runtime_receipt_schema_is_closed_and_target_neutral() -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "configs/runtime-receipt.schema.json").read_text())
    assert schema["additionalProperties"] is False
    assert schema["properties"]["interpreter"]["additionalProperties"] is False
    assert "target" not in json.dumps(schema).lower()


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
            lambda raw: raw["artifacts"][0].update({"url": "https://example.invalid:8443/a"}),
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
    compile(ENVIRONMENT_INVENTORY_SCRIPT, "<environment-inventory>", "exec")


def test_probe_environments_disable_bytecode_writes_on_native_and_wsl() -> None:
    assert PROBE_PYTHON_FLAGS == ("-I", "-B", "-c")
    process = subprocess.run(
        [sys.executable, *PROBE_PYTHON_FLAGS, "import sys; print(sys.dont_write_bytecode)"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert process.stdout.strip() == "True"
    native = _isolated_python_command("python", "probe", "root")
    wsl = _wsl_isolated_python_command("/repo/python", "probe", "/repo")
    assert native == ["python", "-I", "-B", "-c", "probe", "root"]
    assert wsl[6 : 6 + len(WSL_PROBE_ENV)] == list(WSL_PROBE_ENV)
    assert wsl[-6:] == ["/repo/python", "-I", "-B", "-c", "probe", "/repo"]


def test_environment_inventory_probe_uses_selected_isolated_python(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    payload = _installed_inventory()

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = args[0]
        assert command[0] == str(python.resolve())
        assert command[1:4] == ["-I", "-B", "-c"]
        assert kwargs["env"] == {
            "PATH": "",
            "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0",
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "private stderr")

    assert (
        run_environment_inventory_probe(python_path=python, root=tmp_path, runner=runner) == payload
    )


def test_probe_success_is_framework_only_and_sanitized(tmp_path: Path) -> None:
    python = tmp_path / "artifacts/local/runtime/env/bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert args[0][1:4] == ["-I", "-B", "-c"]
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


def _installed_inventory() -> dict[str, object]:
    return {
        "implementation": "CPython",
        "python_version": "3.12.11",
        "cache_tag": "cpython-312",
        "abi_flags": "",
        "prefix_is_selected_environment": True,
        "selected_executable_within_expected_root": True,
        "selected_executable_sha256": hashlib.sha256(b"python-executable").hexdigest(),
        "distributions": [{"name": "example-dependency", "version": "1.0.0"}],
    }


def _cuda_observations() -> dict[str, object]:
    return {
        "status": "observed",
        "driver_version": "13030",
        "cuda_build_version": "13.0",
        "device_capability": [9, 0],
        "gpu_memory_bytes": 16_000_000_000,
    }


def test_installed_receipt_binds_executable_packages_cuda_and_lock(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python-executable")
    package_root.mkdir(parents=True)
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    receipt = build_installed_environment_receipt(
        root=tmp_path,
        lock=lock,
        executable_path=executable,
        package_root=package_root,
        inventory=_installed_inventory(),
        cuda_observations=_cuda_observations(),
    )

    assert receipt["runtime_lock_sha256"] == lock.sha256
    assert receipt["selected_executable"] == "artifacts/local/runtime/env/bin/python"
    assert receipt["installed_distributions"] == [
        {"name": "example-dependency", "version": "1.0.0"}
    ]
    assert receipt["package_tree"]["file_count"] == 1
    assert (
        verify_installed_environment_receipt(
            receipt,
            root=tmp_path,
            lock=lock,
            inventory=_installed_inventory(),
            cuda_observations=_cuda_observations(),
        )["verified"]
        is True
    )


def test_windows_extended_path_text_handles_drive_unc_and_existing_prefix() -> None:
    assert _windows_extended_path_text("C:\\runtime\\file") == "\\\\?\\C:\\runtime\\file"
    assert _windows_extended_path_text("\\\\server\\share\\file") == (
        "\\\\?\\UNC\\server\\share\\file"
    )
    assert _windows_extended_path_text("\\\\?\\C:\\runtime\\file") == (
        "\\\\?\\C:\\runtime\\file"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-length path behavior")
def test_tree_receipt_hashes_regular_file_beyond_legacy_windows_limit(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages"
    deep = package_root.joinpath(*(["nested-segment"] * 20))
    long_file = Path(_windows_extended_path_text(str((deep / "LICENSE.txt").absolute())))
    long_file.parent.mkdir(parents=True)
    long_file.write_bytes(b"complete tree")
    assert len(str((deep / "LICENSE.txt").absolute())) > 260

    receipt = _tree_receipt(tmp_path, package_root)

    assert receipt["file_count"] == 1
    assert receipt["size_bytes"] == len(b"complete tree")


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_tree_receipt_rejects_windows_junction_escape(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages"
    outside = tmp_path / "outside"
    package_root.mkdir()
    outside.mkdir()
    (outside / "escaped.py").write_text("escaped = True\n", encoding="utf-8")
    junction = package_root / "junction"
    process = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        pytest.skip("junction creation is not available")

    with pytest.raises(RuntimeContractError, match="reparse point|package tree path escape"):
        _tree_receipt(tmp_path, package_root)


def test_installed_receipt_rejects_a_forged_executable_digest(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python-executable")
    package_root.mkdir(parents=True)
    inventory = _installed_inventory()
    inventory["selected_executable_sha256"] = "f" * 64
    with pytest.raises(RuntimeContractError, match="executable digest drift"):
        build_installed_environment_receipt(
            root=tmp_path,
            lock=lock,
            executable_path=executable,
            package_root=package_root,
            inventory=inventory,
            cuda_observations=_cuda_observations(),
        )


def test_installed_receipt_rejects_executable_symlink_escape(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside-python"
    outside.write_bytes(b"python-executable")
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    executable.parent.mkdir(parents=True)
    try:
        executable.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not available")
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    package_root.mkdir(parents=True)
    with pytest.raises(RuntimeContractError, match="repository-local"):
        build_installed_environment_receipt(
            root=tmp_path,
            lock=lock,
            executable_path=executable,
            package_root=package_root,
            inventory=_installed_inventory(),
            cuda_observations=_cuda_observations(),
        )


@pytest.mark.parametrize("drift", ["executable", "package", "version", "cuda", "path"])
def test_installed_receipt_fails_closed_on_runtime_drift(tmp_path: Path, drift: str) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python-executable")
    package_root.mkdir(parents=True)
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    receipt = build_installed_environment_receipt(
        root=tmp_path,
        lock=lock,
        executable_path=executable,
        package_root=package_root,
        inventory=_installed_inventory(),
        cuda_observations=_cuda_observations(),
    )
    inventory = _installed_inventory()
    cuda = _cuda_observations()
    if drift == "executable":
        executable.write_bytes(b"changed")
        inventory["selected_executable_sha256"] = hashlib.sha256(b"changed").hexdigest()
    elif drift == "package":
        (package_root / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    elif drift == "version":
        inventory["distributions"] = [{"name": "example-dependency", "version": "1.0.1"}]
    elif drift == "cuda":
        cuda["driver_version"] = "13031"
    else:
        receipt["selected_executable"] = "../outside/python"

    with pytest.raises(RuntimeContractError, match="drift|path|repository-relative"):
        verify_installed_environment_receipt(
            receipt,
            root=tmp_path,
            lock=lock,
            inventory=inventory,
            cuda_observations=cuda,
        )


def test_current_environment_verification_reobserves_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python-executable")
    package_root.mkdir(parents=True)
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    receipt = build_installed_environment_receipt(
        root=tmp_path,
        lock=lock,
        executable_path=executable,
        package_root=package_root,
        inventory=_installed_inventory(),
        cuda_observations=_cuda_observations(),
    )
    calls = 0

    def observe(**kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return dict(receipt)

    monkeypatch.setattr("lowbit_lab.runtime.observe_installed_environment", observe)
    result = verify_current_installed_environment(receipt, root=tmp_path, lock=lock)
    assert result["verified"] is True
    assert calls == 1


def test_installed_receipt_rejects_unlocked_distribution(tmp_path: Path) -> None:
    lock = parse_runtime_lock(_lock(tmp_path), root=tmp_path)
    executable = tmp_path / "artifacts/local/runtime/env/bin/python"
    package_root = tmp_path / "artifacts/local/runtime/env/lib/python3.12/site-packages"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python-executable")
    package_root.mkdir(parents=True)
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    inventory = _installed_inventory()
    inventory["distributions"].append({"name": "unreviewed-package", "version": "9.9.9"})
    with pytest.raises(RuntimeContractError, match="distribution inventory drift"):
        build_installed_environment_receipt(
            root=tmp_path,
            lock=lock,
            executable_path=executable,
            package_root=package_root,
            inventory=inventory,
            cuda_observations=_cuda_observations(),
        )
