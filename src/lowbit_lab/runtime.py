from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from lowbit_lab import __version__

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
RUNTIME_LOCK_KEYS = {
    "schema_version",
    "runtime_id",
    "python_version",
    "artifact_root",
    "resolution",
    "per_artifact_cap_bytes",
    "aggregate_cap_bytes",
    "artifacts",
}
ARTIFACT_KEYS = {
    "role",
    "name",
    "version",
    "url",
    "filename",
    "size_bytes",
    "sha256",
    "binary_format",
    "direct",
}
BINARY_FORMATS = {"standalone_binary", "binary_archive", "wheel"}
ARTIFACT_ROLES = {"uv_bootstrap", "managed_cpython", "python_distribution"}


class RuntimeContractError(ValueError):
    """A fail-closed runtime decision or lock validation failure."""


@dataclass(frozen=True)
class RuntimeArtifact:
    role: str
    name: str
    version: str
    url: str
    filename: str
    size_bytes: int
    sha256: str
    binary_format: str
    direct: bool


@dataclass(frozen=True)
class RuntimeLock:
    schema_version: int
    runtime_id: str
    python_version: str
    artifact_root: str
    per_artifact_cap_bytes: int
    aggregate_cap_bytes: int
    allowed_hosts: tuple[str, ...]
    artifacts: tuple[RuntimeArtifact, ...]
    canonical_json: str
    sha256: str


RECEIPT_KEYS = {
    "schema_version",
    "runtime_lock_sha256",
    "selected_executable",
    "selected_executable_sha256",
    "interpreter",
    "installed_distributions",
    "package_tree",
    "cuda_driver_observations",
}
INTERPRETER_KEYS = {
    "implementation",
    "python_version",
    "cache_tag",
    "abi_flags",
    "prefix_is_selected_environment",
}
CUDA_OBSERVATION_KEYS = {
    "status",
    "driver_version",
    "cuda_build_version",
    "device_capability",
    "gpu_memory_bytes",
}


def _closed_mapping(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeContractError(f"{label} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise RuntimeContractError(f"{label} has unknown keys: {sorted(unknown)}")
    return value


def _positive_bytes(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeContractError(f"{label} must be a positive integer byte count")
    return value


def _envelope_bytes(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeContractError(f"{label} must be a non-negative integer byte count")
    return value


def decide_baseline_runtime(
    *, declarations: list[dict[str, Any]], measured: dict[str, Any]
) -> dict[str, Any]:
    """Choose only from declared, provenance-checked binaries that fit measured resources.

    This is deliberately a read-only proposal. A selection proves neither framework readiness
    nor inference compatibility.
    """
    envelope_fields = {
        "vram_bytes",
        "ram_bytes",
        "disk_bytes",
        "runtime_buffer_bytes",
        "kv_cache_bytes",
    }
    measured_map = _closed_mapping(measured, envelope_fields, "measured envelope")
    if set(measured_map) != envelope_fields:
        raise RuntimeContractError("measured envelope is incomplete")
    measured_bytes = {
        key: _envelope_bytes(value, f"measured.{key}") for key, value in measured_map.items()
    }
    if not isinstance(declarations, list) or not declarations:
        raise RuntimeContractError("runtime declarations must be a non-empty list")

    allowed = {
        "runtime_id",
        "architecture_support",
        "maintained_binary_available",
        "license_and_provenance_verified",
        "required_vram_bytes",
        "required_ram_bytes",
        "required_disk_bytes",
        "runtime_buffer_bytes",
        "kv_cache_bytes",
    }
    outcomes: list[tuple[str, str, list[str]]] = []
    seen: set[str] = set()
    for index, raw in enumerate(declarations):
        declaration = _closed_mapping(raw, allowed, f"declarations[{index}]")
        if set(declaration) != allowed:
            raise RuntimeContractError(f"declarations[{index}] is incomplete")
        runtime_id = declaration["runtime_id"]
        if not isinstance(runtime_id, str) or not SAFE_ID_RE.fullmatch(runtime_id):
            raise RuntimeContractError(f"declarations[{index}].runtime_id is invalid")
        if runtime_id in seen:
            raise RuntimeContractError("runtime declarations contain a duplicate runtime_id")
        seen.add(runtime_id)
        support = declaration["architecture_support"]
        if support not in {"declared", "unsupported", "unknown"}:
            raise RuntimeContractError(
                "architecture_support must be declared, unsupported, or unknown"
            )
        for flag in ("maintained_binary_available", "license_and_provenance_verified"):
            if not isinstance(declaration[flag], bool):
                raise RuntimeContractError(f"{flag} must be boolean")
        demand = {
            name: _envelope_bytes(declaration[name], f"declarations[{index}].{name}")
            for name in (
                "required_vram_bytes",
                "required_ram_bytes",
                "required_disk_bytes",
                "runtime_buffer_bytes",
                "kv_cache_bytes",
            )
        }
        reasons: list[str] = []
        status = "rejected"
        if support == "unknown":
            status, reasons = "deferred", ["ARCHITECTURE_SUPPORT_UNRESOLVED"]
        elif support == "unsupported":
            reasons = ["ARCHITECTURE_UNSUPPORTED"]
        elif not declaration["license_and_provenance_verified"]:
            status, reasons = "deferred", ["PROVENANCE_UNRESOLVED"]
        elif not declaration["maintained_binary_available"]:
            reasons = ["NO_MAINTAINED_BINARY"]
        elif (
            demand["required_vram_bytes"]
            + demand["runtime_buffer_bytes"]
            + demand["kv_cache_bytes"]
            > measured_bytes["vram_bytes"]
            or demand["required_ram_bytes"] > measured_bytes["ram_bytes"]
            or demand["required_disk_bytes"] > measured_bytes["disk_bytes"]
            or demand["runtime_buffer_bytes"] > measured_bytes["runtime_buffer_bytes"]
            or demand["kv_cache_bytes"] > measured_bytes["kv_cache_bytes"]
        ):
            reasons = ["RESOURCE_ENVELOPE_EXCEEDED"]
        else:
            status, reasons = "selected", ["DECLARED_SUPPORTED_BINARY_FITS"]
        outcomes.append((runtime_id, status, reasons))

    selected = next((item for item in outcomes if item[1] == "selected"), None)
    if selected:
        runtime_id, status, reasons = selected
    else:
        deferred = [item for item in outcomes if item[1] == "deferred"]
        status = "deferred" if deferred else "rejected"
        runtime_id = None
        reasons = sorted({reason for _, _, item_reasons in outcomes for reason in item_reasons})
    return {
        "status": status,
        "runtime_id": runtime_id,
        "reason_codes": reasons,
        "inference_compatibility_proven": False,
    }


def _repo_relative_path(root: Path, path_text: Any, label: str) -> str:
    if not isinstance(path_text, str) or not path_text:
        raise RuntimeContractError(f"{label} must be a non-empty repository-relative path")
    path = Path(path_text)
    if path.is_absolute() or PureWindowsPath(path_text).is_absolute() or ".." in path.parts:
        raise RuntimeContractError(f"{label} must be a repository-relative path")
    candidate = (root.resolve() / path).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise RuntimeContractError(f"{label} resolves outside repository")
    return path.as_posix()


def parse_runtime_lock(raw: Any, *, root: Path) -> RuntimeLock:
    lock = _closed_mapping(raw, RUNTIME_LOCK_KEYS, "runtime lock")
    missing = RUNTIME_LOCK_KEYS - set(lock)
    if missing:
        raise RuntimeContractError(f"runtime lock has unresolved fields: {sorted(missing)}")
    if lock["schema_version"] != 1:
        raise RuntimeContractError("runtime lock schema_version must be 1")
    runtime_id = lock["runtime_id"]
    if not isinstance(runtime_id, str) or not SAFE_ID_RE.fullmatch(runtime_id):
        raise RuntimeContractError("runtime_id is invalid")
    python_version = lock["python_version"]
    if not isinstance(python_version, str) or not re.fullmatch(r"3\.12\.\d+", python_version):
        raise RuntimeContractError("managed Python must be an exact 3.12 patch version")
    artifact_root = _repo_relative_path(root, lock["artifact_root"], "artifact_root")
    artifact_root_parts = PurePosixPath(artifact_root).parts
    if artifact_root_parts[:3] != ("artifacts", "local", "runtime"):
        raise RuntimeContractError("artifact_root must be under artifacts/local/runtime")
    resolution_keys = {"status", "binary_only", "apply_index_access", "allowed_hosts"}
    resolution = _closed_mapping(lock["resolution"], resolution_keys, "resolution")
    if set(resolution) != resolution_keys:
        raise RuntimeContractError("runtime resolution is incomplete")
    if resolution["status"] != "complete":
        raise RuntimeContractError("runtime resolution must be complete")
    if resolution["binary_only"] is not True:
        raise RuntimeContractError("runtime resolution must be binary-only")
    if resolution["apply_index_access"] is not False:
        raise RuntimeContractError("runtime apply must not access an index")
    allowed_hosts = resolution["allowed_hosts"]
    if (
        not isinstance(allowed_hosts, list)
        or not allowed_hosts
        or any(not isinstance(host, str) or host != host.lower() for host in allowed_hosts)
        or len(set(allowed_hosts)) != len(allowed_hosts)
    ):
        raise RuntimeContractError("runtime resolution hosts must be unique lowercase names")
    per_cap = _positive_bytes(lock["per_artifact_cap_bytes"], "per_artifact_cap_bytes")
    aggregate_cap = _positive_bytes(lock["aggregate_cap_bytes"], "aggregate_cap_bytes")
    raw_artifacts = lock["artifacts"]
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise RuntimeContractError("artifacts must be a non-empty resolved list")

    artifacts: list[RuntimeArtifact] = []
    identities: set[tuple[str, str, str]] = set()
    locations: set[tuple[str, str]] = set()
    role_counts = {role: 0 for role in ARTIFACT_ROLES}
    for index, value in enumerate(raw_artifacts):
        item = _closed_mapping(value, ARTIFACT_KEYS, f"artifacts[{index}]")
        missing_item = ARTIFACT_KEYS - set(item)
        if missing_item:
            raise RuntimeContractError(
                f"artifacts[{index}] has unresolved fields: {sorted(missing_item)}"
            )
        role = item["role"]
        if role not in ARTIFACT_ROLES:
            raise RuntimeContractError(f"artifacts[{index}].role is unknown")
        role_counts[role] += 1
        name, version = item["name"], item["version"]
        if not all(isinstance(part, str) and part.strip() for part in (name, version)):
            raise RuntimeContractError(f"artifacts[{index}] name and version must be resolved")
        url = item["url"]
        if not isinstance(url, str):
            raise RuntimeContractError(f"artifacts[{index}].url must be immutable HTTPS")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.query
            or parsed.port not in {None, 443}
        ):
            raise RuntimeContractError(f"artifacts[{index}].url must be immutable HTTPS")
        if parsed.hostname not in allowed_hosts:
            raise RuntimeContractError(f"artifacts[{index}].url host is not allowlisted")
        filename = item["filename"]
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or filename in {".", ".."}
        ):
            raise RuntimeContractError(f"artifacts[{index}].filename must be a safe leaf name")
        size = _positive_bytes(item["size_bytes"], f"artifacts[{index}].size_bytes")
        if size > per_cap:
            raise RuntimeContractError(f"artifacts[{index}] exceeds per-artifact cap")
        digest = item["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or len(set(digest)) == 1:
            raise RuntimeContractError(f"artifacts[{index}].sha256 is unresolved")
        binary_format = item["binary_format"]
        if binary_format not in BINARY_FORMATS:
            raise RuntimeContractError("runtime lock permits binary artifacts only")
        lowered = filename.lower()
        if role == "python_distribution" and (
            binary_format != "wheel" or not lowered.endswith(".whl")
        ):
            raise RuntimeContractError("Python distributions must be resolved wheels")
        if binary_format == "wheel" and not lowered.endswith(".whl"):
            raise RuntimeContractError("wheel artifacts must use a .whl filename")
        if not isinstance(item["direct"], bool):
            raise RuntimeContractError(f"artifacts[{index}].direct must be boolean")
        identity = (role, name, version)
        location = (url, filename)
        if identity in identities or location in locations:
            raise RuntimeContractError("runtime lock contains a duplicate artifact")
        identities.add(identity)
        locations.add(location)
        artifacts.append(
            RuntimeArtifact(
                role=role,
                name=name,
                version=version,
                url=url,
                filename=filename,
                size_bytes=size,
                sha256=digest,
                binary_format=binary_format,
                direct=item["direct"],
            )
        )
    if role_counts["uv_bootstrap"] != 1 or role_counts["managed_cpython"] != 1:
        raise RuntimeContractError(
            "runtime lock requires exactly one uv and managed CPython artifact"
        )
    if role_counts["python_distribution"] < 1:
        raise RuntimeContractError("runtime lock must enumerate all direct and transitive wheels")
    if not any(item.role == "python_distribution" and item.direct for item in artifacts):
        raise RuntimeContractError("runtime lock requires at least one direct wheel")
    planned_bytes = sum(item.size_bytes for item in artifacts)
    if planned_bytes > aggregate_cap:
        raise RuntimeContractError("planned artifact bytes exceed aggregate cap")
    canonical = json.dumps(lock, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return RuntimeLock(
        schema_version=1,
        runtime_id=runtime_id,
        python_version=python_version,
        artifact_root=artifact_root,
        per_artifact_cap_bytes=per_cap,
        aggregate_cap_bytes=aggregate_cap,
        allowed_hosts=tuple(allowed_hosts),
        artifacts=tuple(artifacts),
        canonical_json=canonical,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def load_runtime_lock(path: Path, *, root: Path) -> RuntimeLock:
    confined = (root.resolve() / path).resolve() if not path.is_absolute() else path.resolve()
    if not confined.is_relative_to((root.resolve() / "configs").resolve()):
        raise RuntimeContractError("runtime lock must be under repository configs/")
    try:
        raw = json.loads(confined.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeContractError("cannot read runtime lock") from exc
    return parse_runtime_lock(raw, root=root)


def preview_runtime_lock(lock: RuntimeLock) -> dict[str, Any]:
    """Return an exact transfer plan without reading files or performing network I/O."""
    return {
        "schema_version": lock.schema_version,
        "runtime_id": lock.runtime_id,
        "runtime_lock_sha256": lock.sha256,
        "artifact_count": len(lock.artifacts),
        "planned_bytes": sum(item.size_bytes for item in lock.artifacts),
        "per_artifact_cap_bytes": lock.per_artifact_cap_bytes,
        "aggregate_cap_bytes": lock.aggregate_cap_bytes,
        "all_artifacts_resolved": True,
        "binary_only": True,
        "network_performed": False,
        "installation_performed": False,
        "inference_compatibility_proven": False,
    }


def verify_local_artifact_set(lock: RuntimeLock, *, root: Path) -> dict[str, Any]:
    artifact_root = (root.resolve() / lock.artifact_root).resolve()
    if not artifact_root.is_relative_to(root.resolve()):
        raise RuntimeContractError("artifact root resolves outside repository")
    verified = 0
    for item in lock.artifacts:
        candidate = (artifact_root / item.sha256 / item.filename).resolve()
        if not candidate.is_relative_to(artifact_root):
            raise RuntimeContractError("artifact path resolves outside repository")
        try:
            stat = candidate.stat()
        except OSError as exc:
            raise RuntimeContractError(f"local artifact missing: {item.role}") from exc
        if not candidate.is_file():
            raise RuntimeContractError(f"local artifact is not a file: {item.role}")
        if stat.st_size != item.size_bytes:
            raise RuntimeContractError(f"local artifact size mismatch: {item.role}")
        with candidate.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != item.sha256:
            raise RuntimeContractError(f"local artifact hash mismatch: {item.role}")
        verified += stat.st_size
    if verified != sum(item.size_bytes for item in lock.artifacts):
        raise RuntimeContractError("verified artifact byte total drifted from lock")
    return {
        "runtime_lock_sha256": lock.sha256,
        "artifact_count": len(lock.artifacts),
        "verified_bytes": verified,
        "complete": True,
        "installation_performed": False,
    }


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _tree_receipt(root: Path, package_root: Path) -> dict[str, Any]:
    resolved_root = root.resolve()
    resolved_package_root = package_root.resolve()
    if not resolved_package_root.is_relative_to(resolved_root) or not package_root.is_dir():
        raise RuntimeContractError("package tree path must be a repository-local directory")
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for path in sorted(package_root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise RuntimeContractError("package tree contains a symbolic link")
        if not path.is_file():
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(resolved_package_root):
            raise RuntimeContractError("package tree path escape")
        relative = resolved.relative_to(resolved_package_root).as_posix().encode()
        stat = resolved.stat()
        content_digest = _sha256_file(resolved)
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(stat.st_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(content_digest))
        file_count += 1
        byte_count += stat.st_size
    if file_count == 0:
        raise RuntimeContractError("package tree is empty")
    return {
        "root": resolved_package_root.relative_to(resolved_root).as_posix(),
        "file_count": file_count,
        "size_bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def _normalize_distribution_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeContractError("installed distribution name is invalid")
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?", normalized):
        raise RuntimeContractError("installed distribution name is invalid")
    return normalized


def _validated_inventory(
    inventory: Mapping[str, Any], lock: RuntimeLock
) -> tuple[dict[str, Any], list[dict[str, str]], str]:
    inventory_keys = INTERPRETER_KEYS | {"distributions", "selected_executable_sha256"}
    inventory_map = _closed_mapping(
        dict(inventory), inventory_keys, "installed environment inventory"
    )
    if set(inventory_map) != inventory_keys:
        raise RuntimeContractError("installed environment inventory is incomplete")
    interpreter = {key: inventory_map[key] for key in INTERPRETER_KEYS}
    if interpreter["implementation"] != "CPython":
        raise RuntimeContractError("interpreter implementation drift")
    if interpreter["python_version"] != lock.python_version:
        raise RuntimeContractError("interpreter version drift")
    if (
        not isinstance(interpreter["cache_tag"], str)
        or not re.fullmatch(r"cpython-\d{3}", interpreter["cache_tag"])
        or not isinstance(interpreter["abi_flags"], str)
        or len(interpreter["abi_flags"]) > 16
        or interpreter["prefix_is_selected_environment"] is not True
    ):
        raise RuntimeContractError("interpreter identity drift")
    raw_distributions = inventory_map["distributions"]
    if not isinstance(raw_distributions, list) or not raw_distributions:
        raise RuntimeContractError("installed distribution inventory is missing")
    distributions: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in raw_distributions:
        item = _closed_mapping(raw, {"name", "version"}, "installed distribution")
        if set(item) != {"name", "version"}:
            raise RuntimeContractError("installed distribution is incomplete")
        name = _normalize_distribution_name(item["name"])
        version = item["version"]
        if not isinstance(version, str) or not version or len(version) > 128:
            raise RuntimeContractError("installed distribution version is invalid")
        if name in seen:
            raise RuntimeContractError("installed distribution inventory has duplicates")
        seen.add(name)
        distributions.append({"name": name, "version": version})
    distributions.sort(key=lambda item: item["name"])
    expected = sorted(
        (
            {"name": _normalize_distribution_name(item.name), "version": item.version}
            for item in lock.artifacts
            if item.role == "python_distribution"
        ),
        key=lambda item: item["name"],
    )
    expected_by_name = {item["name"]: item["version"] for item in expected}
    actual_by_name = {item["name"]: item["version"] for item in distributions}
    unexpected = set(actual_by_name) - set(expected_by_name)
    if any(
        actual_by_name.get(name) != version for name, version in expected_by_name.items()
    ) or not unexpected.issubset({"pip"}):
        raise RuntimeContractError("installed distribution inventory drift")
    executable_sha256 = inventory_map["selected_executable_sha256"]
    if not isinstance(executable_sha256, str) or not SHA256_RE.fullmatch(executable_sha256):
        raise RuntimeContractError("selected executable digest is invalid")
    return interpreter, distributions, executable_sha256


def _validated_cuda_observations(raw: Mapping[str, Any]) -> dict[str, Any]:
    observations = _closed_mapping(dict(raw), CUDA_OBSERVATION_KEYS, "CUDA/driver observations")
    if set(observations) != CUDA_OBSERVATION_KEYS or observations["status"] != "observed":
        raise RuntimeContractError("CUDA/driver observations are incomplete")
    for key in ("driver_version", "cuda_build_version"):
        if (
            not isinstance(observations[key], str)
            or not observations[key]
            or len(observations[key]) > 64
        ):
            raise RuntimeContractError("CUDA/driver observation drift")
    capability = observations["device_capability"]
    if (
        not isinstance(capability, list)
        or len(capability) != 2
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 99
            for value in capability
        )
    ):
        raise RuntimeContractError("CUDA device capability is invalid")
    memory = observations["gpu_memory_bytes"]
    if not isinstance(memory, int) or isinstance(memory, bool) or memory <= 0:
        raise RuntimeContractError("GPU memory observation is invalid")
    return observations


def build_installed_environment_receipt(
    *,
    root: Path,
    lock: RuntimeLock,
    executable_path: Path,
    package_root: Path,
    inventory: Mapping[str, Any],
    cuda_observations: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a closed receipt from observations made immediately before planning."""
    resolved_root = root.resolve()
    executable = executable_path.absolute()
    try:
        resolved_executable = executable.resolve(strict=True)
    except OSError as exc:
        raise RuntimeContractError("selected executable cannot be resolved") from exc
    if not resolved_executable.is_relative_to(resolved_root):
        raise RuntimeContractError("selected executable path must be a repository-local file")
    relative_executable = executable.relative_to(resolved_root).as_posix()
    expected_executable = f"{lock.artifact_root}/env/bin/python"
    if relative_executable != expected_executable:
        raise RuntimeContractError("selected executable path drift")
    interpreter, distributions, claimed_executable_sha256 = _validated_inventory(inventory, lock)
    try:
        with resolved_executable.open("rb") as handle:
            executable_sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as exc:
        raise RuntimeContractError("selected executable cannot be hashed") from exc
    if claimed_executable_sha256 != executable_sha256:
        raise RuntimeContractError("selected executable digest drift")
    observations = _validated_cuda_observations(cuda_observations)
    return {
        "schema_version": 1,
        "runtime_lock_sha256": lock.sha256,
        "selected_executable": relative_executable,
        "selected_executable_sha256": executable_sha256,
        "interpreter": interpreter,
        "installed_distributions": distributions,
        "package_tree": _tree_receipt(resolved_root, package_root),
        "cuda_driver_observations": observations,
    }


def verify_installed_environment_receipt(
    receipt: Mapping[str, Any],
    *,
    root: Path,
    lock: RuntimeLock,
    inventory: Mapping[str, Any],
    cuda_observations: Mapping[str, Any],
) -> dict[str, Any]:
    """Re-observe and compare every decision-bearing runtime field, failing closed on drift."""
    receipt_map = _closed_mapping(dict(receipt), RECEIPT_KEYS, "installed environment receipt")
    if set(receipt_map) != RECEIPT_KEYS or receipt_map["schema_version"] != 1:
        raise RuntimeContractError("installed environment receipt is incomplete")
    if receipt_map["runtime_lock_sha256"] != lock.sha256:
        raise RuntimeContractError("runtime lock drift")
    executable_relative = _repo_relative_path(
        root, receipt_map["selected_executable"], "selected executable"
    )
    package_tree = _closed_mapping(
        receipt_map["package_tree"], {"root", "file_count", "size_bytes", "sha256"}, "package tree"
    )
    package_relative = _repo_relative_path(root, package_tree.get("root"), "package tree")
    current = build_installed_environment_receipt(
        root=root,
        lock=lock,
        executable_path=root / executable_relative,
        package_root=root / package_relative,
        inventory=inventory,
        cuda_observations=cuda_observations,
    )
    return _compare_environment_receipt(receipt_map, current)


def _compare_environment_receipt(
    receipt: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    if current != receipt:
        raise RuntimeContractError("installed environment receipt drift")
    canonical = json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {"verified": True, "receipt_sha256": hashlib.sha256(canonical.encode()).hexdigest()}


def observe_installed_environment(
    *, root: Path, lock: RuntimeLock, executable_path: Path | None = None
) -> dict[str, Any]:
    """Capture the selected environment and CUDA facts without persisting private paths."""
    from lowbit_lab.runtime_probe import (
        run_environment_inventory_probe,
        run_wsl_cuda_probe,
    )

    executable = executable_path or root / lock.artifact_root / "env/bin/python"
    inventory = run_environment_inventory_probe(python_path=executable, root=root)
    expected_versions = {
        item.name: item.version
        for item in lock.artifacts
        if item.role == "python_distribution" and item.name in {"torch", "transformers"}
    }
    if set(expected_versions) != {"torch", "transformers"}:
        raise RuntimeContractError("runtime lock lacks framework package authority")
    probe = run_wsl_cuda_probe(
        python_path=executable,
        root=root,
        lock_sha256=lock.sha256,
        expected_python_version=lock.python_version,
        expected_package_versions=expected_versions,
    )
    if probe.get("status") != "observed":
        raise RuntimeContractError("CUDA/driver observations are not proven")
    checks = probe["checks"]
    observations = {
        "status": "observed",
        "driver_version": checks["driver"]["version"],
        "cuda_build_version": checks["cuda_build"]["version"],
        "device_capability": checks["device_capability"]["value"],
        "gpu_memory_bytes": checks["gpu"]["bytes"],
    }
    major_minor = ".".join(lock.python_version.split(".")[:2])
    package_root = root / lock.artifact_root / f"env/lib/python{major_minor}/site-packages"
    return build_installed_environment_receipt(
        root=root,
        lock=lock,
        executable_path=executable,
        package_root=package_root,
        inventory=inventory,
        cuda_observations=observations,
    )


def verify_current_installed_environment(
    receipt: Mapping[str, Any], *, root: Path, lock: RuntimeLock
) -> dict[str, Any]:
    """Re-observe immediately before work and reject any receipt or environment drift."""
    receipt_map = _closed_mapping(dict(receipt), RECEIPT_KEYS, "installed environment receipt")
    if set(receipt_map) != RECEIPT_KEYS or receipt_map.get("runtime_lock_sha256") != lock.sha256:
        raise RuntimeContractError("installed environment receipt or runtime lock drift")
    current = observe_installed_environment(root=root, lock=lock)
    return _compare_environment_receipt(receipt_map, current)


def _git_commit(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "uncommitted"


def _git_dirty(root: Path) -> bool:
    try:
        return bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=all"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError):
        return True


def _control_plane_sha256(root: Path) -> str:
    candidates = [
        *root.glob("src/lowbit_lab/*.py"),
        *root.glob("modal/*.py"),
        root / "pyproject.toml",
        root / "uv.lock",
        root / "configs/budget-policy.json",
    ]
    digest = hashlib.sha256()
    for path in sorted(
        (path for path in candidates if path.is_file()), key=lambda item: item.as_posix()
    ):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as handle:
            digest.update(hashlib.file_digest(handle, "sha256").digest())
    return digest.hexdigest()


def runtime_metadata(
    root: Path, selected_name: str | None = None, selected_revision: str | None = None
) -> dict[str, Any]:
    return {
        "lab_version": __version__,
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "git_commit": _git_commit(root),
        "git_dirty": _git_dirty(root),
        "control_plane_sha256": _control_plane_sha256(root),
        "name": selected_name,
        "revision": selected_revision,
    }


def _framework_metadata() -> dict[str, Any]:
    frameworks: dict[str, Any] = {}
    for distribution, module in (
        ("torch", "torch"),
        ("transformers", "transformers"),
        ("llama-cpp-python", "llama_cpp"),
    ):
        if importlib.util.find_spec(module) is None:
            frameworks[module] = {"installed": False}
            continue
        try:
            frameworks[module] = {
                "installed": True,
                "version": importlib.metadata.version(distribution),
            }
        except importlib.metadata.PackageNotFoundError:
            frameworks[module] = {"installed": True, "version": "unknown"}
    if frameworks["torch"]["installed"]:
        import torch

        cuda_available = torch.cuda.is_available()
        frameworks["torch"].update(
            {
                "cuda_build": torch.version.cuda,
                "cuda_available": cuda_available,
                "device_capability": (
                    list(torch.cuda.get_device_capability()) if cuda_available else None
                ),
            }
        )
    return frameworks


def hardware_metadata() -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "gpu": {"detected": False},
        "frameworks": _framework_metadata(),
    }
    executable = shutil.which("nvidia-smi")
    if not executable:
        return metadata
    try:
        output = subprocess.run(
            [
                executable,
                "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        metadata["gpu"] = {"detected": bool(output), "nvidia_smi_rows": output.splitlines()}
    except (OSError, subprocess.SubprocessError) as exc:
        metadata["gpu"] = {"detected": False, "probe_error": type(exc).__name__}
    return metadata
