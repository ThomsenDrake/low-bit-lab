from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from lowbit_lab.runtime import SHA256_RE, RuntimeContractError

CHECK_NAMES = (
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
STATES = {"observed", "missing", "failed", "unknown"}
SAFE_CHECK_KEYS = {"state", "reason_code", "version", "versions", "value", "bytes", "missing"}
OBSERVED_CHECK_KEYS = {
    "os": {"state", "version"},
    "python": {"state", "version"},
    "packages": {"state", "versions"},
    "driver": {"state", "version"},
    "gpu": {"state", "bytes"},
    "cuda_build": {"state", "version"},
    "cuda_availability": {"state"},
    "device_capability": {"state", "value"},
    "small_allocation": {"state", "bytes"},
    "deterministic_operation": {"state"},
    "synchronization": {"state"},
}
ENVIRONMENT_INVENTORY_SCRIPT = r"""
import importlib.metadata
import hashlib
import json
import os
import platform
import re
import sys

items = []
for distribution in importlib.metadata.distributions():
    name = distribution.metadata.get("Name")
    if not isinstance(name, str):
        raise RuntimeError("distribution name missing")
    items.append({"name": re.sub(r"[-_.]+", "-", name).lower(), "version": distribution.version})
items.sort(key=lambda item: item["name"])
selected_executable = os.path.realpath(sys.executable)
selected_prefix = os.path.dirname(os.path.dirname(selected_executable))
expected_root = os.path.realpath(sys.argv[1])
selected_executable_within_expected_root = (
    os.path.commonpath((selected_executable, expected_root)) == expected_root
)
with open(selected_executable, "rb") as executable:
    selected_executable_sha256 = hashlib.file_digest(executable, "sha256").hexdigest()
print(json.dumps({
    "implementation": platform.python_implementation(),
    "python_version": platform.python_version(),
    "cache_tag": sys.implementation.cache_tag,
    "abi_flags": getattr(sys, "abiflags", ""),
    "prefix_is_selected_environment": os.path.realpath(sys.prefix) == selected_prefix,
    "selected_executable_within_expected_root": selected_executable_within_expected_root,
    "selected_executable_sha256": selected_executable_sha256,
    "distributions": items,
}, sort_keys=True))
"""
PROBE_SCRIPT = r"""
import importlib.metadata
import json
import platform
import sys
import ctypes

checks = {name: {"state": "unknown", "reason_code": "NOT_REACHED"} for name in (
    "os", "python", "packages", "driver", "gpu", "cuda_build", "cuda_availability",
    "device_capability", "small_allocation", "deterministic_operation", "synchronization"
)}
is_wsl = platform.system() == "Linux" and "microsoft" in platform.release().lower()
checks["os"] = ({"state": "observed", "version": "WSL2"} if is_wsl else
                {"state": "failed", "reason_code": "WSL_REQUIRED"})
checks["python"] = ({"state": "observed", "version": platform.python_version()}
                    if sys.version_info[:2] == (3, 12) else
                    {"state": "failed", "version": platform.python_version(),
                     "reason_code": "PYTHON_VERSION_MISMATCH"})
versions = {}
missing = []
for name in ("torch", "transformers"):
    try:
        versions[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        missing.append(name)
if not missing:
    checks["packages"] = {"state": "observed", "versions": versions}
else:
    checks["packages"] = {"state": "missing", "reason_code": "PACKAGE_MISSING", "missing": missing}
    print(json.dumps({"schema_version": 1, "checks": checks}, sort_keys=True)); raise SystemExit
try:
    import torch
    build = torch.version.cuda
    checks["cuda_build"] = ({"state": "observed", "version": str(build)} if build else
                            {"state": "missing", "reason_code": "CUDA_BUILD_MISSING"})
    available = bool(torch.cuda.is_available())
    checks["cuda_availability"] = ({"state": "observed"} if available else
                                   {"state": "failed", "reason_code": "CUDA_UNAVAILABLE"})
    if not available:
        print(json.dumps({"schema_version": 1, "checks": checks}, sort_keys=True)); raise SystemExit
    props = torch.cuda.get_device_properties(0)
    checks["gpu"] = {"state": "observed", "bytes": int(props.total_memory)}
    driver_version = ctypes.c_int()
    driver = ctypes.CDLL("libcuda.so.1")
    if driver.cuDriverGetVersion(ctypes.byref(driver_version)) != 0:
        raise RuntimeError("driver query failed")
    checks["driver"] = {"state": "observed", "version": str(driver_version.value)}
    checks["device_capability"] = {
        "state": "observed", "value": list(torch.cuda.get_device_capability(0))
    }
    value = torch.arange(256, dtype=torch.float32, device="cuda")
    checks["small_allocation"] = {
        "state": "observed", "bytes": int(value.numel() * value.element_size())
    }
    result = (value * 2 + 1).cpu()
    expected = torch.arange(256, dtype=torch.float32) * 2 + 1
    checks["deterministic_operation"] = ({"state": "observed"} if torch.equal(result, expected) else
                                         {"state": "failed", "reason_code": "ARITHMETIC_MISMATCH"})
    torch.cuda.synchronize()
    checks["synchronization"] = {"state": "observed"}
except Exception:
    for name in ("driver", "gpu", "device_capability", "small_allocation",
                 "deterministic_operation", "synchronization"):
        if checks[name]["state"] == "unknown":
            checks[name] = {"state": "failed", "reason_code": "PROBE_STAGE_FAILED"}
            break
print(json.dumps({"schema_version": 1, "checks": checks}, sort_keys=True))
"""


def _unknown(reason_code: str, lock_sha256: str, elapsed_ms: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "unknown",
        "reason_code": reason_code,
        "runtime_lock_sha256": lock_sha256,
        "checks": {name: {"state": "unknown", "reason_code": reason_code} for name in CHECK_NAMES},
        "elapsed_ms": elapsed_ms,
        "framework_readiness_proven": False,
        "target_support_proven": False,
        "inference_compatibility_proven": False,
    }


def run_wsl_cuda_probe(
    *,
    python_path: Path,
    root: Path,
    lock_sha256: str,
    expected_python_version: str | None = None,
    expected_package_versions: dict[str, str] | None = None,
    timeout_seconds: int = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if not isinstance(lock_sha256, str) or not SHA256_RE.fullmatch(lock_sha256):
        raise RuntimeContractError("lock_sha256 must be lowercase SHA-256")
    if expected_python_version is not None and (
        not isinstance(expected_python_version, str)
        or not expected_python_version.startswith("3.12.")
    ):
        raise RuntimeContractError("expected Python version must be an exact 3.12 patch")
    if expected_package_versions is not None and (
        set(expected_package_versions) != {"torch", "transformers"}
        or any(
            not isinstance(value, str) or not value for value in expected_package_versions.values()
        )
    ):
        raise RuntimeContractError("expected package versions must identify torch and transformers")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 60
    ):
        raise RuntimeContractError("probe timeout must be between 1 and 60 seconds")
    root = root.resolve()
    executable = python_path.resolve()
    if not executable.is_relative_to(root):
        raise RuntimeContractError("probe Python must be repository-local")
    converted: str | None = None
    if os.name == "nt" and runner is subprocess.run:
        try:
            converted = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "--",
                    "wslpath",
                    "-a",
                    str(executable).replace("\\", "/"),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            exists = (
                subprocess.run(
                    ["wsl.exe", "-d", "Ubuntu", "--", "test", "-f", converted],
                    check=False,
                    timeout=5,
                ).returncode
                == 0
            )
        except (OSError, subprocess.SubprocessError):
            return _unknown("WSL_PATH_FAILED", lock_sha256, 0)
        if not converted.startswith("/") or "\n" in converted:
            return _unknown("WSL_PATH_INVALID", lock_sha256, 0)
        if not exists:
            return _unknown("PYTHON_MISSING", lock_sha256, 0) | {"status": "missing"}
    elif not executable.is_file():
        return _unknown("PYTHON_MISSING", lock_sha256, 0) | {"status": "missing"}
    getuid = getattr(os, "geteuid", None)
    if runner is subprocess.run and getuid is not None and getuid() == 0:
        raise RuntimeContractError("runtime probe refuses root execution")
    started = time.monotonic()
    command = [str(executable), "-I", "-c", PROBE_SCRIPT]
    process_environment = {"PATH": "", "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0"}
    if os.name == "nt" and runner is subprocess.run:
        assert converted is not None
        command = [
            "wsl.exe",
            "-d",
            "Ubuntu",
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "PYTHONNOUSERSITE=1",
            "PYTHONHASHSEED=0",
            converted,
            "-I",
            "-c",
            PROBE_SCRIPT,
        ]
        process_environment = None
    try:
        process = runner(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=process_environment,
        )
    except subprocess.TimeoutExpired:
        return _unknown("PROBE_TIMEOUT", lock_sha256, int((time.monotonic() - started) * 1000))
    except OSError:
        return _unknown(
            "PROBE_LAUNCH_FAILED", lock_sha256, int((time.monotonic() - started) * 1000)
        )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if (
        process.returncode != 0
        or not isinstance(process.stdout, str)
        or len(process.stdout.encode("utf-8", errors="replace")) > 64 * 1024
    ):
        return _unknown("PROBE_SUBPROCESS_FAILED", lock_sha256, elapsed_ms)
    try:
        raw = json.loads(process.stdout)
    except (json.JSONDecodeError, TypeError):
        return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "checks"}
        or raw.get("schema_version") != 1
    ):
        return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
    checks_raw = raw.get("checks")
    if not isinstance(checks_raw, dict) or set(checks_raw) != set(CHECK_NAMES):
        return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
    checks: dict[str, dict[str, Any]] = {}
    for name in CHECK_NAMES:
        value = checks_raw[name]
        if (
            not isinstance(value, dict)
            or set(value) - SAFE_CHECK_KEYS
            or value.get("state") not in STATES
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        state = value["state"]
        if state == "observed" and set(value) != OBSERVED_CHECK_KEYS[name]:
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if state != "observed":
            permitted = {"state", "reason_code"}
            if name == "python":
                permitted.add("version")
            if name == "packages" and state == "missing":
                permitted.add("missing")
            if "reason_code" not in value or set(value) - permitted:
                return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if "missing" in value and (
            not isinstance(value["missing"], list)
            or not set(value["missing"]).issubset({"torch", "transformers"})
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        reason = value.get("reason_code")
        version = value.get("version")
        versions = value.get("versions")
        capability = value.get("value")
        byte_count = value.get("bytes")
        if reason is not None and (
            not isinstance(reason, str)
            or len(reason) > 64
            or not reason.replace("_", "").isalnum()
            or reason.upper() != reason
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if version is not None and (
            not isinstance(version, str)
            or len(version) > 64
            or any(
                character
                not in "0123456789.+-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                for character in version
            )
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if versions is not None and (
            not isinstance(versions, dict)
            or set(versions) != {"torch", "transformers"}
            or any(
                not isinstance(item, str)
                or len(item) > 64
                or any(
                    character
                    not in "0123456789.+-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for character in item
                )
                for item in versions.values()
            )
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if capability is not None and (
            not isinstance(capability, list)
            or len(capability) != 2
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 99
                for item in capability
            )
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        if byte_count is not None and (
            not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0
        ):
            return _unknown("PROBE_OUTPUT_INVALID", lock_sha256, elapsed_ms)
        checks[name] = dict(value)
    if expected_python_version is not None and (
        checks["python"].get("version") != expected_python_version
    ):
        return _unknown("PYTHON_LOCK_MISMATCH", lock_sha256, elapsed_ms)
    if expected_package_versions is not None and (
        checks["packages"].get("versions") != expected_package_versions
    ):
        return _unknown("PACKAGE_LOCK_MISMATCH", lock_sha256, elapsed_ms)
    states = {value["state"] for value in checks.values()}
    if "failed" in states:
        status = "failed"
    elif "missing" in states:
        status = "missing"
    elif "unknown" in states:
        status = "unknown"
    else:
        status = "observed"
    return {
        "schema_version": 1,
        "status": status,
        "runtime_lock_sha256": lock_sha256,
        "checks": checks,
        "elapsed_ms": elapsed_ms,
        "framework_readiness_proven": status == "observed",
        "target_support_proven": False,
        "inference_compatibility_proven": False,
    }


def run_environment_inventory_probe(
    *,
    python_path: Path,
    root: Path,
    timeout_seconds: int = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Read a bounded, path-free inventory from the selected repository-local interpreter."""
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 60
    ):
        raise RuntimeContractError("inventory timeout must be between 1 and 60 seconds")
    resolved_root = root.resolve()
    executable = python_path.resolve()
    if not executable.is_relative_to(resolved_root):
        raise RuntimeContractError("inventory Python must be repository-local")
    converted: str | None = None
    converted_root: str | None = None
    if os.name == "nt" and runner is subprocess.run:
        try:
            converted = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "--",
                    "wslpath",
                    "-a",
                    str(executable).replace("\\", "/"),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            converted_root = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "--",
                    "wslpath",
                    "-a",
                    str(resolved_root).replace("\\", "/"),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeContractError("inventory WSL path conversion failed") from exc
        if (
            not converted.startswith("/")
            or "\n" in converted
            or not converted_root.startswith("/")
            or "\n" in converted_root
        ):
            raise RuntimeContractError("inventory WSL path is invalid")
        command = [
            "wsl.exe",
            "-d",
            "Ubuntu",
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "PYTHONNOUSERSITE=1",
            "PYTHONHASHSEED=0",
            converted,
            "-I",
            "-c",
            ENVIRONMENT_INVENTORY_SCRIPT,
            converted_root,
        ]
        environment = None
    else:
        if not executable.is_file():
            raise RuntimeContractError("inventory Python is missing")
        command = [
            str(executable),
            "-I",
            "-c",
            ENVIRONMENT_INVENTORY_SCRIPT,
            str(resolved_root),
        ]
        environment = {"PATH": "", "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0"}
    try:
        process = runner(
            command,
            cwd=resolved_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeContractError("environment inventory probe failed") from exc
    if (
        process.returncode != 0
        or len(process.stdout.encode("utf-8", errors="replace")) > 1024 * 1024
    ):
        raise RuntimeContractError("environment inventory probe failed")
    try:
        payload = json.loads(process.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeContractError("environment inventory output is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeContractError("environment inventory output is invalid")
    return payload
