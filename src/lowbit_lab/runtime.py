from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from lowbit_lab import __version__


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
                "--query-gpu=name,uuid,memory.total,driver_version",
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
