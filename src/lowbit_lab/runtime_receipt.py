from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from lowbit_lab.jsonio import emit
from lowbit_lab.runtime import (
    RuntimeContractError,
    load_runtime_lock,
    observe_installed_environment,
)
from lowbit_lab.safe_files import SafeFileError, atomic_write, confined_output


class RuntimeReceiptError(RuntimeError):
    pass


def _confined(root: Path, path: Path, label: str) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = path.resolve() if path.is_absolute() else (resolved_root / path).resolve()
    if not candidate.is_relative_to(resolved_root):
        raise RuntimeReceiptError(f"{label} is outside the repository")
    return candidate


def generate_runtime_receipt(
    *, root: Path, runtime_lock_path: Path, output_path: Path, replace: bool = False
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    lock_path = _confined(root, runtime_lock_path, "runtime lock")
    try:
        output = confined_output(root, output_path)
    except SafeFileError as exc:
        raise RuntimeReceiptError(str(exc).replace("evidence", "runtime receipt")) from exc
    existed_before = output.exists()
    if existed_before and not replace:
        raise RuntimeReceiptError("runtime receipt output already exists")
    lock = load_runtime_lock(lock_path, root=root)
    receipt = observe_installed_environment(root=root, lock=lock)
    content = (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    try:
        atomic_write(root, output, content, replace=replace)
    except SafeFileError as exc:
        raise RuntimeReceiptError(str(exc).replace("evidence", "runtime receipt")) from exc
    tree = receipt["package_tree"]
    return {
        "file_count": tree["file_count"],
        "ok": True,
        "provider_contacted": False,
        "receipt_sha256": hashlib.sha256(content).hexdigest(),
        "replaced": existed_before,
        "size_bytes": tree["size_bytes"],
        "weights_transferred": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a confined installed-runtime receipt")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        emit(
            generate_runtime_receipt(
                root=args.root,
                runtime_lock_path=args.runtime_lock,
                output_path=args.output,
                replace=args.replace,
            )
        )
        return 0
    except (OSError, RuntimeContractError, RuntimeReceiptError) as exc:
        emit({"error": type(exc).__name__, "ok": False, "provider_contacted": False})
        return 1


if __name__ == "__main__":
    sys.exit(main())
