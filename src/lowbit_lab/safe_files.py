"""Confined atomic evidence writes that reject filesystem aliases."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


class SafeFileError(RuntimeError):
    pass


def confined_output(root: Path, path: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = Path(os.path.abspath(path if path.is_absolute() else resolved_root / path))
    if not candidate.is_relative_to(resolved_root):
        raise SafeFileError("evidence output is outside the repository")
    current = candidate
    while current != resolved_root:
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode) or (
                os.name == "nt"
                and getattr(metadata, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise SafeFileError("evidence output contains a filesystem alias")
        current = current.parent
    if not candidate.resolve().is_relative_to(resolved_root):
        raise SafeFileError("evidence output is outside the repository")
    return candidate


def atomic_write(root: Path, path: Path, content: bytes, *, replace: bool) -> None:
    """Create or explicitly replace one confined file."""
    root = root.resolve(strict=True)
    output = confined_output(root, path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output = confined_output(root, output)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        confined_output(root, output)
        if replace:
            os.replace(temporary, output)
        else:
            try:
                os.link(temporary, output)
            except FileExistsError as exc:
                raise SafeFileError("evidence output already exists") from exc
            temporary.unlink()
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    if output.read_bytes() != content:
        raise SafeFileError("persisted evidence drift")
