from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Any

import yaml

from lowbit_lab.jsonio import emit

LOCAL_ROOTS = (
    Path("configs/local"),
    Path("docs/plans/local"),
    Path("eval/local"),
    Path("artifacts/local"),
    Path("results/local"),
    Path("reports/local"),
)
PRIVATE_VALUE_KINDS = {
    "target_identifier",
    "target_revision",
    "hardware_evidence",
    "promotion_threshold",
    "private_path",
    "other_sensitive",
}
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
GPU_UUID_RE = re.compile(
    rb"GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    rb"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
PRIVATE_PATH_RES = (
    re.compile(rb"[A-Za-z]:(?:[\\/])+Users(?:[\\/])+[^\\/\s]+(?:[\\/])", re.IGNORECASE),
    re.compile(rb"/ho" rb"me/[^/\s]+/"),
    re.compile(rb"/mnt/[a-zA-Z]/" rb"Users/[^/\s]+/", re.IGNORECASE),
)
CREDENTIAL_RES = (
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        rb"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[\"']?"
        rb"[A-Za-z0-9_./+=-]{12,}",
        re.IGNORECASE,
    ),
)


class PublicationError(ValueError):
    pass


@dataclass(frozen=True)
class PublicationManifest:
    public_remote: str
    private_values: tuple[str, ...]


def _git(root: Path, *args: str, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            input=input_text,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PublicationError("repository inspection failed") from exc
    return result.stdout


def _repository_root(root: Path) -> Path:
    candidate = root.resolve()
    discovered = Path(_git(candidate, "rev-parse", "--show-toplevel").strip()).resolve()
    if discovered != candidate:
        raise PublicationError("scan root must be the repository root")
    return candidate


def _closed_mapping(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise PublicationError(f"{label} has unknown keys")
    return value


def load_manifest(root: Path, path: Path) -> PublicationManifest:
    root = _repository_root(root)
    candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not candidate.is_relative_to(root):
        raise PublicationError("publication manifest must stay inside the repository")
    in_local_root = any(
        candidate.is_relative_to((root / local_root).resolve()) for local_root in LOCAL_ROOTS
    )
    if not in_local_root:
        raise PublicationError("publication manifest must be in an ignored local directory")
    relative = candidate.relative_to(root).as_posix()
    try:
        ignored = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--quiet", "--no-index", "--", relative],
            check=False,
            capture_output=True,
        ).returncode
    except OSError as exc:
        raise PublicationError("cannot verify publication manifest ignore status") from exc
    if ignored != 0:
        raise PublicationError("publication manifest must be in an ignored local directory")
    try:
        raw = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PublicationError("cannot read publication manifest") from exc
    manifest = _closed_mapping(
        raw, {"schema_version", "public_remote", "private_values"}, "publication manifest"
    )
    if manifest.get("schema_version") != 1:
        raise PublicationError("publication manifest schema_version must be 1")
    public_remote = manifest.get("public_remote")
    if not isinstance(public_remote, str) or not REMOTE_RE.fullmatch(public_remote):
        raise PublicationError("publication manifest public_remote is invalid")
    raw_values = manifest.get("private_values")
    if not isinstance(raw_values, list):
        raise PublicationError("publication manifest private_values must be a list")
    values: list[str] = []
    for item in raw_values:
        entry = _closed_mapping(item, {"kind", "value"}, "private value")
        if entry.get("kind") not in PRIVATE_VALUE_KINDS:
            raise PublicationError("private value kind is invalid")
        value = entry.get("value")
        if not isinstance(value, str) or not 3 <= len(value.encode("utf-8")) <= 512:
            raise PublicationError("private value must contain between 3 and 512 UTF-8 bytes")
        values.append(value)
    if len(values) != len(set(values)):
        raise PublicationError("publication manifest private_values must be unique")
    return PublicationManifest(public_remote=public_remote, private_values=tuple(values))


def _remote_base_status(root: Path, remote: str) -> str | None:
    if not REMOTE_RE.fullmatch(remote):
        return "remote_base_unavailable"
    remotes = set(_git(root, "remote").splitlines())
    if remote not in remotes:
        return "remote_base_unavailable"
    prefix = f"refs/remotes/{remote}/"
    refs = [
        line
        for line in _git(root, "for-each-ref", "--format=%(refname)", prefix).splitlines()
        if line and line != f"{prefix}HEAD"
    ]
    try:
        head = _git(root, "symbolic-ref", "--quiet", f"{prefix}HEAD").strip()
    except PublicationError:
        head = ""
    if head:
        return None if head in refs else "remote_base_unavailable"
    if not refs:
        return "remote_base_unavailable"
    if len(refs) > 1:
        return "remote_base_ambiguous"
    return None


def _categories(content: bytes, protected_values: Sequence[bytes]) -> set[str]:
    categories: set[str] = set()
    if any(value in content for value in protected_values):
        categories.add("configured_private_value")
    if any(pattern.search(content) for pattern in PRIVATE_PATH_RES):
        categories.add("private_path")
    if GPU_UUID_RE.search(content):
        categories.add("gpu_uuid")
    if any(pattern.search(content) for pattern in CREDENTIAL_RES):
        categories.add("credential")
    return categories


def _file_chunks(path: Path) -> Iterator[bytes]:
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                yield chunk
    except OSError as exc:
        raise PublicationError("cannot read tracked content") from exc


def _git_object_chunks(root: Path, object_type: str, object_id: str) -> Iterator[bytes]:
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", object_type, object_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise PublicationError("repository object inspection failed") from exc
    if process.stdout is None:
        process.kill()
        raise PublicationError("repository object inspection failed")
    try:
        while chunk := process.stdout.read(64 * 1024):
            yield chunk
    finally:
        process.stdout.close()
    if process.wait() != 0:
        raise PublicationError("repository object inspection failed")


def _tracked_contents(root: Path) -> Iterable[Iterator[bytes]]:
    paths = [item for item in _git(root, "ls-files", "-z").split("\0") if item]
    for relative in paths:
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise PublicationError("tracked path resolves outside repository")
        yield _file_chunks(candidate)
    index_rows = _git(root, "ls-files", "-s", "-z").split("\0")
    object_ids = {row.split(maxsplit=3)[1] for row in index_rows if row.strip()}
    for object_id in object_ids:
        yield _git_object_chunks(root, "blob", object_id)


def _outgoing_contents(root: Path, remote: str) -> Iterable[Iterator[bytes]]:
    rows = _git(root, "rev-list", "--objects", "HEAD", "--not", f"--remotes={remote}").splitlines()
    for row in rows:
        object_id = row.split(maxsplit=1)[0]
        object_type = _git(root, "cat-file", "-t", object_id).strip()
        if object_type in {"blob", "commit"}:
            yield _git_object_chunks(root, object_type, object_id)


def _stream_categories(
    chunks: Iterable[bytes], protected_values: Sequence[bytes]
) -> set[str]:
    categories: set[str] = set()
    overlap_size = max((len(value) for value in protected_values), default=0)
    overlap_size = max(overlap_size, 1024)
    tail = b""
    for chunk in chunks:
        window = tail + chunk
        categories.update(_categories(window, protected_values))
        tail = window[-overlap_size:]
    return categories


def scan_publication(
    root: Path, *, public_remote: str, protected_values: Sequence[str]
) -> dict[str, Any]:
    root = _repository_root(root)
    base_failure = _remote_base_status(root, public_remote)
    if base_failure is not None:
        return {
            "ok": False,
            "findings": [{"category": base_failure, "source": "repository"}],
            "scanned_sources": 0,
        }
    encoded_values = tuple(value.encode("utf-8") for value in protected_values if value)
    if any(not 3 <= len(value) <= 512 for value in encoded_values):
        raise PublicationError("protected values must contain between 3 and 512 UTF-8 bytes")
    findings: set[tuple[str, str]] = set()
    scanned_sources = 0
    sources = chain(
        (("tracked_tree", chunks) for chunks in _tracked_contents(root)),
        (("outgoing_object", chunks) for chunks in _outgoing_contents(root, public_remote)),
    )
    for source, chunks in sources:
        scanned_sources += 1
        findings.update(
            (category, source) for category in _stream_categories(chunks, encoded_values)
        )
    rendered_findings = [
        {"category": category, "source": source} for category, source in sorted(findings)
    ]
    return {
        "ok": not rendered_findings,
        "findings": rendered_findings,
        "scanned_sources": scanned_sources,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed publication disclosure scan")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.root, args.manifest)
        result = scan_publication(
            args.root,
            public_remote=manifest.public_remote,
            protected_values=manifest.private_values,
        )
    except PublicationError:
        result = {
            "ok": False,
            "findings": [{"category": "publication_scan_error", "source": "repository"}],
            "scanned_sources": 0,
        }
    emit(result)
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
