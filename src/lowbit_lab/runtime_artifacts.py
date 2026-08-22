from __future__ import annotations

import argparse
import hashlib
import os
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from lowbit_lab.jsonio import emit
from lowbit_lab.runtime import RuntimeArtifact, RuntimeContractError, RuntimeLock, load_runtime_lock


def _approved_url(url: str, hosts: frozenset[str]) -> bool:
    parsed = urlsplit(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname in hosts
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and not parsed.query
        and parsed.port in {None, 443}
    )


class _ClosedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str]) -> None:
        self._hosts = hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request:
        if not _approved_url(newurl, self._hosts):
            raise RuntimeContractError("runtime artifact redirect left the approved HTTPS hosts")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            raise RuntimeContractError("runtime artifact redirect is unsupported")
        return redirected


def _opener(hosts: frozenset[str]) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _ClosedRedirects(hosts),
    )


def _verify_existing(path: Path, artifact: RuntimeArtifact) -> bool:
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeContractError(f"runtime artifact cache ambiguity: {artifact.role}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != artifact.size_bytes:
        raise RuntimeContractError(f"runtime artifact cache ambiguity: {artifact.role}")
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if digest != artifact.sha256:
        raise RuntimeContractError(f"runtime artifact cache ambiguity: {artifact.role}")
    return True


def fetch_runtime_artifacts(lock: RuntimeLock, *, root: Path) -> dict[str, object]:
    root = root.resolve()
    artifact_root = (root / lock.artifact_root).resolve()
    if not artifact_root.is_relative_to(root):
        raise RuntimeContractError("artifact root resolves outside repository")
    hosts = frozenset(lock.allowed_hosts)
    opener = _opener(hosts)
    fetched = reused = transferred = 0
    artifact_root.mkdir(parents=True, exist_ok=True)
    for artifact in lock.artifacts:
        destination = artifact_root / artifact.sha256 / artifact.filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        if _verify_existing(destination, artifact):
            reused += 1
            continue
        request = urllib.request.Request(
            artifact.url,
            headers={"Accept": "application/octet-stream", "User-Agent": "low-bit-lab/1"},
            method="GET",
        )
        temporary_path: Path | None = None
        try:
            with closing(opener.open(request, timeout=60)) as response:
                if not _approved_url(response.geturl(), hosts) or response.status != 200:
                    raise RuntimeContractError("runtime artifact response identity is invalid")
                declared = response.headers.get("Content-Length")
                if (
                    declared is None
                    or not declared.isdigit()
                    or int(declared) != artifact.size_bytes
                ):
                    raise RuntimeContractError(
                        f"runtime artifact size declaration drifted: {artifact.role}"
                    )
                digest = hashlib.sha256()
                written = 0
                with tempfile.NamedTemporaryFile(
                    mode="w+b", prefix="partial-", dir=destination.parent, delete=False
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    while chunk := response.read(1024 * 1024):
                        written += len(chunk)
                        transferred += len(chunk)
                        if written > artifact.size_bytes or transferred > lock.aggregate_cap_bytes:
                            raise RuntimeContractError("runtime artifact transfer exceeded its cap")
                        digest.update(chunk)
                        temporary.write(chunk)
            if written != artifact.size_bytes or digest.hexdigest() != artifact.sha256:
                raise RuntimeContractError(f"runtime artifact content drifted: {artifact.role}")
            os.replace(temporary_path, destination)
            temporary_path = None
            fetched += 1
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeContractError(
                f"runtime artifact transfer failed: {artifact.role}"
            ) from exc
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
    return {
        "ok": True,
        "runtime_lock_sha256": lock.sha256,
        "artifact_count": len(lock.artifacts),
        "fetched_count": fetched,
        "reused_count": reused,
        "transferred_bytes": transferred,
        "verified_bytes": sum(item.size_bytes for item in lock.artifacts),
        "weights_required": False,
        "remote_submission_performed": False,
        "actual_cloud_cost_usd": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch a closed runtime artifact set")
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    try:
        lock = load_runtime_lock(args.runtime_lock, root=args.root)
        if not args.fetch:
            emit(
                {
                    "ok": True,
                    "mode": "preview",
                    "runtime_lock_sha256": lock.sha256,
                    "artifact_count": len(lock.artifacts),
                    "planned_bytes": sum(item.size_bytes for item in lock.artifacts),
                    "side_effects_performed": False,
                }
            )
            return
        emit(fetch_runtime_artifacts(lock, root=args.root))
    except RuntimeContractError as exc:
        emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
