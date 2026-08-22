from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from lowbit_lab.runtime import RuntimeArtifact, RuntimeContractError
from lowbit_lab.runtime_artifacts import _ClosedRedirects, _verify_existing


def test_existing_artifact_requires_exact_size_and_hash(tmp_path: Path) -> None:
    body = b"wheel"
    artifact = RuntimeArtifact(
        role="python_distribution",
        name="example",
        version="1.0",
        url="https://example.invalid/example.whl",
        filename="example.whl",
        size_bytes=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        binary_format="wheel",
        direct=True,
    )
    path = tmp_path / artifact.filename
    assert _verify_existing(path, artifact) is False
    path.write_bytes(body)
    assert _verify_existing(path, artifact) is True
    path.write_bytes(b"other")
    with pytest.raises(RuntimeContractError, match="cache ambiguity"):
        _verify_existing(path, artifact)


def test_runtime_redirects_are_closed_to_https_allowlist() -> None:
    handler = _ClosedRedirects(frozenset({"example.invalid"}))
    import urllib.request

    request = urllib.request.Request("https://example.invalid/source")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://example.invalid/artifact"
    )
    assert redirected.full_url == "https://example.invalid/artifact"
    with pytest.raises(RuntimeContractError, match="approved HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://escape.invalid/a")
    with pytest.raises(RuntimeContractError, match="approved HTTPS"):
        handler.redirect_request(
            request, None, 302, "Found", {}, "https://example.invalid/a?token=redacted"
        )
