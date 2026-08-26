from __future__ import annotations

import hashlib
import json
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import lowbit_lab.reference_transport as reference_transport
from lowbit_lab.constants import REFERENCE_SIGNED_CDN_AUTHORITY_SHA256
from lowbit_lab.reference_transport import (
    HeadOnlyFetcher,
    ReferenceTransportError,
    validate_topology_evidence,
)

REQUEST = b'{"source_artifacts":[{}]}'


@pytest.fixture(autouse=True)
def _validated_request(monkeypatch):
    monkeypatch.setattr(
        reference_transport,
        "validate_bootstrap_request_bytes",
        lambda value: SimpleNamespace(source_artifacts=({},)),
    )


def _write(path: Path, request: bytes, observed_at: datetime) -> dict[str, object]:
    value: dict[str, object] = {
        "artifacts_observed": 1,
        "authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        "body_bytes_read": 0,
        "kind": "reference_transport_topology",
        "observed_at": observed_at.isoformat(),
        "signed_query_redirect_observed": True,
        "query_material_persisted": False,
        "remote_route_fidelity_proven": False,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "schema_version": 1,
    }
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return value


def test_fresh_sanitized_topology_evidence_is_accepted(tmp_path: Path) -> None:
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    request = REQUEST
    path = tmp_path / "evidence.json"
    expected = _write(path, request, now - timedelta(minutes=14))

    assert validate_topology_evidence(path, request_bytes=request, now=now) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("body_bytes_read", 1),
        ("artifacts_observed", 0),
        ("signed_query_redirect_observed", False),
        ("query_material_persisted", True),
        ("remote_route_fidelity_proven", True),
        ("authority_sha256", "0" * 64),
        ("request_sha256", "0" * 64),
    ],
)
def test_topology_evidence_drift_fails(tmp_path: Path, field: str, value: object) -> None:
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    path = tmp_path / "evidence.json"
    raw = _write(path, REQUEST, now)
    raw[field] = value
    path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ReferenceTransportError):
        validate_topology_evidence(path, request_bytes=REQUEST, now=now)


def test_topology_evidence_older_than_fifteen_minutes_fails(tmp_path: Path) -> None:
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    path = tmp_path / "evidence.json"
    _write(path, REQUEST, now - timedelta(minutes=15, seconds=1))

    with pytest.raises(ReferenceTransportError, match="stale"):
        validate_topology_evidence(path, request_bytes=REQUEST, now=now)


def test_head_failure_traceback_does_not_retain_signed_query(monkeypatch) -> None:
    sentinel = "signed" + "-query-secret"

    class Connection:
        def __init__(self, host: str, address: str) -> None:
            del host, address

        @staticmethod
        def request(method: str, selector: str, *, headers: dict[str, str]) -> None:
            del method, headers
            raise OSError(selector)

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(reference_transport, "PinnedHTTPSConnection", Connection)
    with pytest.raises(ReferenceTransportError) as raised:
        HeadOnlyFetcher().open(
            f"https://us.aws.cdn.hf.co/xet-bridge-us/file?sig={sentinel}",
            resolved_addresses=("8.8.8.8",),
            proxies_disabled=True,
        )

    rendered = "".join(
        traceback.format_exception(type(raised.value), raised.value, raised.value.__traceback__)
    )
    assert sentinel not in rendered
    assert raised.value.__cause__ is None


def test_observer_checks_every_artifact_without_persisting_urls(
    tmp_path: Path, monkeypatch
) -> None:
    origins = ["https://artifacts.example/one", "https://artifacts.example/two"]
    raw = {
        "approved_https_hosts": ["artifacts.example"],
        "source_artifacts": [{"url": origin} for origin in origins],
    }
    request_path = tmp_path / "request.json"
    request_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    request_path.write_bytes(request_bytes)
    monkeypatch.setattr(
        reference_transport,
        "validate_bootstrap_request_bytes",
        lambda value: SimpleNamespace(
            canonical_json=value.decode(), source_artifacts=tuple(raw["source_artifacts"])
        ),
    )
    for name in reference_transport.PROXY_KEYS:
        monkeypatch.delenv(name, raising=False)
    calls: list[str] = []

    def open_once(origin: str, *, approved_hosts, resolver, fetcher):
        del approved_hosts, resolver
        calls.append(origin)
        fetcher.signed_query_redirect_observed = True
        return None

    monkeypatch.setattr(reference_transport, "open_validated_url", open_once)
    output = tmp_path / "topology.json"

    evidence = reference_transport.observe_topology(request_path, output_path=output)

    assert calls == origins
    assert evidence["artifacts_observed"] == 2
    persisted = output.read_text(encoding="utf-8")
    assert all(origin not in persisted for origin in origins)
