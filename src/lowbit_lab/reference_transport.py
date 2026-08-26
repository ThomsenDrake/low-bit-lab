"""Sanitized local topology evidence required immediately before U8 submission."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from lowbit_lab.constants import REFERENCE_SIGNED_CDN_AUTHORITY_SHA256
from lowbit_lab.handoff import canonical_json
from lowbit_lab.reference_backend import PinnedHTTPSConnection, PublicResolver
from lowbit_lab.reference_bootstrap import validate_bootstrap_request_bytes
from lowbit_lab.reference_execution import (
    PROXY_KEYS,
    FetchResponse,
    open_validated_url,
)

TOPOLOGY_EVIDENCE_PATH = Path("reports/local/reference-transport-topology.json")
MAX_TOPOLOGY_AGE_SECONDS = 15 * 60
_FIELDS = {
    "artifacts_observed",
    "authority_sha256",
    "body_bytes_read",
    "kind",
    "observed_at",
    "signed_query_redirect_observed",
    "query_material_persisted",
    "remote_route_fidelity_proven",
    "request_sha256",
    "schema_version",
}


class ReferenceTransportError(RuntimeError):
    """A sanitized transport-evidence validation failure."""


class HeadOnlyFetcher:
    """Direct pinned HEAD client that never reads a response body."""

    def __init__(self) -> None:
        self.signed_query_redirect_observed = False

    def open(
        self, url: str, *, resolved_addresses: tuple[str, ...], proxies_disabled: bool
    ) -> FetchResponse:
        if not proxies_disabled or not resolved_addresses:
            raise ReferenceTransportError("network policy drift")
        parsed = urlsplit(url)
        self.signed_query_redirect_observed |= bool(parsed.query)
        connection = PinnedHTTPSConnection(str(parsed.hostname), resolved_addresses[0])
        selector = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        result: FetchResponse | None = None
        failed = False
        try:
            connection.request("HEAD", selector, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            peer = str(connection.sock.getpeername()[0])  # type: ignore[union-attr]
            length_header = response.getheader("Content-Length")
            length = int(length_header) if length_header is not None else None
            location = response.getheader("Location")
            result = FetchResponse(response.status, peer, length, (), location)
        except (OSError, ValueError, RuntimeError):
            failed = True
        finally:
            connection.close()
        if failed or result is None:
            raise ReferenceTransportError("topology observation failed")
        return result


def observe_topology(
    request_path: Path,
    *,
    output_path: Path = TOPOLOGY_EVIDENCE_PATH,
) -> Mapping[str, object]:
    """Perform one direct HEAD-only observation and persist no URL or query material."""
    if any(os.environ.get(name) for name in PROXY_KEYS):
        raise ReferenceTransportError("ambient proxy prevents topology observation")
    try:
        request_bytes = request_path.read_bytes()
        request = validate_bootstrap_request_bytes(request_bytes)
        raw = json.loads(request.canonical_json)
        origins = tuple(str(item["url"]) for item in raw["source_artifacts"])
        approved = frozenset(raw["approved_https_hosts"])
    except Exception as exc:
        raise ReferenceTransportError("bootstrap request is invalid") from exc
    fetcher = HeadOnlyFetcher()
    resolver = PublicResolver()
    observation_failed = False
    for origin in origins:
        try:
            open_validated_url(
                origin,
                approved_hosts=approved,
                resolver=resolver,
                fetcher=fetcher,
            )
        except Exception:
            observation_failed = True
            break
    if observation_failed:
        raise ReferenceTransportError("topology observation failed")
    if not fetcher.signed_query_redirect_observed:
        raise ReferenceTransportError("signed query redirect was not observed")
    evidence: dict[str, object] = {
        "artifacts_observed": len(origins),
        "authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        "body_bytes_read": 0,
        "kind": "reference_transport_topology",
        "observed_at": datetime.now(UTC).isoformat(),
        "signed_query_redirect_observed": fetcher.signed_query_redirect_observed,
        "query_material_persisted": False,
        "remote_route_fidelity_proven": False,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "schema_version": 1,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (canonical_json(evidence) + "\n").encode()
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(output_path)
    validate_topology_evidence(output_path, request_bytes=request_bytes)
    return evidence


def main(argv: list[str] | None = None) -> int:
    """Small JSON CLI for the authorized local, no-body observation."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(json.dumps({"ok": False, "error": "usage"}, sort_keys=True))
        return 2
    try:
        evidence = observe_topology(Path(args[0]))
    except ReferenceTransportError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "body_bytes_read": evidence["body_bytes_read"],
                "artifacts_observed": evidence["artifacts_observed"],
                "ok": True,
                "signed_query_redirect_observed": evidence[
                    "signed_query_redirect_observed"
                ],
                "query_material_persisted": evidence["query_material_persisted"],
                "remote_route_fidelity_proven": evidence["remote_route_fidelity_proven"],
            },
            sort_keys=True,
        )
    )
    return 0


def validate_topology_evidence(
    path: Path,
    *,
    request_bytes: bytes,
    now: datetime | None = None,
) -> Mapping[str, object]:
    """Require canonical, fresh, body-free evidence bound to the exact request."""
    try:
        encoded = path.read_bytes()
        value = json.loads(encoded.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceTransportError("transport topology evidence is unavailable") from exc
    if not isinstance(value, Mapping):
        raise ReferenceTransportError("transport topology evidence schema drift")
    canonical = (canonical_json(value) + "\n").encode()
    if encoded != canonical or set(value) != _FIELDS:
        raise ReferenceTransportError("transport topology evidence schema drift")
    try:
        observed = datetime.fromisoformat(str(value["observed_at"]))
    except ValueError as exc:
        raise ReferenceTransportError("transport topology evidence time is invalid") from exc
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if observed.tzinfo is None or observed.isoformat() != value["observed_at"]:
        raise ReferenceTransportError("transport topology evidence time is invalid")
    age = (current - observed.astimezone(UTC)).total_seconds()
    if age < 0 or age > MAX_TOPOLOGY_AGE_SECONDS:
        raise ReferenceTransportError("transport topology evidence is stale")
    expected_request = hashlib.sha256(request_bytes).hexdigest()
    try:
        expected_artifacts = len(validate_bootstrap_request_bytes(request_bytes).source_artifacts)
    except Exception as exc:
        raise ReferenceTransportError("bootstrap request is invalid") from exc
    if (
        value["artifacts_observed"] != expected_artifacts
        or not isinstance(value["artifacts_observed"], int)
        or isinstance(value["artifacts_observed"], bool)
        or value["artifacts_observed"] <= 0
        or
        value["kind"] != "reference_transport_topology"
        or value["schema_version"] != 1
        or value["authority_sha256"] != REFERENCE_SIGNED_CDN_AUTHORITY_SHA256
        or value["request_sha256"] != expected_request
        or value["body_bytes_read"] != 0
        or value["signed_query_redirect_observed"] is not True
        or value["query_material_persisted"] is not False
        or value["remote_route_fidelity_proven"] is not False
    ):
        raise ReferenceTransportError("transport topology evidence is not submission-ready")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
