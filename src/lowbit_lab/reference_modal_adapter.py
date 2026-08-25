"""The single, deliberately narrow Modal boundary for the U8 reference action.

Nothing in this module imports Modal until the database has durably consumed U8.
The callable is serialized by value because the reviewed control-plane package is
intentionally not copied into the remote image.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
)
from lowbit_lab.db import DatabaseError, ResultsDatabase
from lowbit_lab.evaluation_lock import EvaluationLockError, validate_pending_evaluation_lock
from lowbit_lab.reference_backend import build_execution_dependencies
from lowbit_lab.reference_bootstrap import (
    ReferenceBootstrapError,
    validate_bootstrap_receipt_bytes,
    validate_bootstrap_request_bytes,
    validate_image_lock,
)
from lowbit_lab.reference_execution import ReferenceExecution
from lowbit_lab.reference_harness import (
    ReferenceHarnessError,
    validate_execution_identity,
    validate_reference_manifest_bytes,
)


class ReferenceModalError(RuntimeError):
    """A safe local description of a paid-boundary failure."""


REMOTE_CONTRACT_KIND = "reference_modal_remote_contract"
REMOTE_RESULT_KIND = "reference_modal_remote_result"
_REMOTE_CONTRACT_FIELDS = {
    "evaluation_lock_bytes_b64",
    "execution_identity",
    "fixtures",
    "image_lock",
    "image_recipe_sha256",
    "kind",
    "provider_image_identity",
    "response_caps",
    "schema_version",
    "serialized_function_sha256",
    "submission_pending_at",
    "timeout_seconds",
    "bootstrap_request_bytes_b64",
}


@dataclass(frozen=True)
class ReferenceModalCapability:
    """Already-reserved capability; constructing it cannot contact a provider."""

    db_path: Path
    root: Path
    config_path: Path
    request_path: Path
    image_lock_path: Path
    provider_capability_path: Path
    billing_authority_path: Path
    billing_receipt_path: Path
    billing_report_path: Path
    publication_manifest_path: Path
    reservation_id: str
    owner_id: str
    authority_root: Path
    provider_environment: str
    bootstrap_request_bytes: bytes
    evaluation_lock_bytes: bytes
    fixture_bytes: Mapping[str, bytes]
    execution_identity: Mapping[str, str]
    image_lock: Mapping[str, object]


@dataclass(frozen=True)
class ValidatedRemoteContract:
    """Closed wire values plus validation products used by the remote entrypoint."""

    raw: Mapping[str, object]
    request: Any
    evaluation_lock: Any
    fixtures: Mapping[str, bytes]
    execution_identity: Mapping[str, str]
    submission_pending_at: datetime


def _validate_fresh_deterministic_gates(capability: ReferenceModalCapability) -> None:
    """Recompute decision-bearing local evidence; no caller boolean is authority."""
    from lowbit_lab.modal_job import load_reference_job_config, plan_reference_bootstrap_preview
    from lowbit_lab.runtime import runtime_metadata

    root = capability.root.resolve()
    if any(
        path.is_absolute() or ".." in path.parts
        for path in (
            capability.config_path,
            capability.request_path,
            capability.image_lock_path,
            capability.provider_capability_path,
            capability.billing_authority_path,
            capability.billing_receipt_path,
            capability.billing_report_path,
            capability.publication_manifest_path,
        )
    ):
        raise ReferenceModalError("fresh deterministic artifact path is not repository-relative")
    try:
        config = load_reference_job_config(root / capability.config_path, root=root)
        request = validate_bootstrap_request_bytes(capability.bootstrap_request_bytes)
        request_raw = json.loads(request.canonical_json)
        preview = plan_reference_bootstrap_preview(
            config,
            root=root,
            request_path=capability.request_path,
            request_sha256=_sha(capability.bootstrap_request_bytes),
            image_lock_path=capability.image_lock_path,
            image_lock_sha256=_sha(_canonical_json(capability.image_lock)),
            provider_capability_path=capability.provider_capability_path,
            provider_capability_sha256=str(
                json.loads(
                    request.canonical_json
                )["provider_capability"]["receipt_sha256"]
            ),
            billing_authority_path=capability.billing_authority_path,
            billing_receipt_path=capability.billing_receipt_path,
            billing_report_path=capability.billing_report_path,
            publication_manifest_path=capability.publication_manifest_path,
        )
        runtime = runtime_metadata(root)
    except Exception as exc:
        raise ReferenceModalError("fresh deterministic gate could not be reproduced") from exc
    empirical = preview.get("empirical")
    if (
        preview.get("bootstrap_ready") is not True
        or preview.get("submit") is not False
        or preview.get("actual_cost_usd") != "0"
        or preview.get("weights_transferred") is not False
        or preview.get("request_sha256") != request.sha256
        or preview.get("image_lock_sha256") != request.image_lock_sha256
        or preview.get("configured_context_tokens") != 262144
        or preview.get("proven_useful_context_tokens") is not None
        or not isinstance(empirical, Mapping)
        or any(value != "pending" for value in empirical.values())
        or runtime.get("git_dirty") is not False
        or runtime.get("git_commit") != request_raw["lineage"]["reviewed_commit"]
        or runtime.get("control_plane_sha256") != request_raw["lineage"]["control_plane_sha256"]
    ):
        raise ReferenceModalError("fresh deterministic gate is not bootstrap-ready")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_b64(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ReferenceModalError(f"{name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ReferenceModalError(f"{name} is invalid") from exc
    if base64.b64encode(decoded).decode() != value:
        raise ReferenceModalError(f"{name} is not canonical")
    return decoded


def _submission_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ReferenceModalError("submission time is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ReferenceModalError("submission time is invalid") from exc
    if parsed.tzinfo is None or parsed.isoformat() != value:
        raise ReferenceModalError("submission time is not canonical")
    return parsed.astimezone(UTC)


def _validate_fixtures(value: object, lock: object) -> tuple[dict[str, bytes], Any]:
    if not isinstance(value, list) or len(value) != 6:
        raise ReferenceModalError("remote contract must bind exactly six fixtures")
    fixtures: dict[str, bytes] = {}
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"fixture_id", "sha256", "bytes_b64"}:
            raise ReferenceModalError("remote fixture schema drift")
        fixture_id, digest = item["fixture_id"], item["sha256"]
        if not isinstance(fixture_id, str) or not isinstance(digest, str):
            raise ReferenceModalError("remote fixture identity is invalid")
        body = _decode_b64(item["bytes_b64"], "fixture bytes")
        if _sha(body) != digest or fixture_id in fixtures:
            raise ReferenceModalError("remote fixture hash binding drift")
        fixtures[fixture_id] = body
    try:
        validated_lock = validate_pending_evaluation_lock(lock, fixture_bytes=fixtures)
    except EvaluationLockError as exc:
        raise ReferenceModalError("remote evaluation lock binding drift") from exc
    return fixtures, validated_lock


def validate_remote_contract_bytes(content: bytes) -> ValidatedRemoteContract:
    """Validate the remote input without any provider or filesystem side effect."""
    try:
        raw = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceModalError("remote contract is invalid JSON") from exc
    if not isinstance(raw, dict) or set(raw) != _REMOTE_CONTRACT_FIELDS:
        raise ReferenceModalError("remote contract schema drift")
    if raw["schema_version"] != 1 or raw["kind"] != REMOTE_CONTRACT_KIND:
        raise ReferenceModalError("remote contract kind drift")
    if content != _canonical_json(raw):
        raise ReferenceModalError("remote contract must be canonical")
    request_bytes = _decode_b64(raw["bootstrap_request_bytes_b64"], "bootstrap request")
    lock_bytes = _decode_b64(raw["evaluation_lock_bytes_b64"], "evaluation lock")
    try:
        request = validate_bootstrap_request_bytes(request_bytes)
        lock_raw = json.loads(lock_bytes)
        image = validate_image_lock(raw["image_lock"])
        identity = validate_execution_identity(raw["execution_identity"])
    except (ReferenceBootstrapError, json.JSONDecodeError, ReferenceHarnessError) as exc:
        raise ReferenceModalError("remote contract lineage drift") from exc
    if lock_bytes != _canonical_json(lock_raw):
        raise ReferenceModalError("evaluation lock must be canonical")
    fixtures, validated_lock = _validate_fixtures(raw["fixtures"], lock_raw)
    request_raw = json.loads(request.canonical_json)
    if (
        raw["image_recipe_sha256"] != image.recipe_sha256
        or request.image_lock_sha256 != image.sha256
        or not isinstance(raw["provider_image_identity"], str)
        or not raw["provider_image_identity"].startswith(("im-", "ap-"))
        or not isinstance(raw["serialized_function_sha256"], str)
        or not SHA256_RE.fullmatch(raw["serialized_function_sha256"])
        or raw["timeout_seconds"] != request_raw["deadline_policy"]["timeout_seconds"]
        or raw["response_caps"] != request_raw["response_caps"]
    ):
        raise ReferenceModalError("remote contract boundary drift")
    return ValidatedRemoteContract(
        raw=raw,
        request=request,
        evaluation_lock=validated_lock,
        fixtures=fixtures,
        execution_identity=identity,
        submission_pending_at=_submission_time(raw["submission_pending_at"]),
    )


def build_remote_contract(
    capability: ReferenceModalCapability,
    *,
    provider_image_identity: str,
    serialized_function_sha256: str,
    submission_pending_at: str,
) -> bytes:
    """Create the one closed payload after the provider has resolved its image identity."""
    if not provider_image_identity.startswith(("im-", "ap-")):
        raise ReferenceModalError("provider image-or-deployment identity is invalid")
    if not SHA256_RE.fullmatch(serialized_function_sha256):
        raise ReferenceModalError("serialized function identity is invalid")
    try:
        request = validate_bootstrap_request_bytes(capability.bootstrap_request_bytes)
        request_raw = json.loads(request.canonical_json)
        lock_raw = json.loads(capability.evaluation_lock_bytes)
        image = validate_image_lock(capability.image_lock)
        identity = validate_execution_identity(capability.execution_identity)
    except (ReferenceBootstrapError, json.JSONDecodeError, ReferenceHarnessError) as exc:
        raise ReferenceModalError("capability lineage is invalid") from exc
    if (
        capability.evaluation_lock_bytes != _canonical_json(lock_raw)
        or request.image_lock_sha256 != image.sha256
    ):
        raise ReferenceModalError("capability lineage is not canonical")
    fixtures = [
        {
            "fixture_id": fixture_id,
            "sha256": _sha(body),
            "bytes_b64": base64.b64encode(body).decode(),
        }
        for fixture_id, body in sorted(capability.fixture_bytes.items())
    ]
    raw = {
        "bootstrap_request_bytes_b64": base64.b64encode(
            capability.bootstrap_request_bytes
        ).decode(),
        "evaluation_lock_bytes_b64": base64.b64encode(capability.evaluation_lock_bytes).decode(),
        "execution_identity": identity,
        "fixtures": fixtures,
        "image_lock": json.loads(image.canonical_json),
        "image_recipe_sha256": image.recipe_sha256,
        "kind": REMOTE_CONTRACT_KIND,
        "provider_image_identity": provider_image_identity,
        "response_caps": request_raw["response_caps"],
        "schema_version": 1,
        "serialized_function_sha256": serialized_function_sha256,
        "submission_pending_at": submission_pending_at,
        "timeout_seconds": request_raw["deadline_policy"]["timeout_seconds"],
    }
    content = _canonical_json(raw)
    validate_remote_contract_bytes(content)
    return content


def _run_closed_remote_contract(content: bytes) -> dict[str, object]:
    """Audited production path, serialized by value rather than importing this package remotely."""
    contract = validate_remote_contract_bytes(content)
    request = contract.request
    lock = contract.evaluation_lock
    fixtures = contract.fixtures
    identity = contract.execution_identity
    elapsed = (datetime.now(UTC) - contract.submission_pending_at).total_seconds()
    if elapsed < 0 or elapsed >= 2700:
        raise ReferenceModalError("submission deadline is unavailable")
    # This fixed ephemeral directory is not caller-controlled and is never mounted or retained.
    dependencies = build_execution_dependencies(
        request,
        lock,
        fixtures,
        identity,
        artifact_root=Path("/tmp/lowbit-lab-reference"),
        image_identity_sha256=_sha(str(contract.raw["provider_image_identity"]).encode()),
    )
    result = ReferenceExecution(
        request, dependencies, deadline_started_monotonic=time.monotonic() - elapsed
    ).run()
    receipt = validate_bootstrap_receipt_bytes(result.receipt, request=request)
    manifest: bytes | None = None
    if result.manifest is not None:
        manifest = result.manifest
        validate_reference_manifest_bytes(
            manifest,
            evaluation_lock_sha256=lock.sha256,
            context_ladder_tokens=request.context_ladder_tokens,
        )
    raw = {
        "contract_sha256": _sha(content),
        "kind": REMOTE_RESULT_KIND,
        "manifest_b64": None if manifest is None else base64.b64encode(manifest).decode(),
        "receipt_b64": base64.b64encode(receipt.canonical_json.encode()).decode(),
        "schema_version": 1,
    }
    return json.loads(_canonical_json(raw))


def _serialized_remote_callable() -> tuple[Any, bytes, tuple[Any, ...]]:
    """Package the reviewed execution graph by value; never mount local source."""
    import sys

    import lowbit_lab.evaluation_lock as evaluation_lock
    import lowbit_lab.reference_backend as reference_backend
    import lowbit_lab.reference_bootstrap as reference_bootstrap
    import lowbit_lab.reference_execution as reference_execution
    import lowbit_lab.reference_harness as reference_harness
    from modal._serialization import serialize
    from modal._vendor import cloudpickle

    modules = (
        sys.modules[__name__],
        evaluation_lock,
        reference_backend,
        reference_bootstrap,
        reference_execution,
        reference_harness,
    )
    for module in modules:
        cloudpickle.register_pickle_by_value(module)

    runner = _run_closed_remote_contract

    def remote_entry(contract_bytes: bytes) -> dict[str, object]:
        return runner(contract_bytes)

    # Modal's FunctionInfo uses this exact serializer during app hydration.
    payload = serialize(remote_entry)
    if len(payload) > 16 << 20:
        raise ReferenceModalError("serialized function exceeds provider cap")
    return remote_entry, payload, modules


def _clear_serialization_policy(modules: tuple[Any, ...]) -> None:
    from modal._vendor import cloudpickle

    for module in modules:
        with suppress(ValueError):
            cloudpickle.unregister_pickle_by_value(module)


def _image_from_lock(modal: Any, image_lock: Mapping[str, object]) -> Any:
    image = validate_image_lock(image_lock)
    raw = json.loads(image.canonical_json)
    base = raw["base_image"]
    assert isinstance(base, Mapping)
    source = modal.Image.from_registry(f"{base['reference']}@{base['digest']}")
    artifacts = raw["dependency_artifacts"]
    assert isinstance(artifacts, list)
    urls = [
        f"{item['url']}#sha256={item['sha256']}" for item in artifacts if isinstance(item, Mapping)
    ]
    if not urls or len(urls) != len(raw["recipe"]["dependency_filenames"]):
        raise ReferenceModalError("image dependency lock is incomplete")
    return source.pip_install(*urls, extra_options="--no-deps --require-hashes")


def _audit_block(
    database: ResultsDatabase, capability: ReferenceModalCapability, reason: str
) -> None:
    with suppress(DatabaseError):
        database.mark_reference_audit_blocked(
            capability.reservation_id,
            owner_id=capability.owner_id,
            reason=f"provider boundary uncertainty: {reason[:64]}",
            occurred_at=datetime.now(UTC).isoformat(),
        )


def submit_reference(capability: ReferenceModalCapability) -> dict[str, object]:
    """The only U8 provider call path. Callers must already hold a reservation."""
    database = ResultsDatabase(capability.db_path)
    # Validate every deterministic byte before consuming the sole action.
    try:
        _validate_fresh_deterministic_gates(capability)
        build_remote_contract(
            capability,
            provider_image_identity="im-placeholder",
            serialized_function_sha256="0" * 64,
            submission_pending_at=datetime.now(UTC).isoformat(),
        )
    except (ReferenceBootstrapError, ReferenceModalError) as exc:
        raise ReferenceModalError("deterministic remote contract gate failed") from exc

    submission_pending_at = datetime.now(UTC).isoformat()
    database.mark_reference_submission_pending(
        capability.reservation_id,
        owner_id=capability.owner_id,
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=capability.authority_root,
        occurred_at=submission_pending_at,
    )
    # This is the local monotonic representation of the durable boundary above.
    started = time.monotonic()
    try:
        import modal

        remote_entry, serialized, serialized_modules = _serialized_remote_callable()
        image = _image_from_lock(modal, capability.image_lock)
        app = modal.App("low-bit-lab-reference-u8", image=image, include_source=False)
        remote = app.function(
            image=image,
            gpu="A100-80GB:1",
            cpu=8,
            memory=98304,
            ephemeral_disk=524288,
            timeout=2700,
            retries=0,
            max_containers=1,
            include_source=False,
            serialized=True,
            restrict_modal_access=True,
            single_use_containers=True,
        )(remote_entry)
        with app.run(environment_name=capability.provider_environment):
            image.build(app)
            # App hydration serializes the function.  The reviewed registration window
            # ends before the one spawn and is always cleared below on failure as well.
            _clear_serialization_policy(serialized_modules)
            image_identity = image.object_id
            app_identity = app.app_id
            if not isinstance(image_identity, str) or not isinstance(app_identity, str):
                raise ReferenceModalError("provider image-or-deployment identity is unavailable")
            _persist_prepared(database, capability, image_identity, app_identity)
            if time.monotonic() - started >= 2700 - 1500:
                raise ReferenceModalError("deadline reserves no longer admit spawn")
            contract = build_remote_contract(
                capability,
                provider_image_identity=image_identity,
                serialized_function_sha256=_sha(serialized),
                submission_pending_at=submission_pending_at,
            )
            call = remote.spawn(contract)
            call_identity = call.object_id
            if not isinstance(call_identity, str) or not call_identity:
                raise ReferenceModalError("provider call identity is unavailable")
            database.mark_reservation_submitted(
                capability.reservation_id,
                owner_id=capability.owner_id,
                provider_job_id=call_identity,
                app_identity=app_identity,
                occurred_at=datetime.now(UTC).isoformat(),
                lease_expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            )
            raw_result = call.get(timeout=2700)
            result = validate_remote_result(raw_result, capability)
            if not isinstance(raw_result, Mapping) or raw_result.get("contract_sha256") != _sha(
                contract
            ):
                raise ReferenceModalError("provider return contract binding drift")
            now = datetime.now(UTC)
            database.mark_settlement_pending(
                capability.reservation_id,
                owner_id=capability.owner_id,
                occurred_at=now.isoformat(),
                provider_terminal_at=now.isoformat(),
                lease_expires_at=(now + timedelta(hours=2)).isoformat(),
            )
    except Exception as exc:
        if "serialized_modules" in locals():
            _clear_serialization_policy(serialized_modules)
        _audit_block(database, capability, type(exc).__name__)
        raise ReferenceModalError("reference provider state requires audit") from exc
    return result


def _persist_prepared(
    database: ResultsDatabase,
    capability: ReferenceModalCapability,
    image_identity: str,
    app_identity: str,
) -> None:
    database.mark_reference_provider_prepared(
        capability.reservation_id,
        owner_id=capability.owner_id,
        provider_image_identity=image_identity,
        app_identity=app_identity,
        occurred_at=datetime.now(UTC).isoformat(),
        lease_expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat(),
    )


def validate_remote_result(
    value: object, capability: ReferenceModalCapability
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {"contract_sha256", "kind", "manifest_b64", "receipt_b64", "schema_version"}
        or value["kind"] != REMOTE_RESULT_KIND
        or value["schema_version"] != 1
    ):
        raise ReferenceModalError("provider return schema drift")
    receipt = _decode_b64(value["receipt_b64"], "receipt")
    request = validate_bootstrap_request_bytes(capability.bootstrap_request_bytes)
    validated_receipt = validate_bootstrap_receipt_bytes(receipt, request=request)
    manifest_raw = value["manifest_b64"]
    if manifest_raw is not None:
        manifest = _decode_b64(manifest_raw, "manifest")
        lock = json.loads(capability.evaluation_lock_bytes)
        fixtures = {key: body for key, body in capability.fixture_bytes.items()}
        validated_lock = validate_pending_evaluation_lock(lock, fixture_bytes=fixtures)
        validate_reference_manifest_bytes(
            manifest,
            evaluation_lock_sha256=validated_lock.sha256,
            context_ladder_tokens=request.context_ladder_tokens,
        )
    return {
        "receipt_sha256": _sha(validated_receipt.canonical_json.encode()),
        "status": validated_receipt.status,
    }
