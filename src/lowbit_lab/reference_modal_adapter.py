"""The single, deliberately narrow Modal boundary for the U8 reference action.

Nothing in this module invokes a Modal execution primitive until the database has
durably consumed U8.
The callable is serialized by value because the reviewed control-plane package is
intentionally not copied into the remote image.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.metadata
import json
import math
import os
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_RECOVERY_AUTHORITY_SHA256,
)
from lowbit_lab.db import DatabaseError, ResultsDatabase
from lowbit_lab.evaluation_lock import EvaluationLockError, validate_pending_evaluation_lock
from lowbit_lab.provider_evidence import validate_provider_capability_receipt
from lowbit_lab.reference_bootstrap import (
    ADDITIONAL_ACTION,
    ORIGINAL_ACTION,
    BootstrapRequest,
    ReferenceBootstrapError,
    validate_bootstrap_receipt_bytes,
    validate_bootstrap_request_bytes,
    validate_image_lock,
)
from lowbit_lab.reference_contract import REFERENCE_APP_NAME
from lowbit_lab.reference_execution import ReferenceDeadlineAbort
from lowbit_lab.reference_harness import (
    ReferenceHarnessError,
    validate_execution_identity,
    validate_reference_manifest_bytes,
)
from lowbit_lab.reference_provider_auth import (
    OFFICIAL_MODAL_SERVER_URL,
    auth_receipt_path,
    provider_environment_overrides_present,
)
from lowbit_lab.reference_transport import TOPOLOGY_EVIDENCE_PATH, validate_topology_evidence


class ReferenceModalError(RuntimeError):
    """A safe local description of a paid-boundary failure."""


REMOTE_CONTRACT_KIND = "reference_modal_remote_contract"
REMOTE_RESULT_KIND = "reference_modal_remote_result"
MODAL_SERIALIZED_FUNCTION_MAX_BYTES = 64 << 10
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
    replacement_entitlement_sha256: str | None = None
    recovery_authority_sha256: str | None = None
    replacement_original_workspace_scope_sha256: str | None = None
    replacement_authenticated_workspace_identity_sha256: str | None = None
    workspace_reconciliation_authority_sha256: str | None = None
    replacement_auth_binding_sha256: str | None = None
    additional_authority_sha256: str | None = None
    additional_authenticated_workspace_identity_sha256: str | None = None
    additional_wsl_parity_receipt_sha256: str | None = None


@dataclass(frozen=True)
class ValidatedRemoteContract:
    """Closed wire values plus validation products used by the remote entrypoint."""

    raw: Mapping[str, object]
    request: Any
    evaluation_lock: Any
    fixtures: Mapping[str, bytes]
    execution_identity: Mapping[str, str]
    submission_pending_at: datetime


@dataclass(frozen=True)
class FreshDeterministicEvidence:
    """Values derived from freshly reproduced local authority, never caller claims."""

    provider_environment: str
    execution_identity: Mapping[str, str]
    config_sha256: str
    reference_execution_scope_sha256: str


@dataclass(frozen=True)
class SerializedRemoteCallable:
    """Exact provider hydration bytes prepared before any budget reservation."""

    entry: Any
    payload: bytes


@dataclass(frozen=True)
class PreparedModalGraph:
    """Fully bound lazy SDK graph prepared before any budget reservation."""

    serialized: SerializedRemoteCallable
    image: Any
    app: Any
    remote: Any


@dataclass(frozen=True)
class ValidatedRemoteResult:
    status: str
    receipt: bytes
    receipt_sha256: str
    manifest: bytes | None
    manifest_sha256: str | None
    full_context_usefulness_proven: bool


def _validate_authority_generation_shape(capability: ReferenceModalCapability) -> None:
    """Reject hybrid or partial authority generations before any paid-state transition."""
    replacement_fields = (
        capability.replacement_entitlement_sha256,
        capability.recovery_authority_sha256,
        capability.replacement_original_workspace_scope_sha256,
        capability.replacement_authenticated_workspace_identity_sha256,
        capability.workspace_reconciliation_authority_sha256,
        capability.replacement_auth_binding_sha256,
    )
    additional_fields = (
        capability.additional_authority_sha256,
        capability.additional_authenticated_workspace_identity_sha256,
        capability.additional_wsl_parity_receipt_sha256,
    )
    replacement = replacement_fields[0] is not None
    additional = additional_fields[0] is not None
    if (
        replacement and additional
        or any(value is not None for value in replacement_fields) != replacement
        or any(value is None for value in replacement_fields) != (not replacement)
        or any(value is not None for value in additional_fields) != additional
        or any(value is None for value in additional_fields) != (not additional)
    ):
        raise ReferenceModalError("reference authority generation is invalid")


def _validated_request_action(content: bytes) -> tuple[BootstrapRequest, str]:
    request = validate_bootstrap_request_bytes(content)
    action = json.loads(request.canonical_json).get("action")
    if action not in {ORIGINAL_ACTION, ADDITIONAL_ACTION}:
        raise ReferenceModalError("fresh request action is invalid")
    return request, action


def _validate_request_authority_generation(capability: ReferenceModalCapability) -> None:
    _validate_authority_generation_shape(capability)
    _, action = _validated_request_action(capability.bootstrap_request_bytes)
    additional_generation = capability.additional_authority_sha256 is not None
    if (action == ADDITIONAL_ACTION) != additional_generation:
        raise ReferenceModalError("request authority generation mismatch")


def validate_reference_preflight(
    capability: ReferenceModalCapability,
) -> FreshDeterministicEvidence:
    """Recompute decision-bearing local evidence; no caller boolean is authority."""
    from lowbit_lab.modal_job import (
        load_reference_job_config,
        plan_reference_additional_preview,
        plan_reference_bootstrap_preview,
    )
    from lowbit_lab.reference_authority import validate_reference_signed_cdn_authority
    from lowbit_lab.reference_orchestrator import validate_reproduced_request
    from lowbit_lab.runtime import runtime_metadata

    _validate_authority_generation_shape(capability)
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
        validate_reference_signed_cdn_authority(root)
        validate_topology_evidence(
            root / TOPOLOGY_EVIDENCE_PATH,
            request_bytes=capability.bootstrap_request_bytes,
        )
        config = load_reference_job_config(root / capability.config_path, root=root)
        request, action = _validated_request_action(capability.bootstrap_request_bytes)
        request_raw = json.loads(request.canonical_json)
        additional = action == ADDITIONAL_ACTION
        validate_reproduced_request(
            root,
            config,
            capability.bootstrap_request_bytes,
            additional=additional,
        )
        image = validate_image_lock(capability.image_lock)
        preview_builder = (
            plan_reference_additional_preview
            if additional
            else plan_reference_bootstrap_preview
        )
        preview = preview_builder(
            config,
            root=root,
            request_path=capability.request_path,
            request_sha256=_sha(capability.bootstrap_request_bytes),
            image_lock_path=capability.image_lock_path,
            image_lock_sha256=_sha(_canonical_json(capability.image_lock)),
            provider_capability_path=capability.provider_capability_path,
            provider_capability_sha256=str(
                request_raw["provider_capability"]["receipt_sha256"]
            ),
            billing_authority_path=capability.billing_authority_path,
            billing_receipt_path=capability.billing_receipt_path,
            billing_report_path=capability.billing_report_path,
            publication_manifest_path=capability.publication_manifest_path,
        )
        runtime = runtime_metadata(root)
        provider_receipt = validate_provider_capability_receipt(
            root / capability.provider_capability_path,
            expected_sha256=str(request_raw["provider_capability"]["receipt_sha256"]),
            image_recipe_sha256=image.recipe_sha256,
            billing_authority_path=root / capability.billing_authority_path,
            billing_receipt_path=root / capability.billing_receipt_path,
            billing_report_path=root / capability.billing_report_path,
        )
        expected_identity = validate_execution_identity(
            {
                "weight_inventory_sha256": config.inputs["weight_inventory_sha256"],
                "provenance_manifest_sha256": config.inputs["provenance_manifest_sha256"],
                "runtime_receipt_sha256": config.inputs["runtime_receipt_sha256"],
                "reviewed_commit_sha256": config.inputs["reviewed_commit_sha256"],
                "resource_spec_sha256": _sha(_canonical_json(config.resources)),
            }
        )
        provider_environment = str(provider_receipt["provider_environment"])
        evaluation_lock_path = root / str(config.authority_files["evaluation_lock_path"])
        capability_identity = validate_execution_identity(capability.execution_identity)
        request_file_bytes = (root / capability.request_path).read_bytes()
        evaluation_lock_file_bytes = evaluation_lock_path.read_bytes()
        canonical_evaluation_lock_bytes = _canonical_evaluation_lock_bytes(
            evaluation_lock_file_bytes
        )
        image_lock_file_bytes = (root / capability.image_lock_path).read_bytes()
        reference_scope = config.reference_execution_scope_sha256
        if reference_scope is None:
            raise ReferenceModalError("fresh reference execution scope is unavailable")
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
        or capability.db_path.resolve() != (root / "results/local/reference.sqlite").resolve()
        or capability.authority_root.resolve() != root
        or capability.provider_environment != provider_environment
        or capability_identity != expected_identity
        or request_file_bytes != capability.bootstrap_request_bytes
        # Config binds exact local bytes; request lineage binds canonical bytes.
        or _sha(evaluation_lock_file_bytes) != config.inputs["evaluation_lock_sha256"]
        or canonical_evaluation_lock_bytes != capability.evaluation_lock_bytes
        or _sha(capability.evaluation_lock_bytes)
        != request_raw["lineage"]["evaluation_lock_sha256"]
        or image_lock_file_bytes != _canonical_json(capability.image_lock)
    ):
        raise ReferenceModalError("fresh deterministic gate is not bootstrap-ready")
    return FreshDeterministicEvidence(
        provider_environment=provider_environment,
        execution_identity=expected_identity,
        config_sha256=config.sha256,
        reference_execution_scope_sha256=reference_scope,
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_evaluation_lock_bytes(content: bytes) -> bytes:
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceModalError("evaluation lock bytes drift") from exc
    return _canonical_json(raw)


def _optional_local_sha(root: Path, path: Path) -> str | None:
    if path.is_absolute() or ".." in path.parts:
        return None
    try:
        return _sha((root / path).read_bytes())
    except OSError:
        return None


def _validate_additional_parity(
    capability: ReferenceModalCapability, prepared: SerializedRemoteCallable
) -> None:
    """Bind the exact admitted payload to the pre-reservation WSL parity receipt."""
    if getattr(capability, "additional_authority_sha256", None) is None:
        return
    expected_receipt_sha256 = capability.additional_wsl_parity_receipt_sha256
    if expected_receipt_sha256 is None or SHA256_RE.fullmatch(expected_receipt_sha256) is None:
        raise ReferenceModalError("additional WSL parity binding is unavailable")
    root = capability.root.resolve()
    path = (
        root
        / "reports/local/reference-wsl-parity-history"
        / f"{expected_receipt_sha256}.json"
    )
    if not path.exists():
        path = root / "reports/local/reference-wsl-parity-receipt.json"
    try:
        content = path.read_bytes()
        raw = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceModalError("additional WSL parity receipt is unavailable") from exc
    if (
        not isinstance(raw, Mapping)
        or _canonical_json(raw) != content
        or _sha(content) != expected_receipt_sha256
        or raw.get("additional_authority_sha256") != capability.additional_authority_sha256
        or raw.get("request_sha256") != _sha(capability.bootstrap_request_bytes)
        or raw.get("serialized_payload_sha256") != _sha(prepared.payload)
        or raw.get("serialized_payload_size_bytes") != len(prepared.payload)
    ):
        raise ReferenceModalError("additional WSL parity binding drift")


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
        or _sha(lock_bytes) != request_raw["lineage"]["evaluation_lock_sha256"]
        or identity["weight_inventory_sha256"] != request_raw["lineage"]["inventory_sha256"]
        or identity["runtime_receipt_sha256"] != request_raw["lineage"]["runtime_receipt_sha256"]
        or identity["reviewed_commit_sha256"] != request_raw["lineage"]["reviewed_commit"]
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


def _build_serialized_remote_callable() -> tuple[Any, bytes, tuple[Any, ...]]:
    """Package only the narrow worker module by value; never mount local source."""
    import lowbit_lab.reference_remote_runtime as remote_runtime
    from modal._serialization import serialize
    from modal._vendor import cloudpickle

    modules = (remote_runtime,)
    registered: list[Any] = []
    try:
        for module in modules:
            cloudpickle.register_pickle_by_value(module)
            registered.append(module)

        # Modal's FunctionInfo uses this exact serializer during app hydration.
        payload = serialize(remote_runtime.remote_entry)
        return remote_runtime.remote_entry, payload, modules
    except Exception:
        _clear_serialization_policy(tuple(registered))
        raise


def prepare_serialized_remote_callable() -> SerializedRemoteCallable:
    """Freeze admissible Modal hydration bytes without retaining global pickle policy."""
    entry, payload, modules = _build_serialized_remote_callable()
    try:
        if len(payload) > MODAL_SERIALIZED_FUNCTION_MAX_BYTES:
            raise ReferenceModalError("serialized function exceeds provider cap")
        return SerializedRemoteCallable(entry=entry, payload=payload)
    finally:
        _clear_serialization_policy(modules)


def _bind_cached_hydration_payload(remote: Any, prepared: SerializedRemoteCallable) -> None:
    """Make pinned Modal hydration return the exact bytes admitted by preflight."""
    info = getattr(remote, "_info", None)
    if (
        info is None
        or getattr(info, "raw_f", None) is not prepared.entry
        or not callable(getattr(info, "is_serialized", None))
        or not info.is_serialized()
    ):
        raise ReferenceModalError("provider function metadata binding drift")

    def cached_payload() -> bytes:
        return prepared.payload

    info.serialized_function = cached_payload
    if info.serialized_function() is not prepared.payload:
        raise ReferenceModalError("provider hydration payload binding drift")


def prepare_local_modal_graph(capability: ReferenceModalCapability) -> PreparedModalGraph:
    """Build Modal's lazy local objects without invoking a provider primitive."""
    try:
        import modal

        prepared = prepare_serialized_remote_callable()
        image = _image_from_lock(modal, capability.image_lock)
        app = modal.App(REFERENCE_APP_NAME, image=image, include_source=False)
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
        )(prepared.entry)
        _bind_cached_hydration_payload(remote, prepared)
        return PreparedModalGraph(serialized=prepared, image=image, app=app, remote=remote)
    except Exception:
        # Every production execution attempt is auditable even though this local
        # failure intentionally occurs before a run or budget reservation exists.
        try:
            database = ResultsDatabase(capability.root.resolve() / "results/local/reference.sqlite")
            database.initialize()
            occurred_at = datetime.now(UTC).isoformat()
            attempt_id = (
                "u8-graph-preflight-" + _sha(f"{occurred_at}:{time.time_ns()}".encode())[:24]
            )
            config_path = (
                capability.config_path.as_posix()
                if not capability.config_path.is_absolute()
                and ".." not in capability.config_path.parts
                else "invalid"
            )
            database.create_attempt(
                attempt_id=attempt_id,
                config_path=config_path,
                raw_config_sha256=_optional_local_sha(
                    capability.root.resolve(), capability.config_path
                ),
                started_at=occurred_at,
            )
            database.fail_attempt(
                attempt_id,
                "local_provider_graph_preflight_failed",
                datetime.now(UTC).isoformat(),
            )
        except Exception as audit_exc:
            raise ReferenceModalError("local provider graph preflight audit failed") from audit_exc
        raise


def _clear_serialization_policy(modules: tuple[Any, ...]) -> None:
    from modal._vendor import cloudpickle

    for module in modules:
        with suppress(ValueError):
            cloudpickle.unregister_pickle_by_value(module)


def _local_deadline_signal() -> Any:
    """Require the interruptible Unix watchdog before consuming one-shot authority."""
    import signal
    import threading

    names = ("SIGALRM", "ITIMER_REAL", "SIG_DFL", "getitimer", "getsignal", "setitimer")
    if (
        not all(hasattr(signal, name) for name in names)
        or threading.current_thread() is not threading.main_thread()
        or signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
        or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
    ):
        raise ReferenceModalError("paid reference execution requires the WSL/Linux watchdog")
    return signal


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
    database.mark_reference_audit_blocked(
        capability.reservation_id,
        owner_id=capability.owner_id,
        reason=f"provider boundary uncertainty: {reason[:64]}",
        occurred_at=datetime.now(UTC).isoformat(),
    )


def _mark_submission_pending(
    database: ResultsDatabase,
    capability: ReferenceModalCapability,
    occurred_at: str,
    *,
    replacement_auth_receipt_bytes: bytes | None = None,
    additional_auth_receipt_bytes: bytes | None = None,
) -> None:
    """Consume exactly one authority generation at the same provider boundary."""
    additional_authority_sha256 = getattr(capability, "additional_authority_sha256", None)
    if additional_authority_sha256 is not None:
        database.mark_reference_additional_submission_pending(
            capability.reservation_id,
            owner_id=capability.owner_id,
            additional_authority_sha256=additional_authority_sha256,
            request_sha256=_sha(capability.bootstrap_request_bytes),
            parity_receipt_sha256=capability.additional_wsl_parity_receipt_sha256 or "",
            auth_receipt_bytes=additional_auth_receipt_bytes or b"",
            authority_root=capability.authority_root,
            occurred_at=occurred_at,
        )
        return
    replacement_entitlement_sha256 = capability.replacement_entitlement_sha256
    if replacement_entitlement_sha256 is None:
        database.mark_reference_submission_pending(
            capability.reservation_id,
            owner_id=capability.owner_id,
            standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
            bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            authority_root=capability.authority_root,
            occurred_at=occurred_at,
        )
        return
    recovery_authority_sha256 = capability.recovery_authority_sha256
    original_workspace_scope_sha256 = capability.replacement_original_workspace_scope_sha256
    authenticated_workspace_identity_sha256 = (
        capability.replacement_authenticated_workspace_identity_sha256
    )
    reconciliation_authority_sha256 = capability.workspace_reconciliation_authority_sha256
    auth_binding_sha256 = capability.replacement_auth_binding_sha256
    if (
        recovery_authority_sha256 != REFERENCE_RECOVERY_AUTHORITY_SHA256
        or original_workspace_scope_sha256 is None
        or authenticated_workspace_identity_sha256 is None
        or reconciliation_authority_sha256 is None
        or auth_binding_sha256 is None
    ):
        raise ReferenceModalError("replacement recovery authority is invalid")
    database.mark_reference_replacement_submission_pending(
        capability.reservation_id,
        entitlement_sha256=replacement_entitlement_sha256,
        owner_id=capability.owner_id,
        recovery_authority_sha256=recovery_authority_sha256,
        auth_receipt_bytes=replacement_auth_receipt_bytes or b"",
        auth_binding_sha256=auth_binding_sha256,
        original_workspace_scope_sha256=original_workspace_scope_sha256,
        authenticated_workspace_identity_sha256=authenticated_workspace_identity_sha256,
        workspace_reconciliation_authority_sha256=reconciliation_authority_sha256,
        authority_root=capability.authority_root,
        occurred_at=occurred_at,
    )


def _build_additional_boundary_auth_receipt(
    *,
    additional_authority_sha256: str,
    reservation_id: str,
    execution_scope_sha256: str,
    authenticated_workspace_identity_sha256: str,
    provider_environment: str,
    sdk_version: str,
) -> bytes:
    """Build a closed receipt containing digests only, never credential values."""
    for digest in (
        additional_authority_sha256,
        execution_scope_sha256,
        authenticated_workspace_identity_sha256,
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise ReferenceModalError("additional provider authentication digest is invalid")
    if (
        not reservation_id
        or not provider_environment
        or not sdk_version
        or additional_authority_sha256 != REFERENCE_ADDITIONAL_AUTHORITY_SHA256
    ):
        raise ReferenceModalError("additional provider authentication binding is invalid")
    return _canonical_json(
        {
            "additional_authority_sha256": additional_authority_sha256,
            "authenticated_workspace_identity_sha256": (
                authenticated_workspace_identity_sha256
            ),
            "environment_overrides_present": False,
            "kind": "reference_additional_provider_auth_receipt",
            "provider_environment": provider_environment,
            "reference_execution_scope_sha256": execution_scope_sha256,
            "reservation_id": reservation_id,
            "schema_version": 1,
            "sdk_version": sdk_version,
            "server_url": OFFICIAL_MODAL_SERVER_URL,
        }
    )


def _persist_additional_boundary_auth_receipt(
    capability: ReferenceModalCapability, content: bytes
) -> None:
    digest = _sha(content)
    path = (
        capability.root.resolve()
        / "reports/local/reference-additional-provider-auth-receipts"
        / f"{digest}.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_new_durable(path, content)


def _validate_modal_sdk_boundary(capability: ReferenceModalCapability) -> str:
    """Authenticate through Modal's opaque profile immediately before consumption."""
    try:
        request = validate_bootstrap_request_bytes(capability.bootstrap_request_bytes)
        request_raw = json.loads(request.canonical_json)
        image = validate_image_lock(capability.image_lock)
        validate_provider_capability_receipt(
            capability.root / capability.provider_capability_path,
            expected_sha256=str(request_raw["provider_capability"]["receipt_sha256"]),
            image_recipe_sha256=image.recipe_sha256,
            billing_authority_path=capability.root / capability.billing_authority_path,
            billing_receipt_path=capability.root / capability.billing_receipt_path,
            billing_report_path=capability.root / capability.billing_report_path,
        )
        from google.protobuf.empty_pb2 import Empty

        from modal.client import _Client
        from modal.config import DEFAULT_SERVER_URL, _check_config, config

        _check_config()
        if (
            DEFAULT_SERVER_URL != OFFICIAL_MODAL_SERVER_URL
            or config.get("server_url", use_env=False) != OFFICIAL_MODAL_SERVER_URL
            or config.get("override_headers", use_env=False) not in (None, {})
        ):
            raise ReferenceModalError("provider profile transport is unsupported")
        async def lookup_workspace() -> object:
            # Modal alone loads the selected profile and attaches its credentials.
            # Lab code neither reads nor copies the credential values.
            client = await _Client.from_env()
            if client.server_url != OFFICIAL_MODAL_SERVER_URL:
                raise ReferenceModalError("provider SDK endpoint is unsupported")
            return await client.stub.WorkspaceNameLookup(Empty(), retry=None, timeout=3)

        response = asyncio.run(lookup_workspace())
        identity_sha256 = _sha(response.username.encode("utf-8"))
    except Exception as exc:
        raise ReferenceModalError("provider SDK boundary identity drift") from exc
    return identity_sha256


def submit_reference(
    capability: ReferenceModalCapability, prepared_graph: PreparedModalGraph
) -> dict[str, object]:
    """The only U8 provider call path. Callers must already hold a reservation."""
    prepared = getattr(prepared_graph, "serialized", None)
    if (
        not isinstance(prepared_graph, PreparedModalGraph)
        or not isinstance(prepared, SerializedRemoteCallable)
        or not callable(prepared.entry)
        or not isinstance(prepared.payload, bytes)
        or len(prepared.payload) > MODAL_SERIALIZED_FUNCTION_MAX_BYTES
    ):
        raise ReferenceModalError("serialized function preflight binding is invalid")
    image = prepared_graph.image
    app = prepared_graph.app
    remote = prepared_graph.remote
    canonical_db_path = capability.root.resolve() / "results/local/reference.sqlite"
    database = ResultsDatabase(canonical_db_path)
    attempt_started_at = datetime.now(UTC).isoformat()
    attempt_id = (
        "u8-preflight-" + _sha(f"{capability.reservation_id}:{time.time_ns()}".encode())[:24]
    )
    audit_config_path = (
        capability.config_path.as_posix()
        if not capability.config_path.is_absolute() and ".." not in capability.config_path.parts
        else "invalid"
    )
    try:
        database.create_attempt(
            attempt_id=attempt_id,
            config_path=audit_config_path,
            raw_config_sha256=_optional_local_sha(
                capability.root.resolve(), capability.config_path
            ),
            started_at=attempt_started_at,
        )
    except Exception as exc:
        if getattr(capability, "additional_authority_sha256", None) is None:
            raise
        try:
            database.release_reference_additional_reservation(
                capability.reservation_id,
                owner_id=capability.owner_id,
                reason="local attempt audit initialization failed",
                occurred_at=datetime.now(UTC).isoformat(),
            )
        except DatabaseError as release_exc:
            raise ReferenceModalError(
                "additional attempt audit failure could not be durably released"
            ) from release_exc
        raise ReferenceModalError("additional attempt audit initialization failed") from exc
    # Validate every deterministic byte before consuming the sole action.
    try:
        _validate_request_authority_generation(capability)
        _validate_additional_parity(capability, prepared)
        fresh = validate_reference_preflight(capability)
        deadline_signal = _local_deadline_signal()
        build_remote_contract(
            capability,
            provider_image_identity="im-placeholder",
            serialized_function_sha256="0" * 64,
            submission_pending_at=datetime.now(UTC).isoformat(),
        )
        reservation = database.get_reservation(capability.reservation_id)
        run_id = str(reservation["run_id"])
        run = database.get_run(run_id)
        if (
            reservation["owner_id"] != capability.owner_id
            or reservation["reference_execution_scope_sha256"]
            != fresh.reference_execution_scope_sha256
            or run["config_sha256"] != fresh.config_sha256
        ):
            raise ReferenceModalError("reservation lineage does not match fresh capability")
        database.link_attempt(attempt_id, run_id, datetime.now(UTC).isoformat())
    except (DatabaseError, ReferenceBootstrapError, ReferenceModalError) as exc:
        if getattr(capability, "additional_authority_sha256", None) is not None:
            database.release_reference_additional_reservation(
                capability.reservation_id,
                owner_id=capability.owner_id,
                reason="deterministic remote contract gate failed",
                occurred_at=datetime.now(UTC).isoformat(),
            )
        database.fail_attempt(
            attempt_id,
            "deterministic_remote_contract_gate_failed",
            datetime.now(UTC).isoformat(),
        )
        raise ReferenceModalError("deterministic remote contract gate failed") from exc

    started = time.monotonic()
    boundary_auth_receipt_bytes: bytes | None = None
    if getattr(capability, "replacement_entitlement_sha256", None) is not None:
        # Re-authenticate after the final slow deterministic preflight and bind the
        # fresh receipt at the exact entitlement-consumption boundary.
        from lowbit_lab.reference_orchestrator import (
            _validate_fresh_auth_receipt,
            verify_workspace_auth,
        )

        try:
            if provider_environment_overrides_present():
                raise ReferenceModalError("ambient provider environment override is forbidden")
            auth = verify_workspace_auth(capability.root)
            expected_original = capability.replacement_original_workspace_scope_sha256
            expected_identity = capability.replacement_authenticated_workspace_identity_sha256
            if (
                auth["original_workspace_scope_sha256"] != expected_original
                or auth["authenticated_workspace_identity_sha256"] != expected_identity
                or auth["reconciliation_authority_sha256"]
                != capability.workspace_reconciliation_authority_sha256
            ):
                raise ReferenceModalError("replacement workspace authentication drift")
            if auth["binding_sha256"] != capability.replacement_auth_binding_sha256:
                raise ReferenceModalError("replacement auth binding drift")
            _validate_fresh_auth_receipt(
                capability.root,
                expected_original_workspace_scope_sha256=str(expected_original),
                expected_authenticated_workspace_identity_sha256=str(expected_identity),
            )
            receipt_sha256 = str(auth["receipt_sha256"])
            boundary_auth_receipt_bytes = (
                capability.root / auth_receipt_path(receipt_sha256)
            ).read_bytes()
            if _sha(boundary_auth_receipt_bytes) != receipt_sha256:
                raise ReferenceModalError("replacement auth receipt bytes drift")
        except Exception as exc:
            raise ReferenceModalError("replacement boundary authentication failed") from exc
    additional_auth_receipt_bytes: bytes | None = None
    try:
        if provider_environment_overrides_present():
            raise ReferenceModalError("ambient provider environment override is forbidden")
        sdk_workspace_identity_sha256 = _validate_modal_sdk_boundary(capability)
        if (
            capability.replacement_entitlement_sha256 is not None
            and sdk_workspace_identity_sha256
            != capability.replacement_authenticated_workspace_identity_sha256
        ):
            raise ReferenceModalError("replacement SDK workspace identity drift")
        if getattr(capability, "additional_authority_sha256", None) is not None:
            expected_workspace_identity = (
                capability.additional_authenticated_workspace_identity_sha256
            )
            if (
                expected_workspace_identity is None
                or sdk_workspace_identity_sha256 != expected_workspace_identity
            ):
                raise ReferenceModalError("additional SDK workspace identity drift")
            additional_auth_receipt_bytes = _build_additional_boundary_auth_receipt(
                additional_authority_sha256=capability.additional_authority_sha256,
                reservation_id=capability.reservation_id,
                execution_scope_sha256=fresh.reference_execution_scope_sha256,
                authenticated_workspace_identity_sha256=expected_workspace_identity,
                provider_environment=capability.provider_environment,
                sdk_version=importlib.metadata.version("modal"),
            )
            _persist_additional_boundary_auth_receipt(
                capability, additional_auth_receipt_bytes
            )
        submission_pending_at = datetime.now(UTC).isoformat()
        _mark_submission_pending(
            database,
            capability,
            submission_pending_at,
            replacement_auth_receipt_bytes=boundary_auth_receipt_bytes,
            additional_auth_receipt_bytes=additional_auth_receipt_bytes,
        )
    except Exception as exc:
        if getattr(capability, "additional_authority_sha256", None) is not None:
            try:
                database.release_reference_additional_reservation(
                    capability.reservation_id,
                    owner_id=capability.owner_id,
                    reason="deterministic provider boundary gate failed",
                    occurred_at=datetime.now(UTC).isoformat(),
                )
            except DatabaseError as release_exc:
                raise ReferenceModalError(
                    "additional pre-boundary state could not be durably released"
                ) from release_exc
            raise ReferenceModalError("additional boundary authentication failed") from exc
        raise

    def provider_deadline_expired(signum: int, frame: object) -> None:
        raise ReferenceDeadlineAbort("absolute provider action deadline exceeded")

    remaining_action_seconds = 2700 - (time.monotonic() - started)
    if remaining_action_seconds <= 0:
        _audit_block(database, capability, "deadline_before_provider_import")
        raise ReferenceModalError("reference provider state requires audit")
    # Starting before the durable transition makes the local clock conservative.
    handler_may_be_installed = False
    timer_may_be_armed = False
    previous_deadline_handler = deadline_signal.SIG_DFL
    try:
        handler_may_be_installed = True
        previous_deadline_handler = deadline_signal.signal(
            deadline_signal.SIGALRM, provider_deadline_expired
        )
        timer_may_be_armed = True
        deadline_signal.setitimer(deadline_signal.ITIMER_REAL, remaining_action_seconds)
        with app.run(environment_name=capability.provider_environment):
            app_identity = app.app_id
            if not isinstance(app_identity, str):
                raise ReferenceModalError("provider app identity is unavailable")
            database.mark_reference_app_identity(
                capability.reservation_id,
                owner_id=capability.owner_id,
                app_identity=app_identity,
                occurred_at=datetime.now(UTC).isoformat(),
                lease_expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            )
            image.build(app)
            image_identity = image.object_id
            if not isinstance(image_identity, str):
                raise ReferenceModalError("provider image-or-deployment identity is unavailable")
            _persist_prepared(database, capability, image_identity, app_identity)
            if time.monotonic() - started >= 2700 - 1500:
                raise ReferenceModalError("deadline reserves no longer admit spawn")
            contract = build_remote_contract(
                capability,
                provider_image_identity=image_identity,
                serialized_function_sha256=_sha(prepared.payload),
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
            remaining = 2700 - (time.monotonic() - started)
            if remaining < 1:
                raise ReferenceModalError("absolute submission deadline expired before result wait")
            raw_result = call.get(timeout=math.floor(remaining))
            validated_result = validate_remote_result(
                raw_result, capability, provider_image_identity=image_identity
            )
            if not isinstance(raw_result, Mapping) or raw_result.get("contract_sha256") != _sha(
                contract
            ):
                raise ReferenceModalError("provider return contract binding drift")
            result = _persist_remote_evidence(capability, validated_result)
            if "manifest_path" in result:
                database.add_artifact(
                    run_id,
                    path=str(result["manifest_path"]),
                    sha256=str(result["manifest_sha256"]),
                    size_bytes=int(result["manifest_size_bytes"]),
                    kind="reference_manifest",
                )
            database.add_artifact(
                run_id,
                path=str(result["receipt_path"]),
                sha256=str(result["receipt_sha256"]),
                size_bytes=int(result["receipt_size_bytes"]),
                kind="bootstrap_receipt",
            )
            now = datetime.now(UTC)
            database.mark_settlement_pending(
                capability.reservation_id,
                owner_id=capability.owner_id,
                occurred_at=now.isoformat(),
                provider_terminal_at=now.isoformat(),
                lease_expires_at=(now + timedelta(hours=2)).isoformat(),
            )
        deadline_signal.setitimer(deadline_signal.ITIMER_REAL, 0)
        timer_may_be_armed = False
        deadline_signal.signal(deadline_signal.SIGALRM, previous_deadline_handler)
        handler_may_be_installed = False
    except (Exception, ReferenceDeadlineAbort) as exc:
        if timer_may_be_armed:
            with suppress(BaseException):
                deadline_signal.setitimer(deadline_signal.ITIMER_REAL, 0)
        if handler_may_be_installed:
            with suppress(BaseException):
                deadline_signal.signal(deadline_signal.SIGALRM, previous_deadline_handler)
        try:
            _audit_block(database, capability, type(exc).__name__)
        except DatabaseError as audit_exc:
            raise ReferenceModalError(
                "reference provider state could not be durably audit-blocked"
            ) from audit_exc
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
    value: object,
    capability: ReferenceModalCapability,
    *,
    provider_image_identity: str,
) -> ValidatedRemoteResult:
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
    receipt_raw = json.loads(validated_receipt.canonical_json)
    runtime_stage = next(
        (stage for stage in receipt_raw["stages"] if stage["stage"] == "runtime_identity"), None
    )
    expected_image_identity = _sha(provider_image_identity.encode())
    if runtime_stage is None:
        raise ReferenceModalError("provider image identity binding drift")
    runtime_measurements = runtime_stage["measurements"]
    if (
        runtime_stage["status"] == "completed"
        and runtime_measurements.get("image_identity_sha256") != expected_image_identity
    ):
        raise ReferenceModalError("provider image identity binding drift")
    if runtime_stage["status"] == "failed" and (
        runtime_measurements.get("image_identity_sha256") != "0" * 64
        or runtime_measurements.get("runtime_identity_sha256") != "0" * 64
    ):
        raise ReferenceModalError("failed runtime identity sentinel drift")
    evaluation = next(
        (stage for stage in receipt_raw["stages"] if stage["stage"] == "evaluation"), None
    )
    expected_manifest_sha256 = (
        None if evaluation is None else evaluation["measurements"]["reference_manifest_sha256"]
    )
    expected_manifest_bytes = (
        0 if evaluation is None else evaluation["measurements"]["reference_manifest_bytes"]
    )
    manifest_raw = value["manifest_b64"]
    if (manifest_raw is None) != (expected_manifest_sha256 is None):
        raise ReferenceModalError("provider manifest presence binding drift")
    manifest: bytes | None = None
    manifest_sha256: str | None = None
    if manifest_raw is not None:
        manifest = _decode_b64(manifest_raw, "manifest")
        manifest_sha256 = _sha(manifest)
        if len(manifest) != expected_manifest_bytes or manifest_sha256 != expected_manifest_sha256:
            raise ReferenceModalError("provider manifest hash binding drift")
        lock = json.loads(capability.evaluation_lock_bytes)
        fixtures = {key: body for key, body in capability.fixture_bytes.items()}
        validated_lock = validate_pending_evaluation_lock(lock, fixture_bytes=fixtures)
        validate_reference_manifest_bytes(
            manifest,
            evaluation_lock_sha256=validated_lock.sha256,
            context_ladder_tokens=request.context_ladder_tokens,
        )
        manifest_json = json.loads(manifest)
        if validate_execution_identity(
            manifest_json["execution_identity"]
        ) != validate_execution_identity(capability.execution_identity):
            raise ReferenceModalError("provider execution identity binding drift")
    receipt_bytes = validated_receipt.canonical_json.encode()
    return ValidatedRemoteResult(
        status=validated_receipt.status,
        receipt=receipt_bytes,
        receipt_sha256=_sha(receipt_bytes),
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        full_context_usefulness_proven=validated_receipt.full_context_usefulness_proven,
    )


def _persist_remote_evidence(
    capability: ReferenceModalCapability, result: ValidatedRemoteResult
) -> dict[str, object]:
    """Persist sanitized provider evidence without overwrite or caller-selected paths."""
    evidence_root = capability.root.resolve() / "reports/local"
    evidence_root.mkdir(parents=True, exist_ok=True)
    suffix = _sha(capability.reservation_id.encode())[:16]
    artifacts: dict[str, object] = {}
    if result.manifest is not None:
        manifest_path = evidence_root / f"u8-reference-manifest-{suffix}.json"
        manifest_sha256, manifest_size = _write_new_durable(manifest_path, result.manifest)
        artifacts["manifest_path"] = manifest_path.relative_to(capability.root.resolve()).as_posix()
        artifacts["manifest_sha256"] = manifest_sha256
        artifacts["manifest_size_bytes"] = manifest_size
    receipt_path = evidence_root / f"u8-bootstrap-receipt-{suffix}.json"
    receipt_sha256, receipt_size = _write_new_durable(receipt_path, result.receipt)
    artifacts.update(
        {
            "full_context_usefulness_proven": result.full_context_usefulness_proven,
            "receipt_path": receipt_path.relative_to(capability.root.resolve()).as_posix(),
            "receipt_sha256": receipt_sha256,
            "receipt_size_bytes": receipt_size,
            "status": result.status,
        }
    )
    return artifacts


def _write_new_durable(path: Path, content: bytes) -> tuple[str, int]:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    persisted = path.read_bytes()
    if persisted != content:
        raise ReferenceModalError("persisted provider evidence verification failed")
    return _sha(persisted), len(persisted)
