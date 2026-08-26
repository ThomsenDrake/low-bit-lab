"""Construct and consume the one closed U8 capability from ignored local evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import uuid
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml

from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_IMMUTABLE_ORIGIN_HOSTS,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_SETTLED_SMOKE_USD,
    REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
    REFERENCE_SIGNED_CDN_MERGE_COMMIT,
    REFERENCE_SIGNED_REDIRECT_POLICY,
)
from lowbit_lab.db import ResultsDatabase, confine_results_db
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.jsonio import emit
from lowbit_lab.modal_job import (
    ReferenceJobConfig,
    load_reference_job_config,
    plan_reference_bootstrap_preview,
)
from lowbit_lab.provenance import parse_weight_inventory
from lowbit_lab.provider_evidence import (
    DEFAULT_BILLING_AUTHORITY,
    DEFAULT_BILLING_RECEIPT,
    DEFAULT_BILLING_REPORT,
    validate_provider_capability_receipt,
)
from lowbit_lab.provider_evidence import (
    DEFAULT_OUTPUT as PROVIDER_CAPABILITY_PATH,
)
from lowbit_lab.reference_bootstrap import (
    EMPIRICAL_FACTS,
    FUTURE_STAGE_RESERVES_SECONDS,
    STAGES,
    canonical_bytes,
    canonical_sha256,
    validate_bootstrap_request_bytes,
    validate_image_lock_bytes,
)
from lowbit_lab.reference_contract import REFERENCE_RESOURCES
from lowbit_lab.reference_modal_adapter import ReferenceModalCapability
from lowbit_lab.reference_transport import observe_topology
from lowbit_lab.runtime import (
    load_runtime_lock,
    runtime_metadata,
    verify_current_installed_environment,
)

CONFIG_PATH = Path("configs/local/reference.yaml")
REQUEST_PATH = Path("reports/local/u8-bootstrap-request.json")
IMAGE_LOCK_PATH = Path("configs/local/reference-image-lock.json")
PUBLICATION_MANIFEST_PATH = Path("configs/local/publication.yaml")
DATABASE_PATH = Path("results/local/reference.sqlite")
_SOURCE_FILES = {
    "chat_template.jinja": "text",
    "config.json": "json",
    "generation_config.json": "json",
    "merges.txt": "tokenizer_data",
    "model.safetensors.index.json": "json",
    "special_tokens_map.json": "json",
    "tokenizer.json": "tokenizer_data",
    "tokenizer_config.json": "json",
    "vocab.json": "tokenizer_data",
}


class ReferenceOrchestratorError(RuntimeError):
    """A sanitized failure before or at the already-audited paid boundary."""


class ReferenceProviderStateUnknown(ReferenceOrchestratorError):
    """Modal may have been contacted; only authoritative evidence can settle the state."""


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_json_bytes(path: Path, label: str) -> tuple[Mapping[str, object], bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError(f"{label} is unavailable") from exc
    if not isinstance(value, Mapping):
        raise ReferenceOrchestratorError(f"{label} schema drift")
    return value, content


def _read_json(path: Path, label: str) -> Mapping[str, object]:
    return _read_json_bytes(path, label)[0]


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)
    if path.read_bytes() != content:
        raise ReferenceOrchestratorError("persisted orchestration evidence drift")


def _manifest_identity(provenance: Mapping[str, object]) -> str:
    identity_manifest = deepcopy(dict(provenance))
    declared = identity_manifest.pop("manifest_sha256", None)
    files = identity_manifest.get("files")
    if not isinstance(files, list):
        raise ReferenceOrchestratorError("provenance manifest identity is incomplete")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("local_content"), dict):
            raise ReferenceOrchestratorError("provenance manifest identity is incomplete")
        item["local_content"].pop("reused", None)
    reproduced = _sha(
        json.dumps(identity_manifest, sort_keys=True, separators=(",", ":")).encode()
    )
    if declared != reproduced:
        raise ReferenceOrchestratorError("provenance manifest identity drift")
    return reproduced


def _validate_frozen_inputs(
    frozen: Mapping[str, object],
    inventory: object,
    evaluation: object,
    runtime_receipt_sha256: str,
) -> None:
    if (
        inventory.source_revision != frozen["source_revision"]
        or inventory.index_tensor_bytes != frozen["weight_inventory_tensor_bytes"]
        or evaluation.sha256 != frozen["evaluation_lock_sha256"]
        or evaluation.context.configured_tokens != frozen["evaluation_max_context_tokens"]
        or runtime_receipt_sha256 != frozen["runtime_receipt_sha256"]
    ):
        raise ReferenceOrchestratorError("frozen source, evaluation, or runtime identity drift")


def refresh_local_config(root: Path) -> ReferenceJobConfig:
    """Bind ignored target configuration to the current clean reviewed tree."""
    root = root.resolve()
    runtime = runtime_metadata(root)
    if runtime["git_dirty"] or runtime["git_commit"] == "uncommitted":
        raise ReferenceOrchestratorError("reviewed tree must be clean and committed")
    path = root / CONFIG_PATH
    current = load_reference_job_config(path, root=root)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReferenceOrchestratorError("reference config is unavailable") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("inputs"), dict):
        raise ReferenceOrchestratorError("reference config schema drift")
    provenance = _read_json(
        root / str(current.authority_files["provenance_manifest_path"]), "provenance manifest"
    )
    provenance_sha = _manifest_identity(provenance)
    files = provenance.get("files")
    if not isinstance(files, list):
        raise ReferenceOrchestratorError("provenance manifest is incomplete")
    by_name = {item.get("path"): item for item in files if isinstance(item, Mapping)}
    try:
        index_entry = by_name["model.safetensors.index.json"]
        tokenizer_entry = by_name["tokenizer.json"]
        index_bytes = (root / index_entry["local_content"]["cache_path"]).read_bytes()
        tokenizer_sha = str(tokenizer_entry["local_content"]["sha256"])
    except (KeyError, OSError, TypeError) as exc:
        raise ReferenceOrchestratorError("provenance cache binding is incomplete") from exc
    runtime_lock = load_runtime_lock(
        root / str(current.authority_files["runtime_lock_path"]), root=root
    )
    evaluation_raw = _read_json(
        root / str(current.authority_files["evaluation_lock_path"]), "evaluation lock"
    )
    fixture_root = root / str(current.authority_files["evaluation_fixture_root"])
    fixture_bytes = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation_raw["fixtures"]
    }
    evaluation = validate_pending_evaluation_lock(
        evaluation_raw, fixture_bytes=fixture_bytes
    )
    source_metadata = _read_json(
        root / str(current.authority_files["source_shard_metadata_path"]),
        "source shard metadata",
    )
    inventory_raw = _read_json(
        root / str(current.authority_files["weight_inventory_path"]), "weight inventory"
    )
    inventory = parse_weight_inventory(
        inventory_raw,
        source_index_bytes=index_bytes,
        source_shards={
            name: (int(item["size_bytes"]), str(item["lfs_sha256"]))
            for name, item in source_metadata.items()
            if isinstance(item, Mapping)
        },
        expected_bindings={
            "provenance_manifest_sha256": provenance_sha,
            "tokenizer_sha256": tokenizer_sha,
            "runtime_lock_sha256": runtime_lock.sha256,
            "evaluation_lock_sha256": evaluation.sha256,
            "source_index_sha256": _sha(index_bytes),
        },
    )
    receipt_path = root / str(current.authority_files["runtime_receipt_path"])
    receipt, receipt_bytes = _read_json_bytes(receipt_path, "runtime receipt")
    verify_current_installed_environment(receipt, root=root, lock=runtime_lock)
    _validate_frozen_inputs(current.inputs, inventory, evaluation, _sha(receipt_bytes))
    commit = str(runtime["git_commit"])
    raw["experiment_id"] = f"phase1-u8-{commit[:12]}"
    raw["inputs"]["reviewed_commit_sha256"] = commit
    raw["inputs"]["control_plane_sha256"] = runtime["control_plane_sha256"]
    raw["inputs"]["weight_inventory_sha256"] = inventory.sha256
    raw["inputs"]["provenance_manifest_sha256"] = provenance_sha
    raw["approval_artifact_path"] = None
    encoded = yaml.safe_dump(raw, sort_keys=False, allow_unicode=False).encode("utf-8")
    _write_atomic(path, encoded)
    return load_reference_job_config(path, root=root)


def _source_artifacts(root: Path, config: ReferenceJobConfig) -> list[dict[str, object]]:
    provenance = _read_json(
        root / str(config.authority_files["provenance_manifest_path"]), "provenance manifest"
    )
    inventory = _read_json(
        root / str(config.authority_files["weight_inventory_path"]), "weight inventory"
    )
    files = provenance.get("files")
    shards = inventory.get("shards")
    if not isinstance(files, list) or not isinstance(shards, list) or not shards:
        raise ReferenceOrchestratorError("source artifact inventory is incomplete")
    reproduced_manifest_sha = _manifest_identity(provenance)
    declared_manifest_sha = provenance.get("manifest_sha256")
    repository = provenance.get("repository")
    source = inventory.get("source")
    if not isinstance(repository, Mapping) or not isinstance(source, Mapping):
        raise ReferenceOrchestratorError("source identity is incomplete")
    identifier = repository.get("identifier")
    revision = repository.get("revision")
    if (
        not isinstance(identifier, str)
        or identifier.count("/") != 1
        or any(part in {"", ".", ".."} for part in identifier.split("/"))
        or "\\" in identifier
        or revision != config.inputs["source_revision"]
        or source.get("identifier") != identifier
        or source.get("revision") != revision
        or declared_manifest_sha != config.inputs["provenance_manifest_sha256"]
        or reproduced_manifest_sha != declared_manifest_sha
    ):
        raise ReferenceOrchestratorError("source identity does not match immutable provenance")
    expected_prefix = f"/{identifier}/resolve/{revision}/"
    by_name = {
        item.get("path"): item for item in files if isinstance(item, Mapping)
    }
    index = by_name.get("model.safetensors.index.json")
    if not isinstance(index, Mapping) or not isinstance(index.get("http"), Mapping):
        raise ReferenceOrchestratorError("source index origin is unavailable")
    index_url = str(index["http"].get("requested_url"))
    parsed_index = urlsplit(index_url)
    if parsed_index.query or parsed_index.fragment or not parsed_index.path.endswith(
        "/model.safetensors.index.json"
    ) or (
        parsed_index.scheme != "https"
        or parsed_index.hostname not in REFERENCE_IMMUTABLE_ORIGIN_HOSTS
        or parsed_index.username is not None
        or parsed_index.password is not None
        or parsed_index.port not in (None, 443)
        or parsed_index.path != expected_prefix + "model.safetensors.index.json"
    ):
        raise ReferenceOrchestratorError("source index origin is not immutable and query-free")
    base_path = parsed_index.path.rsplit("/", 1)[0] + "/"
    raw_artifacts: list[tuple[str, str, int, str]] = []
    for shard in sorted(shards, key=lambda item: str(item.get("path"))):
        if not isinstance(shard, Mapping):
            raise ReferenceOrchestratorError("weight shard inventory schema drift")
        name = str(shard.get("path"))
        if "/" in name or "\\" in name or not name.endswith(".safetensors"):
            raise ReferenceOrchestratorError("weight shard name is unsafe")
        url = urlunsplit((parsed_index.scheme, parsed_index.netloc, base_path + name, "", ""))
        raw_artifacts.append(
            ("safetensors", str(shard.get("content_sha256")), int(shard.get("size_bytes")), url)
        )
    for name in sorted(_SOURCE_FILES):
        item = by_name.get(name)
        if item is None and name == "special_tokens_map.json":
            continue
        if not isinstance(item, Mapping):
            raise ReferenceOrchestratorError("required source metadata is unavailable")
        local = item.get("local_content")
        http = item.get("http")
        if not isinstance(local, Mapping) or not isinstance(http, Mapping):
            raise ReferenceOrchestratorError("source metadata binding is incomplete")
        requested_url = str(http.get("requested_url"))
        parsed = urlsplit(requested_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in REFERENCE_IMMUTABLE_ORIGIN_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
            or parsed.path != expected_prefix + name
        ):
            raise ReferenceOrchestratorError("source metadata origin is not provenance-bound")
        raw_artifacts.append(
            (
                _SOURCE_FILES[name],
                str(local.get("sha256")),
                int(local.get("size_bytes")),
                requested_url,
            )
        )
    return [
        {"format": kind, "ordinal": ordinal, "sha256": digest, "size_bytes": size, "url": url}
        for ordinal, (kind, digest, size, url) in enumerate(raw_artifacts)
    ]


def build_bootstrap_request(root: Path, config: ReferenceJobConfig) -> bytes:
    """Build canonical target-neutral wire bytes; target details remain inside the bytes."""
    root = root.resolve()
    image_path = root / IMAGE_LOCK_PATH
    image = validate_image_lock_bytes(image_path.read_bytes())
    runtime_lock = load_runtime_lock(
        root / str(config.authority_files["runtime_lock_path"]), root=root
    )
    evaluation_bytes = (root / str(config.authority_files["evaluation_lock_path"])).read_bytes()
    evaluation_raw = json.loads(evaluation_bytes)
    fixture_root = root / str(config.authority_files["evaluation_fixture_root"])
    fixture_bytes = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation_raw["fixtures"]
    }
    evaluation = validate_pending_evaluation_lock(evaluation_raw, fixture_bytes=fixture_bytes)
    provider_path = root / PROVIDER_CAPABILITY_PATH
    provider_sha = _sha(provider_path.read_bytes())
    provider = validate_provider_capability_receipt(
        provider_path,
        expected_sha256=provider_sha,
        image_recipe_sha256=image.recipe_sha256,
        billing_authority_path=root / DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=root / DEFAULT_BILLING_RECEIPT,
        billing_report_path=root / DEFAULT_BILLING_REPORT,
    )
    memory = _read_json(
        root / str(config.gates["memory_fit_evidence_path"]), "memory lower-bound evidence"
    )
    artifacts = _source_artifacts(root, config)
    hosts = sorted(
        {str(urlsplit(str(item["url"])).hostname) for item in artifacts}
        | {host for host, _ in REFERENCE_SIGNED_REDIRECT_POLICY}
    )
    resources = dict(REFERENCE_RESOURCES)
    resources["max_concurrent_containers"] = 1
    source_hashes = {
        key: value
        for key, value in config.inputs.items()
        if key not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
        and value is not None
    }
    request = {
        "action": "u8_reference_once",
        "approved_https_hosts": hosts,
        "authority": {
            "bootstrap_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "merge_commit": REFERENCE_BOOTSTRAP_MERGE_COMMIT,
            "parent_sha256": REFERENCE_AUTHORITY_SHA256,
            "signed_cdn_merge_commit": REFERENCE_SIGNED_CDN_MERGE_COMMIT,
            "signed_cdn_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        },
        "budget": {
            "cumulative_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
            "incremental_reserved_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
            "no_overlapping_reservations": True,
            "provider_hard_dollar_cap": False,
            "settled_before_usd": str(REFERENCE_SETTLED_SMOKE_USD),
        },
        "configured_context_tokens": 262144,
        "context_ladder_tokens": [8192, 32768, 131072, 262144],
        "deadline_policy": {
            "absolute_deadline_starts_at": "submission_pending",
            "future_stage_reserves_seconds": FUTURE_STAGE_RESERVES_SECONDS,
            "minimum_transfer_projection_bytes": 67108864,
            "projection_rounding": "against_admission",
            "timeout_seconds": 2700,
            "unused_time_flows_forward": True,
        },
        "image_lock": {"recipe_sha256": image.recipe_sha256, "sha256": image.sha256},
        "kind": "reference_bootstrap_request",
        "known_memory_lower_bound_bytes": memory.get("known_required_lower_bound_bytes"),
        "lineage": {
            "control_plane_sha256": config.inputs["control_plane_sha256"],
            "evaluation_lock_sha256": evaluation.sha256,
            "inventory_sha256": config.inputs["weight_inventory_sha256"],
            "reviewed_commit": config.inputs["reviewed_commit_sha256"],
            "runtime_lock_sha256": runtime_lock.sha256,
            "runtime_receipt_sha256": config.inputs["runtime_receipt_sha256"],
            "source_hashes_sha256": canonical_sha256(source_hashes),
            "source_revision": config.inputs["source_revision"],
        },
        "provider_capability": {
            "image_recipe_sha256": image.recipe_sha256,
            "proven": True,
            "receipt_sha256": provider_sha,
            "remote_contact_performed": False,
            "sdk_version": provider["sdk"]["version"],
        },
        "readiness": {
            "deterministic": "bootstrap_ready",
            "empirical": {fact: "pending" for fact in EMPIRICAL_FACTS},
        },
        "resources": resources,
        "response_caps": {
            "max_failure_code_chars": 64,
            "max_measurements_per_stage": 16,
            "max_receipt_bytes": 65536,
            "max_stages": len(STAGES),
        },
        "restrictions": {
            "application_retries": 0,
            "destructive_cleanup": False,
            "executable_artifacts": False,
            "fallback_gpu": False,
            "local_data_mount": False,
            "local_source_mount": False,
            "persistent_volumes": False,
            "provider_retries": 0,
            "remote_code": False,
            "scheduling": False,
            "secrets": False,
            "user_payloads": False,
            "weights_source": "remote_immutable_public_only",
        },
        "schema_version": 1,
        "source_artifacts": artifacts,
        "source_artifacts_sha256": canonical_sha256(artifacts),
    }
    encoded = canonical_bytes(request)
    validate_bootstrap_request_bytes(encoded)
    return encoded


def validate_reproduced_request(
    root: Path, config: ReferenceJobConfig, request_bytes: bytes
) -> None:
    """Require the paid consumer to reproduce every source entry from local authority."""
    if build_bootstrap_request(root, config) != request_bytes:
        raise ReferenceOrchestratorError("bootstrap request does not match local provenance")


def _capability(root: Path, config: ReferenceJobConfig, request: bytes) -> ReferenceModalCapability:
    evaluation_path = Path(str(config.authority_files["evaluation_lock_path"]))
    evaluation_bytes = (root / evaluation_path).read_bytes()
    evaluation = json.loads(evaluation_bytes)
    fixture_root = root / str(config.authority_files["evaluation_fixture_root"])
    fixtures = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation["fixtures"]
    }
    image = json.loads((root / IMAGE_LOCK_PATH).read_text(encoding="utf-8"))
    provider = _read_json(root / PROVIDER_CAPABILITY_PATH, "provider capability")
    identity = {
        "weight_inventory_sha256": str(config.inputs["weight_inventory_sha256"]),
        "provenance_manifest_sha256": str(config.inputs["provenance_manifest_sha256"]),
        "runtime_receipt_sha256": str(config.inputs["runtime_receipt_sha256"]),
        "reviewed_commit_sha256": str(config.inputs["reviewed_commit_sha256"]),
        "resource_spec_sha256": _sha(canonical_bytes(config.resources)),
    }
    return ReferenceModalCapability(
        db_path=root / DATABASE_PATH,
        root=root,
        config_path=CONFIG_PATH,
        request_path=REQUEST_PATH,
        image_lock_path=IMAGE_LOCK_PATH,
        provider_capability_path=PROVIDER_CAPABILITY_PATH,
        billing_authority_path=DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=DEFAULT_BILLING_RECEIPT,
        billing_report_path=DEFAULT_BILLING_REPORT,
        publication_manifest_path=PUBLICATION_MANIFEST_PATH,
        reservation_id="",
        owner_id="",
        authority_root=root,
        provider_environment=str(provider["billing"]["environment_identity"]),
        bootstrap_request_bytes=request,
        evaluation_lock_bytes=evaluation_bytes,
        fixture_bytes=fixtures,
        execution_identity=identity,
        image_lock=image,
    )


def prepare(root: Path) -> tuple[ReferenceJobConfig, bytes, ReferenceModalCapability]:
    root = root.resolve()
    config = refresh_local_config(root)
    request = build_bootstrap_request(root, config)
    _write_atomic(root / REQUEST_PATH, request)
    request_sha = _sha(request)
    image_sha = _sha((root / IMAGE_LOCK_PATH).read_bytes())
    provider_sha = _sha((root / PROVIDER_CAPABILITY_PATH).read_bytes())
    preview = plan_reference_bootstrap_preview(
        config,
        root=root,
        request_path=REQUEST_PATH,
        request_sha256=request_sha,
        image_lock_path=IMAGE_LOCK_PATH,
        image_lock_sha256=image_sha,
        provider_capability_path=PROVIDER_CAPABILITY_PATH,
        provider_capability_sha256=provider_sha,
        billing_authority_path=DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=DEFAULT_BILLING_RECEIPT,
        billing_report_path=DEFAULT_BILLING_REPORT,
        publication_manifest_path=PUBLICATION_MANIFEST_PATH,
    )
    if preview["bootstrap_ready"] is not True or preview["blockers"]:
        raise ReferenceOrchestratorError("deterministic bootstrap gates are not ready")
    return config, request, _capability(root, config, request)


def _watchdog_ready() -> None:
    if (
        os.name == "nt"
        or not all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer"))
    ):
        raise ReferenceOrchestratorError("paid execution requires the WSL/Linux watchdog")


def execute(root: Path, *, confirm_request_sha256: str) -> Mapping[str, object]:
    """Reserve once and cross the existing adapter boundary after fresh local checks."""
    root = root.resolve()
    _watchdog_ready()
    config, request, unreserved = prepare(root)
    request_sha = _sha(request)
    if confirm_request_sha256 != request_sha:
        raise ReferenceOrchestratorError("request confirmation does not match fresh bytes")
    observe_topology(root / REQUEST_PATH)
    from lowbit_lab.reference_modal_adapter import (
        submit_reference,
        validate_reference_preflight,
    )

    validate_reference_preflight(unreserved)
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    database.initialize()
    now = datetime.now(UTC)
    expires = now + timedelta(hours=1)
    reservation_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    packet_sha = canonical_sha256(
        {
            "bootstrap_authority_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "config_sha256": config.sha256,
            "request_sha256": request_sha,
            "signed_cdn_authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
            "standing_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        }
    )
    approval_digest = canonical_sha256(
        {
            "action": "u8_reference_once",
            "challenge_sha256": config.challenge_sha256,
            "packet_sha256": packet_sha,
            "standing_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        }
    )
    database.reserve_reference_run(
        reservation_id=reservation_id,
        attempt_id=attempt_id,
        run_id=run_id,
        experiment_id=config.experiment_id,
        config_sha256=config.sha256,
        config_json=config.canonical_json,
        source_hashes={
            key: value
            for key, value in config.inputs.items()
            if key not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
            and value is not None
        },
        runtime={"receipt_sha256": config.inputs["runtime_receipt_sha256"]},
        hardware={},
        requested_cost_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        phase_cap_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        total_cap_usd=str(REFERENCE_CUMULATIVE_CAP_USD),
        single_job_cap_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        idempotency_key=str(uuid.uuid4()),
        owner_id=owner_id,
        lease_expires_at=expires.isoformat(),
        started_at=now.isoformat(),
        challenge_sha256=config.challenge_sha256,
        approval_digest=approval_digest,
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=root,
        standing_packet_sha256=packet_sha,
        approval_expires_at=expires.isoformat(),
        attempt_config_path=CONFIG_PATH.as_posix(),
        attempt_raw_config_sha256=_sha((root / CONFIG_PATH).read_bytes()),
    )
    capability = replace(unreserved, reservation_id=reservation_id, owner_id=owner_id)
    try:
        return submit_reference(capability)
    except Exception:
        try:
            reservation = database.get_reservation(reservation_id)
        except Exception:
            raise ReferenceProviderStateUnknown("reference provider state requires audit") from None
        if reservation.get("status") == "reserved":
            raise ReferenceOrchestratorError("reference stopped before Modal contact") from None
        raise ReferenceProviderStateUnknown("reference provider state requires audit") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gate the one U8 reference action")
    parser.add_argument("--root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    live = sub.add_parser("execute")
    live.add_argument("--confirm-request-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    command = None
    try:
        args = _parser().parse_args(argv)
        command = args.command
        if command == "prepare":
            config, request, _ = prepare(args.root)
            emit(
                {
                    "configured_context_tokens": 262144,
                    "execution_scope_sha256": config.reference_execution_scope_sha256,
                    "ok": True,
                    "provider_contacted": False,
                    "proven_useful_context_tokens": None,
                    "request_sha256": _sha(request),
                }
            )
            return 0
        result = execute(args.root, confirm_request_sha256=args.confirm_request_sha256)
        emit({"ok": True, "provider_contacted": True, "result": result})
        return 0
    except Exception as exc:
        emit(
            {
                "command": command,
                "error": type(exc).__name__,
                "ok": False,
                "provider_contacted": (
                    "unknown" if isinstance(exc, ReferenceProviderStateUnknown) else False
                ),
            },
            stream=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
