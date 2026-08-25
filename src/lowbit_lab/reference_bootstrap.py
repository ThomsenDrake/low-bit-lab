"""Closed, target-neutral contracts for the one-shot reference bootstrap.

This module is deliberately pure: it parses bytes, validates closed schemas,
and derives identities.  It performs no file access, provider contact, model
loading, or authority consumption.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from os.path import basename
from typing import Any
from urllib.parse import unquote, urlsplit

from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_SETTLED_SMOKE_USD,
)
from lowbit_lab.reference_contract import REFERENCE_RESOURCES

REQUEST_KIND = "reference_bootstrap_request"
IMAGE_LOCK_KIND = "reference_modal_image_lock"
STAGE_KIND = "reference_bootstrap_stage_receipt"
RECEIPT_KIND = "reference_bootstrap_receipt"

CONFIGURED_CONTEXT_TOKENS = 262_144
STAGES = (
    "runtime_identity",
    "source_transfer",
    "hash_verification",
    "model_load",
    "evaluation",
    "evidence_finalization",
)
EMPIRICAL_FACTS = (
    "cold_path_timing",
    "context_usefulness",
    "empirical_fit",
    "provider_image_identity",
    "runtime_allocator_overhead",
    "usable_gpu_memory",
)
ALLOWED_ARTIFACT_FORMATS = frozenset({"json", "safetensors", "text", "tokenizer_data"})
BUILD_STEPS = (
    "from_registry_by_digest",
    "install_hashed_public_python_artifacts",
)
DEPENDENCY_ARTIFACT_HOSTS = frozenset(
    {"download-r2.pytorch.org", "files.pythonhosted.org"}
)
FUTURE_STAGE_RESERVES_SECONDS = {
    "evaluation": 840,
    "finalization": 60,
    "load": 420,
    "verification": 180,
}
_PYTHON_PATCH_RE = re.compile(r"3\.[0-9]+\.[0-9]+")
_PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class ReferenceBootstrapError(ValueError):
    """Raised when bootstrap contract bytes or semantics drift."""


@dataclass(frozen=True)
class ImageLock:
    canonical_json: str
    sha256: str
    recipe_sha256: str


@dataclass(frozen=True)
class BootstrapRequest:
    canonical_json: str
    sha256: str
    source_artifacts: tuple[Mapping[str, Any], ...]
    context_ladder_tokens: tuple[int, ...]
    image_lock_sha256: str


@dataclass(frozen=True)
class StageReceipt:
    canonical_json: str
    sha256: str
    stage: str
    ordinal: int
    status: str


@dataclass(frozen=True)
class BootstrapReceipt:
    canonical_json: str
    sha256: str
    status: str
    stages: tuple[StageReceipt, ...]
    full_context_usefulness_proven: bool


def canonical_json(value: object) -> str:
    """Return the only accepted JSON representation for remote contracts."""
    _validate_json_types(value, "value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(value: object) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _validate_json_types(value: object, label: str) -> None:
    if value is None or isinstance(value, str | bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise ReferenceBootstrapError(f"{label} must not contain floating-point values")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReferenceBootstrapError(f"{label} keys must be strings")
            _validate_json_types(item, f"{label}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_types(item, f"{label}[{index}]")
        return
    raise ReferenceBootstrapError(f"{label} contains an unsupported JSON value")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReferenceBootstrapError("bootstrap JSON contains duplicate keys")
        result[key] = value
    return result


def _parse_canonical(content: bytes, label: str) -> Mapping[str, Any]:
    if not isinstance(content, bytes) or content.startswith(b"\xef\xbb\xbf"):
        raise ReferenceBootstrapError(f"{label} must be UTF-8 JSON bytes without a BOM")
    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ReferenceBootstrapError(f"{label} contains {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceBootstrapError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ReferenceBootstrapError(f"{label} must be an object")
    if content != canonical_bytes(value):
        raise ReferenceBootstrapError(f"{label} bytes are not canonical")
    return value


def _closed(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReferenceBootstrapError(f"{label} must be an object")
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing:
        raise ReferenceBootstrapError(f"{label} is missing keys: {sorted(missing)}")
    if unknown:
        raise ReferenceBootstrapError(f"{label} has unknown keys: {sorted(unknown)}")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReferenceBootstrapError(f"{label} must be a lowercase SHA-256")
    return value


def _commit(value: object, label: str) -> str:
    if not isinstance(value, str) or IMMUTABLE_REVISION_RE.fullmatch(value) is None:
        raise ReferenceBootstrapError(f"{label} must be a lowercase immutable revision")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReferenceBootstrapError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReferenceBootstrapError(f"{label} must be a nonnegative integer")
    return value


def _exact_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReferenceBootstrapError(f"{label} must be a non-empty exact string")
    return value


def _validate_image_lock_mapping(raw: object) -> ImageLock:
    lock = _closed(
        raw,
        {
            "base_image",
            "builder",
            "dependency_artifacts",
            "kind",
            "python_patch_version",
            "recipe",
            "recipe_sha256",
            "schema_version",
        },
        "image lock",
    )
    if lock["schema_version"] != 1 or lock["kind"] != IMAGE_LOCK_KIND:
        raise ReferenceBootstrapError("image lock identity drift")
    base = _closed(lock["base_image"], {"digest", "reference"}, "base image")
    base_reference = _exact_string(base["reference"], "base image reference")
    if "@" in base_reference or any(mark in base_reference for mark in ("://", "?", "#")):
        raise ReferenceBootstrapError("base image reference must be a registry name without tag")
    digest = _exact_string(base["digest"], "base image digest")
    if not digest.startswith("sha256:") or SHA256_RE.fullmatch(digest[7:]) is None:
        raise ReferenceBootstrapError("base image digest must be sha256:<lowercase digest>")
    python_version = _exact_string(lock["python_patch_version"], "Python patch version")
    if _PYTHON_PATCH_RE.fullmatch(python_version) is None:
        raise ReferenceBootstrapError("Python version must be pinned to a patch release")

    builder = _closed(
        lock["builder"], {"distribution", "python_sources_sha256", "version"}, "builder"
    )
    if builder["distribution"] != "modal":
        raise ReferenceBootstrapError("image builder must be modal")
    _exact_string(builder["version"], "builder version")
    _sha256(builder["python_sources_sha256"], "builder source identity")

    artifacts = lock["dependency_artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ReferenceBootstrapError("dependency artifacts must be a non-empty list")
    filenames: list[str] = []
    coordinates: list[tuple[str, str]] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = _closed(
            raw_artifact,
            {"filename", "name", "sha256", "size_bytes", "url", "version"},
            f"dependency artifact {index}",
        )
        name = _exact_string(artifact["name"], f"dependency artifact {index} name")
        version = _exact_string(artifact["version"], f"dependency artifact {index} version")
        filename = _exact_string(artifact["filename"], f"dependency artifact {index} filename")
        url = _exact_string(artifact["url"], f"dependency artifact {index} URL")
        parsed_url = urlsplit(url)
        if (
            _PACKAGE_RE.fullmatch(name) is None
            or _VERSION_RE.fullmatch(version) is None
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
            or not filename.endswith((".whl", ".tar.gz"))
            or parsed_url.scheme != "https"
            or parsed_url.hostname not in DEPENDENCY_ARTIFACT_HOSTS
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.port not in (None, 443)
            or parsed_url.query
            or parsed_url.fragment
            or unquote(parsed_url.path.rsplit("/", 1)[-1]) != filename
        ):
            raise ReferenceBootstrapError("dependency artifact identity is unsafe")
        _sha256(artifact["sha256"], f"dependency artifact {index} hash")
        _positive_int(artifact["size_bytes"], f"dependency artifact {index} size")
        filenames.append(filename)
        coordinates.append((name, version))
    if filenames != sorted(filenames) or len(set(filenames)) != len(filenames):
        raise ReferenceBootstrapError("dependency artifacts must be uniquely filename-sorted")
    if len(set(coordinates)) != len(coordinates):
        raise ReferenceBootstrapError("dependency package coordinates must be unique")

    recipe = _closed(
        lock["recipe"],
        {
            "base_image_digest",
            "build_steps",
            "dependency_artifacts_sha256",
            "dependency_filenames",
            "network_install_enabled",
            "python_patch_version",
        },
        "image recipe",
    )
    if (
        recipe["base_image_digest"] != digest
        or recipe["python_patch_version"] != python_version
        or recipe["dependency_filenames"] != filenames
        or recipe["dependency_artifacts_sha256"] != canonical_sha256(artifacts)
        or recipe["build_steps"] != list(BUILD_STEPS)
        or recipe["network_install_enabled"] is not True
    ):
        raise ReferenceBootstrapError("image recipe does not reproduce the locked inputs")
    recipe_sha256 = _sha256(lock["recipe_sha256"], "image recipe hash")
    if recipe_sha256 != canonical_sha256(recipe):
        raise ReferenceBootstrapError("image recipe hash mismatch")
    encoded = canonical_json(lock)
    return ImageLock(encoded, hashlib.sha256(encoded.encode()).hexdigest(), recipe_sha256)


def validate_image_lock(raw: object) -> ImageLock:
    """Validate an already-parsed closed image lock."""
    _validate_json_types(raw, "image lock")
    return _validate_image_lock_mapping(raw)


def validate_image_lock_bytes(content: bytes) -> ImageLock:
    return _validate_image_lock_mapping(_parse_canonical(content, "image lock"))


def build_image_lock_from_pylock(
    pylock: Mapping[str, Any],
    *,
    base_image_reference: str,
    base_image_digest: str,
    python_patch_version: str,
    builder_version: str,
    builder_sources_sha256: str,
    missing_sizes: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Select the single platform wheel already resolved for every locked package."""
    packages = pylock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReferenceBootstrapError("pylock packages must be a non-empty list")
    size_overrides = dict(missing_sizes or {})
    artifacts: list[dict[str, object]] = []
    for index, raw_package in enumerate(packages):
        optional_keys = (
            {"marker"}
            if isinstance(raw_package, Mapping) and "marker" in raw_package
            else set()
        )
        package = _closed(
            raw_package,
            {"name", "version", "wheels"} | optional_keys,
            f"pylock package {index}",
        )
        wheels = package["wheels"]
        if not isinstance(wheels, list) or len(wheels) != 1:
            raise ReferenceBootstrapError("pylock must resolve exactly one wheel per package")
        wheel = wheels[0]
        if not isinstance(wheel, Mapping):
            raise ReferenceBootstrapError("pylock wheel must be an object")
        url = _exact_string(wheel.get("url"), f"pylock package {index} URL")
        filename = unquote(basename(urlsplit(url).path))
        hashes = wheel.get("hashes")
        if not isinstance(hashes, Mapping) or set(hashes) != {"sha256"}:
            raise ReferenceBootstrapError("pylock wheel requires one SHA-256")
        name = _exact_string(package["name"], f"pylock package {index} name")
        size = wheel.get("size", size_overrides.get(name))
        artifacts.append(
            {
                "filename": filename,
                "name": name,
                "sha256": hashes["sha256"],
                "size_bytes": size,
                "url": url,
                "version": package["version"],
            }
        )
    artifacts.sort(key=lambda item: str(item["filename"]))
    recipe = {
        "base_image_digest": base_image_digest,
        "build_steps": list(BUILD_STEPS),
        "dependency_artifacts_sha256": canonical_sha256(artifacts),
        "dependency_filenames": [item["filename"] for item in artifacts],
        "network_install_enabled": True,
        "python_patch_version": python_patch_version,
    }
    lock: dict[str, object] = {
        "base_image": {
            "digest": base_image_digest,
            "reference": base_image_reference,
        },
        "builder": {
            "distribution": "modal",
            "python_sources_sha256": builder_sources_sha256,
            "version": builder_version,
        },
        "dependency_artifacts": artifacts,
        "kind": IMAGE_LOCK_KIND,
        "python_patch_version": python_patch_version,
        "recipe": recipe,
        "recipe_sha256": canonical_sha256(recipe),
        "schema_version": 1,
    }
    validate_image_lock(lock)
    unknown_overrides = set(size_overrides) - {str(item["name"]) for item in artifacts}
    if unknown_overrides:
        raise ReferenceBootstrapError("image lock size override names are unknown")
    return lock


def _validate_https_host(value: object, label: str) -> str:
    host = _exact_string(value, label)
    if host != host.lower() or _HOST_RE.fullmatch(host) is None:
        raise ReferenceBootstrapError(f"{label} must be a lowercase DNS host")
    return host


def _validate_source_artifacts(
    value: object, approved_hosts: tuple[str, ...]
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise ReferenceBootstrapError("source artifacts must be a non-empty list")
    validated: list[Mapping[str, Any]] = []
    urls: list[str] = []
    digests: list[str] = []
    safetensors = 0
    for expected_ordinal, raw in enumerate(value):
        artifact = _closed(
            raw,
            {"format", "ordinal", "sha256", "size_bytes", "url"},
            f"source artifact {expected_ordinal}",
        )
        if artifact["ordinal"] != expected_ordinal:
            raise ReferenceBootstrapError("source artifact ordinals must be contiguous")
        artifact_format = artifact["format"]
        if artifact_format not in ALLOWED_ARTIFACT_FORMATS:
            raise ReferenceBootstrapError("source artifact format is not data-only")
        safetensors += int(artifact_format == "safetensors")
        digest = _sha256(artifact["sha256"], f"source artifact {expected_ordinal} hash")
        _positive_int(artifact["size_bytes"], f"source artifact {expected_ordinal} size")
        url = _exact_string(artifact["url"], f"source artifact {expected_ordinal} URL")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.port not in (None, 443)
            or parsed.hostname not in approved_hosts
            or not parsed.path.startswith("/")
        ):
            raise ReferenceBootstrapError(
                "source artifact URL is outside the closed HTTPS origin set"
            )
        urls.append(url)
        digests.append(digest)
        validated.append(artifact)
    if len(set(urls)) != len(urls) or len(set(digests)) != len(digests):
        raise ReferenceBootstrapError(
            "source artifacts contain duplicate URL or content identities"
        )
    if safetensors == 0:
        raise ReferenceBootstrapError("source artifacts must include safetensors weights")
    return tuple(validated)


def _validate_request_mapping(raw: object) -> BootstrapRequest:
    request = _closed(
        raw,
        {
            "action",
            "approved_https_hosts",
            "authority",
            "budget",
            "configured_context_tokens",
            "context_ladder_tokens",
            "deadline_policy",
            "image_lock",
            "kind",
            "known_memory_lower_bound_bytes",
            "lineage",
            "provider_capability",
            "readiness",
            "resources",
            "response_caps",
            "restrictions",
            "schema_version",
            "source_artifacts",
            "source_artifacts_sha256",
        },
        "bootstrap request",
    )
    if (
        request["schema_version"] != 1
        or request["kind"] != REQUEST_KIND
        or request["action"] != "u8_reference_once"
    ):
        raise ReferenceBootstrapError("bootstrap request identity drift")

    authority = _closed(
        request["authority"],
        {"bootstrap_sha256", "merge_commit", "parent_sha256"},
        "bootstrap authority binding",
    )
    if authority != {
        "bootstrap_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        "merge_commit": REFERENCE_BOOTSTRAP_MERGE_COMMIT,
        "parent_sha256": REFERENCE_AUTHORITY_SHA256,
    }:
        raise ReferenceBootstrapError("bootstrap authority binding drift")

    lineage = _closed(
        request["lineage"],
        {
            "control_plane_sha256",
            "evaluation_lock_sha256",
            "inventory_sha256",
            "reviewed_commit",
            "runtime_lock_sha256",
            "runtime_receipt_sha256",
            "source_hashes_sha256",
            "source_revision",
        },
        "bootstrap lineage",
    )
    _commit(lineage["reviewed_commit"], "reviewed commit")
    _commit(lineage["source_revision"], "source revision")
    for key in set(lineage) - {"reviewed_commit", "source_revision"}:
        _sha256(lineage[key], key)

    raw_hosts = request["approved_https_hosts"]
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise ReferenceBootstrapError("approved HTTPS hosts must be a non-empty list")
    hosts = tuple(_validate_https_host(host, "approved HTTPS host") for host in raw_hosts)
    if hosts != tuple(sorted(set(hosts))):
        raise ReferenceBootstrapError("approved HTTPS hosts must be unique and sorted")
    artifacts = _validate_source_artifacts(request["source_artifacts"], hosts)
    if _sha256(request["source_artifacts_sha256"], "source artifacts hash") != canonical_sha256(
        list(artifacts)
    ):
        raise ReferenceBootstrapError("source artifact list hash mismatch")

    image_lock_raw = request["image_lock"]
    image_binding = _closed(
        image_lock_raw, {"recipe_sha256", "sha256"}, "image lock binding"
    )
    image_lock_sha256 = _sha256(image_binding["sha256"], "image lock hash")
    recipe_sha256 = _sha256(image_binding["recipe_sha256"], "image recipe hash")
    capability = _closed(
        request["provider_capability"],
        {
            "image_recipe_sha256",
            "proven",
            "receipt_sha256",
            "remote_contact_performed",
            "sdk_version",
        },
        "provider capability binding",
    )
    if (
        capability["proven"] is not True
        or capability["remote_contact_performed"] is not False
        or capability["image_recipe_sha256"] != recipe_sha256
    ):
        raise ReferenceBootstrapError("provider capability does not bind the image recipe offline")
    _sha256(capability["receipt_sha256"], "provider capability receipt hash")
    _exact_string(capability["sdk_version"], "provider SDK version")

    resources = dict(REFERENCE_RESOURCES)
    resources["max_concurrent_containers"] = 1
    if request["resources"] != resources:
        raise ReferenceBootstrapError("reference resources drift from the fixed envelope")
    known_memory_lower_bound = _positive_int(
        request["known_memory_lower_bound_bytes"], "known memory lower bound"
    )
    if known_memory_lower_bound > 85_899_345_920:
        raise ReferenceBootstrapError("known memory lower bound exceeds physical GPU capacity")
    budget = _closed(
        request["budget"],
        {
            "cumulative_cap_usd",
            "incremental_reserved_usd",
            "no_overlapping_reservations",
            "provider_hard_dollar_cap",
            "settled_before_usd",
        },
        "bootstrap budget",
    )
    expected_budget = {
        "cumulative_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
        "incremental_reserved_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
        "no_overlapping_reservations": True,
        "provider_hard_dollar_cap": False,
        "settled_before_usd": str(REFERENCE_SETTLED_SMOKE_USD),
    }
    if budget != expected_budget or Decimal(
        str(budget["incremental_reserved_usd"])
    ) != Decimal("4.00"):
        raise ReferenceBootstrapError("bootstrap budget drift")

    if request["configured_context_tokens"] != CONFIGURED_CONTEXT_TOKENS:
        raise ReferenceBootstrapError("configured context must remain 262144 tokens")
    raw_ladder = request["context_ladder_tokens"]
    if (
        not isinstance(raw_ladder, list)
        or not raw_ladder
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in raw_ladder
        )
        or raw_ladder != sorted(set(raw_ladder))
        or raw_ladder[-1] != CONFIGURED_CONTEXT_TOKENS
    ):
        raise ReferenceBootstrapError("context ladder must be increasing and end at 262144")

    deadline = _closed(
        request["deadline_policy"],
        {
            "absolute_deadline_starts_at",
            "future_stage_reserves_seconds",
            "minimum_transfer_projection_bytes",
            "projection_rounding",
            "timeout_seconds",
            "unused_time_flows_forward",
        },
        "deadline policy",
    )
    if deadline != {
        "absolute_deadline_starts_at": "submission_pending",
        "future_stage_reserves_seconds": FUTURE_STAGE_RESERVES_SECONDS,
        "minimum_transfer_projection_bytes": 67_108_864,
        "projection_rounding": "against_admission",
        "timeout_seconds": 2700,
        "unused_time_flows_forward": True,
    }:
        raise ReferenceBootstrapError("deadline policy drift")

    response_caps = _closed(
        request["response_caps"],
        {
            "max_failure_code_chars",
            "max_measurements_per_stage",
            "max_receipt_bytes",
            "max_stages",
        },
        "response caps",
    )
    if response_caps != {
        "max_failure_code_chars": 64,
        "max_measurements_per_stage": 16,
        "max_receipt_bytes": 65_536,
        "max_stages": len(STAGES),
    }:
        raise ReferenceBootstrapError("response caps drift")

    restrictions = _closed(
        request["restrictions"],
        {
            "application_retries",
            "destructive_cleanup",
            "executable_artifacts",
            "fallback_gpu",
            "local_data_mount",
            "local_source_mount",
            "persistent_volumes",
            "provider_retries",
            "remote_code",
            "scheduling",
            "secrets",
            "user_payloads",
            "weights_source",
        },
        "bootstrap restrictions",
    )
    expected_restrictions = {
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
    }
    if restrictions != expected_restrictions:
        raise ReferenceBootstrapError("bootstrap restriction drift")

    readiness = _closed(request["readiness"], {"deterministic", "empirical"}, "readiness")
    empirical = _closed(readiness["empirical"], set(EMPIRICAL_FACTS), "empirical readiness")
    if readiness["deterministic"] != "bootstrap_ready" or any(
        empirical[fact] != "pending" for fact in EMPIRICAL_FACTS
    ):
        raise ReferenceBootstrapError("bootstrap readiness must not pre-claim empirical evidence")

    encoded = canonical_json(request)
    return BootstrapRequest(
        canonical_json=encoded,
        sha256=hashlib.sha256(encoded.encode()).hexdigest(),
        source_artifacts=artifacts,
        context_ladder_tokens=tuple(raw_ladder),
        image_lock_sha256=image_lock_sha256,
    )


def validate_bootstrap_request(raw: object) -> BootstrapRequest:
    _validate_json_types(raw, "bootstrap request")
    return _validate_request_mapping(raw)


def validate_bootstrap_request_bytes(content: bytes) -> BootstrapRequest:
    return _validate_request_mapping(_parse_canonical(content, "bootstrap request"))


def validate_request_image_lock(
    request: BootstrapRequest, image_lock: ImageLock
) -> None:
    """Prove that the separately persisted image lock is the request's exact lock."""
    raw = json.loads(request.canonical_json)
    binding = raw["image_lock"]
    if (
        binding["sha256"] != image_lock.sha256
        or binding["recipe_sha256"] != image_lock.recipe_sha256
    ):
        raise ReferenceBootstrapError("request image lock binding drift")


_STAGE_MEASUREMENTS: dict[str, set[str]] = {
    "runtime_identity": {
        "device_free_bytes",
        "device_total_bytes",
        "image_identity_sha256",
        "runtime_identity_sha256",
    },
    "source_transfer": {"artifacts_received", "bytes_received"},
    "hash_verification": {"artifacts_verified", "bytes_verified"},
    "model_load": {
        "device_free_before_bytes",
        "known_required_bytes",
        "loaded",
        "peak_allocated_bytes",
        "peak_reserved_bytes",
    },
    "evaluation": {
        "configured_context_tokens",
        "full_context_completed",
        "levels_completed",
        "max_completed_context_tokens",
        "reference_manifest_bytes",
        "reference_manifest_sha256",
        "usefulness_proven",
    },
    "evidence_finalization": {"receipt_bytes"},
}


def _validate_stage_mapping(raw: object, request: BootstrapRequest) -> StageReceipt:
    stage_receipt = _closed(
        raw,
        {
            "elapsed_ms",
            "failure_code",
            "kind",
            "measurements",
            "ordinal",
            "remaining_ms",
            "request_sha256",
            "schema_version",
            "stage",
            "status",
        },
        "stage receipt",
    )
    if stage_receipt["schema_version"] != 1 or stage_receipt["kind"] != STAGE_KIND:
        raise ReferenceBootstrapError("stage receipt identity drift")
    if stage_receipt["request_sha256"] != request.sha256:
        raise ReferenceBootstrapError("stage receipt request identity drift")
    ordinal = _nonnegative_int(stage_receipt["ordinal"], "stage ordinal")
    if ordinal >= len(STAGES) or stage_receipt["stage"] != STAGES[ordinal]:
        raise ReferenceBootstrapError("stage receipt order drift")
    status = stage_receipt["status"]
    if status not in {"completed", "failed"}:
        raise ReferenceBootstrapError("stage receipt status is unknown")
    _nonnegative_int(stage_receipt["elapsed_ms"], "stage elapsed time")
    _nonnegative_int(stage_receipt["remaining_ms"], "stage remaining time")
    failure_code = stage_receipt["failure_code"]
    if status == "completed" and failure_code is not None:
        raise ReferenceBootstrapError("completed stage cannot have a failure code")
    if status == "failed" and (
        not isinstance(failure_code, str) or _FAILURE_CODE_RE.fullmatch(failure_code) is None
    ):
        raise ReferenceBootstrapError("failed stage requires a sanitized failure code")

    stage = STAGES[ordinal]
    measurements = _closed(
        stage_receipt["measurements"], _STAGE_MEASUREMENTS[stage], f"{stage} measurements"
    )
    if len(measurements) > 16:
        raise ReferenceBootstrapError("stage measurements exceed the response cap")
    for name, value in measurements.items():
        if name == "reference_manifest_sha256" and value is None:
            continue
        if name.endswith("sha256"):
            _sha256(value, f"{stage}.{name}")
        elif name in {"loaded", "full_context_completed", "usefulness_proven"}:
            if not isinstance(value, bool):
                raise ReferenceBootstrapError(f"{stage}.{name} must be boolean")
        else:
            _nonnegative_int(value, f"{stage}.{name}")
    if stage == "evaluation":
        if measurements["configured_context_tokens"] != CONFIGURED_CONTEXT_TOKENS:
            raise ReferenceBootstrapError("stage receipt reduced configured context")
        maximum = measurements["max_completed_context_tokens"]
        if maximum not in {0, *request.context_ladder_tokens}:
            raise ReferenceBootstrapError("completed context is outside the locked ladder")
        if measurements["full_context_completed"] is True and maximum != CONFIGURED_CONTEXT_TOKENS:
            raise ReferenceBootstrapError("full-context completion is inconsistent")
        if (
            measurements["usefulness_proven"] is True
            and measurements["full_context_completed"] is not True
        ):
            raise ReferenceBootstrapError("context usefulness cannot exceed completed evidence")
        manifest_sha = measurements["reference_manifest_sha256"]
        manifest_bytes = measurements["reference_manifest_bytes"]
        if status == "completed" and (
            manifest_sha is None
            or manifest_bytes <= 0
            or not measurements["full_context_completed"]
        ):
            raise ReferenceBootstrapError("completed evaluation must bind the reference manifest")
        if status == "failed" and (manifest_sha is not None or manifest_bytes != 0):
            raise ReferenceBootstrapError("failed evaluation cannot bind a reference manifest")
    encoded = canonical_json(stage_receipt)
    return StageReceipt(
        canonical_json=encoded,
        sha256=hashlib.sha256(encoded.encode()).hexdigest(),
        stage=stage,
        ordinal=ordinal,
        status=str(status),
    )


def validate_stage_receipt(raw: object, *, request: BootstrapRequest) -> StageReceipt:
    _validate_json_types(raw, "stage receipt")
    return _validate_stage_mapping(raw, request)


def _validate_receipt_mapping(raw: object, request: BootstrapRequest) -> BootstrapReceipt:
    receipt = _closed(
        raw,
        {
            "configured_context_tokens",
            "empirical_facts",
            "full_context_usefulness_proven",
            "kind",
            "max_completed_context_tokens",
            "request_sha256",
            "schema_version",
            "stages",
            "status",
            "terminal_failure",
        },
        "bootstrap receipt",
    )
    if receipt["schema_version"] != 1 or receipt["kind"] != RECEIPT_KIND:
        raise ReferenceBootstrapError("bootstrap receipt identity drift")
    if receipt["request_sha256"] != request.sha256:
        raise ReferenceBootstrapError("bootstrap receipt request identity drift")
    if receipt["configured_context_tokens"] != CONFIGURED_CONTEXT_TOKENS:
        raise ReferenceBootstrapError("bootstrap receipt reduced configured context")
    status = receipt["status"]
    if status not in {"succeeded", "failed"}:
        raise ReferenceBootstrapError("bootstrap receipt status is unknown")
    raw_stages = receipt["stages"]
    if not isinstance(raw_stages, list) or not raw_stages or len(raw_stages) > len(STAGES):
        raise ReferenceBootstrapError("bootstrap receipt has an invalid stage count")
    stages = tuple(_validate_stage_mapping(stage, request) for stage in raw_stages)
    if tuple(stage.ordinal for stage in stages) != tuple(range(len(stages))):
        raise ReferenceBootstrapError("bootstrap receipt stages are not contiguous")
    failures = [stage for stage in stages if stage.status == "failed"]
    if failures and (len(failures) != 1 or failures[0] != stages[-1]):
        raise ReferenceBootstrapError("no stage may follow a failed stage")
    if status == "succeeded" and (
        failures
        or len(stages) != len(STAGES)
        or any(stage.status != "completed" for stage in stages)
    ):
        raise ReferenceBootstrapError("successful receipt must complete every stage")
    if status == "failed" and not failures:
        raise ReferenceBootstrapError("failed receipt must end at one failed stage")

    terminal_failure = receipt["terminal_failure"]
    if status == "succeeded" and terminal_failure is not None:
        raise ReferenceBootstrapError("successful receipt cannot have terminal failure")
    if status == "failed":
        failure = _closed(terminal_failure, {"code", "stage"}, "terminal failure")
        failed_stage = json.loads(failures[0].canonical_json)
        if (
            failure["stage"] != failures[0].stage
            or failure["code"] != failed_stage["failure_code"]
        ):
            raise ReferenceBootstrapError("terminal failure does not match the failed stage")

    facts = _closed(receipt["empirical_facts"], set(EMPIRICAL_FACTS), "empirical facts")
    if any(not isinstance(facts[fact], bool) for fact in EMPIRICAL_FACTS):
        raise ReferenceBootstrapError("empirical facts must be booleans")
    required_provider_facts = (
        "cold_path_timing",
        "provider_image_identity",
        "runtime_allocator_overhead",
        "usable_gpu_memory",
    )
    if status == "succeeded" and any(
        facts[fact] is not True for fact in required_provider_facts
    ):
        raise ReferenceBootstrapError("successful receipt is missing provider-derived facts")
    maximum = _nonnegative_int(receipt["max_completed_context_tokens"], "maximum completed context")
    if maximum not in {0, *request.context_ladder_tokens}:
        raise ReferenceBootstrapError("receipt context is outside the locked ladder")
    usefulness = receipt["full_context_usefulness_proven"]
    if not isinstance(usefulness, bool):
        raise ReferenceBootstrapError("full-context usefulness state must be boolean")
    if usefulness and (
        maximum != CONFIGURED_CONTEXT_TOKENS or facts["context_usefulness"] is not True
    ):
        raise ReferenceBootstrapError("full-context usefulness is not supported by evidence")
    encoded = canonical_json(receipt)
    if len(encoded.encode()) > 65_536:
        raise ReferenceBootstrapError("bootstrap receipt exceeds the response cap")
    return BootstrapReceipt(
        canonical_json=encoded,
        sha256=hashlib.sha256(encoded.encode()).hexdigest(),
        status=str(status),
        stages=stages,
        full_context_usefulness_proven=usefulness,
    )


def validate_bootstrap_receipt(raw: object, *, request: BootstrapRequest) -> BootstrapReceipt:
    _validate_json_types(raw, "bootstrap receipt")
    return _validate_receipt_mapping(raw, request)


def validate_bootstrap_receipt_bytes(
    content: bytes, *, request: BootstrapRequest
) -> BootstrapReceipt:
    return _validate_receipt_mapping(_parse_canonical(content, "bootstrap receipt"), request)
