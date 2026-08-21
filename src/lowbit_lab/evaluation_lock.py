from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass

from lowbit_lab.constants import EVALUATION_FAMILIES
from lowbit_lab.evaluation import ContextState, validate_context_state

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
APPROVED_SOURCE_CLASSIFICATIONS = frozenset({"public", "licensed", "synthetic"})
KNOWN_METRICS = {
    "coding": frozenset({"exact_match", "pass_rate"}),
    "tool_call_validity": frozenset({"schema_valid_rate", "argument_accuracy"}),
    "long_context_retrieval": frozenset({"retrieval_accuracy", "exact_match"}),
    "throughput": frozenset(
        {"cold_load_seconds", "prefill_tokens_per_second", "decode_tokens_per_second"}
    ),
    "memory": frozenset({"peak_vram_bytes", "peak_ram_bytes"}),
    "soak": frozenset({"failure_free_rate", "runtime_errors", "completed_minutes"}),
}
AGGREGATION_METHODS = frozenset({"arithmetic_mean", "median", "minimum"})
THRESHOLD_OPERATORS = frozenset({"gte", "lte"})

_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_PRIVATE_PATH_PATTERNS = (
    re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]"),
    re.compile(r"(?i)/mnt/[a-z]/" r"Users/[^/\s]+/"),
    re.compile(r"/ho" r"me/[^/\s]+/"),
    re.compile(r"\\\\[^\\\s]+\\[^\\\s]+"),
)
_PERSONAL_WORK_PATTERNS = (
    re.compile(r"(?i)\b(?:employee|customer|client|patient)[_-]?id\b"),
    re.compile(r"(?i)\b(?:confidential|proprietary|internal[-_ ]only|work[-_ ]product)\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
)


class EvaluationLockError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureLock:
    family: str
    fixture_id: str
    version: str
    sha256: str
    source_classification: str
    source_reference: str
    license: str
    seed: int
    scorer_id: str
    metrics: tuple[str, ...]


@dataclass(frozen=True)
class PendingEvaluationLock:
    schema_version: int
    suite_id: str
    suite_version: str
    fixtures: tuple[FixtureLock, ...]
    scorer: Mapping[str, object]
    metrics: Mapping[str, tuple[str, ...]]
    aggregation: Mapping[str, object]
    context: ContextState
    canonical_json: str
    sha256: str
    status: str = "pending_threshold_authority"
    promotion_authorized: bool = False
    candidate_execution: str = "blocked"


@dataclass(frozen=True)
class FullEvaluationLock:
    base_lock_sha256: str
    authority_sha256: str
    canonical_json: str
    sha256: str
    status: str = "locked"
    promotion_authorized: bool = True
    candidate_execution: str = "allowed"


def _closed_mapping(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EvaluationLockError(f"{label} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown:
        raise EvaluationLockError(f"{label} has unknown keys")
    if missing:
        raise EvaluationLockError(f"{label} is missing keys")
    return value


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID_RE.fullmatch(value):
        raise EvaluationLockError(f"{label} must be a safe identifier")
    return value


def _version(value: object, label: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise EvaluationLockError(f"{label} must be a semantic version")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise EvaluationLockError(f"{label} must be lowercase SHA-256")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EvaluationLockError(f"{label} must be a positive integer")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value.strip() != value:
        raise EvaluationLockError(f"{label} must be a non-empty exact string")
    return value


def _privacy_reason(text: str) -> str | None:
    if any(pattern.search(text) for pattern in _CREDENTIAL_PATTERNS):
        return "credential-shaped text"
    if any(pattern.search(text) for pattern in _PRIVATE_PATH_PATTERNS):
        return "absolute private path"
    if any(pattern.search(text) for pattern in _PERSONAL_WORK_PATTERNS):
        return "regulated data indicator"
    return None


def _validate_private_text(text: str) -> None:
    reason = _privacy_reason(text)
    if reason is not None:
        raise EvaluationLockError(f"privacy validation failed: {reason}")


def _privacy_scan_object(value: object) -> None:
    if isinstance(value, str):
        _validate_private_text(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                _validate_private_text(key)
            _privacy_scan_object(item)
    elif isinstance(value, list):
        for item in value:
            _privacy_scan_object(item)


def validate_fixture_privacy(content: bytes) -> None:
    if not isinstance(content, bytes):
        raise EvaluationLockError("fixture material must be bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluationLockError("privacy validation failed: fixture is not UTF-8") from exc
    if "placeholder_not_locked" in text:
        raise EvaluationLockError("fixture status placeholder_not_locked is forbidden")
    _validate_private_text(text)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_scorer(value: object, label: str = "scorer") -> Mapping[str, object]:
    scorer = _closed_mapping(value, {"id", "version", "sha256", "runtime"}, label)
    _safe_id(scorer["id"], f"{label}.id")
    _version(scorer["version"], f"{label}.version")
    _sha256(scorer["sha256"], f"{label}.sha256")
    runtime = _closed_mapping(
        scorer["runtime"], {"id", "version", "sha256"}, f"{label}.runtime"
    )
    _safe_id(runtime["id"], f"{label}.runtime.id")
    _nonempty(runtime["version"], f"{label}.runtime.version")
    _sha256(runtime["sha256"], f"{label}.runtime.sha256")
    return scorer


def _validate_aggregation(value: object) -> Mapping[str, object]:
    aggregation = _closed_mapping(value, {"method", "missing"}, "aggregation")
    if aggregation["method"] not in AGGREGATION_METHODS or aggregation["missing"] != "fail":
        raise EvaluationLockError("aggregation is not a known fail-closed rule")
    return aggregation


def _validate_metrics(value: object) -> dict[str, tuple[str, ...]]:
    metrics = _closed_mapping(value, set(EVALUATION_FAMILIES), "metrics")
    result: dict[str, tuple[str, ...]] = {}
    for family in EVALUATION_FAMILIES:
        family_metrics = metrics[family]
        if (
            not isinstance(family_metrics, list)
            or not family_metrics
            or any(metric not in KNOWN_METRICS[family] for metric in family_metrics)
            or len(family_metrics) != len(set(family_metrics))
        ):
            raise EvaluationLockError(f"metrics for {family} are unknown or duplicated")
        result[family] = tuple(family_metrics)
    return result


def _validate_fixture(
    value: object,
    *,
    scorer_id: str,
    declared_metrics: Mapping[str, tuple[str, ...]],
    fixture_bytes: Mapping[str, bytes],
) -> FixtureLock:
    fixture = _closed_mapping(
        value,
        {
            "family",
            "fixture_id",
            "version",
            "sha256",
            "source",
            "seed",
            "scorer_id",
            "metrics",
        },
        "fixture",
    )
    family = fixture["family"]
    if family not in EVALUATION_FAMILIES:
        raise EvaluationLockError("fixture families must match the closed registry")
    fixture_id = _safe_id(fixture["fixture_id"], "fixture.fixture_id")
    version = _version(fixture["version"], "fixture.version")
    digest = _sha256(fixture["sha256"], "fixture.sha256")
    source = _closed_mapping(
        fixture["source"], {"classification", "reference", "license"}, "fixture.source"
    )
    classification = source["classification"]
    if classification not in APPROVED_SOURCE_CLASSIFICATIONS:
        raise EvaluationLockError("fixture source classification is not approved")
    reference = _nonempty(source["reference"], "fixture source reference")
    license_name = _nonempty(source["license"], "fixture source license")
    seed = _positive_int(fixture["seed"], "fixture seed")
    if fixture["scorer_id"] != scorer_id:
        raise EvaluationLockError("fixture scorer identity drift")
    raw_metrics = fixture["metrics"]
    if not isinstance(raw_metrics, list) or tuple(raw_metrics) != declared_metrics[family]:
        raise EvaluationLockError("fixture metrics drift from suite metrics")
    content = fixture_bytes.get(fixture_id)
    if content is None:
        raise EvaluationLockError("fixture material is missing")
    # This gate intentionally precedes fixture hashing.
    validate_fixture_privacy(content)
    if _sha256_bytes(content) != digest:
        raise EvaluationLockError("fixture hash mismatch")
    return FixtureLock(
        family=family,
        fixture_id=fixture_id,
        version=version,
        sha256=digest,
        source_classification=str(classification),
        source_reference=reference,
        license=license_name,
        seed=seed,
        scorer_id=scorer_id,
        metrics=declared_metrics[family],
    )


def validate_pending_evaluation_lock(
    raw: object, *, fixture_bytes: Mapping[str, bytes]
) -> PendingEvaluationLock:
    top = _closed_mapping(
        raw,
        {
            "schema_version",
            "suite_id",
            "suite_version",
            "fixtures",
            "scorer",
            "metrics",
            "aggregation",
            "confidence",
            "context",
            "resources",
            "stop_policy",
            "threshold_authority",
            "promotion_authorized",
            "candidate_execution",
        },
        "evaluation lock",
    )
    # Lock metadata is scanned before fixture bytes or the canonical lock are hashed.
    _privacy_scan_object(raw)
    if top["schema_version"] != 1:
        raise EvaluationLockError("evaluation lock schema_version must be 1")
    suite_id = _safe_id(top["suite_id"], "suite_id")
    suite_version = _version(top["suite_version"], "suite_version")
    scorer = _validate_scorer(top["scorer"])
    scorer_id = str(scorer["id"])
    metrics = _validate_metrics(top["metrics"])
    aggregation = _validate_aggregation(top["aggregation"])

    confidence = _closed_mapping(
        top["confidence"], {"method", "level", "resamples", "seed"}, "confidence"
    )
    if confidence["method"] != "bootstrap_percentile" or confidence["level"] != "0.95":
        raise EvaluationLockError("confidence method is unsupported")
    _positive_int(confidence["resamples"], "confidence resamples")
    _positive_int(confidence["seed"], "confidence seed")

    context_raw = _closed_mapping(
        top["context"],
        {
            "configured_tokens",
            "runtime_initialized",
            "usefulness_proven",
            "retrieval_evidence_sha256",
        },
        "context",
    )
    evidence = context_raw["retrieval_evidence_sha256"]
    if evidence is not None:
        _sha256(evidence, "context retrieval evidence")
    try:
        context = validate_context_state(
            configured_tokens=context_raw["configured_tokens"],
            runtime_initialized=context_raw["runtime_initialized"],
            usefulness_proven=context_raw["usefulness_proven"],
            retrieval_evidence_sha256=evidence,
        )
    except ValueError as exc:
        raise EvaluationLockError(str(exc)) from exc

    resources = _closed_mapping(
        top["resources"],
        {
            "weights_required",
            "allow_cloud_upload",
            "remote_submission_enabled",
            "scheduling_enabled",
            "destructive_cleanup_enabled",
            "requested_cloud_cost_usd",
            "actual_cloud_cost_usd",
            "max_wall_clock_seconds",
            "max_ram_bytes",
            "max_vram_bytes",
        },
        "resources",
    )
    for flag in (
        "weights_required",
        "allow_cloud_upload",
        "remote_submission_enabled",
        "scheduling_enabled",
        "destructive_cleanup_enabled",
    ):
        if resources[flag] is not False:
            raise EvaluationLockError(
                "resource protocol cannot enable external or destructive work"
            )
    if resources["requested_cloud_cost_usd"] != "0" or resources["actual_cloud_cost_usd"] != "0":
        raise EvaluationLockError("resource protocol cloud cost must remain zero")
    for limit in ("max_wall_clock_seconds", "max_ram_bytes", "max_vram_bytes"):
        _positive_int(resources[limit], f"resources.{limit}")

    stop_policy = _closed_mapping(
        top["stop_policy"],
        {
            "fixture_hash_mismatch",
            "privacy_violation",
            "scorer_drift",
            "resource_limit",
            "unknown_state",
        },
        "stop_policy",
    )
    if any(value != "stop" for value in stop_policy.values()):
        raise EvaluationLockError("every stop policy condition must stop")
    authority = _closed_mapping(top["threshold_authority"], {"status"}, "threshold authority")
    if authority["status"] != "absent":
        raise EvaluationLockError("pending lock threshold authority marker must be absent")
    if top["promotion_authorized"] is not False or top["candidate_execution"] != "blocked":
        raise EvaluationLockError("pending lock must block promotion and candidate execution")

    fixtures_raw = top["fixtures"]
    if not isinstance(fixtures_raw, list) or len(fixtures_raw) != len(EVALUATION_FAMILIES):
        raise EvaluationLockError("fixtures must contain exactly six families")
    if all(isinstance(fixture, Mapping) for fixture in fixtures_raw):
        families = tuple(fixture.get("family") for fixture in fixtures_raw)
        if families != EVALUATION_FAMILIES:
            raise EvaluationLockError("fixture families must match the closed registry order")
        for key in ("fixture_id", "version", "sha256", "seed"):
            values = [fixture.get(key) for fixture in fixtures_raw]
            if len(values) == len(set(values)):
                continue
            raise EvaluationLockError(f"fixture {key} values must be unique")
    fixtures = tuple(
        _validate_fixture(
            fixture,
            scorer_id=scorer_id,
            declared_metrics=metrics,
            fixture_bytes=fixture_bytes,
        )
        for fixture in fixtures_raw
    )
    if set(fixture_bytes) != {fixture.fixture_id for fixture in fixtures}:
        raise EvaluationLockError("fixture material set must exactly match the lock")

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return PendingEvaluationLock(
        schema_version=1,
        suite_id=suite_id,
        suite_version=suite_version,
        fixtures=fixtures,
        scorer=scorer,
        metrics=metrics,
        aggregation=aggregation,
        context=context,
        canonical_json=canonical,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def apply_threshold_authority(
    pending: PendingEvaluationLock, extension: object
) -> FullEvaluationLock:
    raw = _closed_mapping(
        extension,
        {
            "schema_version",
            "base_lock_sha256",
            "authority_id",
            "authority_version",
            "authority_sha256",
            "approved_by_human",
            "scorer",
            "aggregation",
            "thresholds",
        },
        "threshold authority extension",
    )
    if raw["schema_version"] != 1:
        raise EvaluationLockError("threshold authority schema_version must be 1")
    _privacy_scan_object(extension)
    if raw["base_lock_sha256"] != pending.sha256:
        raise EvaluationLockError("threshold authority base lock mismatch")
    _safe_id(raw["authority_id"], "authority_id")
    _version(raw["authority_version"], "authority_version")
    authority_sha256 = _sha256(raw["authority_sha256"], "authority_sha256")
    if raw["approved_by_human"] is not True:
        raise EvaluationLockError("threshold authority requires explicit human approval")
    scorer = _validate_scorer(raw["scorer"], "authority scorer")
    if scorer != pending.scorer:
        raise EvaluationLockError("authority scorer is incompatible with the pending lock")
    aggregation = _validate_aggregation(raw["aggregation"])
    if aggregation != pending.aggregation:
        raise EvaluationLockError("authority aggregation is incompatible with the pending lock")
    thresholds = raw["thresholds"]
    if not isinstance(thresholds, list) or not thresholds:
        raise EvaluationLockError("authority thresholds must be a non-empty list")
    seen: set[tuple[str, str]] = set()
    for value in thresholds:
        threshold = _closed_mapping(
            value, {"family", "metric", "operator", "value"}, "threshold"
        )
        family = threshold["family"]
        if family not in EVALUATION_FAMILIES:
            raise EvaluationLockError("threshold family is unknown")
        metric = threshold["metric"]
        if metric not in pending.metrics[family]:
            raise EvaluationLockError("threshold metric is unknown for its family")
        if threshold["operator"] not in THRESHOLD_OPERATORS:
            raise EvaluationLockError("threshold operator is unsupported")
        number = threshold["value"]
        if (
            not isinstance(number, int | float)
            or isinstance(number, bool)
            or not math.isfinite(number)
        ):
            raise EvaluationLockError("threshold value must be a finite number")
        key = (str(family), str(metric))
        if key in seen:
            raise EvaluationLockError("threshold family and metric pairs must be unique")
        seen.add(key)
    if {family for family, _ in seen} != set(EVALUATION_FAMILIES):
        raise EvaluationLockError("threshold authority must cover every evaluation family")

    authority_payload = {
        key: raw[key]
        for key in (
            "schema_version",
            "authority_id",
            "authority_version",
            "scorer",
            "aggregation",
            "thresholds",
        )
    }
    computed_authority_sha256 = hashlib.sha256(
        json.dumps(
            authority_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()
    if authority_sha256 != computed_authority_sha256:
        raise EvaluationLockError("threshold authority content hash mismatch")

    identity = {
        "schema_version": 1,
        "base_lock_sha256": pending.sha256,
        "authority": extension,
        "status": "locked",
        "promotion_authorized": True,
        "candidate_execution": "allowed",
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return FullEvaluationLock(
        base_lock_sha256=pending.sha256,
        authority_sha256=authority_sha256,
        canonical_json=canonical,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )
