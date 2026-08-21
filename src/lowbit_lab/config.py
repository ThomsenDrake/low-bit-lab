from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from lowbit_lab.constants import EVALUATION_FAMILIES

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
IMMUTABLE_REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")


class ConfigError(ValueError):
    pass


def confine_experiment_config(root: Path, path: Path) -> Path:
    root = root.resolve()
    configs_root = (root / "configs").resolve()
    if not configs_root.is_relative_to(root):
        raise ConfigError("configs directory resolves outside repository")
    candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not candidate.is_relative_to(configs_root):
        raise ConfigError("experiment config must resolve under repository configs/")
    return candidate


def _closed_mapping(value: Any, allowed: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError(f"{label} has unknown keys: {sorted(unknown)}")
    return value


@dataclass(frozen=True)
class SourceRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class ModalPolicy:
    requested_cost_usd: str
    gpu_type: str
    gpu_count: int
    wall_clock_seconds: int
    checkpoint_path: str
    cleanup: str
    submit: bool


@dataclass(frozen=True)
class ExperimentConfig:
    schema_version: int
    experiment_id: str
    phase: int
    mode: str
    target_status: str
    target_identifier: str | None
    target_revision: str | None
    target_license: str | None
    tokenizer_path: str | None
    tokenizer_sha256: str | None
    weights_required: bool
    configured_context_tokens: int
    useful_context_proven: bool
    sources: tuple[SourceRef, ...]
    runtime_name: str
    runtime_revision: str
    modal: ModalPolicy
    evaluations: tuple[str, ...]
    allow_cloud_upload: bool
    canonical_json: str
    sha256: str


def _canonical(raw: dict[str, Any]) -> tuple[str, str]:
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return canonical, hashlib.sha256(canonical.encode()).hexdigest()


def _safe_repo_relative(path_text: str, label: str) -> str:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ConfigError(f"{label} must be a non-empty repository-relative path")
    return path.as_posix()


def load_experiment_config(path: Path) -> ExperimentConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config: {exc}") from exc
    required = {
        "schema_version",
        "experiment_id",
        "phase",
        "mode",
        "target",
        "weights_required",
        "context",
        "sources",
        "runtime",
        "modal",
        "evaluations",
        "privacy",
    }
    top = _closed_mapping(raw, required, "config")
    missing = required - set(top)
    if missing:
        raise ConfigError(f"config is missing keys: {sorted(missing)}")
    if top["schema_version"] != 1:
        raise ConfigError("schema_version must be 1")
    if not isinstance(top["experiment_id"], str) or not ID_RE.fullmatch(top["experiment_id"]):
        raise ConfigError("experiment_id is not a safe immutable identifier")
    if not isinstance(top["phase"], int) or isinstance(top["phase"], bool) or top["phase"] < 0:
        raise ConfigError("phase must be a non-negative integer")
    if top["mode"] not in {"local_dry_run", "modal_dry_run"}:
        raise ConfigError("Phase 0 mode must be local_dry_run or modal_dry_run")
    if top["weights_required"] is not False:
        raise ConfigError("Phase 0 configs must set weights_required: false")

    target = _closed_mapping(
        top["target"],
        {"status", "identifier", "revision", "license", "tokenizer_path", "tokenizer_sha256"},
        "target",
    )
    target_status = target.get("status")
    if target_status not in {"unconfigured", "configured"}:
        raise ConfigError("target.status must be unconfigured or configured")
    target_identifier = target.get("identifier")
    target_revision = target.get("revision")
    target_license = target.get("license")
    tokenizer_path_value = target.get("tokenizer_path")
    tokenizer_sha256 = target.get("tokenizer_sha256")
    target_details = (
        target_identifier,
        target_revision,
        target_license,
        tokenizer_path_value,
        tokenizer_sha256,
    )
    if target_status == "unconfigured":
        if any(value is not None for value in target_details):
            raise ConfigError("an unconfigured target cannot contain target details")
        tokenizer_path = None
    else:
        if not isinstance(target_identifier, str) or not target_identifier.strip():
            raise ConfigError("configured target.identifier is required")
        if not isinstance(target_revision, str) or not IMMUTABLE_REVISION_RE.fullmatch(
            target_revision
        ):
            raise ConfigError("configured target.revision must be an immutable lowercase hash")
        if not isinstance(target_license, str) or not target_license.strip():
            raise ConfigError("configured target.license is required")
        if tokenizer_path_value is None:
            if tokenizer_sha256 is not None:
                raise ConfigError("target.tokenizer_sha256 requires target.tokenizer_path")
            tokenizer_path = None
        else:
            if not isinstance(tokenizer_path_value, str):
                raise ConfigError("target.tokenizer_path must be a string or null")
            tokenizer_path = _safe_repo_relative(tokenizer_path_value, "target.tokenizer_path")
            if not isinstance(tokenizer_sha256, str) or not SHA256_RE.fullmatch(tokenizer_sha256):
                raise ConfigError("target.tokenizer_sha256 must be lowercase SHA-256")

    context = _closed_mapping(top["context"], {"configured_tokens", "useful_proven"}, "context")
    configured_tokens = context.get("configured_tokens")
    if (
        not isinstance(configured_tokens, int)
        or isinstance(configured_tokens, bool)
        or not 1 <= configured_tokens <= 1_048_576
    ):
        raise ConfigError("configured_tokens must be between 1 and 1048576")
    if context.get("useful_proven") is not False:
        raise ConfigError("Phase 0 cannot claim useful context is proven")

    source_values = top["sources"]
    if not isinstance(source_values, list) or not source_values:
        raise ConfigError("sources must be a non-empty list")
    sources: list[SourceRef] = []
    for index, value in enumerate(source_values):
        source = _closed_mapping(value, {"path", "sha256"}, f"sources[{index}]")
        source_path = _safe_repo_relative(source.get("path"), f"sources[{index}].path")
        digest = source.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ConfigError(f"sources[{index}].sha256 must be lowercase SHA-256")
        sources.append(SourceRef(source_path, digest))

    runtime = _closed_mapping(top["runtime"], {"name", "revision"}, "runtime")
    if not all(isinstance(runtime.get(key), str) and runtime[key] for key in ("name", "revision")):
        raise ConfigError("runtime name and revision are required")

    modal = _closed_mapping(
        top["modal"],
        {
            "requested_cost_usd",
            "gpu_type",
            "gpu_count",
            "wall_clock_seconds",
            "checkpoint_path",
            "cleanup",
            "submit",
        },
        "modal",
    )
    if not isinstance(modal.get("requested_cost_usd"), str):
        raise ConfigError("modal.requested_cost_usd must be a decimal string")
    if not isinstance(modal.get("gpu_type"), str) or not modal["gpu_type"].strip():
        raise ConfigError("modal.gpu_type must be a non-empty string")
    gpu_count = modal.get("gpu_count")
    if not isinstance(gpu_count, int) or isinstance(gpu_count, bool) or not 0 <= gpu_count <= 8:
        raise ConfigError("modal.gpu_count must be between 0 and 8")
    wall_clock = modal.get("wall_clock_seconds")
    if (
        not isinstance(wall_clock, int)
        or isinstance(wall_clock, bool)
        or not 1 <= wall_clock <= 86_400
    ):
        raise ConfigError("modal.wall_clock_seconds must be between 1 and 86400")
    checkpoint_path = _safe_repo_relative(modal.get("checkpoint_path"), "modal.checkpoint_path")
    if not checkpoint_path.startswith("artifacts/checkpoints/"):
        raise ConfigError("checkpoint_path must be under artifacts/checkpoints/")
    if modal.get("cleanup") not in {"retain", "delete_ephemeral_only"}:
        raise ConfigError("modal.cleanup must be retain or delete_ephemeral_only")
    if modal.get("submit") is not False:
        raise ConfigError("Modal submission is disabled in Phase 0")

    evaluations = top["evaluations"]
    if (
        not isinstance(evaluations, list)
        or not evaluations
        or not all(isinstance(item, str) and item for item in evaluations)
    ):
        raise ConfigError("evaluations must be a non-empty string list")
    if len(evaluations) != len(set(evaluations)):
        raise ConfigError("evaluations must be unique")
    unknown_evaluations = set(evaluations) - set(EVALUATION_FAMILIES)
    if unknown_evaluations:
        raise ConfigError(f"unknown evaluations: {sorted(unknown_evaluations)}")
    privacy = _closed_mapping(top["privacy"], {"allow_cloud_upload"}, "privacy")
    if privacy.get("allow_cloud_upload") is not False:
        raise ConfigError("cloud upload must remain disabled in Phase 0")

    canonical, digest = _canonical(top)
    return ExperimentConfig(
        schema_version=1,
        experiment_id=top["experiment_id"],
        phase=top["phase"],
        mode=top["mode"],
        target_status=target_status,
        target_identifier=target_identifier,
        target_revision=target_revision,
        target_license=target_license,
        tokenizer_path=tokenizer_path,
        tokenizer_sha256=tokenizer_sha256,
        weights_required=False,
        configured_context_tokens=configured_tokens,
        useful_context_proven=False,
        sources=tuple(sources),
        runtime_name=runtime["name"],
        runtime_revision=runtime["revision"],
        modal=ModalPolicy(
            requested_cost_usd=modal["requested_cost_usd"],
            gpu_type=modal["gpu_type"],
            gpu_count=gpu_count,
            wall_clock_seconds=wall_clock,
            checkpoint_path=checkpoint_path,
            cleanup=modal["cleanup"],
            submit=False,
        ),
        evaluations=tuple(evaluations),
        allow_cloud_upload=False,
        canonical_json=canonical,
        sha256=digest,
    )


def verify_sources(config: ExperimentConfig, root: Path) -> dict[str, str]:
    root = root.resolve()
    verified: dict[str, str] = {}
    for source in config.sources:
        candidate = (root / source.path).resolve()
        if not candidate.is_relative_to(root):
            raise ConfigError(f"source is outside repository: {source.path}")
        try:
            with candidate.open("rb") as handle:
                actual = hashlib.file_digest(handle, "sha256").hexdigest()
        except OSError as exc:
            raise ConfigError(f"cannot read source: {source.path}") from exc
        if actual != source.sha256:
            raise ConfigError(f"source hash mismatch: {source.path}")
        verified[source.path] = actual
    return verified
