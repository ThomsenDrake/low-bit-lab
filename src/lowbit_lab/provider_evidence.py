"""Offline proof of Modal identity and billing evidence surfaces.

This module imports and inspects the pinned SDK, but it never constructs a
client or calls a provider API.  The generated receipt is intentionally local:
it can contain provider identifiers from an already-settled smoke action.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import inspect
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE
from lowbit_lab.jsonio import emit

DEFAULT_OUTPUT = Path("reports/local/reference-provider-capabilities.json")
DEFAULT_BILLING_AUTHORITY = Path("reports/local/provider-billing-authority.json")
DEFAULT_BILLING_RECEIPT = Path("reports/local/provider-smoke-billing.json")
DEFAULT_BILLING_REPORT = Path("reports/local/modal-billing-20260824T2300-20260825T0100.json")
EXPECTED_MODAL_VERSION = "1.5.3"
REPORT_FIELDS = frozenset(
    {"object_id", "description", "environment", "interval_start", "resource", "cost"}
)


class ProviderEvidenceError(ValueError):
    """Raised when an offline provider capability cannot be proven exactly."""


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_value(value: object) -> str:
    return _sha256(_canonical_bytes(value)[:-1])


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProviderEvidenceError("provider evidence contains duplicate keys")
        value[key] = item
    return value


def _load_json(path: Path, label: str) -> tuple[object, bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProviderEvidenceError(f"cannot read {label}") from exc
    return value, content


def _closed(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ProviderEvidenceError(f"{label} schema is closed")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ProviderEvidenceError(f"{label} must be a lowercase SHA-256")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ProviderEvidenceError(f"{label} must be a non-empty exact string")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ProviderEvidenceError(f"{label} must be a positive integer")
    return value


def _aware_timestamp(value: object, label: str) -> str:
    raw = _nonempty(value, label)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderEvidenceError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProviderEvidenceError(f"{label} must be timezone-aware")
    return raw


def _source_digest(value: object, label: str) -> str:
    try:
        source = inspect.getsource(value)
    except (OSError, TypeError) as exc:
        raise ProviderEvidenceError(f"{label} source is unavailable") from exc
    return _sha256(source.encode("utf-8"))


def _public_property(owner: type[object], name: str, label: str) -> property:
    if name.startswith("_"):
        raise ProviderEvidenceError(f"{label} uses a private SDK attribute")
    value = inspect.getattr_static(owner, name, None)
    if not isinstance(value, property) or value.fget is None:
        raise ProviderEvidenceError(f"{label} is not a stable SDK property")
    return value


def _public_callable(owner: type[object], name: str, label: str) -> object:
    if name.startswith("_"):
        raise ProviderEvidenceError(f"{label} uses a private SDK attribute")
    value = inspect.getattr_static(owner, name, None)
    if value is None or not callable(getattr(owner, name, None)):
        raise ProviderEvidenceError(f"{label} is not a stable SDK callable")
    return getattr(owner, name)


def _distribution_fingerprint(distribution: importlib.metadata.Distribution) -> str:
    entries: list[dict[str, str]] = []
    for item in distribution.files or ():
        relative = Path(str(item).replace("\\", "/"))
        if ".." in relative.parts or relative.suffix != ".py" or relative.parts[:1] != ("modal",):
            continue
        try:
            content = distribution.locate_file(item).read_bytes()
        except OSError as exc:
            raise ProviderEvidenceError("installed Modal SDK files are incomplete") from exc
        entries.append({"path": relative.as_posix(), "sha256": _sha256(content)})
    if not entries:
        raise ProviderEvidenceError("installed Modal SDK has no inspectable Python files")
    return _sha256_value(sorted(entries, key=lambda entry: entry["path"]))


def inspect_modal_sdk() -> dict[str, object]:
    """Inspect only local SDK objects; no client, credentials, or provider call is created."""
    try:
        distribution = importlib.metadata.distribution("modal")
        modal = importlib.import_module("modal")
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise ProviderEvidenceError("pinned Modal SDK is unavailable") from exc
    version = distribution.version
    if version != EXPECTED_MODAL_VERSION:
        raise ProviderEvidenceError("installed Modal SDK version does not match the pin")

    image_id = _public_property(modal.Image, "object_id", "image identity")
    app_id = _public_property(modal.App, "app_id", "app identity")
    call_id = _public_property(modal.FunctionCall, "object_id", "call identity")
    image_build = _public_callable(modal.Image, "build", "image build")
    app_run = _public_callable(modal.App, "run", "app run")
    spawn = _public_callable(modal.Function, "spawn", "function spawn")

    return {
        "distribution": "modal",
        "version": version,
        "python_sources_sha256": _distribution_fingerprint(distribution),
        "identity_surfaces": {
            "image": {
                "owner": "modal.Image",
                "identity_field": "object_id",
                "lifecycle_method": "build",
                "available_at": "after_build_inside_initialized_app_before_spawn",
                "identity_source_sha256": _source_digest(image_id.fget, "image identity"),
                "lifecycle_source_sha256": _source_digest(image_build, "image build"),
            },
            "app": {
                "owner": "modal.App",
                "identity_field": "app_id",
                "lifecycle_method": "run",
                "available_at": "inside_initialized_app_before_spawn",
                "identity_source_sha256": _source_digest(app_id.fget, "app identity"),
                "lifecycle_source_sha256": _source_digest(app_run, "app run"),
            },
            "call": {
                "owner": "modal.FunctionCall",
                "identity_field": "object_id",
                "lifecycle_method": "modal.Function.spawn",
                "available_at": "immediately_after_spawn",
                "identity_source_sha256": _source_digest(call_id.fget, "call identity"),
                "lifecycle_source_sha256": _source_digest(spawn, "function spawn"),
            },
        },
    }


def _billing_capability(
    authority_path: Path,
    receipt_path: Path,
    report_path: Path,
) -> dict[str, object]:
    authority_value, authority_bytes = _load_json(authority_path, "billing authority")
    authority = _closed(
        authority_value,
        {
            "schema_version",
            "kind",
            "provider",
            "environment_scope_sha256",
            "attribution_method_sha256",
            "authoritative_report_identity_sha256",
            "billing_completeness_delay_seconds",
        },
        "billing authority",
    )
    if (
        authority["schema_version"] != 2
        or authority["kind"] != "provider_billing_authority_contract"
        or authority["provider"] != "modal"
    ):
        raise ProviderEvidenceError("billing authority is unsupported")
    authority_sha256 = _sha256(authority_bytes)
    environment_scope = _digest(authority["environment_scope_sha256"], "billing environment scope")
    attribution_method = _digest(
        authority["attribution_method_sha256"], "billing attribution method"
    )
    report_identity = _digest(
        authority["authoritative_report_identity_sha256"],
        "authoritative report identity",
    )
    delay = _positive_int(
        authority["billing_completeness_delay_seconds"],
        "billing completeness delay",
    )

    receipt_value, receipt_bytes = _load_json(receipt_path, "settled billing receipt")
    receipt = _closed(
        receipt_value,
        {
            "actual_cost_usd",
            "authoritative_report_identity_sha256",
            "billing_authority_sha256",
            "covered_through",
            "kind",
            "provider_job_id",
            "schema_version",
        },
        "settled billing receipt",
    )
    if receipt["schema_version"] != 1 or receipt["kind"] != "provider_billing_report_receipt":
        raise ProviderEvidenceError("settled billing receipt is unsupported")
    if (
        receipt["billing_authority_sha256"] != authority_sha256
        or receipt["authoritative_report_identity_sha256"] != report_identity
    ):
        raise ProviderEvidenceError("settled billing lineage is mismatched")
    call_identity = _nonempty(receipt["provider_job_id"], "billing call identity")
    if not call_identity.startswith("fc-"):
        raise ProviderEvidenceError("billing call identity has an unsupported shape")
    covered_through = _aware_timestamp(receipt["covered_through"], "billing covered_through")
    try:
        actual_cost = Decimal(_nonempty(receipt["actual_cost_usd"], "actual billing cost"))
    except InvalidOperation as exc:
        raise ProviderEvidenceError("actual billing cost is invalid") from exc
    if not actual_cost.is_finite() or actual_cost < 0:
        raise ProviderEvidenceError("actual billing cost is invalid")

    report_value, report_bytes = _load_json(report_path, "authoritative billing report")
    if (
        not isinstance(report_value, Sequence)
        or isinstance(report_value, str | bytes)
        or not report_value
    ):
        raise ProviderEvidenceError("billing report must contain itemized rows")
    app_ids: set[str] = set()
    environments: set[str] = set()
    descriptions: set[str] = set()
    interval_starts: set[str] = set()
    total = Decimal("0")
    for raw_row in report_value:
        row = _closed(raw_row, set(REPORT_FIELDS), "billing report row")
        app_identity = _nonempty(row["object_id"], "billing app identity")
        if not app_identity.startswith("ap-"):
            raise ProviderEvidenceError("billing app identity has an unsupported shape")
        app_ids.add(app_identity)
        environments.add(_nonempty(row["environment"], "billing environment identity"))
        descriptions.add(_nonempty(row["description"], "billing description"))
        interval_starts.add(_nonempty(row["interval_start"], "billing interval start"))
        _nonempty(row["resource"], "billing resource")
        try:
            cost = Decimal(_nonempty(row["cost"], "billing row cost"))
        except InvalidOperation as exc:
            raise ProviderEvidenceError("billing row cost is invalid") from exc
        if not cost.is_finite() or cost < 0:
            raise ProviderEvidenceError("billing row cost is invalid")
        total += cost
    if not (len(app_ids) == len(environments) == len(descriptions) == len(interval_starts) == 1):
        raise ProviderEvidenceError("billing report attribution is aggregate or ambiguous")
    if total != actual_cost:
        raise ProviderEvidenceError("billing report rows do not equal the settled cost")

    return {
        "provider": "modal",
        "authority_sha256": authority_sha256,
        "environment_scope_sha256": environment_scope,
        "attribution_method_sha256": attribution_method,
        "authoritative_report_identity_sha256": report_identity,
        "completeness_delay_seconds": delay,
        "settled_receipt_sha256": _sha256(receipt_bytes),
        "itemized_report_sha256": _sha256(report_bytes),
        "covered_through": covered_through,
        "granularity": "dedicated_app_environment_hour_resource",
        "report_fields": sorted(REPORT_FIELDS),
        "app_identity_field": "object_id",
        "call_identity_field": "provider_job_id",
        "environment_identity_field": "environment",
        "app_identity": next(iter(app_ids)),
        "call_identity": call_identity,
        "environment_identity": next(iter(environments)),
        "interval_start": next(iter(interval_starts)),
        "actual_cost_usd": format(actual_cost, "f"),
        "attribution_constraints": [
            "one_dedicated_app",
            "one_provider_call",
            "one_environment",
            "one_unambiguous_settlement_window",
            "itemized_resource_cost_sum_matches_receipt",
        ],
    }


def _validate_receipt_shape(value: object, expected_image_recipe_sha256: str) -> Mapping[str, Any]:
    receipt = _closed(
        value,
        {
            "schema_version",
            "kind",
            "provider",
            "inspection_mode",
            "remote_contact_performed",
            "image_recipe_sha256",
            "sdk",
            "billing",
            "proven",
        },
        "provider capability receipt",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["kind"] != "reference_provider_capability_receipt"
        or receipt["provider"] != "modal"
        or receipt["inspection_mode"] != "offline_local_sdk_and_settled_evidence"
        or receipt["remote_contact_performed"] is not False
        or receipt["proven"] is not True
    ):
        raise ProviderEvidenceError("provider capability receipt is unsupported")
    if _digest(receipt["image_recipe_sha256"], "image recipe") != expected_image_recipe_sha256:
        raise ProviderEvidenceError("provider capability image recipe drift")

    sdk = _closed(
        receipt["sdk"],
        {"distribution", "version", "python_sources_sha256", "identity_surfaces"},
        "provider SDK capability",
    )
    if sdk["distribution"] != "modal" or sdk["version"] != EXPECTED_MODAL_VERSION:
        raise ProviderEvidenceError("provider SDK capability is unsupported")
    _digest(sdk["python_sources_sha256"], "provider SDK sources")
    surfaces = _closed(sdk["identity_surfaces"], {"image", "app", "call"}, "identity surfaces")
    expected_surfaces = {
        "image": (
            "modal.Image",
            "object_id",
            "build",
            "after_build_inside_initialized_app_before_spawn",
        ),
        "app": ("modal.App", "app_id", "run", "inside_initialized_app_before_spawn"),
        "call": (
            "modal.FunctionCall",
            "object_id",
            "modal.Function.spawn",
            "immediately_after_spawn",
        ),
    }
    for name, expected in expected_surfaces.items():
        surface = _closed(
            surfaces[name],
            {
                "owner",
                "identity_field",
                "lifecycle_method",
                "available_at",
                "identity_source_sha256",
                "lifecycle_source_sha256",
            },
            f"{name} identity surface",
        )
        if any(not isinstance(item, str) or item.startswith("_") for item in surface.values()):
            raise ProviderEvidenceError(f"{name} identity surface is private or unstable")
        identity = tuple(
            surface[key] for key in ("owner", "identity_field", "lifecycle_method", "available_at")
        )
        if identity != expected:
            raise ProviderEvidenceError(f"{name} identity surface is unsupported")
        _digest(surface["identity_source_sha256"], f"{name} identity source")
        _digest(surface["lifecycle_source_sha256"], f"{name} lifecycle source")

    billing = _closed(
        receipt["billing"],
        {
            "provider",
            "authority_sha256",
            "environment_scope_sha256",
            "attribution_method_sha256",
            "authoritative_report_identity_sha256",
            "completeness_delay_seconds",
            "settled_receipt_sha256",
            "itemized_report_sha256",
            "covered_through",
            "granularity",
            "report_fields",
            "app_identity_field",
            "call_identity_field",
            "environment_identity_field",
            "app_identity",
            "call_identity",
            "environment_identity",
            "interval_start",
            "actual_cost_usd",
            "attribution_constraints",
        },
        "billing capability",
    )
    if (
        billing["provider"] != "modal"
        or billing["granularity"] != "dedicated_app_environment_hour_resource"
        or billing["report_fields"] != sorted(REPORT_FIELDS)
        or billing["app_identity_field"] != "object_id"
        or billing["call_identity_field"] != "provider_job_id"
        or billing["environment_identity_field"] != "environment"
        or billing["attribution_constraints"]
        != [
            "one_dedicated_app",
            "one_provider_call",
            "one_environment",
            "one_unambiguous_settlement_window",
            "itemized_resource_cost_sum_matches_receipt",
        ]
    ):
        raise ProviderEvidenceError("billing attribution capability is aggregate or unsupported")
    for name in (
        "authority_sha256",
        "environment_scope_sha256",
        "attribution_method_sha256",
        "authoritative_report_identity_sha256",
        "settled_receipt_sha256",
        "itemized_report_sha256",
    ):
        _digest(billing[name], name)
    _positive_int(billing["completeness_delay_seconds"], "billing completeness delay")
    _aware_timestamp(billing["covered_through"], "billing covered_through")
    for name in ("app_identity", "call_identity", "environment_identity", "interval_start"):
        _nonempty(billing[name], name)
    if not billing["app_identity"].startswith("ap-") or not billing["call_identity"].startswith(
        "fc-"
    ):
        raise ProviderEvidenceError("billing provider identifiers are absent")
    try:
        parsed_cost = Decimal(_nonempty(billing["actual_cost_usd"], "actual billing cost"))
    except InvalidOperation as exc:
        raise ProviderEvidenceError("actual billing cost is invalid") from exc
    if not parsed_cost.is_finite() or parsed_cost < 0:
        raise ProviderEvidenceError("actual billing cost is invalid")
    return receipt


def build_provider_capability_receipt(
    *,
    image_recipe_sha256: str,
    billing_authority_path: Path,
    billing_receipt_path: Path,
    billing_report_path: Path,
) -> dict[str, object]:
    """Build a reproducible receipt from local SDK and already-settled evidence."""
    image_recipe_sha256 = _digest(image_recipe_sha256, "image recipe")
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "reference_provider_capability_receipt",
        "provider": "modal",
        "inspection_mode": "offline_local_sdk_and_settled_evidence",
        "remote_contact_performed": False,
        "image_recipe_sha256": image_recipe_sha256,
        "sdk": inspect_modal_sdk(),
        "billing": _billing_capability(
            billing_authority_path, billing_receipt_path, billing_report_path
        ),
        "proven": True,
    }
    _validate_receipt_shape(receipt, image_recipe_sha256)
    return receipt


def validate_provider_capability_receipt(
    path: Path,
    *,
    expected_sha256: str,
    image_recipe_sha256: str,
    billing_authority_path: Path,
    billing_receipt_path: Path,
    billing_report_path: Path,
) -> dict[str, object]:
    """Reproduce the receipt and reject byte, SDK, or settled-evidence drift."""
    expected_sha256 = _digest(expected_sha256, "provider capability receipt")
    value, content = _load_json(path, "provider capability receipt")
    if _sha256(content) != expected_sha256:
        raise ProviderEvidenceError("provider capability receipt SHA-256 mismatch")
    if content != _canonical_bytes(value):
        raise ProviderEvidenceError("provider capability receipt is not canonical")
    _validate_receipt_shape(value, image_recipe_sha256)
    reproduced = build_provider_capability_receipt(
        image_recipe_sha256=image_recipe_sha256,
        billing_authority_path=billing_authority_path,
        billing_receipt_path=billing_receipt_path,
        billing_report_path=billing_report_path,
    )
    if value != reproduced:
        raise ProviderEvidenceError("provider capability receipt has drifted")
    return {
        "proven": True,
        "receipt_sha256": expected_sha256,
        "remote_contact_performed": False,
        "image_identity_available_before_spawn": True,
        "sdk_version": value["sdk"]["version"],
        "provider_environment": value["billing"]["environment_identity"],
        "billing_attribution_granularity": value["billing"]["granularity"],
        "billing_completeness_delay_seconds": value["billing"]["completeness_delay_seconds"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect offline Modal evidence capabilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "validate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--root", type=Path, default=Path("."))
        subparser.add_argument("--image-recipe-sha256", required=True)
        subparser.add_argument("--billing-authority", type=Path, default=DEFAULT_BILLING_AUTHORITY)
        subparser.add_argument("--billing-receipt", type=Path, default=DEFAULT_BILLING_RECEIPT)
        subparser.add_argument("--billing-report", type=Path, default=DEFAULT_BILLING_REPORT)
        subparser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    subparsers.choices["validate"].add_argument("--expected-sha256", required=True)
    return parser


def _under_root(root: Path, path: Path, label: str) -> Path:
    root = root.resolve(strict=True)
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ProviderEvidenceError(f"{label} is outside the repository")
    return resolved


def main() -> int:
    args = _parser().parse_args()
    try:
        root = args.root.resolve(strict=True)
        paths = {
            "billing_authority_path": _under_root(
                root, args.billing_authority, "billing authority"
            ),
            "billing_receipt_path": _under_root(root, args.billing_receipt, "billing receipt"),
            "billing_report_path": _under_root(root, args.billing_report, "billing report"),
        }
        output = _under_root(root, args.output, "provider capability output")
        if args.command == "generate":
            receipt = build_provider_capability_receipt(
                image_recipe_sha256=args.image_recipe_sha256, **paths
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            content = _canonical_bytes(receipt)
            output.write_bytes(content)
            result = {
                "ok": True,
                "command": "generate",
                "receipt_sha256": _sha256(content),
                "remote_contact_performed": False,
            }
        else:
            result = {
                "ok": True,
                "command": "validate",
                **validate_provider_capability_receipt(
                    output,
                    expected_sha256=args.expected_sha256,
                    image_recipe_sha256=args.image_recipe_sha256,
                    **paths,
                ),
            }
    except ProviderEvidenceError as exc:
        emit({"ok": False, "error": str(exc)})
        return 2
    emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
