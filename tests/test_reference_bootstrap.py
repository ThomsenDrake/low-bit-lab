from __future__ import annotations

import json

import pytest

from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
)
from lowbit_lab.reference_bootstrap import (
    EMPIRICAL_FACTS,
    ReferenceBootstrapError,
    build_image_lock_from_pylock,
    canonical_bytes,
    canonical_sha256,
    validate_bootstrap_receipt,
    validate_bootstrap_request,
    validate_bootstrap_request_bytes,
    validate_image_lock,
    validate_request_image_lock,
    validate_stage_receipt,
)
from lowbit_lab.reference_contract import REFERENCE_RESOURCES

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
REV_A = "1" * 40
REV_B = "2" * 40


def _image_lock() -> dict[str, object]:
    recipe = {
        "base_image_digest": f"sha256:{SHA_A}",
        "build_steps": [
            "from_registry_by_digest",
            "install_hashed_public_python_artifacts",
        ],
        "dependency_artifacts_sha256": "",
        "dependency_filenames": ["runtime-1.0-py3-none-any.whl"],
        "network_install_enabled": True,
        "python_patch_version": "3.12.11",
    }
    artifacts = [
        {
            "filename": "runtime-1.0-py3-none-any.whl",
            "name": "runtime",
            "sha256": SHA_C,
            "size_bytes": 1024,
            "url": (
                "https://files.pythonhosted.org/packages/aa/bb/"
                "runtime-1.0-py3-none-any.whl"
            ),
            "version": "1.0",
        }
    ]
    recipe["dependency_artifacts_sha256"] = canonical_sha256(artifacts)
    return {
        "base_image": {"digest": f"sha256:{SHA_A}", "reference": "example/runtime"},
        "builder": {
            "distribution": "modal",
            "python_sources_sha256": SHA_B,
            "version": "1.5.3",
        },
        "dependency_artifacts": artifacts,
        "kind": "reference_modal_image_lock",
        "python_patch_version": "3.12.11",
        "recipe": recipe,
        "recipe_sha256": canonical_sha256(recipe),
        "schema_version": 1,
    }


def _request() -> dict[str, object]:
    image = validate_image_lock(_image_lock())
    artifacts = [
        {
            "format": "safetensors",
            "ordinal": 0,
            "sha256": SHA_A,
            "size_bytes": 2048,
            "url": "https://artifacts.example/weights.safetensors",
        },
        {
            "format": "json",
            "ordinal": 1,
            "sha256": SHA_B,
            "size_bytes": 256,
            "url": "https://artifacts.example/config.json",
        },
    ]
    resources = dict(REFERENCE_RESOURCES)
    resources["max_concurrent_containers"] = 1
    return {
        "action": "u8_reference_once",
        "approved_https_hosts": ["artifacts.example"],
        "authority": {
            "bootstrap_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "merge_commit": REFERENCE_BOOTSTRAP_MERGE_COMMIT,
            "parent_sha256": REFERENCE_AUTHORITY_SHA256,
        },
        "budget": {
            "cumulative_cap_usd": "4.00270969",
            "incremental_reserved_usd": "4.00",
            "no_overlapping_reservations": True,
            "provider_hard_dollar_cap": False,
            "settled_before_usd": "0.00270969",
        },
        "configured_context_tokens": 262144,
        "context_ladder_tokens": [8192, 32768, 131072, 262144],
        "deadline_policy": {
            "absolute_deadline_starts_at": "submission_pending",
            "future_stage_reserves_seconds": {
                "evaluation": 840,
                "finalization": 60,
                "load": 420,
                "verification": 180,
            },
            "minimum_transfer_projection_bytes": 67108864,
            "projection_rounding": "against_admission",
            "timeout_seconds": 2700,
            "unused_time_flows_forward": True,
        },
        "image_lock": {"recipe_sha256": image.recipe_sha256, "sha256": image.sha256},
        "kind": "reference_bootstrap_request",
        "known_memory_lower_bound_bytes": 75_000_000_000,
        "lineage": {
            "control_plane_sha256": SHA_A,
            "evaluation_lock_sha256": SHA_B,
            "inventory_sha256": SHA_C,
            "reviewed_commit": REV_A,
            "runtime_lock_sha256": SHA_A,
            "runtime_receipt_sha256": SHA_B,
            "source_hashes_sha256": SHA_C,
            "source_revision": REV_B,
        },
        "provider_capability": {
            "image_recipe_sha256": image.recipe_sha256,
            "proven": True,
            "receipt_sha256": SHA_C,
            "remote_contact_performed": False,
            "sdk_version": "1.5.3",
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
            "max_stages": 6,
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


def test_valid_contract_is_bootstrap_ready_but_empirical_facts_remain_pending() -> None:
    request = _request()
    validated = validate_bootstrap_request_bytes(canonical_bytes(request))
    assert validated.sha256 == canonical_sha256(request)
    assert request["readiness"] == {
        "deterministic": "bootstrap_ready",
        "empirical": {fact: "pending" for fact in EMPIRICAL_FACTS},
    }


@pytest.mark.parametrize("change", ["missing", "unknown"])
def test_request_schema_is_closed(change: str) -> None:
    request = _request()
    if change == "missing":
        del request["budget"]
    else:
        request["extra"] = True
    with pytest.raises(ReferenceBootstrapError, match="missing keys|unknown keys"):
        validate_bootstrap_request(request)


def test_request_rejects_duplicate_and_noncanonical_json() -> None:
    request = _request()
    content = canonical_bytes(request)
    duplicate = content[:-1] + b',"schema_version":1}'
    with pytest.raises(ReferenceBootstrapError, match="duplicate keys"):
        validate_bootstrap_request_bytes(duplicate)
    with pytest.raises(ReferenceBootstrapError, match="not canonical"):
        validate_bootstrap_request_bytes(json.dumps(request, indent=2).encode())


def test_fixed_resource_and_context_envelopes_cannot_drift() -> None:
    resource_drift = _request()
    resource_drift["resources"]["timeout_seconds"] = 2699  # type: ignore[index]
    with pytest.raises(ReferenceBootstrapError, match="resources drift"):
        validate_bootstrap_request(resource_drift)

    context_drift = _request()
    context_drift["context_ladder_tokens"] = [8192, 131072]
    with pytest.raises(ReferenceBootstrapError, match="end at 262144"):
        validate_bootstrap_request(context_drift)


def test_image_lock_rejects_recipe_dependency_and_builder_drift() -> None:
    recipe_drift = _image_lock()
    recipe_drift["recipe"]["python_patch_version"] = "3.12.10"  # type: ignore[index]
    with pytest.raises(ReferenceBootstrapError, match="does not reproduce"):
        validate_image_lock(recipe_drift)

    dependency_drift = _image_lock()
    dependency_drift["dependency_artifacts"].append(  # type: ignore[union-attr]
        {
            "filename": "unbound-1.0-py3-none-any.whl",
            "name": "unbound",
            "sha256": SHA_A,
            "size_bytes": 512,
            "url": (
                "https://files.pythonhosted.org/packages/aa/bb/"
                "unbound-1.0-py3-none-any.whl"
            ),
            "version": "1.0",
        }
    )
    with pytest.raises(ReferenceBootstrapError, match="does not reproduce"):
        validate_image_lock(dependency_drift)

    builder_drift = _image_lock()
    builder_drift["builder"]["distribution"] = "other"  # type: ignore[index]
    with pytest.raises(ReferenceBootstrapError, match="must be modal"):
        validate_image_lock(builder_drift)


def test_image_lock_builds_from_one_resolved_hashed_wheel_per_package() -> None:
    pylock = {
        "packages": [
            {
                "name": "runtime",
                "version": "1.0",
                "wheels": [
                    {
                        "url": (
                            "https://files.pythonhosted.org/packages/aa/bb/"
                            "runtime-1.0-py3-none-any.whl"
                        ),
                        "hashes": {"sha256": SHA_C},
                    }
                ],
            }
        ]
    }
    lock = build_image_lock_from_pylock(
        pylock,
        base_image_reference="example/runtime",
        base_image_digest=f"sha256:{SHA_A}",
        python_patch_version="3.12.11",
        builder_version="1.5.3",
        builder_sources_sha256=SHA_B,
        missing_sizes={"runtime": 1024},
    )
    assert validate_image_lock(lock).recipe_sha256 == lock["recipe_sha256"]
    assert lock["dependency_artifacts"][0]["size_bytes"] == 1024  # type: ignore[index]


def test_request_binds_exact_image_lock_and_known_memory_lower_bound() -> None:
    request = validate_bootstrap_request(_request())
    image = validate_image_lock(_image_lock())
    validate_request_image_lock(request, image)

    drifted = _image_lock()
    drifted["builder"]["python_sources_sha256"] = SHA_A  # type: ignore[index]
    with pytest.raises(ReferenceBootstrapError, match="image lock binding drift"):
        validate_request_image_lock(request, validate_image_lock(drifted))

    impossible = _request()
    impossible["known_memory_lower_bound_bytes"] = 85_899_345_921
    with pytest.raises(ReferenceBootstrapError, match="exceeds physical GPU capacity"):
        validate_bootstrap_request(impossible)


def _runtime_stage(request_sha256: str) -> dict[str, object]:
    return {
        "elapsed_ms": 100,
        "failure_code": None,
        "kind": "reference_bootstrap_stage_receipt",
        "measurements": {
            "device_free_bytes": 80_000_000_000,
            "device_total_bytes": 85_000_000_000,
            "image_identity_sha256": SHA_A,
            "runtime_identity_sha256": SHA_B,
        },
        "ordinal": 0,
        "remaining_ms": 2_699_900,
        "request_sha256": request_sha256,
        "schema_version": 1,
        "stage": "runtime_identity",
        "status": "completed",
    }


def test_stage_receipt_binds_request_order_and_closed_measurements() -> None:
    request = validate_bootstrap_request(_request())
    stage = validate_stage_receipt(_runtime_stage(request.sha256), request=request)
    assert stage.stage == "runtime_identity"

    drift = _runtime_stage(request.sha256)
    drift["measurements"]["raw_log"] = "forbidden"  # type: ignore[index]
    with pytest.raises(ReferenceBootstrapError, match="unknown keys"):
        validate_stage_receipt(drift, request=request)


def test_receipt_keeps_configured_context_distinct_from_proven_usefulness() -> None:
    request = validate_bootstrap_request(_request())
    stage = _runtime_stage(request.sha256)
    stage["failure_code"] = "insufficient_memory"
    stage["status"] = "failed"
    receipt = {
        "configured_context_tokens": 262144,
        "empirical_facts": {fact: False for fact in EMPIRICAL_FACTS},
        "full_context_usefulness_proven": False,
        "kind": "reference_bootstrap_receipt",
        "max_completed_context_tokens": 0,
        "request_sha256": request.sha256,
        "schema_version": 1,
        "stages": [stage],
        "status": "failed",
        "terminal_failure": {"code": "insufficient_memory", "stage": "runtime_identity"},
    }
    validated = validate_bootstrap_receipt(receipt, request=request)
    assert validated.full_context_usefulness_proven is False
    assert json.loads(validated.canonical_json)["configured_context_tokens"] == 262144
