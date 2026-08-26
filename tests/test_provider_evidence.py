from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from lowbit_lab import provider_evidence
from lowbit_lab.provider_evidence import (
    ProviderEvidenceError,
    build_provider_capability_receipt,
    inspect_modal_sdk,
    validate_provider_capability_receipt,
)

RECIPE_SHA256 = "a" * 64


def _write(path: Path, value: object) -> str:
    content = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _evidence(root: Path) -> dict[str, Path]:
    authority = {
        "schema_version": 2,
        "kind": "provider_billing_authority_contract",
        "provider": "modal",
        "environment_scope_sha256": "b" * 64,
        "attribution_method_sha256": "c" * 64,
        "authoritative_report_identity_sha256": "d" * 64,
        "billing_completeness_delay_seconds": 3600,
    }
    authority_path = root / "reports/local/billing-authority.json"
    authority_sha256 = _write(authority_path, authority)
    receipt = {
        "actual_cost_usd": "0.03",
        "authoritative_report_identity_sha256": "d" * 64,
        "billing_authority_sha256": authority_sha256,
        "covered_through": "2026-08-25T01:00:00Z",
        "kind": "provider_billing_report_receipt",
        "provider_job_id": "fc-test-call",
        "schema_version": 1,
    }
    receipt_path = root / "reports/local/billing-receipt.json"
    _write(receipt_path, receipt)
    report = [
        {
            "object_id": "ap-test-app",
            "description": "provider-capability-test",
            "environment": "isolated-test",
            "interval_start": "2026-08-25T00:00:00",
            "resource": "A100-80GB",
            "cost": "0.02",
        },
        {
            "object_id": "ap-test-app",
            "description": "provider-capability-test",
            "environment": "isolated-test",
            "interval_start": "2026-08-25T00:00:00",
            "resource": "CPU",
            "cost": "0.01",
        },
    ]
    report_path = root / "reports/local/billing-report.json"
    _write(report_path, report)
    return {
        "billing_authority_path": authority_path,
        "billing_receipt_path": receipt_path,
        "billing_report_path": report_path,
    }


@pytest.fixture
def capability(tmp_path: Path) -> tuple[dict[str, object], dict[str, Path], Path, str]:
    evidence = _evidence(tmp_path)
    receipt = build_provider_capability_receipt(image_recipe_sha256=RECIPE_SHA256, **evidence)
    path = tmp_path / "reports/local/capability.json"
    digest = _write(path, receipt)
    return receipt, evidence, path, digest


def test_local_sdk_inspection_binds_public_identity_lifecycle_without_client() -> None:
    sdk = inspect_modal_sdk()
    assert sdk["version"] == "1.5.3"
    surfaces = sdk["identity_surfaces"]
    assert surfaces["image"]["available_at"] == "after_build_inside_initialized_app_before_spawn"
    assert surfaces["app"]["identity_field"] == "app_id"
    assert surfaces["call"]["lifecycle_method"] == "modal.Function.spawn"


def test_receipt_reproduces_from_settled_itemized_evidence(capability) -> None:
    _, evidence, path, digest = capability
    result = validate_provider_capability_receipt(
        path,
        expected_sha256=digest,
        image_recipe_sha256=RECIPE_SHA256,
        **evidence,
    )
    assert result == {
        "proven": True,
        "receipt_sha256": digest,
        "remote_contact_performed": False,
        "image_identity_available_before_spawn": True,
        "sdk_version": "1.5.3",
        "provider_environment": "isolated-test",
        "billing_attribution_granularity": "dedicated_app_environment_hour_resource",
        "billing_completeness_delay_seconds": 3600,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["sdk"].pop("python_sources_sha256"), "schema is closed"),
        (
            lambda value: value["sdk"]["identity_surfaces"]["image"].update(
                {"identity_field": "_object_id"}
            ),
            "private or unstable",
        ),
        (
            lambda value: value["billing"].update({"granularity": "workspace_total"}),
            "aggregate or unsupported",
        ),
        (lambda value: value["billing"].update({"call_identity": ""}), "non-empty"),
        (
            lambda value: value["billing"].update({"covered_through": "2026-08-25T01:00:00"}),
            "timezone-aware",
        ),
        (
            lambda value: value["billing"].update({"completeness_delay_seconds": 0}),
            "positive integer",
        ),
    ],
)
def test_receipt_rejects_missing_unstable_aggregate_or_incomplete_capabilities(
    capability, mutation, message: str
) -> None:
    receipt, evidence, path, _ = capability
    changed = json.loads(json.dumps(receipt))
    mutation(changed)
    digest = _write(path, changed)
    with pytest.raises(ProviderEvidenceError, match=message):
        validate_provider_capability_receipt(
            path,
            expected_sha256=digest,
            image_recipe_sha256=RECIPE_SHA256,
            **evidence,
        )


def test_receipt_rejects_noncanonical_bytes_and_evidence_drift(capability) -> None:
    receipt, evidence, path, _ = capability
    path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ProviderEvidenceError, match="not canonical"):
        validate_provider_capability_receipt(
            path,
            expected_sha256=digest,
            image_recipe_sha256=RECIPE_SHA256,
            **evidence,
        )

    digest = _write(path, receipt)
    report = json.loads(evidence["billing_report_path"].read_text(encoding="utf-8"))
    for row in report:
        row["description"] = "changed-dedicated-app"
    _write(evidence["billing_report_path"], report)
    with pytest.raises(ProviderEvidenceError, match="has drifted"):
        validate_provider_capability_receipt(
            path,
            expected_sha256=digest,
            image_recipe_sha256=RECIPE_SHA256,
            **evidence,
        )


def test_itemized_billing_rejects_multiple_apps_or_cost_mismatch(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    report_path = evidence["billing_report_path"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report[1]["object_id"] = "ap-another-app"
    _write(report_path, report)
    with pytest.raises(ProviderEvidenceError, match="aggregate or ambiguous"):
        build_provider_capability_receipt(image_recipe_sha256=RECIPE_SHA256, **evidence)

    report[1]["object_id"] = "ap-test-app"
    report[1]["cost"] = "0.02"
    _write(report_path, report)
    with pytest.raises(ProviderEvidenceError, match="settled cost"):
        build_provider_capability_receipt(image_recipe_sha256=RECIPE_SHA256, **evidence)


def test_json_cli_generates_and_validates_without_remote_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence = _evidence(tmp_path)
    output = tmp_path / "reports/local/capability.json"
    relative = {name: path.relative_to(tmp_path) for name, path in evidence.items()}
    monkeypatch.setattr(
        "sys.argv",
        [
            "provider-evidence",
            "generate",
            "--root",
            str(tmp_path),
            "--image-recipe-sha256",
            RECIPE_SHA256,
            "--billing-authority",
            str(relative["billing_authority_path"]),
            "--billing-receipt",
            str(relative["billing_receipt_path"]),
            "--billing-report",
            str(relative["billing_report_path"]),
            "--output",
            str(output.relative_to(tmp_path)),
        ],
    )
    assert provider_evidence.main() == 0
    generated = json.loads(capsys.readouterr().out)
    assert generated["remote_contact_performed"] is False

    monkeypatch.setattr(
        "sys.argv",
        [
            "provider-evidence",
            "validate",
            "--root",
            str(tmp_path),
            "--image-recipe-sha256",
            RECIPE_SHA256,
            "--billing-authority",
            str(relative["billing_authority_path"]),
            "--billing-receipt",
            str(relative["billing_receipt_path"]),
            "--billing-report",
            str(relative["billing_report_path"]),
            "--output",
            str(output.relative_to(tmp_path)),
            "--expected-sha256",
            generated["receipt_sha256"],
        ],
    )
    assert provider_evidence.main() == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["proven"] is True
    assert validated["remote_contact_performed"] is False
