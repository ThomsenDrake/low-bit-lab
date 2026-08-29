from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import lowbit_lab.reference_modal_adapter as modal_adapter
import lowbit_lab.reference_orchestrator as orchestrator
from lowbit_lab.constants import (
    REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
    REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
)
from lowbit_lab.db import ResultsDatabase
from lowbit_lab.reference_contract import additional_reference_binding
from lowbit_lab.reference_modal_adapter import (
    PreparedModalGraph,
    ReferenceModalCapability,
    ReferenceModalError,
    SerializedRemoteCallable,
)
from lowbit_lab.reference_provider_auth import MODAL_AUTH_OVERRIDE_KEYS, auth_receipt_path

_REAL_MERGED_MAIN_GATE = orchestrator._require_merged_clean_main


@pytest.fixture(autouse=True)
def _merged_main_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orchestrator, "_require_merged_clean_main", lambda root: "f" * 40)


@pytest.mark.parametrize(
    "value",
    ["2026-08-27T14:00:00", "2026-08-27T14:00:00Z", "2026-08-27T14:00:00+00:00"],
)
def test_modal_billing_interval_normalizes_exact_utc_forms(value: str) -> None:
    assert orchestrator._parse_modal_billing_interval(value).isoformat() == (
        "2026-08-27T14:00:00+00:00"
    )


@pytest.mark.parametrize(
    "value",
    [
        "2026-08-27",
        "2026-08-27T14:00",
        "2026-08-27 14:00:00",
        "2026-08-27 14:00:00+00:00",
        "2026-08-27T14:00:00+0000",
        "2026-08-27T14:00:00.000000+00:00",
        "2026-08-27T10:00:00-04:00",
        "not-a-time",
    ],
)
def test_modal_billing_interval_rejects_format_or_timezone_drift(value: str) -> None:
    with pytest.raises(orchestrator.ReferenceOrchestratorError):
        orchestrator._parse_modal_billing_interval(value)


def _capability(root: Path) -> ReferenceModalCapability:
    return ReferenceModalCapability(
        db_path=root / orchestrator.DATABASE_PATH,
        root=root,
        config_path=orchestrator.CONFIG_PATH,
        request_path=orchestrator.REQUEST_PATH,
        image_lock_path=orchestrator.IMAGE_LOCK_PATH,
        provider_capability_path=orchestrator.PROVIDER_CAPABILITY_PATH,
        billing_authority_path=orchestrator.DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=orchestrator.DEFAULT_BILLING_RECEIPT,
        billing_report_path=orchestrator.DEFAULT_BILLING_REPORT,
        publication_manifest_path=orchestrator.PUBLICATION_MANIFEST_PATH,
        reservation_id="",
        owner_id="",
        authority_root=root,
        provider_environment="low-bit-lab",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"lock",
        fixture_bytes={},
        execution_identity={},
        image_lock={},
    )


def test_bootstrap_request_consumes_flat_validated_sdk_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image_path = tmp_path / orchestrator.IMAGE_LOCK_PATH
    provider_path = tmp_path / orchestrator.PROVIDER_CAPABILITY_PATH
    evaluation_path = tmp_path / "eval/local/lock.json"
    fixture_root = tmp_path / "eval/local/fixtures"
    for path in (image_path, provider_path, evaluation_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    fixture_root.mkdir(parents=True)
    evaluation_path.write_text('{"fixtures":[]}', encoding="utf-8")
    config = SimpleNamespace(
        authority_files={
            "runtime_lock_path": "runtime.json",
            "evaluation_lock_path": "eval/local/lock.json",
            "evaluation_fixture_root": "eval/local/fixtures",
        },
        gates={"memory_fit_evidence_path": "memory.json"},
        inputs={
            "control_plane_sha256": "1" * 64,
            "weight_inventory_sha256": "2" * 64,
            "reviewed_commit_sha256": "3" * 40,
            "runtime_receipt_sha256": "4" * 64,
            "source_revision": "5" * 40,
            "weight_inventory_tensor_bytes": 1,
            "evaluation_max_context_tokens": 262144,
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_image_lock_bytes",
        lambda _content: SimpleNamespace(recipe_sha256="6" * 64, sha256="7" * 64),
    )
    monkeypatch.setattr(
        orchestrator, "load_runtime_lock", lambda *_a, **_k: SimpleNamespace(sha256="8" * 64)
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_pending_evaluation_lock",
        lambda *_a, **_k: SimpleNamespace(sha256="9" * 64),
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_provider_capability_receipt",
        lambda *_a, **_k: {"sdk_version": "validated-sdk"},
    )
    monkeypatch.setattr(
        orchestrator, "_read_json", lambda *_a, **_k: {"known_required_lower_bound_bytes": 1}
    )
    monkeypatch.setattr(
        orchestrator,
        "_source_artifacts",
        lambda *_a, **_k: [
            {"url": "https://huggingface.co/public/revision/file", "sha256": "a" * 64}
        ],
    )
    monkeypatch.setattr(orchestrator, "validate_bootstrap_request_bytes", lambda _value: None)

    request = json.loads(orchestrator.build_bootstrap_request(tmp_path, config))

    assert request["provider_capability"]["sdk_version"] == "validated-sdk"

    def reject_receipt(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("receipt drift")

    monkeypatch.setattr(orchestrator, "validate_provider_capability_receipt", reject_receipt)
    with pytest.raises(RuntimeError, match="receipt drift"):
        orchestrator.build_bootstrap_request(tmp_path, config)


def test_source_artifacts_use_query_free_origins_and_complete_inventory(tmp_path: Path) -> None:
    identifier = "public-owner/public-model"
    revision = "1" * 40
    provenance = {
        "repository": {"identifier": identifier, "revision": revision},
        "files": [
            {
                "path": name,
                "http": {
                    "requested_url": f"https://huggingface.co/{identifier}/resolve/{revision}/{name}"
                },
                "local_content": {"sha256": f"{index + 1:064x}", "size_bytes": 10 + index},
            }
            for index, name in enumerate(sorted(orchestrator._SOURCE_FILES))
        ],
    }
    identity = json.loads(json.dumps(provenance))
    provenance["manifest_sha256"] = orchestrator._sha(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    inventory = {
        "source": {"identifier": identifier, "revision": revision},
        "shards": [
            {
                "path": "model-00001-of-00001.safetensors",
                "content_sha256": "f" * 64,
                "size_bytes": 123,
            }
        ],
    }
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/provenance.json").write_text(json.dumps(provenance))
    (tmp_path / "artifacts/inventory.json").write_text(json.dumps(inventory))
    config = SimpleNamespace(
        inputs={
            "source_revision": revision,
            "provenance_manifest_sha256": provenance["manifest_sha256"],
        },
        authority_files={
            "provenance_manifest_path": "artifacts/provenance.json",
            "weight_inventory_path": "artifacts/inventory.json",
        },
    )

    artifacts = orchestrator._source_artifacts(tmp_path, config)

    assert len(artifacts) == 1 + len(orchestrator._SOURCE_FILES)
    assert artifacts[0]["format"] == "safetensors"
    assert artifacts[0]["url"].endswith("/model-00001-of-00001.safetensors")
    assert all("?" not in str(item["url"]) for item in artifacts)
    assert [item["ordinal"] for item in artifacts] == list(range(len(artifacts)))


def test_source_artifacts_reject_mutable_origin_host(tmp_path: Path) -> None:
    identifier = "public-owner/public-model"
    revision = "1" * 40
    provenance = {
        "repository": {"identifier": identifier, "revision": revision},
        "files": [
            {
                "path": name,
                "http": {
                    "requested_url": f"https://unapproved.example/{identifier}/resolve/{revision}/{name}"
                },
                "local_content": {"sha256": f"{index + 1:064x}", "size_bytes": 10 + index},
            }
            for index, name in enumerate(sorted(orchestrator._SOURCE_FILES))
        ],
    }
    provenance["manifest_sha256"] = orchestrator._sha(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
    )
    inventory = {
        "source": {"identifier": identifier, "revision": revision},
        "shards": [
            {
                "path": "model-00001-of-00001.safetensors",
                "content_sha256": "f" * 64,
                "size_bytes": 123,
            }
        ],
    }
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/provenance.json").write_text(json.dumps(provenance))
    (tmp_path / "artifacts/inventory.json").write_text(json.dumps(inventory))
    config = SimpleNamespace(
        inputs={
            "source_revision": revision,
            "provenance_manifest_sha256": provenance["manifest_sha256"],
        },
        authority_files={
            "provenance_manifest_path": "artifacts/provenance.json",
            "weight_inventory_path": "artifacts/inventory.json",
        },
    )

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="origin"):
        orchestrator._source_artifacts(tmp_path, config)


def test_refresh_local_config_reproduces_stale_authority_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / orchestrator.CONFIG_PATH
    config_path.parent.mkdir(parents=True)
    receipt_bytes = b'{"receipt":"exact bytes"}\n'
    receipt_sha256 = orchestrator._sha(receipt_bytes)
    evaluation_bytes = b'{\n  "fixtures": [{"fixture_id": "fixture"}]\n}\n'
    evaluation_sha256 = orchestrator._sha(evaluation_bytes)
    config_path.write_text(
        f"""inputs:
  reviewed_commit_sha256: stale
  source_revision: "5555555555555555555555555555555555555555"
  weight_inventory_tensor_bytes: 55
  evaluation_lock_sha256: "{evaluation_sha256}"
  evaluation_max_context_tokens: 262144
  runtime_receipt_sha256: "{receipt_sha256}"
""",
        encoding="utf-8",
    )
    cache = tmp_path / "artifacts/index.json"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"index")
    fixture_root = tmp_path / "eval/fixtures"
    fixture_root.mkdir(parents=True)
    (fixture_root / "fixture.json").write_bytes(b"fixture")
    (tmp_path / "eval/lock.json").write_bytes(evaluation_bytes)
    receipt_path = tmp_path / "artifacts/receipt.json"
    receipt_path.write_bytes(receipt_bytes)
    current = SimpleNamespace(
        inputs={
            "source_revision": "5" * 40,
            "weight_inventory_tensor_bytes": 55,
            "evaluation_lock_sha256": evaluation_sha256,
            "evaluation_max_context_tokens": 262144,
            "runtime_receipt_sha256": receipt_sha256,
        },
        authority_files={
            "provenance_manifest_path": "artifacts/provenance.json",
            "runtime_lock_path": "configs/runtime.json",
            "evaluation_lock_path": "eval/lock.json",
            "evaluation_fixture_root": "eval/fixtures",
            "source_shard_metadata_path": "artifacts/shards.json",
            "weight_inventory_path": "artifacts/inventory.json",
            "runtime_receipt_path": "artifacts/receipt.json",
        },
    )
    provenance = {
        "files": [
            {
                "path": "model.safetensors.index.json",
                "local_content": {"cache_path": "artifacts/index.json"},
            },
            {"path": "tokenizer.json", "local_content": {"sha256": "b" * 64}},
        ]
    }
    provenance["manifest_sha256"] = orchestrator._sha(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
    )
    evidence = {
        "provenance.json": provenance,
        "lock.json": {"fixtures": [{"fixture_id": "fixture"}]},
        "shards.json": {"shard": {"size_bytes": 1, "lfs_sha256": "c" * 64}},
        "inventory.json": {},
        "receipt.json": {},
    }
    monkeypatch.setattr(orchestrator, "load_reference_job_config", lambda path, root: current)
    monkeypatch.setattr(
        orchestrator,
        "runtime_metadata",
        lambda root: {
            "git_dirty": False,
            "git_commit": "1" * 40,
            "control_plane_sha256": "2" * 64,
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "_read_json",
        lambda path, label: evidence[path.name],
    )
    monkeypatch.setattr(
        orchestrator, "load_runtime_lock", lambda path, root: SimpleNamespace(sha256="3" * 64)
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_pending_evaluation_lock",
        lambda raw, fixture_bytes: SimpleNamespace(
            sha256="4" * 64, context=SimpleNamespace(configured_tokens=262144)
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "parse_weight_inventory",
        lambda *args, **kwargs: SimpleNamespace(
            source_revision="5" * 40, sha256="6" * 64, index_tensor_bytes=55
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "verify_current_installed_environment",
        lambda receipt, root, lock: {"verified": True},
    )

    orchestrator.refresh_local_config(tmp_path)

    refreshed = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert refreshed["experiment_id"] == "phase1-u8-111111111111"
    assert refreshed["inputs"] == {
        "reviewed_commit_sha256": "1" * 40,
        "source_revision": "5" * 40,
        "weight_inventory_tensor_bytes": 55,
        "evaluation_lock_sha256": evaluation_sha256,
        "evaluation_max_context_tokens": 262144,
        "runtime_receipt_sha256": receipt_sha256,
        "control_plane_sha256": "2" * 64,
        "weight_inventory_sha256": "6" * 64,
        "provenance_manifest_sha256": provenance["manifest_sha256"],
    }
    assert refreshed["approval_artifact_path"] is None


def test_refresh_local_config_rejects_frozen_evaluation_drift(
    tmp_path: Path,
) -> None:
    del tmp_path
    frozen = {
        "source_revision": "1" * 40,
        "weight_inventory_tensor_bytes": 55,
        "evaluation_lock_sha256": "2" * 64,
        "evaluation_max_context_tokens": 262144,
        "runtime_receipt_sha256": "3" * 64,
    }
    inventory = SimpleNamespace(source_revision="1" * 40, index_tensor_bytes=55)
    changed = SimpleNamespace(sha256="2" * 64, context=SimpleNamespace(configured_tokens=262144))
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="identity drift"):
        orchestrator._validate_frozen_inputs(frozen, inventory, changed, "f" * 64, "3" * 64)


def test_capability_canonicalizes_verified_local_evaluation_lock(tmp_path: Path) -> None:
    evaluation = {"fixtures": [{"fixture_id": "fixture"}]}
    evaluation_path = tmp_path / "eval/local/lock.json"
    fixture_root = tmp_path / "eval/local/fixtures"
    evaluation_path.parent.mkdir(parents=True)
    fixture_root.mkdir(parents=True)
    evaluation_path.write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    (fixture_root / "fixture.json").write_bytes(b"fixture")
    image_path = tmp_path / orchestrator.IMAGE_LOCK_PATH
    provider_path = tmp_path / orchestrator.PROVIDER_CAPABILITY_PATH
    image_path.parent.mkdir(parents=True, exist_ok=True)
    provider_path.parent.mkdir(parents=True, exist_ok=True)
    image_path.write_text("{}", encoding="utf-8")
    provider_path.write_text("{}", encoding="utf-8")
    config = SimpleNamespace(
        authority_files={
            "evaluation_lock_path": "eval/local/lock.json",
            "evaluation_fixture_root": "eval/local/fixtures",
        },
        inputs={
            "weight_inventory_sha256": "1" * 64,
            "provenance_manifest_sha256": "2" * 64,
            "runtime_receipt_sha256": "3" * 64,
            "reviewed_commit_sha256": "4" * 40,
        },
        resources={"gpu_type": "A100-80GB"},
    )

    request = json.dumps(
        {
            "image_lock": {"recipe_sha256": "5" * 64},
            "provider_capability": {"receipt_sha256": "6" * 64},
        }
    ).encode()
    observed: dict[str, object] = {}

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            orchestrator,
            "validate_bootstrap_request_bytes",
            lambda content: SimpleNamespace(canonical_json=content.decode()),
        )

        def validate_provider(
            path: Path,
            *,
            expected_sha256: str,
            image_recipe_sha256: str,
            billing_authority_path: Path,
            billing_receipt_path: Path,
            billing_report_path: Path,
        ) -> dict[str, object]:
            observed.update(
                {
                    "path": path,
                    "expected_sha256": expected_sha256,
                    "image_recipe_sha256": image_recipe_sha256,
                    "billing_authority_path": billing_authority_path,
                    "billing_receipt_path": billing_receipt_path,
                    "billing_report_path": billing_report_path,
                }
            )
            return {"provider_environment": "validated-environment"}

        monkeypatch.setattr(
            orchestrator,
            "validate_provider_capability_receipt",
            validate_provider,
        )
        capability = orchestrator._capability(tmp_path, config, request)

    assert capability.evaluation_lock_bytes == orchestrator.canonical_bytes(evaluation)
    assert capability.evaluation_lock_bytes != evaluation_path.read_bytes()
    assert capability.provider_environment == "validated-environment"
    assert observed["path"] == provider_path
    assert observed["expected_sha256"] == "6" * 64
    assert observed["image_recipe_sha256"] == "5" * 64


def test_prepare_writes_only_ignored_request_and_does_not_touch_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = SimpleNamespace(reference_execution_scope_sha256="a" * 64)
    capability = _capability(tmp_path)
    monkeypatch.setattr(orchestrator, "refresh_local_config", lambda root: config)
    monkeypatch.setattr(orchestrator, "build_bootstrap_request", lambda root, value: b"request")
    monkeypatch.setattr(
        orchestrator,
        "plan_reference_bootstrap_preview",
        lambda *args, **kwargs: {"bootstrap_ready": True, "blockers": []},
    )
    monkeypatch.setattr(orchestrator, "_capability", lambda root, value, request: capability)
    for path in (
        orchestrator.IMAGE_LOCK_PATH,
        orchestrator.PROVIDER_CAPABILITY_PATH,
    ):
        full = tmp_path / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(b"evidence")

    prepared, request, result = orchestrator.prepare(tmp_path)

    assert prepared is config
    assert request == b"request"
    assert result is capability
    assert (tmp_path / orchestrator.REQUEST_PATH).read_bytes() == b"request"
    assert not (tmp_path / orchestrator.DATABASE_PATH).exists()


def test_additional_binding_is_reproducible_and_authority_bound() -> None:
    inputs = {
        "config_sha256": "1" * 64,
        "config_challenge_sha256": "2" * 64,
        "request_sha256": "3" * 64,
        "execution_scope_sha256": "4" * 64,
    }
    first = additional_reference_binding(**inputs)
    second = additional_reference_binding(**inputs)

    assert first == second
    assert first.packet_sha256 != first.challenge_sha256
    assert first.challenge_sha256 != first.capability_sha256
    assert additional_reference_binding(**{**inputs, "request_sha256": "5" * 64}) != first


def test_prepare_additional_is_local_and_binds_available_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = SimpleNamespace(
        sha256="1" * 64,
        challenge_sha256="2" * 64,
        reference_execution_scope_sha256="3" * 64,
    )
    capability = _capability(tmp_path)
    monkeypatch.setattr(orchestrator, "refresh_local_config", lambda root: config)
    monkeypatch.setattr(
        orchestrator,
        "validate_reference_additional_authority",
        lambda root, path: REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    )

    class Database:
        def __init__(self, path: Path) -> None:
            self.path = path

        def initialize(self) -> None:
            return None

        def reference_additional_grant(self) -> dict[str, object]:
            return {
                "state": "available",
                "authority_sha256": REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
                "prior_settlement_receipt_sha256": (REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256),
                "prior_execution_scope_sha256": (REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256),
                "prior_actual_cost_usd": "0.00564445",
                "active_reservation_id": None,
            }

    monkeypatch.setattr(orchestrator, "ResultsDatabase", Database)
    monkeypatch.setattr(
        orchestrator,
        "build_bootstrap_request",
        lambda root, value, *, additional=False: b"additional-request"
        if additional
        else b"original-request",
    )
    monkeypatch.setattr(orchestrator, "validate_reproduced_request", lambda *a, **k: None)
    monkeypatch.setattr(
        orchestrator,
        "plan_reference_additional_preview",
        lambda *args, **kwargs: {"bootstrap_ready": True, "blockers": []},
    )
    monkeypatch.setattr(orchestrator, "_capability", lambda root, value, request: capability)
    for path in (orchestrator.IMAGE_LOCK_PATH, orchestrator.PROVIDER_CAPABILITY_PATH):
        full = tmp_path / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(b"evidence")

    prepared, request, result, binding = orchestrator.prepare_additional(tmp_path)

    assert prepared is config
    assert request == b"additional-request"
    assert result.request_path == orchestrator.ADDITIONAL_REQUEST_PATH
    assert result.bootstrap_request_bytes == capability.bootstrap_request_bytes
    assert (tmp_path / orchestrator.ADDITIONAL_REQUEST_PATH).read_bytes() == request
    assert binding == additional_reference_binding(
        config_sha256=config.sha256,
        config_challenge_sha256=config.challenge_sha256,
        request_sha256=orchestrator._sha(request),
        execution_scope_sha256=config.reference_execution_scope_sha256,
    )


def test_status_reports_additional_state_without_implying_proven_context(
    tmp_path: Path,
) -> None:
    database = ResultsDatabase(tmp_path / orchestrator.DATABASE_PATH)
    database.initialize()

    status = orchestrator.reference_status(tmp_path)

    assert status["additional"] == {
        "authority_sha256": REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
        "billing_state": None,
        "execution_evidence_recorded": False,
        "experiment_state": None,
        "state": "available",
    }
    assert status["cumulative_actual_cost_usd"] == "0"
    assert status["configured_context_tokens"] == 262144
    assert status["proven_useful_context_tokens"] is None


@pytest.mark.parametrize(
    ("grant", "reservation", "experiment", "expected"),
    [
        ("available", None, None, "available"),
        ("available", "reserved", "created", "reserved"),
        ("consumed", "submission_pending", "created", "consumed"),
        ("consumed", "audit_blocked", "failed", "audit-blocked"),
        ("consumed", "settled", "completed", "settled-success"),
        ("consumed", "failed", "failed", "settled-failure"),
    ],
)
def test_additional_status_state_is_explicit(
    grant: str,
    reservation: str | None,
    experiment: str | None,
    expected: str,
) -> None:
    assert orchestrator._additional_status_state(grant, reservation, experiment) == expected


def test_paid_request_reproduction_rejects_artifact_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "build_bootstrap_request", lambda root, config: b"expected")
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="local provenance"):
        orchestrator.validate_reproduced_request(tmp_path, SimpleNamespace(), b"changed")


def test_execute_confirmation_mismatch_prevents_topology_reservation_and_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(orchestrator, "_watchdog_ready", lambda: None)
    monkeypatch.setattr(
        orchestrator,
        "prepare",
        lambda root: (SimpleNamespace(), b"request", _capability(tmp_path)),
    )
    monkeypatch.setattr(orchestrator, "observe_topology", lambda path: calls.append("topology"))

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="confirmation"):
        orchestrator.execute(tmp_path, confirm_request_sha256="0" * 64)

    assert calls == []
    assert not (tmp_path / orchestrator.DATABASE_PATH).exists()


def test_execute_reserves_once_then_hands_closed_capability_to_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = b"request"
    config = SimpleNamespace(
        challenge_sha256="1" * 64,
        sha256="2" * 64,
        canonical_json="{}",
        experiment_id="reference-test",
        inputs={
            "source_revision": "3" * 40,
            "weight_inventory_sha256": "4" * 64,
            "runtime_receipt_sha256": "5" * 64,
            "formula_authority_sha256": "6" * 64,
            "reviewed_commit_sha256": "7" * 40,
            "control_plane_sha256": "8" * 64,
            "provenance_manifest_sha256": "9" * 64,
            "evaluation_lock_sha256": "a" * 64,
            "weight_inventory_tensor_bytes": 1,
            "evaluation_max_context_tokens": 262144,
        },
    )
    unreserved = _capability(tmp_path)
    (tmp_path / orchestrator.CONFIG_PATH).parent.mkdir(parents=True)
    (tmp_path / orchestrator.CONFIG_PATH).write_bytes(b"config")
    calls: list[object] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            calls.append(("db", path))

        def initialize(self) -> None:
            calls.append("initialize")

        def register_reference_challenge(self, **kwargs: object) -> None:
            calls.append("challenge")

        def attach_reference_approval(self, **kwargs: object) -> None:
            calls.append("approval")

        def create_attempt(self, **kwargs: object) -> None:
            calls.append("attempt")

        def reserve_reference_run(self, **kwargs: object) -> None:
            calls.append(("reserve", kwargs["requested_cost_usd"]))

    monkeypatch.setattr(orchestrator, "_watchdog_ready", lambda: None)
    monkeypatch.setattr(orchestrator, "prepare", lambda root: (config, request, unreserved))
    monkeypatch.setattr(orchestrator, "observe_topology", lambda path: calls.append("topology"))
    monkeypatch.setattr(orchestrator, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(orchestrator, "confine_results_db", lambda root, path: root / path)
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.validate_reference_preflight",
        lambda capability: calls.append("preflight"),
    )
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.prepare_local_modal_graph",
        lambda capability: calls.append("serialize")
        or PreparedModalGraph(
            serialized=SerializedRemoteCallable(entry=lambda value: {}, payload=b"blob"),
            image=object(),
            app=object(),
            remote=object(),
        ),
    )
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.submit_reference",
        lambda capability, prepared: calls.append(("submit", capability, prepared))
        or {"status": "settlement_pending"},
    )

    result = orchestrator.execute(tmp_path, confirm_request_sha256=orchestrator._sha(request))

    assert result == {"status": "settlement_pending"}
    assert calls.count("topology") == 2
    assert calls.count("preflight") == 1
    assert ("reserve", "4.00") in calls
    final_topology = len(calls) - 1 - calls[::-1].index("topology")
    database_open = calls.index(("db", tmp_path / orchestrator.DATABASE_PATH))
    assert calls.index("preflight") < calls.index("serialize") < final_topology < database_open
    submitted = next(item[1] for item in calls if isinstance(item, tuple) and item[0] == "submit")
    assert submitted.reservation_id
    assert submitted.owner_id
    assert submitted.bootstrap_request_bytes == request


def test_serialized_size_failure_precedes_database_and_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = b"request"
    calls: list[str] = []
    monkeypatch.setattr(orchestrator, "_watchdog_ready", lambda: None)
    monkeypatch.setattr(
        orchestrator,
        "prepare",
        lambda root: (SimpleNamespace(), request, _capability(tmp_path)),
    )
    monkeypatch.setattr(orchestrator, "observe_topology", lambda path: calls.append("topology"))
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.validate_reference_preflight",
        lambda capability: calls.append("preflight"),
    )
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.prepare_local_modal_graph",
        lambda capability: (_ for _ in ()).throw(
            ReferenceModalError("serialized function exceeds provider cap")
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "ResultsDatabase",
        lambda path: (_ for _ in ()).throw(AssertionError("database boundary crossed")),
    )

    with pytest.raises(ReferenceModalError, match="provider cap"):
        orchestrator.execute(
            tmp_path,
            confirm_request_sha256=orchestrator._sha(request),
        )

    assert calls == ["topology", "preflight"]


def test_cli_failure_is_sanitized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert orchestrator.main(["--root", str(tmp_path), "prepare"]) == 1
    output = json.loads(capsys.readouterr().err)
    assert output == {
        "command": "prepare",
        "error": "ReferenceOrchestratorError",
        "ok": False,
        "provider_contacted": False,
    }


@pytest.mark.parametrize("contacted", (False, True))
def test_replacement_capture_cli_reports_read_only_provider_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    contacted: bool,
) -> None:
    def capture(
        root: Path,
        *,
        query_start: str,
        query_end: str,
        runner: object | None = None,
    ) -> dict[str, object]:
        assert callable(runner)
        if contacted:
            runner([], check=False)
        raise orchestrator.ReferenceOrchestratorError("capture failed")

    monkeypatch.setattr(orchestrator, "capture_replacement_billing", capture)
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *args, **kwargs: object())
    assert (
        orchestrator.main(
            [
                "--root",
                str(tmp_path),
                "billing-capture-replacement",
                "--query-start",
                "2026-08-26T14:00:00Z",
                "--query-end",
                "2026-08-26T16:00:00Z",
            ]
        )
        == 1
    )
    output = json.loads(capsys.readouterr().err)
    assert output == {
        "command": "billing-capture-replacement",
        "error": "ReferenceOrchestratorError",
        "ok": False,
        "provider_contacted": False,
        "provider_read_only_contacted": contacted,
    }


@pytest.mark.parametrize(
    ("case", "mode", "provider_job_id", "app_identity", "object_id", "empty"),
    (
        ("success", "call", "fc-" + "C" * 22, None, "fc-" + "C" * 22, False),
        ("failure", "call", "fc-" + "D" * 22, None, "fc-" + "D" * 22, False),
        ("app", "app", None, "ap-" + "A" * 22, "ap-" + "A" * 22, False),
        (
            "dual_call",
            "call",
            "fc-" + "E" * 22,
            "ap-" + "E" * 22,
            "fc-" + "E" * 22,
            False,
        ),
        (
            "dual_app",
            "app",
            "fc-" + "F" * 22,
            "ap-" + "F" * 22,
            "ap-" + "F" * 22,
            False,
        ),
        ("billing", "billing_only", None, None, "ap-" + "B" * 22, False),
        ("zero", "workspace_zero_preidentity", None, None, None, True),
    ),
)
def test_additional_capture_builds_closed_modes_consumed_by_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    mode: str,
    provider_job_id: str | None,
    app_identity: str | None,
    object_id: str | None,
    empty: bool,
) -> None:
    workspace = "1" * 64
    binding = "2" * 64
    authority_sha = "3" * 64
    report_identity = "4" * 64
    environment_scope = "5" * 64
    pre_bytes = b'{"pre":true}'
    post_bytes = b'{"post":true}'
    pre_sha = hashlib.sha256(pre_bytes).hexdigest()
    post_sha = hashlib.sha256(post_bytes).hexdigest()
    for digest, content in ((pre_sha, pre_bytes), (post_sha, post_bytes)):
        path = tmp_path / auth_receipt_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    request = tmp_path / orchestrator.ADDITIONAL_REQUEST_PATH
    request.parent.mkdir(parents=True, exist_ok=True)
    request.write_bytes(b"request")
    remote_receipt = None
    if case in {"success", "failure"}:
        remote_receipt = json.dumps({"status": case}, sort_keys=True).encode()
        remote_path = tmp_path / "reports/local/u8-bootstrap-receipt-test.json"
        remote_path.parent.mkdir(parents=True, exist_ok=True)
        remote_path.write_bytes(remote_receipt)
    billing_authority = tmp_path / orchestrator.DEFAULT_BILLING_AUTHORITY
    billing_authority.parent.mkdir(parents=True, exist_ok=True)
    billing_authority.write_bytes(b"authority")
    monkeypatch.setattr(orchestrator, "provider_environment_overrides_present", lambda: False)
    monkeypatch.setattr(
        orchestrator,
        "load_reference_job_config",
        lambda *args, **kwargs: SimpleNamespace(
            provider={"environment_scope_sha256": environment_scope}
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "_validated_provider_capability",
        lambda *args: {"provider_environment": "low-bit-lab"},
    )
    monkeypatch.setattr(
        orchestrator,
        "verify_provider_billing_authority",
        lambda *args, **kwargs: {
            "attribution_method_sha256": "6" * 64,
            "authoritative_report_identity_sha256": report_identity,
            "billing_completeness_delay_seconds": 1,
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "_additional_audit_row",
        lambda database: {
            "reservation_id": "reservation",
            "run_id": "run",
            "reference_execution_scope_sha256": "7" * 64,
            "billing_authority_sha256": authority_sha,
            "authoritative_report_identity_sha256": report_identity,
            "billing_completeness_delay_seconds": 1,
            "heartbeat_at": "2026-08-28T12:30:00+00:00",
            "provider_job_id": provider_job_id,
            "app_identity": app_identity,
            "authority_sha256": orchestrator.REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
            "consumed_at": "2026-08-28T12:00:00+00:00",
            "auth_binding_sha256": binding,
            "original_workspace_scope_sha256": "8" * 64,
            "authenticated_workspace_identity_sha256": workspace,
            "execution_receipt_sha256": (
                None if remote_receipt is None else hashlib.sha256(remote_receipt).hexdigest()
            ),
            "execution_manifest_sha256": None,
        },
    )
    auths = iter(
        (
            {
                "authenticated_workspace_identity_sha256": workspace,
                "binding_sha256": binding,
                "receipt_sha256": pre_sha,
            },
            {
                "authenticated_workspace_identity_sha256": workspace,
                "binding_sha256": binding,
                "receipt_sha256": post_sha,
            },
        )
    )
    monkeypatch.setattr(orchestrator, "verify_workspace_auth", lambda *a, **k: next(auths))
    rows = []
    if not empty:
        rows.append(
            {
                "cost": "0.25",
                "description": orchestrator.REFERENCE_APP_NAME,
                "environment": "low-bit-lab",
                "interval_start": "2026-08-28T13:00:00Z",
                "object_id": object_id,
                "resource": "A100-80GB",
            }
        )
    raw = orchestrator.CANONICAL_EMPTY_REPORT if empty else (json.dumps(rows) + "\n").encode()
    monkeypatch.setattr(
        orchestrator,
        "_run_modal_cli",
        lambda *args, **kwargs: raw,
    )

    result = orchestrator.capture_additional_billing(
        tmp_path,
        query_start="2026-08-28T12:00:00Z",
        query_end="2026-08-28T16:00:00Z",
    )

    receipt = json.loads((tmp_path / orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH).read_bytes())
    assert result["attribution_mode"] == receipt["attribution_mode"] == mode
    assert receipt["pre_auth_receipt_sha256"] == pre_sha
    assert receipt["post_auth_receipt_sha256"] == post_sha
    observed: dict[str, object] = {}

    class FakeDatabase:
        def settle_reference_additional_billing(self, *args: object, **kwargs: object) -> str:
            observed["args"] = args
            observed["kwargs"] = kwargs
            return "9" * 64

    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: FakeDatabase())
    settled = orchestrator.settle_additional_billing(tmp_path)
    assert settled["settlement_receipt_sha256"] == "9" * 64
    assert observed["args"] == (
        (tmp_path / orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH).read_bytes(),
        (tmp_path / orchestrator.ADDITIONAL_IDENTITY_EVIDENCE_PATH).read_bytes(),
        (tmp_path / orchestrator.ADDITIONAL_BILLING_REPORT_PATH).read_bytes(),
    )
    assert observed["kwargs"]["pre_auth_receipt_bytes"] == pre_bytes
    assert observed["kwargs"]["post_auth_receipt_bytes"] == post_bytes
    assert observed["kwargs"]["remote_receipt_bytes"] == remote_receipt


@pytest.mark.parametrize(
    "outputs",
    (
        (" M tracked.py\n", "main\n", "a" * 40 + "\n", "a" * 40 + "\n"),
        ("", "feature\n", "a" * 40 + "\n", "a" * 40 + "\n"),
        ("", "main\n", "a" * 40 + "\n", "b" * 40 + "\n"),
    ),
)
def test_live_gate_rejects_dirty_nonmain_or_unmerged_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outputs: tuple[str, str, str, str],
) -> None:
    responses = iter(outputs)
    monkeypatch.setattr(
        orchestrator.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=next(responses), stderr=""),
    )
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="clean merged"):
        _REAL_MERGED_MAIN_GATE(tmp_path)


def test_live_gate_accepts_exact_clean_origin_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = "a" * 40
    responses = iter(("", "main\n", head + "\n", head + "\n"))
    monkeypatch.setattr(
        orchestrator.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=next(responses), stderr=""),
    )
    assert _REAL_MERGED_MAIN_GATE(tmp_path) == head


def _write_auth_fixture(
    root: Path,
    profile: str = "private-profile-name",
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> None:
    workspace_identity = orchestrator._sha(profile.encode())
    workspace_scope = "b" * 64
    config = root / orchestrator.CONFIG_PATH
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "provider:\n  workspace_scope_sha256: '" + workspace_scope + "'\n",
        encoding="utf-8",
    )
    binding = {
        "authenticated_workspace_identity_sha256": workspace_identity,
        "kind": "reference_modal_workspace_auth_binding",
        "original_workspace_scope_sha256": workspace_scope,
        "provider": "modal",
        "reconciliation_authority_sha256": (
            orchestrator.REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
        ),
        "schema_version": 2,
    }
    path = root / orchestrator.AUTH_BINDING_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(orchestrator.canonical_bytes(binding))
    if monkeypatch is not None:
        monkeypatch.setattr(
            orchestrator,
            "validate_workspace_scope_reconciliation_authority",
            lambda root: {
                "original_workspace_scope_sha256": workspace_scope,
                "authenticated_workspace_identity_sha256": workspace_identity,
            },
        )


def _write_billing_authority_fixture(root: Path) -> str:
    path = root / orchestrator.DEFAULT_BILLING_AUTHORITY
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "attribution_method_sha256": "b" * 64,
                "authoritative_report_identity_sha256": "e" * 64,
                "billing_completeness_delay_seconds": 3600,
                "environment_scope_sha256": "d" * 64,
                "kind": "provider_billing_authority_contract",
                "provider": "modal",
                "schema_version": 2,
            }
        ),
        encoding="utf-8",
    )
    return orchestrator._sha(path.read_bytes())


def test_auth_receipt_never_persists_profile_display_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = "private-profile-name"
    _write_auth_fixture(tmp_path, profile, monkeypatch)

    def runner(*args: object, **kwargs: object) -> SimpleNamespace:
        stdout = orchestrator._sha(profile.encode()).encode() + b"\n"
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    receipt = orchestrator.verify_workspace_auth(tmp_path, runner=runner)

    persisted = (tmp_path / orchestrator.AUTH_RECEIPT_PATH).read_bytes()
    assert profile.encode() not in persisted
    assert "profile" not in json.loads(persisted)
    assert receipt["authenticated_workspace_identity_sha256"] == orchestrator._sha(profile.encode())
    assert receipt["original_workspace_scope_sha256"] == "b" * 64


def test_workspace_probe_accepts_pinned_modal_shape_and_strips_auth_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = "private-profile-name"
    for key in (
        "MODAL_TOKEN_ID",
        "MODAL_TOKEN_SECRET",
        "MODAL_PROFILE",
        "MODAL_CONFIG_PATH",
        "MODAL_ENVIRONMENT",
    ):
        monkeypatch.setenv(key, "must-not-be-read")

    def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
        assert command[1:4] == ["-I", "-B", "-c"]
        assert command[4] == orchestrator._ACTIVE_WORKSPACE_DIGEST_SCRIPT
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert not any(key in environment for key in MODAL_AUTH_OVERRIDE_KEYS)
        assert kwargs["shell"] is False
        return SimpleNamespace(
            returncode=0,
            stdout=orchestrator._sha(profile.encode()).encode() + b"\n",
            stderr=b"",
        )

    assert orchestrator._current_workspace_digest(runner=runner) == orchestrator._sha(
        profile.encode()
    )


def test_workspace_probe_is_credential_opaque_and_uses_pinned_client_rpc() -> None:
    script = orchestrator._ACTIVE_WORKSPACE_DIGEST_SCRIPT
    assert "_Client.from_env()" in script
    assert "client.server_url==DEFAULT_SERVER_URL" in script
    assert "WorkspaceNameLookup(Empty(),retry=None,timeout=3)" in script
    assert "from modal_proto.api_pb2 import Empty" in script
    assert "_lookup_workspace" not in script
    assert "token_id" not in script
    assert "token_secret" not in script


@pytest.mark.parametrize(
    "key",
    [
        "HTTPS_PROXY",
        "SSL_CERT_FILE",
        "PYTHONPATH",
        "MODAL_SERVER_URL",
        "MODAL_OVERRIDE_HEADERS",
        "MODAL_FUTURE_SETTING",
    ],
)
def test_workspace_auth_rejects_transport_or_import_override_before_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    _write_auth_fixture(tmp_path)
    monkeypatch.setenv(key, "must-not-be-read")
    called = False

    def runner(*args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal called
        called = True
        return SimpleNamespace(returncode=0, stdout=b"[]", stderr=b"")

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="override"):
        orchestrator.verify_workspace_auth(tmp_path, runner=runner)
    assert called is False
    assert not (tmp_path / orchestrator.AUTH_RECEIPT_PATH).exists()


def test_workspace_auth_binding_cannot_be_rebound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / orchestrator.CONFIG_PATH
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "provider:\n  workspace_scope_sha256: '" + "b" * 64 + "'\n",
        encoding="utf-8",
    )

    def runner_for(profile: str) -> object:
        return lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=orchestrator._sha(profile.encode()).encode() + b"\n",
            stderr=b"",
        )

    monkeypatch.setattr(
        orchestrator,
        "validate_workspace_scope_reconciliation_authority",
        lambda root: {
            "original_workspace_scope_sha256": "b" * 64,
            "authenticated_workspace_identity_sha256": orchestrator._sha(b"first-profile"),
        },
    )
    orchestrator.bind_workspace_auth(tmp_path, runner=runner_for("first-profile"))
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="immutable|mismatch"):
        orchestrator.bind_workspace_auth(tmp_path, runner=runner_for("second-profile"))

    persisted = (tmp_path / orchestrator.AUTH_BINDING_PATH).read_bytes()
    assert b"first-profile" not in persisted
    assert b"second-profile" not in persisted


def test_paid_execute_rejects_ambient_modal_auth_override_before_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    monkeypatch.setenv("MODAL_PROFILE", "must-not-be-read")
    monkeypatch.setattr(orchestrator, "_watchdog_ready", lambda: None)
    monkeypatch.setattr(
        orchestrator,
        "prepare",
        lambda root: events.append("prepared"),
    )
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="override"):
        orchestrator.execute(tmp_path, confirm_request_sha256="0" * 64, replacement=True)
    assert events == []


@pytest.mark.parametrize("report", [orchestrator.CANONICAL_EMPTY_REPORT + b"\n", b"[ ]", b"{}"])
def test_billing_capture_rejects_noncanonical_provider_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report: bytes,
) -> None:
    profile = "private-profile-name"
    _write_auth_fixture(tmp_path, profile, monkeypatch)
    authority_sha256 = _write_billing_authority_fixture(tmp_path)
    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: object())
    monkeypatch.setattr(
        orchestrator,
        "_original_preidentity_row",
        lambda database: {
            "reservation_id": "reservation",
            "reference_execution_scope_sha256": "c" * 64,
            "billing_authority_sha256": authority_sha256,
            "authoritative_report_identity_sha256": "e" * 64,
            "billing_completeness_delay_seconds": 3600,
            "consumed_at": "2026-08-26T18:30:00+00:00",
            "heartbeat_at": "2026-08-26T19:00:00+00:00",
            "updated_at": "2026-08-26T19:00:00+00:00",
        },
    )

    def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
        stdout = (
            orchestrator._sha(profile.encode()).encode() + b"\n"
            if command[4] == orchestrator._ACTIVE_WORKSPACE_DIGEST_SCRIPT
            else report
        )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="canonical zero"):
        orchestrator.capture_workspace_zero_billing(
            tmp_path,
            query_start="2026-08-26T18:00:00Z",
            query_end="2026-08-26T22:00:00Z",
            runner=runner,
        )

    assert not (tmp_path / orchestrator.WORKSPACE_ZERO_REPORT_PATH).exists()


def test_billing_capture_persists_exact_provider_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = "private-profile-name"
    _write_auth_fixture(tmp_path, profile, monkeypatch)
    authority_sha256 = _write_billing_authority_fixture(tmp_path)
    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: object())
    monkeypatch.setattr(
        orchestrator,
        "_original_preidentity_row",
        lambda database: {
            "reservation_id": "reservation",
            "reference_execution_scope_sha256": "c" * 64,
            "billing_authority_sha256": authority_sha256,
            "authoritative_report_identity_sha256": "e" * 64,
            "billing_completeness_delay_seconds": 3600,
            "consumed_at": "2026-08-26T18:30:00+00:00",
            "heartbeat_at": "2026-08-26T19:00:00+00:00",
            "updated_at": "2026-08-26T19:00:00+00:00",
        },
    )

    def runner(command: list[str], **kwargs: object) -> SimpleNamespace:
        stdout = (
            orchestrator._sha(profile.encode()).encode() + b"\n"
            if command[4] == orchestrator._ACTIVE_WORKSPACE_DIGEST_SCRIPT
            else orchestrator.CANONICAL_EMPTY_REPORT
        )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    result = orchestrator.capture_workspace_zero_billing(
        tmp_path,
        query_start="2026-08-26T18:00:00Z",
        query_end="2026-08-26T22:00:00Z",
        runner=runner,
    )

    assert (
        tmp_path / orchestrator.WORKSPACE_ZERO_REPORT_PATH
    ).read_bytes() == orchestrator.CANONICAL_EMPTY_REPORT
    assert result["provider_contacted"] is False
    assert result["provider_read_only_contacted"] is True
    assert (
        profile.encode() not in (tmp_path / orchestrator.WORKSPACE_ZERO_RECEIPT_PATH).read_bytes()
    )
    billing_receipt = json.loads((tmp_path / orchestrator.WORKSPACE_ZERO_RECEIPT_PATH).read_bytes())
    pre = tmp_path / auth_receipt_path(billing_receipt["pre_auth_receipt_sha256"])
    post = tmp_path / auth_receipt_path(billing_receipt["post_auth_receipt_sha256"])
    assert pre.is_file() and post.is_file() and pre != post
    assert orchestrator._sha(pre.read_bytes()) == billing_receipt["pre_auth_receipt_sha256"]
    assert orchestrator._sha(post.read_bytes()) == billing_receipt["post_auth_receipt_sha256"]


def test_replacement_capture_filters_private_workspace_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority_sha256 = _write_billing_authority_fixture(tmp_path)
    app_id = "ap-" + "A" * 22
    config_sha256 = "7" * 64
    request_bytes = json.dumps(
        {
            "image_lock": {"recipe_sha256": "5" * 64},
            "provider_capability": {"receipt_sha256": "6" * 64},
        }
    ).encode()
    standing_packet_sha256 = orchestrator.canonical_sha256(
        {
            "bootstrap_authority_sha256": orchestrator.REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "config_sha256": config_sha256,
            "request_sha256": orchestrator._sha(request_bytes),
            "signed_cdn_authority_sha256": (orchestrator.REFERENCE_SIGNED_CDN_AUTHORITY_SHA256),
            "standing_authority_sha256": orchestrator.REFERENCE_AUTHORITY_SHA256,
        }
    )
    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: object())
    monkeypatch.setattr(
        orchestrator,
        "_replacement_audit_row",
        lambda database: {
            "reservation_id": "replacement",
            "reference_execution_scope_sha256": "c" * 64,
            "billing_authority_sha256": authority_sha256,
            "authoritative_report_identity_sha256": "e" * 64,
            "billing_completeness_delay_seconds": 3600,
            "entitlement_sha256": "f" * 64,
            "consumed_at": "2026-08-26T14:27:54+00:00",
            "heartbeat_at": "2026-08-26T14:29:27+00:00",
            "auth_binding_sha256": "b" * 64,
            "original_workspace_scope_sha256": "1" * 64,
            "authenticated_workspace_identity_sha256": "2" * 64,
            "standing_packet_sha256": standing_packet_sha256,
        },
    )

    def load_config(path: Path, *, root: Path) -> SimpleNamespace:
        assert path == tmp_path / orchestrator.CONFIG_PATH
        assert root == tmp_path
        return SimpleNamespace(
            provider={"environment_scope_sha256": "d" * 64}, sha256=config_sha256
        )

    monkeypatch.setattr(orchestrator, "load_reference_job_config", load_config)
    request_path = tmp_path / orchestrator.REQUEST_PATH
    request_path.parent.mkdir(parents=True, exist_ok=True)
    request_path.write_bytes(request_bytes)
    monkeypatch.setattr(
        orchestrator,
        "validate_bootstrap_request_bytes",
        lambda content: SimpleNamespace(canonical_json=content.decode()),
    )
    observed_provider: dict[str, object] = {}

    def validate_provider(
        path: Path,
        *,
        expected_sha256: str,
        image_recipe_sha256: str,
        billing_authority_path: Path,
        billing_receipt_path: Path,
        billing_report_path: Path,
    ) -> dict[str, object]:
        observed_provider.update(
            {
                "path": path,
                "expected_sha256": expected_sha256,
                "image_recipe_sha256": image_recipe_sha256,
                "billing_authority_path": billing_authority_path,
                "billing_receipt_path": billing_receipt_path,
                "billing_report_path": billing_report_path,
            }
        )
        return {"provider_environment": "low-bit-lab"}

    monkeypatch.setattr(orchestrator, "validate_provider_capability_receipt", validate_provider)
    auth_count = 0

    def auth(
        root: Path, *, runner: object | None = None, write_latest: bool = True
    ) -> dict[str, str]:
        nonlocal auth_count
        assert root == tmp_path
        assert runner is None
        assert write_latest is False
        auth_count += 1
        return {
            "authenticated_workspace_identity_sha256": "2" * 64,
            "binding_sha256": "b" * 64,
            "receipt_sha256": str(auth_count) * 64,
        }

    monkeypatch.setattr(orchestrator, "verify_workspace_auth", auth)
    observed_commands: list[list[str]] = []
    app_rows = [
        {
            "app_id": app_id,
            "created_at": "2026-08-26T14:28:16+00:00",
            "description": "low-bit-lab-reference-u8",
            "state": "stopped",
            "stopped_at": "2026-08-26T14:29:28+00:00",
            "tasks": "0",
        },
        {
            "app_id": "ap-" + "B" * 22,
            "created_at": "2026-08-26T14:00:00+00:00",
            "description": "private-project-name",
            "state": "stopped",
            "stopped_at": "2026-08-26T14:01:00+00:00",
            "tasks": "0",
        },
    ]
    billing_rows = [
        {
            "cost": "0.01",
            "description": "low-bit-lab-reference-u8",
            "environment": "low-bit-lab",
            "interval_start": "2026-08-26T14:00:00",
            "object_id": app_id,
            "resource": "cpu",
        },
        {
            "cost": "9.99",
            "description": "private-project-name",
            "environment": "low-bit-lab",
            "interval_start": "2026-08-26T14:00:00+00:00",
            "object_id": "ap-" + "B" * 22,
            "resource": "cpu",
        },
    ]

    def modal_runner(rows: list[dict[str, object]], apps: list[dict[str, object]] = app_rows):
        def run(arguments: list[str], *, runner: object | None = None) -> bytes:
            assert runner is None
            observed_commands.append(arguments)
            return json.dumps(apps if arguments[0] == "app" else rows).encode()

        return run

    monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(billing_rows))

    result = orchestrator.capture_replacement_billing(
        tmp_path,
        query_start="2026-08-26T14:00:00Z",
        query_end="2026-08-26T16:00:00Z",
    )

    assert result["actual_cost_usd"] == "0.01"
    assert observed_commands == [
        ["app", "list", "--env", "low-bit-lab", "--json"],
        [
            "billing",
            "report",
            "--start",
            "2026-08-26T14:00:00Z",
            "--end",
            "2026-08-26T16:00:00Z",
            "--resolution",
            "h",
            "--show-resources",
            "--json",
        ],
    ]

    persisted = (tmp_path / orchestrator.REPLACEMENT_REPORT_PATH).read_bytes()
    app_evidence = json.loads((tmp_path / orchestrator.REPLACEMENT_APP_EVIDENCE_PATH).read_bytes())
    receipt = json.loads((tmp_path / orchestrator.REPLACEMENT_RECEIPT_PATH).read_bytes())
    assert app_evidence["running_tasks"] == 0
    assert "tasks" not in app_evidence
    assert receipt["environment_scope_sha256"] == "d" * 64
    assert observed_provider["path"] == tmp_path / orchestrator.PROVIDER_CAPABILITY_PATH
    assert observed_provider["expected_sha256"] == "6" * 64
    assert observed_provider["image_recipe_sha256"] == "5" * 64
    assert observed_provider["billing_authority_path"] == (
        tmp_path / orchestrator.DEFAULT_BILLING_AUTHORITY
    )
    assert observed_provider["billing_receipt_path"] == (
        tmp_path / orchestrator.DEFAULT_BILLING_RECEIPT
    )
    assert observed_provider["billing_report_path"] == (
        tmp_path / orchestrator.DEFAULT_BILLING_REPORT
    )
    assert b"private-project-name" not in persisted
    assert b"9.99" not in persisted
    assert json.loads(persisted)["rows"] == [
        {
            "cost": "0.01",
            "interval_start": "2026-08-26T14:00:00+00:00",
            "object_id": app_id,
            "resource": "cpu",
        }
    ]
    for field, value in (
        ("cost", 0.01),
        ("interval_start", 1),
        ("object_id", 1),
        ("object_id", "invalid"),
        ("resource", 1),
        ("resource", ""),
    ):
        observed_commands.clear()
        drifted_rows = [dict(row) for row in billing_rows]
        drifted_rows[0][field] = value
        monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(drifted_rows))
        with pytest.raises(orchestrator.ReferenceOrchestratorError, match="type drift"):
            orchestrator.capture_replacement_billing(
                tmp_path,
                query_start="2026-08-26T14:00:00Z",
                query_end="2026-08-26T16:00:00Z",
            )
    ambiguous_rows = [dict(row) for row in billing_rows]
    ambiguous_rows.append({**billing_rows[0], "object_id": "ap-" + "C" * 22})
    monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(ambiguous_rows))
    observed_commands.clear()
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="ambiguous"):
        orchestrator.capture_replacement_billing(
            tmp_path,
            query_start="2026-08-26T14:00:00Z",
            query_end="2026-08-26T16:00:00Z",
        )

    duplicate_apps = [dict(app_rows[0]), {**app_rows[0], "app_id": "ap-" + "D" * 22}]
    observed_commands.clear()
    monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(billing_rows, duplicate_apps))
    with pytest.raises(
        orchestrator.ReferenceOrchestratorError, match="unique stopped replacement app"
    ):
        orchestrator.capture_replacement_billing(
            tmp_path,
            query_start="2026-08-26T14:00:00Z",
            query_end="2026-08-26T16:00:00Z",
        )
    assert observed_commands == [["app", "list", "--env", "low-bit-lab", "--json"]]

    observed_commands.clear()
    monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(billing_rows, []))
    billing_only = orchestrator.capture_replacement_billing(
        tmp_path,
        query_start="2026-08-26T14:00:00Z",
        query_end="2026-08-26T16:00:00Z",
    )
    app_evidence = json.loads((tmp_path / orchestrator.REPLACEMENT_APP_EVIDENCE_PATH).read_bytes())
    assert billing_only["actual_cost_usd"] == "0.01"
    assert app_evidence == {
        "app_id": app_id,
        "identity_source": "authoritative_filtered_billing_report",
        "kind": "reference_replacement_billing_app_identity",
        "recent_app_listing": "not_returned",
        "schema_version": 2,
    }
    assert observed_commands == [
        ["app", "list", "--env", "low-bit-lab", "--json"],
        [
            "billing",
            "report",
            "--start",
            "2026-08-26T14:00:00Z",
            "--end",
            "2026-08-26T16:00:00Z",
            "--resolution",
            "h",
            "--show-resources",
            "--json",
        ],
    ]

    for rows in (
        [],
        [billing_rows[0], {**billing_rows[0], "object_id": "ap-" + "C" * 22}],
    ):
        monkeypatch.setattr(orchestrator, "_run_modal_cli", modal_runner(rows, []))
        with pytest.raises(
            orchestrator.ReferenceOrchestratorError,
            match="unique replacement billing app identity is unavailable",
        ):
            orchestrator.capture_replacement_billing(
                tmp_path,
                query_start="2026-08-26T14:00:00Z",
                query_end="2026-08-26T16:00:00Z",
            )

    for field, value in (
        ("state", "running"),
        ("tasks", "1"),
        ("created_at", "2026-08-26T13:00:00+00:00"),
    ):
        ineligible_app = {**app_rows[0], field: value}
        monkeypatch.setattr(
            orchestrator,
            "_run_modal_cli",
            modal_runner(billing_rows, [ineligible_app]),
        )
        with pytest.raises(
            orchestrator.ReferenceOrchestratorError,
            match="listed replacement app is ineligible",
        ):
            orchestrator.capture_replacement_billing(
                tmp_path,
                query_start="2026-08-26T14:00:00Z",
                query_end="2026-08-26T16:00:00Z",
            )


def test_replacement_capture_rejects_local_lineage_before_provider_contact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_sha256 = "7" * 64
    request_bytes = json.dumps(
        {
            "image_lock": {"recipe_sha256": "5" * 64},
            "provider_capability": {"receipt_sha256": "6" * 64},
        }
    ).encode()
    request_path = tmp_path / orchestrator.REQUEST_PATH
    request_path.parent.mkdir(parents=True)
    request_path.write_bytes(request_bytes)
    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: object())
    row = {
        "billing_completeness_delay_seconds": 3600,
        "consumed_at": "2026-08-26T14:27:54+00:00",
        "heartbeat_at": "2026-08-26T14:29:27+00:00",
        "standing_packet_sha256": "0" * 64,
    }
    monkeypatch.setattr(orchestrator, "_replacement_audit_row", lambda database: row)
    monkeypatch.setattr(
        orchestrator,
        "load_reference_job_config",
        lambda path, *, root: SimpleNamespace(
            provider={"environment_scope_sha256": "d" * 64}, sha256=config_sha256
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_bootstrap_request_bytes",
        lambda content: SimpleNamespace(canonical_json=content.decode()),
    )
    capability_drift = False

    def validate_provider(
        path: Path,
        *,
        expected_sha256: str,
        image_recipe_sha256: str,
        billing_authority_path: Path,
        billing_receipt_path: Path,
        billing_report_path: Path,
    ) -> dict[str, object]:
        if capability_drift:
            raise ValueError("capability drift")
        return {"provider_environment": "low-bit-lab"}

    monkeypatch.setattr(orchestrator, "validate_provider_capability_receipt", validate_provider)

    def forbid_auth(
        root: Path, *, runner: object | None = None, write_latest: bool = True
    ) -> dict[str, object]:
        raise AssertionError("workspace authentication must not start")

    def forbid_modal(arguments: list[str], *, runner: object | None = None) -> bytes:
        raise AssertionError("Modal CLI must not be contacted")

    monkeypatch.setattr(orchestrator, "verify_workspace_auth", forbid_auth)
    monkeypatch.setattr(orchestrator, "_run_modal_cli", forbid_modal)
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="packet lineage drift"):
        orchestrator.capture_replacement_billing(
            tmp_path,
            query_start="2026-08-26T14:00:00Z",
            query_end="2026-08-26T16:00:00Z",
        )

    row["standing_packet_sha256"] = orchestrator.canonical_sha256(
        {
            "bootstrap_authority_sha256": orchestrator.REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "config_sha256": config_sha256,
            "request_sha256": orchestrator._sha(request_bytes),
            "signed_cdn_authority_sha256": (orchestrator.REFERENCE_SIGNED_CDN_AUTHORITY_SHA256),
            "standing_authority_sha256": orchestrator.REFERENCE_AUTHORITY_SHA256,
        }
    )
    capability_drift = True
    with pytest.raises(ValueError, match="capability drift"):
        orchestrator.capture_replacement_billing(
            tmp_path,
            query_start="2026-08-26T14:00:00Z",
            query_end="2026-08-26T16:00:00Z",
        )
    for path in (
        orchestrator.REPLACEMENT_APP_EVIDENCE_PATH,
        orchestrator.REPLACEMENT_REPORT_PATH,
        orchestrator.REPLACEMENT_RECEIPT_PATH,
    ):
        assert not (tmp_path / path).exists()


def test_local_settlement_source_has_no_submission_adapter_import() -> None:
    import inspect

    source = inspect.getsource(orchestrator.settle_workspace_zero)
    assert "reference_modal_adapter" not in source
    assert "submit_reference" not in source


def test_replacement_settlement_rejects_oversized_report_before_database_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "_require_merged_clean_main", lambda root: "a" * 40)

    class NoDatabaseWrite:
        def settle_reference_replacement_billing(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("database settlement must not start")

    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: NoDatabaseWrite())
    for path, content in (
        (
            orchestrator.REPLACEMENT_RECEIPT_PATH,
            json.dumps(
                {
                    "actual_cost_usd": "0",
                    "pre_auth_receipt_sha256": "a" * 64,
                    "post_auth_receipt_sha256": "b" * 64,
                }
            ).encode(),
        ),
        (orchestrator.REPLACEMENT_APP_EVIDENCE_PATH, b"{}"),
        (
            orchestrator.REPLACEMENT_REPORT_PATH,
            b" " * (orchestrator.MAX_FILTERED_BILLING_REPORT_BYTES + 1),
        ),
    ):
        output = tmp_path / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="byte limit"):
        orchestrator.settle_replacement_billing(tmp_path)


def test_additional_settlement_is_local_and_passes_exact_evidence_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "_require_merged_clean_main", lambda root: "a" * 40)
    pre, post = "a" * 64, "b" * 64
    remote = b'{"remote":"receipt"}'
    receipt = json.dumps(
        {
            "actual_cost_usd": "0.25",
            "execution_receipt_sha256": hashlib.sha256(remote).hexdigest(),
            "post_auth_receipt_sha256": post,
            "pre_auth_receipt_sha256": pre,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    bodies = {
        orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH: receipt,
        orchestrator.ADDITIONAL_IDENTITY_EVIDENCE_PATH: b'{"identity":true}',
        orchestrator.ADDITIONAL_BILLING_REPORT_PATH: b'{"rows":[]}',
        orchestrator.DEFAULT_BILLING_AUTHORITY: b'{"authority":true}',
        orchestrator.ADDITIONAL_REQUEST_PATH: b'{"request":true}',
        orchestrator.auth_receipt_path(pre): b'{"pre":true}',
        orchestrator.auth_receipt_path(post): b'{"post":true}',
        Path("reports/local/u8-bootstrap-receipt-fixed.json"): remote,
    }
    for relative, content in bodies.items():
        output = tmp_path / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
    observed: dict[str, object] = {}

    class FakeDatabase:
        def settle_reference_additional_billing(self, *args: object, **kwargs: object) -> str:
            observed["args"] = args
            observed["kwargs"] = kwargs
            return "c" * 64

    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: FakeDatabase())
    result = orchestrator.settle_additional_billing(tmp_path)

    assert result == {
        "actual_cost_usd": "0.25",
        "provider_contacted": False,
        "settlement_receipt_sha256": "c" * 64,
    }
    assert observed["args"] == (
        receipt,
        b'{"identity":true}',
        b'{"rows":[]}',
    )
    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["remote_receipt_bytes"] == remote
    assert kwargs["pre_auth_receipt_bytes"] == b'{"pre":true}'
    assert kwargs["post_auth_receipt_bytes"] == b'{"post":true}'


def test_recovery_authority_materialization_is_create_once_and_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator,
        "build_reference_recovery_authority",
        lambda: {"kind": "test-recovery-authority", "schema_version": 1},
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_reference_recovery_authority",
        lambda root: orchestrator.REFERENCE_RECOVERY_AUTHORITY_SHA256,
    )
    first = orchestrator.materialize_recovery_authority(tmp_path)
    second = orchestrator.materialize_recovery_authority(tmp_path)
    assert (
        first
        == second
        == {"recovery_authority_sha256": orchestrator.REFERENCE_RECOVERY_AUTHORITY_SHA256}
    )
    output = tmp_path / orchestrator.RECOVERY_AUTHORITY_PATH
    output.write_bytes(output.read_bytes() + b" ")
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="immutable"):
        orchestrator.materialize_recovery_authority(tmp_path)


def test_recovery_authority_repairs_only_exact_legacy_missing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = {"kind": "test-recovery-authority", "schema_version": 1}
    monkeypatch.setattr(orchestrator, "build_reference_recovery_authority", lambda: value)
    monkeypatch.setattr(
        orchestrator,
        "validate_reference_recovery_authority",
        lambda root: orchestrator.REFERENCE_RECOVERY_AUTHORITY_SHA256,
    )
    output = tmp_path / orchestrator.RECOVERY_AUTHORITY_PATH
    output.parent.mkdir(parents=True)
    legacy = orchestrator.canonical_bytes(value)
    output.write_bytes(legacy)

    result = orchestrator.materialize_recovery_authority(tmp_path)

    assert output.read_bytes() == legacy + b"\n"
    assert result == {"recovery_authority_sha256": orchestrator.REFERENCE_RECOVERY_AUTHORITY_SHA256}


def _sqlite_fixture(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3

    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE state(value TEXT NOT NULL)")
        connection.execute("INSERT INTO state VALUES (?)", (value,))
        connection.commit()
    finally:
        connection.close()


def test_wsl_transfer_marker_precedes_import_and_resumes_same_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    _sqlite_fixture(durable / orchestrator.DATABASE_PATH, "durable")
    _sqlite_fixture(mirror / orchestrator.DATABASE_PATH, "prior-mirror")
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)

    result = orchestrator.begin_wsl_state_transfer(durable, mirror)

    marker = durable / orchestrator.WSL_TRANSFER_MARKER_PATH
    assert marker.exists()
    assert result["marker_sha256"] == hashlib.sha256(marker.read_bytes()).hexdigest()
    assert (mirror / orchestrator.DATABASE_PATH).read_bytes() == (
        durable / orchestrator.DATABASE_PATH
    ).read_bytes()
    backups = list((mirror / orchestrator.WSL_DATABASE_BACKUP_ROOT).glob("*.sqlite"))
    assert len(backups) == 1
    assert orchestrator._database_integrity(backups[0]) == "ok"
    resumed = orchestrator.begin_wsl_state_transfer(durable, mirror)
    assert resumed["resumed"] is True
    assert resumed["transfer_id"] == result["transfer_id"]


def test_paid_state_owner_rejects_native_windows(tmp_path: Path) -> None:
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="WSL2 ext4"):
        orchestrator._require_wsl_ext4_root(tmp_path)


def test_paid_state_owner_rejects_wsl_drvfs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator.sys, "platform", "linux")
    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: "microsoft-standard-WSL2")
    monkeypatch.setattr(orchestrator, "_linux_filesystem_type", lambda root: "9p")
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="WSL2 ext4"):
        orchestrator._require_wsl_ext4_root(tmp_path)


def test_interrupted_wsl_import_preserves_durable_state_and_active_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    durable_db = durable / orchestrator.DATABASE_PATH
    _sqlite_fixture(durable_db, "durable")
    before = durable_db.read_bytes()
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)
    real_copy = orchestrator._copy_database_atomic

    def fail_import(source: Path, destination: Path) -> None:
        if destination == mirror / orchestrator.DATABASE_PATH:
            raise OSError("injected interruption")
        real_copy(source, destination)

    monkeypatch.setattr(orchestrator, "_copy_database_atomic", fail_import)
    with pytest.raises(OSError, match="interruption"):
        orchestrator.begin_wsl_state_transfer(durable, mirror)

    assert durable_db.read_bytes() == before
    assert (durable / orchestrator.WSL_TRANSFER_MARKER_PATH).exists()
    monkeypatch.setattr(orchestrator, "_copy_database_atomic", real_copy)
    resumed = orchestrator.begin_wsl_state_transfer(durable, mirror)
    assert resumed["resumed"] is True
    assert (mirror / orchestrator.DATABASE_PATH).read_bytes() == before


def test_wsl_reparity_is_append_only_after_contact_free_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    _sqlite_fixture(durable / orchestrator.DATABASE_PATH, "durable")
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)
    orchestrator.begin_wsl_state_transfer(durable, mirror)
    first = mirror / orchestrator.WSL_PARITY_RECEIPT_PATH
    first.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b'{"generation":"original"}')
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="WSL owns"):
        orchestrator.begin_wsl_state_transfer(durable, mirror)
    assert first.read_bytes() == b'{"generation":"original"}'


@pytest.mark.parametrize(
    ("reservation_status", "provider_job_id", "allowed"),
    (("released", None, True), ("audit_blocked", None, False), ("released", "fc-x", False)),
)
def test_wsl_reparity_requires_all_released_and_no_provider_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reservation_status: str,
    provider_job_id: str | None,
    allowed: bool,
) -> None:
    class Result:
        def __init__(self, value: object) -> None:
            self.value = value

        def fetchone(self) -> object:
            return self.value

        def fetchall(self) -> object:
            return self.value

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str) -> Result:
            if "reference_additional_grants" in query:
                return Result(
                    {
                        "state": "available",
                        "active_reservation_id": None,
                        "active_execution_scope_sha256": None,
                        "consumed_at": None,
                        "consumed_auth_receipt_sha256": None,
                    }
                )
            return Result(
                [
                    {
                        "status": reservation_status,
                        "provider_job_id": provider_job_id,
                        "app_identity": None,
                        "submitted_at": None,
                        "provider_actual_cost_usd": None,
                    }
                ]
            )

    class Database:
        def connect_readonly(self) -> Connection:
            return Connection()

    monkeypatch.setattr(orchestrator, "ResultsDatabase", lambda path: Database())
    monkeypatch.setattr(orchestrator, "confine_results_db", lambda root, path: tmp_path / path)
    if allowed:
        orchestrator._validate_wsl_reparity_state(tmp_path)
    else:
        with pytest.raises(orchestrator.ReferenceOrchestratorError, match="contact-free"):
            orchestrator._validate_wsl_reparity_state(tmp_path)


def test_prepare_additional_rejects_active_windows_ownership_marker(
    tmp_path: Path,
) -> None:
    marker = tmp_path / orchestrator.WSL_TRANSFER_MARKER_PATH
    marker.parent.mkdir(parents=True)
    mirror = "/srv/low-bit-lab"
    marker.write_bytes(
        orchestrator.canonical_bytes(
            {
                "database_sha256": "1" * 64,
                "database_size_bytes": 1,
                "kind": "reference_wsl_ownership_transfer",
                "schema_version": 1,
                "transfer_id": "00000000-0000-0000-0000-000000000001",
                "wsl_mirror_path": mirror,
                "wsl_mirror_path_sha256": hashlib.sha256(mirror.encode()).hexdigest(),
            }
        )
    )

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="WSL owns"):
        orchestrator.prepare_additional(tmp_path)
    assert not (tmp_path / orchestrator.DATABASE_PATH).exists()


def test_wsl_parity_binds_all_paid_lineage_and_exact_payload_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    _sqlite_fixture(durable / orchestrator.DATABASE_PATH, "durable")
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)
    orchestrator.begin_wsl_state_transfer(durable, mirror)
    monkeypatch.setattr(orchestrator, "_tracked_tree_sha256", lambda root: "2" * 64)
    monkeypatch.setattr(
        orchestrator,
        "validate_reference_additional_authority",
        lambda root, path: orchestrator.REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    )
    monkeypatch.setattr(orchestrator, "validate_reproduced_request", lambda *a, **k: None)
    files = {
        "eval.json": b'{"evaluation":true}',
        "provenance.json": b'{"provenance":true}',
        "runtime.json": b'{"runtime":true}',
    }
    for name, content in files.items():
        (mirror / name).write_bytes(content)
    workspace = "4" * 64
    scope = "5" * 64
    auth_binding = {
        "authenticated_workspace_identity_sha256": workspace,
        "kind": "reference_modal_workspace_auth_binding",
        "original_workspace_scope_sha256": scope,
        "provider": "modal",
        "reconciliation_authority_sha256": (
            orchestrator.REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
        ),
        "schema_version": 2,
    }
    auth_binding_bytes = orchestrator.canonical_bytes(auth_binding)
    auth = {
        "binding_sha256": hashlib.sha256(auth_binding_bytes).hexdigest(),
        "kind": "reference_modal_workspace_auth_receipt",
    }
    provider = {"sdk_version": "1.2.3"}
    for relative, value in (
        (orchestrator.AUTH_BINDING_PATH, auth_binding),
        (orchestrator.AUTH_RECEIPT_PATH, auth),
        (orchestrator.PROVIDER_CAPABILITY_PATH, provider),
    ):
        path = mirror / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(orchestrator.canonical_bytes(value))
    monkeypatch.setattr(orchestrator, "_configured_workspace_scope", lambda root: scope)
    monkeypatch.setattr(
        orchestrator,
        "validate_workspace_scope_reconciliation_authority",
        lambda root: {
            "authenticated_workspace_identity_sha256": workspace,
            "original_workspace_scope_sha256": scope,
        },
    )
    monkeypatch.setattr(orchestrator, "_validate_fresh_auth_receipt", lambda *a, **k: None)
    monkeypatch.setattr(
        orchestrator,
        "_validated_provider_capability",
        lambda root, request: {"sdk_version": "1.2.3"},
    )
    monkeypatch.setattr(orchestrator, "_manifest_identity", lambda value: "6" * 64)
    evaluation_sha = hashlib.sha256(files["eval.json"]).hexdigest()
    runtime_sha = hashlib.sha256(files["runtime.json"]).hexdigest()
    config = SimpleNamespace(
        challenge_sha256="7" * 64,
        reference_execution_scope_sha256="8" * 64,
        sha256="3" * 64,
        authority_files={
            "evaluation_lock_path": "eval.json",
            "provenance_manifest_path": "provenance.json",
            "runtime_receipt_path": "runtime.json",
        },
        inputs={
            "evaluation_lock_sha256": evaluation_sha,
            "provenance_manifest_sha256": "6" * 64,
            "reviewed_commit_sha256": "f" * 40,
            "runtime_receipt_sha256": runtime_sha,
        },
    )
    payload = b"exact-modal-hydration"

    receipt = orchestrator.record_wsl_execution_parity(
        mirror,
        durable,
        config=config,
        request_bytes=b"request",
        serialized_payload=payload,
        serialized_payload_confirmation=payload,
    )

    assert receipt["database_integrity"] == "ok"
    assert receipt["git_head"] == "f" * 40
    assert receipt["git_tracked_tree_sha256"] == "2" * 64
    assert receipt["serialized_payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert receipt["serialized_payload_size_bytes"] == len(payload)
    assert receipt["provider_sdk_version"] == "1.2.3"
    assert receipt["provider_contacted"] is False
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="reproduction drift"):
        orchestrator.record_wsl_execution_parity(
            mirror,
            durable,
            config=config,
            request_bytes=b"request",
            serialized_payload=payload,
            serialized_payload_confirmation=b"drift",
        )


def test_terminal_wsl_return_is_hash_verified_recoverable_and_clears_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    durable_db = durable / orchestrator.DATABASE_PATH
    _sqlite_fixture(durable_db, "durable")
    durable_before = durable_db.read_bytes()
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)
    transfer = orchestrator.begin_wsl_state_transfer(durable, mirror)
    marker_bytes = (durable / orchestrator.WSL_TRANSFER_MARKER_PATH).read_bytes()
    scope = "7" * 64
    request = b'{"request":true}'
    parity = {
        "kind": "reference_wsl_execution_parity_receipt",
        "marker_sha256": transfer["marker_sha256"],
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "schema_version": 1,
        "transfer_id": transfer["transfer_id"],
        "execution_scope_sha256": scope,
    }
    parity_bytes = orchestrator.canonical_bytes(parity)
    parity_path = mirror / orchestrator.WSL_PARITY_RECEIPT_PATH
    parity_path.parent.mkdir(parents=True, exist_ok=True)
    parity_path.write_bytes(parity_bytes)
    parity_generation = (
        mirror
        / orchestrator.WSL_PARITY_HISTORY_ROOT
        / f"{hashlib.sha256(parity_bytes).hexdigest()}.json"
    )
    parity_generation.parent.mkdir(parents=True)
    parity_generation.write_bytes(parity_bytes)
    identity = orchestrator.canonical_bytes({"identity": True})
    report = orchestrator.canonical_bytes({"rows": []})
    pre = orchestrator.canonical_bytes({"pre": True})
    post = orchestrator.canonical_bytes({"post": True})
    settlement = orchestrator.canonical_bytes(
        {
            "additional_authority_sha256": orchestrator.REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
            "execution_manifest_sha256": None,
            "execution_receipt_sha256": None,
            "execution_scope_sha256": scope,
            "filtered_report_sha256": hashlib.sha256(report).hexdigest(),
            "identity_evidence_sha256": hashlib.sha256(identity).hexdigest(),
            "kind": orchestrator.ADDITIONAL_RECEIPT_KIND,
            "post_auth_receipt_sha256": hashlib.sha256(post).hexdigest(),
            "pre_auth_receipt_sha256": hashlib.sha256(pre).hexdigest(),
            "schema_version": 1,
        }
    )
    for relative, content in (
        (orchestrator.ADDITIONAL_REQUEST_PATH, request),
        (orchestrator.ADDITIONAL_IDENTITY_EVIDENCE_PATH, identity),
        (orchestrator.ADDITIONAL_BILLING_REPORT_PATH, report),
        (orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH, settlement),
        (orchestrator.auth_receipt_path(hashlib.sha256(pre).hexdigest()), pre),
        (orchestrator.auth_receipt_path(hashlib.sha256(post).hexdigest()), post),
    ):
        path = mirror / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    mirror_db = mirror / orchestrator.DATABASE_PATH
    import sqlite3

    connection = sqlite3.connect(mirror_db)
    connection.execute("UPDATE state SET value = 'settled' WHERE value = 'durable'")
    connection.commit()
    connection.close()
    monkeypatch.setattr(
        orchestrator,
        "reference_status",
        lambda root: {
            "additional": {"state": "settled-failure", "execution_scope_sha256": scope}
        },
    )

    returned = orchestrator.return_wsl_state(durable, mirror)

    assert returned["terminal_state"] == "settled-failure"
    assert returned["database_sha256"] == hashlib.sha256(mirror_db.read_bytes()).hexdigest()
    assert durable_db.read_bytes() == mirror_db.read_bytes()
    assert not (durable / orchestrator.WSL_TRANSFER_MARKER_PATH).exists()
    history = durable / orchestrator.WSL_TRANSFER_HISTORY_ROOT / f"{transfer['transfer_id']}.json"
    assert history.read_bytes() == marker_bytes
    backups = list((durable / orchestrator.WSL_DATABASE_BACKUP_ROOT).glob("*.sqlite"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == durable_before
    assert (durable / orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH).read_bytes() == settlement
    assert (
        durable / orchestrator.WSL_PARITY_HISTORY_ROOT / parity_generation.name
    ).read_bytes() == parity_bytes
    assert not (durable / "weights").exists()

    monkeypatch.setattr(
        orchestrator,
        "reference_status",
        lambda root: {
            "additional": {"state": "settled-success", "execution_evidence_recorded": True},
            "proven_useful_context_tokens": None,
        },
    )
    proposal = orchestrator.compile_u9_proposal(durable)
    assert proposal["status"] == "proposal"
    assert proposal["configured_context_tokens"] == 262144
    assert proposal["proven_useful_context_tokens"] is None


def test_nonterminal_wsl_state_cannot_clear_ownership_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    durable = tmp_path / "durable"
    mirror = tmp_path / "mirror"
    durable.mkdir()
    mirror.mkdir()
    _sqlite_fixture(durable / orchestrator.DATABASE_PATH, "durable")
    monkeypatch.setattr(orchestrator, "_require_wsl_ext4_root", lambda root: None)
    transfer = orchestrator.begin_wsl_state_transfer(durable, mirror)
    parity_path = mirror / orchestrator.WSL_PARITY_RECEIPT_PATH
    parity_path.parent.mkdir(parents=True, exist_ok=True)
    parity_path.write_bytes(
        orchestrator.canonical_bytes(
            {
                "marker_sha256": transfer["marker_sha256"],
                "transfer_id": transfer["transfer_id"],
            }
        )
    )
    monkeypatch.setattr(
        orchestrator,
        "reference_status",
        lambda root: {"additional": {"state": "audit-blocked"}},
    )

    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="not terminal"):
        orchestrator.return_wsl_state(durable, mirror)
    assert (durable / orchestrator.WSL_TRANSFER_MARKER_PATH).exists()


def test_execute_additional_proves_parity_before_reservation_and_submits_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "mirror"
    durable = tmp_path / "durable"
    root.mkdir()
    durable.mkdir()
    config_path = root / orchestrator.CONFIG_PATH
    config_path.parent.mkdir(parents=True)
    config_path.write_bytes(b"config")
    events: list[str] = []
    config = SimpleNamespace(
        experiment_id="experiment",
        sha256="1" * 64,
        challenge_sha256="2" * 64,
        canonical_json=json.dumps(
            {
                "inputs": {},
                "gates": {"formula_approval_sha256": "3" * 64},
                "provider": {"trust_override_sha256": "4" * 64},
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        inputs={"runtime_receipt_sha256": "5" * 64},
        reference_execution_scope_sha256="6" * 64,
    )
    capability = _capability(root)
    binding = additional_reference_binding(
        config_sha256=config.sha256,
        config_challenge_sha256=config.challenge_sha256,
        request_sha256=hashlib.sha256(b"request").hexdigest(),
        execution_scope_sha256=config.reference_execution_scope_sha256,
    )
    graphs = [
        PreparedModalGraph(
            SerializedRemoteCallable(lambda: None, b"payload"), object(), object(), object()
        )
        for _ in range(2)
    ]

    class Database:
        def __init__(self, path: Path) -> None:
            pass

        def initialize(self) -> None:
            events.append("initialize")

        def reserve_reference_run(self, **kwargs: object) -> None:
            assert kwargs["additional_authority_sha256"] == REFERENCE_ADDITIONAL_AUTHORITY_SHA256
            assert kwargs["total_cap_usd"] == "4.00564445"
            events.append("reserve")

    monkeypatch.setattr(orchestrator, "ResultsDatabase", Database)
    monkeypatch.setattr(orchestrator, "_watchdog_ready", lambda: None)
    monkeypatch.setattr(orchestrator, "provider_environment_overrides_present", lambda: False)
    monkeypatch.setattr(
        orchestrator,
        "prepare_additional",
        lambda root: (config, b"request", capability, binding),
    )
    monkeypatch.setattr(orchestrator, "observe_topology", lambda path: events.append("topology"))
    monkeypatch.setattr(
        orchestrator,
        "verify_workspace_auth",
        lambda root: {"authenticated_workspace_identity_sha256": "7" * 64},
    )
    monkeypatch.setattr(
        orchestrator,
        "record_wsl_execution_parity",
        lambda *args, **kwargs: events.append("parity") or {"parity_receipt_sha256": "8" * 64},
    )
    monkeypatch.setattr(modal_adapter, "validate_reference_preflight", lambda cap: None)
    monkeypatch.setattr(modal_adapter, "prepare_local_modal_graph", lambda cap: graphs.pop(0))
    monkeypatch.setattr(
        modal_adapter,
        "submit_reference",
        lambda cap, graph: events.append("submit")
        or {
            "status": "failed",
            "full_context_usefulness_proven": False,
        },
    )

    result = orchestrator.execute_additional(
        root, durable, confirm_request_sha256=hashlib.sha256(b"request").hexdigest()
    )

    assert result["status"] == "failed"
    assert events.count("submit") == 1
    assert events.index("parity") < events.index("reserve") < events.index("submit")


def test_u9_proposal_is_locked_until_successful_settlement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator,
        "reference_status",
        lambda root: {"additional": {"state": "settled-failure"}},
    )
    with pytest.raises(orchestrator.ReferenceOrchestratorError, match="successful settled"):
        orchestrator.compile_u9_proposal(tmp_path)
    assert not (tmp_path / orchestrator.U9_PROPOSAL_PATH).exists()


def test_u9_success_emits_proposal_only_without_candidate_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = tmp_path / orchestrator.ADDITIONAL_SETTLEMENT_RECEIPT_PATH
    receipt.parent.mkdir(parents=True)
    receipt.write_bytes(b'{"settled":true}')
    monkeypatch.setattr(
        orchestrator,
        "reference_status",
        lambda root: {
            "additional": {
                "state": "settled-success",
                "execution_evidence_recorded": True,
            },
            "proven_useful_context_tokens": None,
        },
    )

    proposal = orchestrator.compile_u9_proposal(tmp_path)

    assert proposal["status"] == "proposal"
    assert proposal["thresholds"] == {}
    assert proposal["candidate_execution_authorized"] is False
    assert proposal["numeric_threshold_approval_authorized"] is False
    assert proposal["configured_context_tokens"] == 262144
    assert proposal["proven_useful_context_tokens"] is None
