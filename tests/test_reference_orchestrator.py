from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import lowbit_lab.reference_orchestrator as orchestrator
from lowbit_lab.reference_modal_adapter import ReferenceModalCapability


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
        ]
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
        ]
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
        }
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
        }
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
        orchestrator._validate_frozen_inputs(
            frozen, inventory, changed, "f" * 64, "3" * 64
        )


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
    provider_path.write_text(
        json.dumps({"billing": {"environment_identity": "environment"}}), encoding="utf-8"
    )
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

    capability = orchestrator._capability(tmp_path, config, b"request")

    assert capability.evaluation_lock_bytes == orchestrator.canonical_bytes(evaluation)
    assert capability.evaluation_lock_bytes != evaluation_path.read_bytes()


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


def test_paid_request_reproduction_rejects_artifact_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        orchestrator, "build_bootstrap_request", lambda root, config: b"expected"
    )
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
    monkeypatch.setattr(
        orchestrator, "prepare", lambda root: (config, request, unreserved)
    )
    monkeypatch.setattr(orchestrator, "observe_topology", lambda path: calls.append("topology"))
    monkeypatch.setattr(orchestrator, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(orchestrator, "confine_results_db", lambda root, path: root / path)
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.validate_reference_preflight",
        lambda capability: calls.append("preflight"),
    )
    monkeypatch.setattr(
        "lowbit_lab.reference_modal_adapter.submit_reference",
        lambda capability: calls.append(("submit", capability)) or {"status": "settlement_pending"},
    )

    result = orchestrator.execute(
        tmp_path, confirm_request_sha256=orchestrator._sha(request)
    )

    assert result == {"status": "settlement_pending"}
    assert calls.count("topology") == 1
    assert calls.count("preflight") == 1
    assert ("reserve", "4.00") in calls
    submitted = next(item[1] for item in calls if isinstance(item, tuple) and item[0] == "submit")
    assert submitted.reservation_id
    assert submitted.owner_id
    assert submitted.bootstrap_request_bytes == request


def test_cli_failure_is_sanitized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert orchestrator.main(["--root", str(tmp_path), "prepare"]) == 1
    output = json.loads(capsys.readouterr().err)
    assert output == {
        "command": "prepare",
        "error": "ReferenceOrchestratorError",
        "ok": False,
        "provider_contacted": False,
    }
