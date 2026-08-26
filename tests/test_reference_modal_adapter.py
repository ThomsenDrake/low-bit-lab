from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import lowbit_lab.reference_modal_adapter as adapter
from lowbit_lab.constants import EVALUATION_FAMILIES
from lowbit_lab.reference_modal_adapter import ReferenceModalError


class FakeDeadlineSignal:
    SIGALRM = 1
    ITIMER_REAL = 0
    SIG_DFL = 0

    def signal(self, signum: int, handler: object) -> None:
        return None

    def setitimer(self, which: int, seconds: float) -> None:
        pass


def test_remote_contract_rejects_unbound_or_noncanonical_input() -> None:
    with pytest.raises(ReferenceModalError, match="schema drift"):
        adapter.validate_remote_contract_bytes(b"{}")
    with pytest.raises(ReferenceModalError, match="invalid JSON"):
        adapter.validate_remote_contract_bytes(b"not-json")


def test_evaluation_lock_transport_canonicalizes_persisted_json() -> None:
    persisted = b'{\n  "fixtures": []\n}\n'
    assert adapter._canonical_evaluation_lock_bytes(persisted) == b'{"fixtures":[]}'
    with pytest.raises(ReferenceModalError, match="evaluation lock bytes drift"):
        adapter._canonical_evaluation_lock_bytes(b"not-json")


def test_remote_result_binds_manifest_bytes_to_the_validated_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = {
        "provenance_manifest_sha256": "a" * 64,
        "resource_spec_sha256": "b" * 64,
        "reviewed_commit_sha256": "c" * 40,
        "runtime_receipt_sha256": "d" * 64,
        "weight_inventory_sha256": "e" * 64,
    }
    manifest_raw = {
        "evaluation_lock_sha256": "a" * 64,
        "execution_identity": identity,
        "executor_identity": {"runtime_sha256": "f" * 64, "scorer_sha256": "0" * 64},
        "kind": "reference_metrics",
        "measurements": [
            {
                "context_level_tokens": 262144 if family == "long_context_retrieval" else 1,
                "family": family,
                "fixture_id": f"fixture-{family}",
                "metrics": {"score": 1.0},
                "response_bytes": 1,
                "response_sha256": "1" * 64,
                "response_tokens": 1,
                "status": "completed",
            }
            for family in EVALUATION_FAMILIES
        ],
        "schema_version": 1,
        "status": "completed",
    }
    manifest = json.dumps(manifest_raw, sort_keys=True, separators=(",", ":")).encode()
    provider_image_identity = "im-one"
    receipt_raw = {
        "stages": [
            {
                "stage": "runtime_identity",
                "status": "completed",
                "measurements": {
                    "image_identity_sha256": hashlib.sha256(
                        provider_image_identity.encode()
                    ).hexdigest()
                },
            },
            {
                "stage": "evaluation",
                "measurements": {
                    "reference_manifest_bytes": len(manifest),
                    "reference_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                },
            },
        ]
    }
    receipt = json.dumps(receipt_raw, sort_keys=True, separators=(",", ":")).encode()
    validated_receipt = SimpleNamespace(
        canonical_json=receipt.decode(),
        status="succeeded",
        full_context_usefulness_proven=True,
    )
    monkeypatch.setattr(
        adapter,
        "validate_bootstrap_request_bytes",
        lambda value: SimpleNamespace(context_ladder_tokens=(262144,)),
    )
    monkeypatch.setattr(
        adapter, "validate_bootstrap_receipt_bytes", lambda value, request: validated_receipt
    )
    monkeypatch.setattr(
        adapter,
        "validate_pending_evaluation_lock",
        lambda value, fixture_bytes: SimpleNamespace(sha256="a" * 64),
    )
    capability = SimpleNamespace(
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"{}",
        fixture_bytes={},
        execution_identity=identity,
    )
    value = {
        "contract_sha256": "a" * 64,
        "kind": adapter.REMOTE_RESULT_KIND,
        "manifest_b64": base64.b64encode(manifest).decode(),
        "receipt_b64": base64.b64encode(receipt).decode(),
        "schema_version": 1,
    }
    result = adapter.validate_remote_result(
        value, capability, provider_image_identity=provider_image_identity
    )
    assert result.manifest == manifest
    assert result.full_context_usefulness_proven is True

    value["manifest_b64"] = base64.b64encode(b"tampered").decode()
    with pytest.raises(ReferenceModalError, match="manifest hash binding drift"):
        adapter.validate_remote_result(
            value, capability, provider_image_identity=provider_image_identity
        )

    value["manifest_b64"] = base64.b64encode(manifest).decode()
    with pytest.raises(ReferenceModalError, match="provider image identity binding drift"):
        adapter.validate_remote_result(value, capability, provider_image_identity="im-other")

    capability.execution_identity = {**identity, "resource_spec_sha256": "2" * 64}
    with pytest.raises(ReferenceModalError, match="execution identity binding drift"):
        adapter.validate_remote_result(
            value, capability, provider_image_identity=provider_image_identity
        )


def test_remote_result_preserves_valid_runtime_failure_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace(sha256="a" * 64, context_ladder_tokens=(262144,))
    receipt_raw = {
        "configured_context_tokens": 262144,
        "empirical_facts": {
            "cold_path_timing": False,
            "context_usefulness": False,
            "empirical_fit": False,
            "provider_image_identity": False,
            "runtime_allocator_overhead": False,
            "usable_gpu_memory": False,
        },
        "full_context_usefulness_proven": False,
        "kind": "reference_bootstrap_receipt",
        "max_completed_context_tokens": 0,
        "request_sha256": request.sha256,
        "schema_version": 1,
        "stages": [
            {
                "elapsed_ms": 0,
                "failure_code": "malformed_metrics",
                "kind": "reference_bootstrap_stage_receipt",
                "measurements": {
                    "device_free_bytes": 0,
                    "device_total_bytes": 0,
                    "image_identity_sha256": "0" * 64,
                    "runtime_identity_sha256": "0" * 64,
                },
                "ordinal": 0,
                "remaining_ms": 2700000,
                "request_sha256": request.sha256,
                "schema_version": 1,
                "stage": "runtime_identity",
                "status": "failed",
            }
        ],
        "status": "failed",
        "terminal_failure": {"code": "malformed_metrics", "stage": "runtime_identity"},
    }
    receipt = json.dumps(receipt_raw, sort_keys=True, separators=(",", ":")).encode()
    monkeypatch.setattr(adapter, "validate_bootstrap_request_bytes", lambda value: request)
    capability = SimpleNamespace(bootstrap_request_bytes=b"request")
    result = adapter.validate_remote_result(
        {
            "contract_sha256": "a" * 64,
            "kind": adapter.REMOTE_RESULT_KIND,
            "manifest_b64": None,
            "receipt_b64": base64.b64encode(receipt).decode(),
            "schema_version": 1,
        },
        capability,
        provider_image_identity="im-one",
    )
    assert result.status == "failed"
    assert result.receipt == receipt

    receipt_raw["stages"][0]["measurements"]["image_identity_sha256"] = "2" * 64
    drifted = json.dumps(receipt_raw, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ReferenceModalError, match="sentinel drift"):
        adapter.validate_remote_result(
            {
                "contract_sha256": "a" * 64,
                "kind": adapter.REMOTE_RESULT_KIND,
                "manifest_b64": None,
                "receipt_b64": base64.b64encode(drifted).decode(),
                "schema_version": 1,
            },
            capability,
            provider_image_identity="im-one",
        )


def test_image_recipe_uses_digest_and_every_hashed_url(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = {
        "base_image": {"reference": "registry.example/runtime", "digest": "sha256:" + "a" * 64},
        "dependency_artifacts": [
            {"url": "https://example.invalid/a.whl", "sha256": "b" * 64},
        ],
        "recipe": {"dependency_filenames": ["a.whl"]},
    }
    image_lock = SimpleNamespace(canonical_json=adapter._canonical_json(raw).decode())
    monkeypatch.setattr(adapter, "validate_image_lock", lambda value: image_lock)

    calls: list[object] = []

    class FakeImage:
        def pip_install(self, *urls: str, extra_options: str):
            calls.append((urls, extra_options))
            return self

    class FakeModal:
        class Image:
            @staticmethod
            def from_registry(reference: str) -> FakeImage:
                calls.append(reference)
                return FakeImage()

    adapter._image_from_lock(FakeModal, {})
    assert calls[0] == "registry.example/runtime@sha256:" + "a" * 64
    assert calls[1] == (
        ("https://example.invalid/a.whl#sha256=" + "b" * 64,),
        "--no-deps --require-hashes",
    )


def test_image_recipe_treats_hostile_url_as_one_pip_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = {
        "base_image": {"reference": "registry.example/runtime", "digest": "sha256:" + "a" * 64},
        "dependency_artifacts": [
            {"url": "https://example.invalid/a.whl;touch-should-not-run", "sha256": "b" * 64},
        ],
        "recipe": {"dependency_filenames": ["a.whl"]},
    }
    image_lock = SimpleNamespace(canonical_json=adapter._canonical_json(raw).decode())
    monkeypatch.setattr(adapter, "validate_image_lock", lambda value: image_lock)
    calls: list[tuple[tuple[str, ...], str]] = []

    class FakeImage:
        def pip_install(self, *urls: str, extra_options: str):
            calls.append((urls, extra_options))
            return self

    class FakeModal:
        class Image:
            @staticmethod
            def from_registry(reference: str) -> FakeImage:
                return FakeImage()

    adapter._image_from_lock(FakeModal, {})
    assert calls[0][0] == ("https://example.invalid/a.whl;touch-should-not-run#sha256=" + "b" * 64,)


def test_serialized_callable_round_trips_without_repository_on_import_path(tmp_path: Path) -> None:
    """The function blob, not a package mount, supplies its reviewed validation code."""
    _, payload, modules = adapter._serialized_remote_callable()
    payload_path = tmp_path / "reference-entry.bin"
    payload_path.write_bytes(payload)
    site_packages = Path(sys.executable).parent.parent / "Lib" / "site-packages"
    code = (
        "import sys;"
        f"sys.path.insert(0, r'{site_packages}');"
        "from modal._vendor import cloudpickle;"
        f"entry=cloudpickle.loads(open(r'{payload_path}','rb').read());"
        "\ntry: entry(b'{}')\nexcept Exception as exc: print(type(exc).__name__, str(exc))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code], check=False, capture_output=True, text=True
    )
    assert completed.returncode == 0
    assert "ReferenceModalError remote contract schema drift" in completed.stdout
    assert "low-bit-lab" not in completed.stderr
    assert len(payload) < 16 << 20
    adapter._clear_serialization_policy(modules)


def test_modal_hydration_serializer_matches_the_audited_function_bytes() -> None:
    entry, payload, modules = adapter._serialized_remote_callable()
    try:
        from modal._utils.function_utils import FunctionInfo

        assert FunctionInfo(entry, serialized=True).serialized_function() == payload
    finally:
        adapter._clear_serialization_policy(modules)


def test_fake_modal_persists_image_then_call_identity_and_uses_one_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[object] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            assert path == tmp_path / "results/local/reference.sqlite"

        def create_attempt(self, *args, **kwargs) -> None:
            events.append("attempt_received")

        def get_reservation(self, reservation_id: str) -> dict[str, str]:
            return {
                "run_id": "run-one",
                "owner_id": "owner",
                "reference_execution_scope_sha256": "scope",
            }

        def get_run(self, run_id: str) -> dict[str, str]:
            return {"config_sha256": "config"}

        def link_attempt(self, *args, **kwargs) -> None:
            events.append("attempt_linked")

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            events.append("pending")

        def mark_reference_provider_prepared(self, *args, **kwargs) -> None:
            events.append(("prepared", kwargs["provider_image_identity"], kwargs["app_identity"]))

        def mark_reservation_submitted(self, *args, **kwargs) -> None:
            events.append(("submitted", kwargs["provider_job_id"], kwargs["app_identity"]))

        def mark_settlement_pending(self, *args, **kwargs) -> None:
            events.append("settlement_pending")

        def add_artifact(self, *args, **kwargs) -> None:
            events.append(("artifact", kwargs["kind"]))

        def mark_reference_audit_blocked(self, *args, **kwargs) -> None:
            events.append("audit_blocked")

    class FakeCall:
        object_id = "fc-one"

        def get(self, *, timeout: int):
            assert 0 < timeout <= 2700
            events.append("get")
            return {
                "contract_sha256": adapter._sha(b"contract"),
                "kind": adapter.REMOTE_RESULT_KIND,
                "manifest_b64": None,
                "receipt_b64": "",
                "schema_version": 1,
            }

    class FakeFunction:
        def spawn(self, content: bytes) -> FakeCall:
            assert content == b"contract"
            events.append("spawn")
            return FakeCall()

    class FakeImage:
        object_id = "im-one"

        def build(self, app) -> None:
            assert app.app_id == "ap-one"
            events.append("build")

    class FakeRun:
        def __enter__(self):
            events.append("run")
            return self

        def __exit__(self, *unused) -> None:
            events.append("run_exit")

    class FakeApp:
        app_id = "ap-one"

        def __init__(self, name: str, *, image, include_source: bool) -> None:
            assert name == "low-bit-lab-reference-u8"
            assert include_source is False
            assert image.object_id == "im-one"

        def run(self, *, environment_name: str) -> FakeRun:
            assert environment_name == "low-bit-lab"
            return FakeRun()

        def function(self, **kwargs):
            assert kwargs == {
                "image": fake_image,
                "gpu": "A100-80GB:1",
                "cpu": 8,
                "memory": 98304,
                "ephemeral_disk": 524288,
                "timeout": 2700,
                "retries": 0,
                "max_containers": 1,
                "include_source": False,
                "serialized": True,
                "restrict_modal_access": True,
                "single_use_containers": True,
            }
            events.append("decorate")
            return lambda callable_: FakeFunction()

    fake_image = FakeImage()
    fake_modal = SimpleNamespace(App=FakeApp)
    monkeypatch.setitem(sys.modules, "modal", fake_modal)
    monkeypatch.setattr(adapter, "_local_deadline_signal", lambda: FakeDeadlineSignal())
    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(
        adapter,
        "validate_reference_preflight",
        lambda capability: adapter.FreshDeterministicEvidence(
            provider_environment="low-bit-lab",
            execution_identity={},
            config_sha256="config",
            reference_execution_scope_sha256="scope",
        ),
    )
    monkeypatch.setattr(adapter, "validate_bootstrap_request_bytes", lambda value: object())
    monkeypatch.setattr(adapter, "validate_remote_contract_bytes", lambda value: {})
    monkeypatch.setattr(adapter, "build_remote_contract", lambda *args, **kwargs: b"contract")
    monkeypatch.setattr(
        adapter, "_serialized_remote_callable", lambda: (lambda value: {}, b"blob", ())
    )
    monkeypatch.setattr(adapter, "_clear_serialization_policy", lambda modules: None)
    monkeypatch.setattr(adapter, "_image_from_lock", lambda modal, lock: fake_image)
    monkeypatch.setattr(
        adapter,
        "validate_remote_result",
        lambda value, capability, **kwargs: adapter.ValidatedRemoteResult(
            status="failed",
            receipt=b"receipt",
            receipt_sha256=adapter._sha(b"receipt"),
            manifest=None,
            manifest_sha256=None,
            full_context_usefulness_proven=False,
        ),
    )

    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results/local/reference.sqlite",
        root=tmp_path,
        config_path=Path("config.yaml"),
        request_path=Path("request.json"),
        image_lock_path=Path("image-lock.json"),
        provider_capability_path=Path("provider.json"),
        billing_authority_path=Path("billing-authority.json"),
        billing_receipt_path=Path("billing-receipt.json"),
        billing_report_path=Path("billing-report.json"),
        publication_manifest_path=Path("publication.json"),
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
        provider_environment="low-bit-lab",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"lock",
        fixture_bytes={},
        execution_identity={},
        image_lock={},
    )
    result = adapter.submit_reference(capability)
    assert result["status"] == "failed"
    assert result["full_context_usefulness_proven"] is False
    assert (tmp_path / str(result["receipt_path"])).read_bytes() == b"receipt"
    assert events == [
        "attempt_received",
        "attempt_linked",
        "pending",
        "decorate",
        "run",
        "build",
        ("prepared", "im-one", "ap-one"),
        "spawn",
        ("submitted", "fc-one", "ap-one"),
        "get",
        ("artifact", "bootstrap_receipt"),
        "settlement_pending",
        "run_exit",
    ]


def test_fresh_preview_failure_prevents_the_database_boundary_and_modal_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    boundaries: list[str] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            pass

        def create_attempt(self, *args, **kwargs) -> None:
            boundaries.append(f"attempt_received:{kwargs['config_path']}")

        def fail_attempt(self, *args, **kwargs) -> None:
            boundaries.append("attempt_failed")

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            boundaries.append("pending")

    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(
        adapter,
        "validate_reference_preflight",
        lambda capability: (_ for _ in ()).throw(ReferenceModalError("dirty tree")),
    )
    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results/local/reference.sqlite",
        root=tmp_path,
        config_path=tmp_path.parent / "private" / "config.yaml",
        request_path=Path("request.json"),
        image_lock_path=Path("image-lock.json"),
        provider_capability_path=Path("provider.json"),
        billing_authority_path=Path("billing-authority.json"),
        billing_receipt_path=Path("billing-receipt.json"),
        billing_report_path=Path("billing-report.json"),
        publication_manifest_path=Path("publication.json"),
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
        provider_environment="low-bit-lab",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"lock",
        fixture_bytes={},
        execution_identity={},
        image_lock={},
    )
    with pytest.raises(ReferenceModalError, match="deterministic remote contract gate failed"):
        adapter.submit_reference(capability)
    assert boundaries == ["attempt_received:invalid", "attempt_failed"]


def test_missing_reservation_is_recorded_as_a_failed_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            pass

        def create_attempt(self, *args, **kwargs) -> None:
            events.append("received")

        def get_reservation(self, reservation_id: str) -> dict[str, str]:
            raise adapter.DatabaseError("missing")

        def fail_attempt(self, *args, **kwargs) -> None:
            events.append("failed")

    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(adapter, "_local_deadline_signal", lambda: FakeDeadlineSignal())
    monkeypatch.setattr(
        adapter,
        "validate_reference_preflight",
        lambda capability: adapter.FreshDeterministicEvidence(
            provider_environment="low-bit-lab",
            execution_identity={},
            config_sha256="config",
            reference_execution_scope_sha256="scope",
        ),
    )
    monkeypatch.setattr(adapter, "build_remote_contract", lambda *args, **kwargs: b"contract")
    capability = SimpleNamespace(
        root=tmp_path,
        config_path=Path("config.yaml"),
        reservation_id="missing",
        owner_id="owner",
    )
    with pytest.raises(ReferenceModalError, match="deterministic remote contract gate failed"):
        adapter.submit_reference(capability)
    assert events == ["received", "failed"]


@pytest.mark.parametrize("watchdog_failure", ["handler", "timer"])
def test_watchdog_install_failure_after_boundary_is_audit_blocked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, watchdog_failure: str
) -> None:
    events: list[str] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            pass

        def create_attempt(self, *args, **kwargs) -> None:
            events.append("received")

        def get_reservation(self, reservation_id: str) -> dict[str, str]:
            return {
                "run_id": "run-one",
                "owner_id": "owner",
                "reference_execution_scope_sha256": "scope",
            }

        def get_run(self, run_id: str) -> dict[str, str]:
            return {"config_sha256": "config"}

        def link_attempt(self, *args, **kwargs) -> None:
            events.append("linked")

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            events.append("pending")

        def mark_reference_audit_blocked(self, *args, **kwargs) -> None:
            events.append("audit_blocked")

    class FailingSignal(FakeDeadlineSignal):
        def signal(self, signum: int, handler: object) -> None:
            if watchdog_failure == "handler":
                raise RuntimeError("handler install failed")
            return None

        def setitimer(self, which: int, seconds: float) -> None:
            if watchdog_failure == "timer" and seconds > 0:
                raise RuntimeError("timer arm failed")

    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(adapter, "_local_deadline_signal", lambda: FailingSignal())
    monkeypatch.setattr(
        adapter,
        "validate_reference_preflight",
        lambda capability: adapter.FreshDeterministicEvidence(
            provider_environment="low-bit-lab",
            execution_identity={},
            config_sha256="config",
            reference_execution_scope_sha256="scope",
        ),
    )
    monkeypatch.setattr(adapter, "build_remote_contract", lambda *args, **kwargs: b"contract")
    capability = SimpleNamespace(
        root=tmp_path,
        config_path=Path("config.yaml"),
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
    )
    with pytest.raises(ReferenceModalError, match="requires audit"):
        adapter.submit_reference(capability)
    assert events == ["received", "linked", "pending", "audit_blocked"]


def test_serialization_failure_clears_every_registered_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered: list[object] = []
    unregistered: list[object] = []
    monkeypatch.setattr("modal._vendor.cloudpickle.register_pickle_by_value", registered.append)
    monkeypatch.setattr("modal._vendor.cloudpickle.unregister_pickle_by_value", unregistered.append)
    monkeypatch.setattr(
        "modal._serialization.serialize", lambda value: (_ for _ in ()).throw(RuntimeError())
    )
    with pytest.raises(RuntimeError):
        adapter._serialized_remote_callable()
    assert registered
    assert unregistered == registered


def test_audit_block_persistence_failure_is_fatal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            pass

        def create_attempt(self, *args, **kwargs) -> None:
            pass

        def get_reservation(self, reservation_id: str) -> dict[str, str]:
            return {
                "run_id": "run-one",
                "owner_id": "owner",
                "reference_execution_scope_sha256": "scope",
            }

        def get_run(self, run_id: str) -> dict[str, str]:
            return {"config_sha256": "config"}

        def link_attempt(self, *args, **kwargs) -> None:
            pass

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            pass

        def mark_reference_audit_blocked(self, *args, **kwargs) -> None:
            raise adapter.DatabaseError("write failed")

    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(adapter, "_local_deadline_signal", lambda: FakeDeadlineSignal())
    monkeypatch.setattr(
        adapter,
        "validate_reference_preflight",
        lambda capability: adapter.FreshDeterministicEvidence(
            provider_environment="low-bit-lab",
            execution_identity={},
            config_sha256="config",
            reference_execution_scope_sha256="scope",
        ),
    )
    monkeypatch.setattr(adapter, "build_remote_contract", lambda *args, **kwargs: b"contract")
    monkeypatch.setitem(sys.modules, "modal", SimpleNamespace())
    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results/local/reference.sqlite",
        root=tmp_path,
        config_path=Path("config.yaml"),
        request_path=Path("request.json"),
        image_lock_path=Path("image-lock.json"),
        provider_capability_path=Path("provider.json"),
        billing_authority_path=Path("billing-authority.json"),
        billing_receipt_path=Path("billing-receipt.json"),
        billing_report_path=Path("billing-report.json"),
        publication_manifest_path=Path("publication.json"),
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
        provider_environment="low-bit-lab",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"lock",
        fixture_bytes={},
        execution_identity={},
        image_lock={},
    )
    with pytest.raises(ReferenceModalError, match="could not be durably audit-blocked"):
        adapter.submit_reference(capability)
