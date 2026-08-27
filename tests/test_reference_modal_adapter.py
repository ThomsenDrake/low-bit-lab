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


def _prepared(entry=None, payload: bytes = b"blob") -> adapter.SerializedRemoteCallable:
    return adapter.SerializedRemoteCallable(
        entry=(lambda value: {}) if entry is None else entry,
        payload=payload,
    )


def _prepared_graph() -> adapter.PreparedModalGraph:
    return adapter.PreparedModalGraph(
        serialized=_prepared(),
        image=object(),
        app=object(),
        remote=object(),
    )


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


def test_fresh_preflight_consumes_flat_validated_provider_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lowbit_lab.modal_job as modal_job
    import lowbit_lab.reference_authority as reference_authority
    import lowbit_lab.reference_orchestrator as orchestrator
    import lowbit_lab.runtime as runtime

    request_path = Path("reports/local/request.json")
    image_path = Path("configs/modal/image.json")
    provider_path = Path("reports/local/provider.json")
    evaluation_path = Path("eval/local/evaluation.json")
    for path, content in (
        (request_path, b"request"),
        (image_path, b"{}"),
        (provider_path, b"provider"),
        (evaluation_path, b'{"fixtures":[]}\n'),
    ):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    canonical_evaluation = b'{"fixtures":[]}'
    resources = {"gpu_type": "A100-80GB"}
    identity = {
        "weight_inventory_sha256": "1" * 64,
        "provenance_manifest_sha256": "2" * 64,
        "runtime_receipt_sha256": "3" * 64,
        "reviewed_commit_sha256": "4" * 40,
        "resource_spec_sha256": adapter._sha(adapter._canonical_json(resources)),
    }
    request_raw = {
        "lineage": {
            "reviewed_commit": "4" * 40,
            "control_plane_sha256": "6" * 64,
            "evaluation_lock_sha256": adapter._sha(canonical_evaluation),
        },
        "provider_capability": {"receipt_sha256": "7" * 64},
    }
    request = SimpleNamespace(
        canonical_json=json.dumps(request_raw),
        sha256=adapter._sha(b"request"),
        image_lock_sha256=adapter._sha(b"{}"),
    )
    config = SimpleNamespace(
        sha256="8" * 64,
        reference_execution_scope_sha256="9" * 64,
        authority_files={"evaluation_lock_path": evaluation_path.as_posix()},
        inputs={
            **identity,
            "evaluation_lock_sha256": adapter._sha(b'{"fixtures":[]}\n'),
        },
        resources=resources,
    )
    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results/local/reference.sqlite",
        root=tmp_path,
        config_path=Path("configs/local/reference.yaml"),
        request_path=request_path,
        image_lock_path=image_path,
        provider_capability_path=provider_path,
        billing_authority_path=Path("reports/local/billing-authority.json"),
        billing_receipt_path=Path("reports/local/billing-receipt.json"),
        billing_report_path=Path("reports/local/billing-report.json"),
        publication_manifest_path=Path("reports/publication.json"),
        reservation_id="",
        owner_id="",
        authority_root=tmp_path,
        provider_environment="validated-environment",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=canonical_evaluation,
        fixture_bytes={},
        execution_identity=identity,
        image_lock={},
    )
    preview = {
        "bootstrap_ready": True,
        "submit": False,
        "actual_cost_usd": "0",
        "weights_transferred": False,
        "request_sha256": request.sha256,
        "image_lock_sha256": request.image_lock_sha256,
        "configured_context_tokens": 262144,
        "proven_useful_context_tokens": None,
        "empirical": {"memory": "pending", "timing": "pending"},
    }
    monkeypatch.setattr(
        reference_authority, "validate_reference_signed_cdn_authority", lambda _r: None
    )
    monkeypatch.setattr(adapter, "validate_topology_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(modal_job, "load_reference_job_config", lambda *_a, **_k: config)
    monkeypatch.setattr(modal_job, "plan_reference_bootstrap_preview", lambda *_a, **_k: preview)
    monkeypatch.setattr(orchestrator, "validate_reproduced_request", lambda *_a, **_k: None)
    monkeypatch.setattr(
        runtime,
        "runtime_metadata",
        lambda _r: {
            "git_dirty": False,
            "git_commit": "4" * 40,
            "control_plane_sha256": "6" * 64,
        },
    )
    monkeypatch.setattr(adapter, "validate_bootstrap_request_bytes", lambda _b: request)
    monkeypatch.setattr(
        adapter,
        "validate_provider_capability_receipt",
        lambda *_a, **_k: {"provider_environment": "validated-environment"},
    )
    monkeypatch.setattr(
        adapter, "validate_image_lock", lambda _v: SimpleNamespace(recipe_sha256="a" * 64)
    )
    monkeypatch.setattr(adapter, "validate_execution_identity", lambda value: dict(value))

    evidence = adapter.validate_reference_preflight(capability)

    assert evidence.provider_environment == "validated-environment"


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
    _, payload, modules = adapter._build_serialized_remote_callable()
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
    assert len(payload) > adapter.MODAL_SERIALIZED_FUNCTION_MAX_BYTES
    adapter._clear_serialization_policy(modules)


def test_modal_hydration_uses_the_exact_cached_audited_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry, payload, modules = adapter._build_serialized_remote_callable()
    try:
        from modal._utils.function_utils import FunctionInfo

        info = FunctionInfo(entry, serialized=True)
        remote = SimpleNamespace(_info=info)
        prepared = adapter.SerializedRemoteCallable(entry=entry, payload=payload)
        adapter._bind_cached_hydration_payload(remote, prepared)
        monkeypatch.setattr(
            "modal._serialization.serialize",
            lambda value: (_ for _ in ()).throw(AssertionError("must use cached bytes")),
        )
        assert info.serialized_function() is payload
    finally:
        adapter._clear_serialization_policy(modules)


@pytest.mark.parametrize(
    ("payload_size", "accepted"),
    (
        (adapter.MODAL_SERIALIZED_FUNCTION_MAX_BYTES, True),
        (adapter.MODAL_SERIALIZED_FUNCTION_MAX_BYTES + 1, False),
    ),
)
def test_serialized_callable_enforces_exact_modal_cap_and_cleans_on_rejection(
    monkeypatch: pytest.MonkeyPatch, payload_size: int, accepted: bool
) -> None:
    modules = (object(),)
    cleared: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        adapter,
        "_build_serialized_remote_callable",
        lambda: (lambda value: {}, b"x" * payload_size, modules),
    )
    monkeypatch.setattr(adapter, "_clear_serialization_policy", cleared.append)

    if accepted:
        prepared = adapter.prepare_serialized_remote_callable()
        assert len(prepared.payload) == adapter.MODAL_SERIALIZED_FUNCTION_MAX_BYTES
        assert cleared == [modules]
    else:
        with pytest.raises(adapter.ReferenceModalError, match="provider cap"):
            adapter.prepare_serialized_remote_callable()
        assert cleared == [modules]


def test_graph_preflight_failure_is_audited_without_run_or_reservation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = Path("configs/local/reference.yaml")
    config = tmp_path / config_path
    config.parent.mkdir(parents=True)
    config.write_bytes(b"config")
    capability = SimpleNamespace(
        root=tmp_path,
        config_path=config_path,
        image_lock={},
    )
    monkeypatch.setattr(
        adapter,
        "prepare_serialized_remote_callable",
        lambda: (_ for _ in ()).throw(
            ReferenceModalError("serialized function exceeds provider cap")
        ),
    )

    with pytest.raises(ReferenceModalError, match="provider cap"):
        adapter.prepare_local_modal_graph(capability)

    database = adapter.ResultsDatabase(tmp_path / "results/local/reference.sqlite")
    with database.connect() as connection:
        attempts = connection.execute(
            "SELECT status, run_id, failure_reason FROM attempts"
        ).fetchall()
        reservations = connection.execute(
            "SELECT reservation_id FROM budget_reservations"
        ).fetchall()
    assert [tuple(row) for row in attempts] == [
        ("failed", None, "local_provider_graph_preflight_failed")
    ]
    assert reservations == []


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
    monkeypatch.setattr(adapter, "_validate_modal_sdk_boundary", lambda capability: None)
    monkeypatch.setattr(
        adapter,
        "_bind_cached_hydration_payload",
        lambda remote, prepared: events.append("bind_cached_payload"),
    )
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
        replacement_entitlement_sha256=None,
        provider_environment="low-bit-lab",
        bootstrap_request_bytes=b"request",
        evaluation_lock_bytes=b"lock",
        fixture_bytes={},
        execution_identity={},
        image_lock={},
    )
    monkeypatch.setattr(adapter, "prepare_serialized_remote_callable", _prepared)
    prepared_graph = adapter.prepare_local_modal_graph(capability)
    result = adapter.submit_reference(capability, prepared_graph)
    assert result["status"] == "failed"
    assert result["full_context_usefulness_proven"] is False
    assert (tmp_path / str(result["receipt_path"])).read_bytes() == b"receipt"
    assert events == [
        "decorate",
        "bind_cached_payload",
        "attempt_received",
        "attempt_linked",
        "pending",
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
        adapter.submit_reference(capability, _prepared_graph())
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
        adapter.submit_reference(capability, _prepared_graph())
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
    monkeypatch.setattr(adapter, "_validate_modal_sdk_boundary", lambda capability: None)
    capability = SimpleNamespace(
        root=tmp_path,
        config_path=Path("config.yaml"),
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
        replacement_entitlement_sha256=None,
    )
    with pytest.raises(ReferenceModalError, match="requires audit"):
        adapter.submit_reference(capability, _prepared_graph())
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
        adapter.prepare_serialized_remote_callable()
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
    monkeypatch.setattr(adapter, "_validate_modal_sdk_boundary", lambda capability: None)
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
        adapter.submit_reference(capability, _prepared_graph())


def test_replacement_boundary_consumes_entitlement_instead_of_original_slot(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeDatabase:
        def mark_reference_submission_pending(self, *args: object, **kwargs: object) -> None:
            calls.append(("original", kwargs))

        def mark_reference_replacement_submission_pending(
            self, *args: object, **kwargs: object
        ) -> None:
            calls.append(("replacement", kwargs))

    capability = SimpleNamespace(
        reservation_id="replacement-reservation",
        owner_id="owner",
        authority_root=tmp_path,
        replacement_entitlement_sha256="a" * 64,
        recovery_authority_sha256=adapter.REFERENCE_RECOVERY_AUTHORITY_SHA256,
        replacement_original_workspace_scope_sha256="8" * 64,
        replacement_authenticated_workspace_identity_sha256="7" * 64,
        workspace_reconciliation_authority_sha256="9" * 64,
        replacement_auth_binding_sha256="6" * 64,
    )

    adapter._mark_submission_pending(FakeDatabase(), capability, "2026-08-27T02:00:00+00:00")

    assert [name for name, _ in calls] == ["replacement"]
    assert calls[0][1]["entitlement_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "override_key",
    [
        "MODAL_TOKEN_ID",
        "MODAL_SERVER_URL",
        "MODAL_OVERRIDE_HEADERS",
        "MODAL_FUTURE_SETTING",
        "HTTPS_PROXY",
        "PYTHONPATH",
    ],
)
def test_replacement_boundary_rejects_ambient_modal_override_before_consumption(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, override_key: str
) -> None:
    events: list[str] = []

    class FakeDatabase:
        def __init__(self, path: Path) -> None:
            pass

        def create_attempt(self, *args: object, **kwargs: object) -> None:
            events.append("received")

        def get_reservation(self, reservation_id: str) -> dict[str, str]:
            return {
                "run_id": "run-one",
                "owner_id": "owner",
                "reference_execution_scope_sha256": "scope",
            }

        def get_run(self, run_id: str) -> dict[str, str]:
            return {"config_sha256": "config"}

        def link_attempt(self, *args: object, **kwargs: object) -> None:
            events.append("linked")

        def mark_reference_replacement_submission_pending(
            self, *args: object, **kwargs: object
        ) -> None:
            events.append("pending")

    monkeypatch.setenv(override_key, "must-not-be-read")
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
        reservation_id="reservation",
        owner_id="owner",
        authority_root=tmp_path,
        replacement_entitlement_sha256="a" * 64,
        replacement_original_workspace_scope_sha256="8" * 64,
        replacement_authenticated_workspace_identity_sha256="7" * 64,
        workspace_reconciliation_authority_sha256="9" * 64,
        replacement_auth_binding_sha256="6" * 64,
    )
    with pytest.raises(ReferenceModalError, match="boundary authentication failed"):
        adapter.submit_reference(capability, _prepared_graph())
    assert events == ["received", "linked"]
