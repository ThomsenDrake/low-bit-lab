from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import lowbit_lab.reference_modal_adapter as adapter
from lowbit_lab.reference_modal_adapter import ReferenceModalError


def test_remote_contract_rejects_unbound_or_noncanonical_input() -> None:
    with pytest.raises(ReferenceModalError, match="schema drift"):
        adapter.validate_remote_contract_bytes(b"{}")
    with pytest.raises(ReferenceModalError, match="invalid JSON"):
        adapter.validate_remote_contract_bytes(b"not-json")


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
            assert path == tmp_path / "results.sqlite"

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            events.append("pending")

        def mark_reference_provider_prepared(self, *args, **kwargs) -> None:
            events.append(("prepared", kwargs["provider_image_identity"], kwargs["app_identity"]))

        def mark_reservation_submitted(self, *args, **kwargs) -> None:
            events.append(("submitted", kwargs["provider_job_id"], kwargs["app_identity"]))

        def mark_settlement_pending(self, *args, **kwargs) -> None:
            events.append("settlement_pending")

        def mark_reference_audit_blocked(self, *args, **kwargs) -> None:
            events.append("audit_blocked")

    class FakeCall:
        object_id = "fc-one"

        def get(self, *, timeout: int):
            assert timeout == 2700
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
    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(adapter, "_validate_fresh_deterministic_gates", lambda capability: None)
    monkeypatch.setattr(adapter, "validate_bootstrap_request_bytes", lambda value: object())
    monkeypatch.setattr(adapter, "validate_remote_contract_bytes", lambda value: {})
    monkeypatch.setattr(adapter, "build_remote_contract", lambda *args, **kwargs: b"contract")
    monkeypatch.setattr(
        adapter, "_serialized_remote_callable", lambda: (lambda value: {}, b"blob", ())
    )
    monkeypatch.setattr(adapter, "_clear_serialization_policy", lambda modules: None)
    monkeypatch.setattr(adapter, "_image_from_lock", lambda modal, lock: fake_image)
    monkeypatch.setattr(
        adapter, "validate_remote_result", lambda value, capability: {"status": "failed"}
    )

    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results.sqlite",
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
    assert adapter.submit_reference(capability) == {"status": "failed"}
    assert events == [
        "pending",
        "decorate",
        "run",
        "build",
        ("prepared", "im-one", "ap-one"),
        "spawn",
        ("submitted", "fc-one", "ap-one"),
        "get",
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

        def mark_reference_submission_pending(self, *args, **kwargs) -> None:
            boundaries.append("pending")

    monkeypatch.setattr(adapter, "ResultsDatabase", FakeDatabase)
    monkeypatch.setattr(
        adapter,
        "_validate_fresh_deterministic_gates",
        lambda capability: (_ for _ in ()).throw(ReferenceModalError("dirty tree")),
    )
    capability = adapter.ReferenceModalCapability(
        db_path=tmp_path / "results.sqlite",
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
    with pytest.raises(ReferenceModalError, match="deterministic remote contract gate failed"):
        adapter.submit_reference(capability)
    assert boundaries == []
