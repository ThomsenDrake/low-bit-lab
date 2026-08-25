from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from lowbit_lab.constants import EVALUATION_FAMILIES
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.reference_backend import (
    ProductionReferenceBackend,
    build_execution_dependencies,
)
from lowbit_lab.reference_bootstrap import BootstrapRequest, canonical_json, canonical_sha256
from lowbit_lab.reference_execution import ExecutionFailure, StoredArtifact
from lowbit_lab.reference_harness import ReferenceObservation, ReferenceRequest

SHA = "a" * 64
METRICS = {
    "coding": ["exact_match"],
    "tool_call_validity": ["schema_valid_rate"],
    "long_context_retrieval": ["retrieval_accuracy"],
    "throughput": ["decode_tokens_per_second"],
    "memory": ["peak_vram_bytes"],
    "soak": ["failure_free_rate", "runtime_errors", "completed_minutes"],
}


def _execution_identity() -> dict[str, str]:
    return {
        "weight_inventory_sha256": "1" * 64,
        "provenance_manifest_sha256": "2" * 64,
        "runtime_receipt_sha256": "3" * 64,
        "reviewed_commit_sha256": "4" * 40,
        "resource_spec_sha256": "5" * 64,
    }


def _evaluation_lock(ladder: list[int] | None = None):
    materials = {
        family: json.dumps({"case_id": family, "input": "synthetic"}).encode()
        for family in EVALUATION_FAMILIES
    }
    materials["long_context_retrieval"] = json.dumps(
        {
            "expected": "violet",
            "id": "retrieval-1",
            "needle": "The verification color is violet.",
            "prompt": "What is the verification color?",
        }
    ).encode()
    fixtures = [
        {
            "family": family,
            "fixture_id": f"generic-{family}",
            "version": f"1.0.{index}",
            "sha256": hashlib.sha256(materials[family]).hexdigest(),
            "source": {
                "classification": "synthetic",
                "reference": f"generated-{index}",
                "license": "CC0-1.0",
            },
            "seed": 100 + index,
            "scorer_id": "deterministic-json-scorer",
            "metrics": METRICS[family],
        }
        for index, family in enumerate(EVALUATION_FAMILIES, 1)
    ]
    levels = ladder or [8192, 262144]
    raw = {
        "schema_version": 2,
        "suite_id": "generic-evaluation-suite",
        "suite_version": "2.0.0",
        "fixtures": fixtures,
        "fixture_order": [item["fixture_id"] for item in fixtures],
        "scorer": {
            "id": "deterministic-json-scorer",
            "version": "1.0.0",
            "sha256": "b" * 64,
            "runtime": {"id": "python", "version": "3.12", "sha256": "c" * 64},
        },
        "generation": {
            "batch_size": 1,
            "do_sample": False,
            "temperature": "0",
            "top_p": "1",
            "response_caps_tokens": {family: 1 for family in EVALUATION_FAMILIES},
            "response_caps_bytes": {family: 32 for family in EVALUATION_FAMILIES},
        },
        "metrics": METRICS,
        "aggregation": {"method": "arithmetic_mean", "missing": "fail"},
        "confidence": {
            "method": "bootstrap_percentile",
            "level": "0.95",
            "resamples": 10,
            "seed": 7,
        },
        "context": {
            "configured_tokens": 262144,
            "ladder_tokens": levels,
            "stop_on_first_failure": True,
            "runtime_initialized": False,
            "usefulness_proven": False,
            "retrieval_evidence_sha256": None,
        },
        "resources": {
            "weights_required": False,
            "allow_cloud_upload": False,
            "remote_submission_enabled": False,
            "scheduling_enabled": False,
            "destructive_cleanup_enabled": False,
            "requested_cloud_cost_usd": "0",
            "actual_cloud_cost_usd": "0",
            "max_wall_clock_seconds": 300,
            "max_ram_bytes": 1024,
            "max_vram_bytes": 1024,
        },
        "stop_policy": {
            name: "stop"
            for name in (
                "fixture_hash_mismatch",
                "privacy_violation",
                "scorer_drift",
                "resource_limit",
                "unknown_state",
            )
        },
        "threshold_authority": {"status": "absent"},
        "promotion_authorized": False,
        "candidate_execution": "blocked",
    }
    fixture_bytes = {f"generic-{family}": content for family, content in materials.items()}
    return validate_pending_evaluation_lock(raw, fixture_bytes=fixture_bytes), fixture_bytes


def _request(files: list[tuple[str, str, bytes]], lock_sha: str) -> BootstrapRequest:
    artifacts = [
        {
            "format": format_name,
            "ordinal": ordinal,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "url": f"https://artifacts.example/{name}",
        }
        for ordinal, (name, format_name, content) in enumerate(files)
    ]
    raw = {
        "approved_https_hosts": ["artifacts.example"],
        "configured_context_tokens": 262144,
        "context_ladder_tokens": [8192, 262144],
        "lineage": {"evaluation_lock_sha256": lock_sha},
        "source_artifacts": artifacts,
    }
    encoded = canonical_json(raw)
    return BootstrapRequest(
        canonical_json=encoded,
        sha256=canonical_sha256(raw),
        source_artifacts=tuple(artifacts),
        context_ladder_tokens=(8192, 262144),
        image_lock_sha256=SHA,
    )


def _files() -> list[tuple[str, str, bytes]]:
    config = json.dumps(
        {
            "architectures": ["ExampleForCausalLM"],
            "max_position_embeddings": 262144,
            "torch_dtype": "bfloat16",
        }
    ).encode()
    index = json.dumps(
        {"metadata": {"total_size": 4}, "weight_map": {"layer": "model.safetensors"}}
    ).encode()
    return [
        ("config.json", "json", config),
        ("model.safetensors.index.json", "json", index),
        ("model.safetensors", "safetensors", b"SAFE"),
        ("tokenizer.json", "tokenizer_data", b'{"version":"1.0"}'),
        ("tokenizer_config.json", "json", b'{"model_max_length":262144}'),
    ]


@dataclass
class FakeValue:
    dtype: str = "torch.bfloat16"
    device: str = "cuda:0"


@dataclass
class FakeModel:
    config: object
    values: list[FakeValue] = field(default_factory=lambda: [FakeValue()])

    def parameters(self):
        return iter(self.values)

    def buffers(self):
        return iter(())


class FakeRuntime:
    bfloat16 = object()

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path, dict[str, object]]] = []
        self.architectures = ["ExampleForCausalLM"]
        self.model_architectures = ["ExampleForCausalLM"]
        self.evaluate_calls: list[tuple[str, int]] = []

    def inspect_safetensors(self, path: Path) -> None:
        self.calls.append(("inspect", path, {}))

    def load_config(self, root: Path, **kwargs):
        self.calls.append(("config", root, kwargs))
        return type("Config", (), {"architectures": self.architectures, "auto_map": None})()

    def load_tokenizer(self, root: Path, **kwargs):
        self.calls.append(("tokenizer", root, kwargs))
        return object()

    def load_model(self, root: Path, **kwargs):
        self.calls.append(("model", root, kwargs))
        config = type("Config", (), {"architectures": self.model_architectures})()
        return FakeModel(config)

    def memory_before(self) -> int:
        return 1000

    def memory_peaks(self) -> tuple[int, int]:
        return 10, 20

    def evaluate_reference(
        self, bundle: object, request: ReferenceRequest, *, deadline_monotonic: float
    ) -> ReferenceObservation:
        del bundle, deadline_monotonic
        self.evaluate_calls.append((request.family, request.context_level_tokens))
        values = {
            "exact_match": 1.0,
            "pass_rate": 1.0,
            "schema_valid_rate": 1.0,
            "argument_accuracy": 1.0,
            "retrieval_accuracy": 1.0,
            "decode_tokens_per_second": 10.0,
            "peak_vram_bytes": 10,
            "failure_free_rate": 1.0,
            "runtime_errors": 0,
            "completed_minutes": 1.0,
        }
        response = b'{"arguments":{"value":4},"name":"report_result"}'
        return ReferenceObservation(
            status="completed",
            metrics={name: values[name] for name in request.metrics},
            response=response[: request.response_cap_bytes],
            generated_tokens=1,
        )


def _artifacts(root: Path, files, request) -> tuple[StoredArtifact, ...]:
    result = []
    for expected, (name, _, content) in zip(request.source_artifacts, files, strict=True):
        path = root / name
        path.write_bytes(content)
        result.append(
            StoredArtifact(
                ordinal=expected["ordinal"],
                format=expected["format"],
                size_bytes=expected["size_bytes"],
                sha256=expected["sha256"],
                handle=path,
            )
        )
    return tuple(result)


def _backend(tmp_path: Path, files=None, runtime=None, ladder=None):
    lock, fixtures = _evaluation_lock(ladder)
    actual_files = files or _files()
    request = _request(actual_files, lock.sha256)
    backend = ProductionReferenceBackend(
        request, lock, fixtures, _execution_identity(), runtime or FakeRuntime()
    )
    return backend, request, actual_files


def test_fake_small_safetensors_path_is_local_explicit_and_single_device(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    backend, request, files = _backend(tmp_path, runtime=runtime)
    loaded = backend.load(_artifacts(tmp_path, files, request))
    assert loaded.loaded is True
    calls = {name: kwargs for name, _, kwargs in runtime.calls if name != "inspect"}
    assert calls["config"] == {"local_files_only": True, "trust_remote_code": False}
    assert calls["tokenizer"] == {"local_files_only": True, "trust_remote_code": False}
    assert calls["model"] == {
        "device_map": {"": "cuda:0"},
        "local_files_only": True,
        "model_kind": "causal_lm",
        "dtype": runtime.bfloat16,
        "trust_remote_code": False,
        "use_safetensors": True,
    }
    deadline = time.monotonic() + 100
    assert (
        backend.evaluate_context(loaded.model, 8192, deadline_monotonic=deadline).completed is True
    )
    final = backend.evaluate_context(loaded.model, 262144, deadline_monotonic=deadline)
    assert final.completed is True and final.usefulness_proven is True
    assert final.manifest is not None
    manifest = json.loads(final.manifest)
    assert {item["family"] for item in manifest["measurements"]} == set(EVALUATION_FAMILIES)
    retrieval_calls = [
        call for call in runtime.evaluate_calls if call[0] == "long_context_retrieval"
    ]
    assert retrieval_calls == [("long_context_retrieval", 8192), ("long_context_retrieval", 262144)]


def test_production_dependency_graph_constructs_without_network_or_inference(
    tmp_path: Path,
) -> None:
    lock, fixtures = _evaluation_lock()
    files = _files()
    request = _request(files, lock.sha256)
    runtime = FakeRuntime()

    dependencies = build_execution_dependencies(
        request,
        lock,
        fixtures,
        _execution_identity(),
        artifact_root=tmp_path / "artifacts",
        image_identity_sha256="e" * 64,
        runtime=runtime,
    )

    assert dependencies.loader is dependencies.evaluator
    assert runtime.calls == []
    writer = dependencies.store.begin(0, request.source_artifacts[0]["size_bytes"])
    writer.write(files[0][2])
    assert writer.finish() == tmp_path / "artifacts" / "config.json"


def test_nested_text_config_selects_bound_image_text_factory(tmp_path: Path) -> None:
    files = _files()
    config = json.loads(files[0][2])
    config.pop("torch_dtype")
    config.pop("max_position_embeddings")
    config["text_config"] = {"dtype": "bfloat16", "max_position_embeddings": 262144}
    config["vision_config"] = {"model_type": "generic_vision"}
    files[0] = ("config.json", "json", json.dumps(config).encode())
    runtime = FakeRuntime()
    backend, request, _ = _backend(tmp_path, files=files, runtime=runtime)

    backend.load(_artifacts(tmp_path, files, request))

    model_call = next(call for call in runtime.calls if call[0] == "model")
    assert model_call[2]["model_kind"] == "image_text_to_text"


@pytest.mark.parametrize(
    "name,format_name",
    [
        ("pytorch_model.bin", "safetensors"),
        ("model.py", "text"),
        ("kernel.so", "text"),
        ("weights.pt", "safetensors"),
    ],
)
def test_executable_pickle_native_and_generic_torch_files_fail_before_loading(
    tmp_path: Path, name: str, format_name: str
) -> None:
    files = _files() + [(name, format_name, b"bad")]
    backend, request, _ = _backend(tmp_path, files=files)
    with pytest.raises(ExecutionFailure, match="unsafe_artifact"):
        backend.load(_artifacts(tmp_path, files, request))


def test_unbound_tokenizer_data_and_remote_code_fail_before_inference(tmp_path: Path) -> None:
    files = _files() + [("extra-tokenizer.json", "tokenizer_data", b"{}")]
    backend, request, _ = _backend(tmp_path, files=files)
    with pytest.raises(ExecutionFailure, match="unsafe_artifact"):
        backend.load(_artifacts(tmp_path, files, request))

    files = _files()
    config = json.loads(files[0][2])
    config["auto_map"] = {"AutoModel": "custom.Model"}
    files[0] = ("config.json", "json", json.dumps(config).encode())
    backend, request, _ = _backend(tmp_path, files=files)
    with pytest.raises(ExecutionFailure, match="remote_code"):
        backend.load(_artifacts(tmp_path, files, request))


@pytest.mark.parametrize("drift", ["dtype", "device"])
def test_dtype_device_and_architecture_drift_fail(tmp_path: Path, drift: str) -> None:
    runtime = FakeRuntime()
    backend, request, files = _backend(tmp_path, runtime=runtime)
    loaded = backend.load(_artifacts(tmp_path, files, request))
    if drift == "dtype":
        loaded.model.model.values[0].dtype = "torch.float32"
    if drift == "device":
        loaded.model.model.values[0].device = "cuda:1"
    with pytest.raises(ExecutionFailure, match=f"{drift}_drift"):
        backend.evaluate_context(loaded.model, 8192, deadline_monotonic=time.monotonic() + 100)


def test_architecture_drift_fails_during_load(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    runtime.model_architectures = ["OtherForCausalLM"]
    backend, request, files = _backend(tmp_path, runtime=runtime)
    with pytest.raises(ExecutionFailure, match="architecture_mismatch"):
        backend.load(_artifacts(tmp_path, files, request))


def test_context_ladder_or_evaluation_binding_drift_fails_before_inference(tmp_path: Path) -> None:
    lock, fixtures = _evaluation_lock([8192, 131072, 262144])
    files = _files()
    request = _request(files, lock.sha256)
    with pytest.raises(ExecutionFailure, match="context_ladder_drift"):
        ProductionReferenceBackend(request, lock, fixtures, _execution_identity(), FakeRuntime())

    lock, fixtures = _evaluation_lock()
    request = _request(files, lock.sha256)
    fixtures = dict(fixtures)
    fixtures["generic-coding"] = b'{"expected":"drift"}'
    with pytest.raises(ExecutionFailure, match="evaluation_lock_drift"):
        ProductionReferenceBackend(request, lock, fixtures, _execution_identity(), FakeRuntime())

    identity = _execution_identity()
    identity.pop("provenance_manifest_sha256")
    lock, fixtures = _evaluation_lock()
    request = _request(files, lock.sha256)
    with pytest.raises(ExecutionFailure, match="execution_identity_drift"):
        ProductionReferenceBackend(request, lock, fixtures, identity, FakeRuntime())

    lock, fixtures = _evaluation_lock()
    request = _request(files, "d" * 64)
    with pytest.raises(ExecutionFailure, match="evaluation_lock_drift"):
        ProductionReferenceBackend(request, lock, fixtures, _execution_identity(), FakeRuntime())


def test_artifact_metadata_and_local_path_are_exactly_bound(tmp_path: Path) -> None:
    backend, request, files = _backend(tmp_path)
    artifacts = list(_artifacts(tmp_path, files, request))
    artifacts[0] = replace(artifacts[0], sha256="f" * 64)
    with pytest.raises(ExecutionFailure, match="artifact_binding_drift"):
        backend.load(tuple(artifacts))

    outside = tmp_path.parent / "config.json"
    outside.write_bytes(files[0][2])
    artifacts = list(_artifacts(tmp_path, files, request))
    artifacts[0] = replace(artifacts[0], handle=outside)
    with pytest.raises(ExecutionFailure, match="artifact_root_drift"):
        backend.load(tuple(artifacts))
