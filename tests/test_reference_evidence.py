from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import lowbit_lab.reference_evidence as module
from lowbit_lab.reference_evidence import (
    FiniteBound,
    ReferenceEvidenceError,
    canonical_bytes,
    canonical_sha256,
    derive_cold_path_evidence,
    derive_memory_fit_evidence,
    verify_cold_path_evidence_reproducible,
    verify_memory_evidence_reproducible,
    write_canonical,
)
from lowbit_lab.reference_gates import verify_cold_path_time_evidence, verify_memory_fit_evidence


def _write(path: Path, value: object) -> str:
    data = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _sources(tmp_path: Path, *, layer_count_matches: bool = True) -> dict[str, object]:
    values = {
        "inventory": {"index": {"tensor_bytes": 1000}},
        "architecture": {
            "text_config": {
                "dtype": "bfloat16",
                "mamba_ssm_dtype": "float32",
                "head_dim": 8,
                "layer_types": ["linear_attention", "full_attention"],
                "num_hidden_layers": 2 if layer_count_matches else 3,
                "max_position_embeddings": 128,
                "num_key_value_heads": 2,
                "linear_num_key_heads": 2,
                "linear_key_head_dim": 4,
                "linear_num_value_heads": 3,
                "linear_value_head_dim": 5,
                "linear_conv_kernel_dim": 4,
            }
        },
        "runtime": {"schema_version": 1, "kind": "runtime_receipt"},
        "image": {
            "schema_version": 1,
            "kind": "reference_image_build_identity",
            "proven": True,
            "resolved_image_identity": "sha256:resolved",
            "blockers": [],
        },
        "evaluation": {"context": {"configured_tokens": 128, "usefulness_proven": False}},
    }
    result: dict[str, object] = {"maximum_context_tokens": 128}
    for name, value in values.items():
        path = tmp_path / f"{name}.json"
        result[f"{name}_path" if name != "architecture" else "architecture_path"] = path
        digest_name = {
            "inventory": "inventory_sha256",
            "architecture": "architecture_sha256",
            "runtime": "runtime_receipt_sha256",
            "image": "image_build_identity_sha256",
            "evaluation": "evaluation_lock_sha256",
        }[name]
        path_name = {
            "runtime": "runtime_receipt_path",
            "image": "image_build_identity_path",
            "evaluation": "evaluation_lock_path",
        }.get(name)
        if path_name:
            result[path_name] = result.pop(f"{name}_path")
        result[digest_name] = _write(path, value)
    return result


def _scope(sources: dict[str, object]) -> dict[str, object]:
    return {
        "weight_inventory_sha256": sources["inventory_sha256"],
        "runtime_receipt_sha256": sources["runtime_receipt_sha256"],
        "image_build_identity_sha256": sources["image_build_identity_sha256"],
        "evaluation_lock_sha256": sources["evaluation_lock_sha256"],
        "maximum_context_tokens": 128,
    }


def _bound(
    tmp_path: Path, sources: dict[str, object], metric: str, value: int, direction: str
) -> FiniteBound:
    unit = "seconds" if metric.endswith("seconds") else "bytes"
    receipt = {
        "schema_version": 1,
        "kind": "reference_finite_bound_receipt",
        "metric": metric,
        "value": value,
        "bound_direction": direction,
        "unit": unit,
        "source_locator": "/value",
        "arithmetic": "measured maximum plus fixed reserve",
        "rounding": "ceiling_to_integer_second"
        if unit == "seconds"
        else ("floor_to_integer_byte" if direction == "lower" else "ceiling_to_integer_byte"),
        "valid_for_context_tokens": 128,
        "scope": _scope(sources),
    }
    digest = canonical_sha256(receipt)
    path = tmp_path / "receipts" / f"{digest}.json"
    write_canonical(path, receipt)
    return FiniteBound(path, digest)


def test_unapproved_caller_receipts_cannot_prove_fit(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    bounds = {
        "runtime_overhead_bound": _bound(tmp_path, sources, "runtime_overhead_bytes", 200, "upper"),
        "allocator_reserve_bound": _bound(
            tmp_path, sources, "allocator_reserve_bytes", 300, "upper"
        ),
        "usable_gpu_memory_bound": _bound(
            tmp_path, sources, "usable_gpu_memory_bytes", 10000, "lower"
        ),
    }
    _, evidence = derive_memory_fit_evidence(**sources, **bounds)
    assert evidence["proven"] is False
    assert all("not_independently_authorized" in x for x in evidence["blockers"])


def test_hybrid_cache_includes_full_kv_recurrent_and_conv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources = _sources(tmp_path)
    bounds = {
        "runtime_overhead_bound": _bound(tmp_path, sources, "runtime_overhead_bytes", 200, "upper"),
        "allocator_reserve_bound": _bound(
            tmp_path, sources, "allocator_reserve_bytes", 300, "upper"
        ),
        "usable_gpu_memory_bound": _bound(
            tmp_path, sources, "usable_gpu_memory_bytes", 10000, "lower"
        ),
    }
    monkeypatch.setattr(
        module,
        "APPROVED_FINITE_BOUND_RECEIPT_SHA256S",
        frozenset(x.receipt_sha256 for x in bounds.values()),
    )
    method, evidence = derive_memory_fit_evidence(**sources, **bounds)
    # full KV=8192, recurrent=2*4*3*5*4=480, conv=3*(8+15)*4=276
    assert method["cache_state_inputs"]["full_attention_kv_bytes"] == 8192
    assert method["cache_state_inputs"]["linear_recurrent_state_bytes"] == 480
    assert method["cache_state_inputs"]["linear_conv_state_bytes"] == 276
    assert evidence["required_bytes"] == 1000 + 8192 + 480 + 276 + 200 + 300
    assert evidence["proven"] is False  # 10,448 > 10,000


def test_layer_type_count_drift_fails_closed(tmp_path: Path) -> None:
    sources = _sources(tmp_path, layer_count_matches=False)
    method, evidence = derive_memory_fit_evidence(**sources)
    assert method["cache_state_inputs"] is None
    assert "cache_state_architecture_unknown" in evidence["blockers"]


def test_receipt_scope_value_and_hash_are_verified(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    bound = _bound(tmp_path, sources, "runtime_overhead_bytes", 200, "upper")
    raw = json.loads(bound.receipt_path.read_text())
    raw["scope"]["maximum_context_tokens"] = 127
    bound.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ReferenceEvidenceError, match="SHA-256 mismatch"):
        derive_memory_fit_evidence(**sources, runtime_overhead_bound=bound)


def test_cold_path_binds_all_runtime_inputs_and_stays_unproven(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    args = {
        k: v for k, v in sources.items() if k != "architecture_path" and k != "architecture_sha256"
    }
    method, evidence = derive_cold_path_evidence(**args, timeout_seconds=2700)
    assert method["bindings"]["weight_inventory_sha256"] == sources["inventory_sha256"]
    assert method["bindings"]["runtime_receipt_sha256"] == sources["runtime_receipt_sha256"]
    assert (
        method["bindings"]["image_build_identity_sha256"] == sources["image_build_identity_sha256"]
    )
    assert evidence["proven"] is False
    assert len(evidence["blockers"]) == 5


def test_unresolved_image_identity_is_an_explicit_blocker(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    image_path = sources["image_build_identity_path"]
    assert isinstance(image_path, Path)
    unresolved = {
        "schema_version": 1,
        "kind": "reference_image_build_identity",
        "proven": False,
        "resolved_image_identity": None,
        "blockers": ["provider_image_identity_unresolved"],
    }
    sources["image_build_identity_sha256"] = _write(image_path, unresolved)
    _, evidence = derive_memory_fit_evidence(**sources)
    assert evidence["proven"] is False
    assert "image_build_identity_unproven" in evidence["blockers"]


def test_schema_v2_reproducibility_and_gate_binding(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    method, evidence = derive_memory_fit_evidence(**sources)
    method_path, evidence_path = tmp_path / "memory-method.json", tmp_path / "memory.json"
    method_sha, evidence_sha = (
        write_canonical(method_path, method),
        write_canonical(evidence_path, evidence),
    )
    assert verify_memory_evidence_reproducible(
        method_path=method_path,
        method_sha256=method_sha,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha,
        inventory_path=sources["inventory_path"],
        architecture_path=sources["architecture_path"],
        expected_architecture_sha256=str(sources["architecture_sha256"]),
        runtime_receipt_path=sources["runtime_receipt_path"],
        image_build_identity_path=sources["image_build_identity_path"],
        evaluation_lock_path=sources["evaluation_lock_path"],
        receipt_root=tmp_path / "receipts",
    )
    result = verify_memory_fit_evidence(
        evidence_path,
        expected_sha256=evidence_sha,
        expected_inventory_sha256=str(sources["inventory_sha256"]),
        expected_tensor_bytes=1000,
        expected_method_sha256=method_sha,
        expected_evaluation_lock_sha256=str(sources["evaluation_lock_sha256"]),
        expected_maximum_context_tokens=128,
        expected_runtime_receipt_sha256=str(sources["runtime_receipt_sha256"]),
        expected_image_build_identity_sha256=str(sources["image_build_identity_sha256"]),
        require_schema_v2=True,
    )
    assert result.proven is False

    cold_args = {
        k: v for k, v in sources.items() if k not in {"architecture_path", "architecture_sha256"}
    }
    cold_method, cold_evidence = derive_cold_path_evidence(**cold_args, timeout_seconds=2700)
    cp, ep = tmp_path / "cold-method.json", tmp_path / "cold.json"
    cs, es = write_canonical(cp, cold_method), write_canonical(ep, cold_evidence)
    assert verify_cold_path_evidence_reproducible(
        method_path=cp,
        method_sha256=cs,
        evidence_path=ep,
        evidence_sha256=es,
        inventory_path=sources["inventory_path"],
        runtime_receipt_path=sources["runtime_receipt_path"],
        image_build_identity_path=sources["image_build_identity_path"],
        evaluation_lock_path=sources["evaluation_lock_path"],
        receipt_root=tmp_path / "receipts",
    )
    assert not verify_cold_path_time_evidence(
        ep,
        expected_sha256=es,
        timeout_seconds=2700,
        expected_method_sha256=cs,
        expected_evaluation_lock_sha256=str(sources["evaluation_lock_sha256"]),
        expected_maximum_context_tokens=128,
        expected_inventory_sha256=str(sources["inventory_sha256"]),
        expected_runtime_receipt_sha256=str(sources["runtime_receipt_sha256"]),
        expected_image_build_identity_sha256=str(sources["image_build_identity_sha256"]),
        require_schema_v2=True,
    ).proven


def test_declared_architecture_digest_drift_blocks_reproduction(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    method, evidence = derive_memory_fit_evidence(**sources)
    method_path, evidence_path = tmp_path / "memory-method.json", tmp_path / "memory.json"
    method_sha = write_canonical(method_path, method)
    evidence_sha = write_canonical(evidence_path, evidence)

    with pytest.raises(ReferenceEvidenceError, match="architecture metadata binding mismatch"):
        verify_memory_evidence_reproducible(
            method_path=method_path,
            method_sha256=method_sha,
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha,
            inventory_path=sources["inventory_path"],
            architecture_path=sources["architecture_path"],
            expected_architecture_sha256="f" * 64,
            runtime_receipt_path=sources["runtime_receipt_path"],
            image_build_identity_path=sources["image_build_identity_path"],
            evaluation_lock_path=sources["evaluation_lock_path"],
            receipt_root=tmp_path / "receipts",
        )


def test_source_bytes_are_hash_bound_and_method_bytes_are_canonical(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    inventory_path = sources["inventory_path"]
    assert isinstance(inventory_path, Path)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    sources["inventory_sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    _, source_evidence = derive_memory_fit_evidence(**sources)
    assert source_evidence["inventory_sha256"] == sources["inventory_sha256"]

    sources = _sources(tmp_path / "canonical")
    method, evidence = derive_memory_fit_evidence(**sources)
    method_path = tmp_path / "noncanonical-method.json"
    method_path.write_text(json.dumps(method, sort_keys=True), encoding="utf-8")
    evidence_path = tmp_path / "evidence.json"
    evidence_sha = write_canonical(evidence_path, evidence)
    with pytest.raises(ReferenceEvidenceError, match="canonical JSON bytes"):
        verify_memory_evidence_reproducible(
            method_path=method_path,
            method_sha256=hashlib.sha256(method_path.read_bytes()).hexdigest(),
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha,
            inventory_path=sources["inventory_path"],
            architecture_path=sources["architecture_path"],
            expected_architecture_sha256=str(sources["architecture_sha256"]),
            runtime_receipt_path=sources["runtime_receipt_path"],
            image_build_identity_path=sources["image_build_identity_path"],
            evaluation_lock_path=sources["evaluation_lock_path"],
            receipt_root=tmp_path / "receipts",
        )


def test_duplicate_json_keys_are_rejected_even_with_matching_digest(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    inventory_path = sources["inventory_path"]
    assert isinstance(inventory_path, Path)
    inventory_path.write_bytes(b'{"index":{"tensor_bytes":1000},"index":{"tensor_bytes":1}}\n')
    sources["inventory_sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    with pytest.raises(ReferenceEvidenceError, match="duplicate keys"):
        derive_memory_fit_evidence(**sources)
