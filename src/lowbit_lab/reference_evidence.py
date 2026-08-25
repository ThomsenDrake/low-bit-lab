from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lowbit_lab.config import SHA256_RE
from lowbit_lab.handoff import canonical_json
from lowbit_lab.reference_gates import A100_80GB_BYTES, MEMORY_FORMULA, TIME_FORMULA


class ReferenceEvidenceError(ValueError):
    pass


MEMORY_METHOD_ID = "reference-memory-upper-bounds"
MEMORY_METHOD_VERSION = "2.1.0"
COLD_PATH_METHOD_ID = "reference-cold-path-upper-bounds"
COLD_PATH_METHOD_VERSION = "2.1.0"

# A bound is an exact reviewed capability, not a caller assertion. The initial set is
# intentionally empty because current local metadata supplies no finite empirical bounds.
APPROVED_FINITE_BOUND_RECEIPT_SHA256S: frozenset[str] = frozenset()


@dataclass(frozen=True)
class FiniteBound:
    receipt_path: Path
    receipt_sha256: str


def canonical_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def write_canonical(path: Path, value: object) -> str:
    content = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _load_json(
    path: Path,
    expected_sha256: str,
    label: str,
    *,
    require_canonical: bool = True,
) -> tuple[dict[str, Any], str]:
    if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
        raise ReferenceEvidenceError(f"{label} expected digest must be a lowercase SHA-256")
    try:
        content = path.read_bytes()
        text = content.decode("utf-8")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ReferenceEvidenceError(f"{label} contains duplicate keys")
                result[key] = value
            return result

        value = json.loads(text, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceEvidenceError(f"cannot read {label}") from exc
    digest = hashlib.sha256(content).hexdigest()
    if digest != expected_sha256:
        raise ReferenceEvidenceError(f"{label} SHA-256 mismatch")
    if not isinstance(value, dict):
        raise ReferenceEvidenceError(f"{label} must be an object")
    if require_canonical and content != canonical_bytes(value):
        raise ReferenceEvidenceError(f"{label} must use canonical JSON bytes")
    return value, digest


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReferenceEvidenceError(f"{label} must be a positive integer")
    return value


def _closed(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReferenceEvidenceError(f"{label} schema is closed")
    return value


def _scope(
    *,
    inventory_sha256: str,
    runtime_receipt_sha256: str,
    image_build_identity_sha256: str,
    evaluation_lock_sha256: str,
    maximum_context_tokens: int,
) -> dict[str, object]:
    result: dict[str, object] = {
        "weight_inventory_sha256": inventory_sha256,
        "runtime_receipt_sha256": runtime_receipt_sha256,
        "image_build_identity_sha256": image_build_identity_sha256,
        "evaluation_lock_sha256": evaluation_lock_sha256,
        "maximum_context_tokens": maximum_context_tokens,
    }
    for name in result.keys() - {"maximum_context_tokens"}:
        if SHA256_RE.fullmatch(str(result[name])) is None:
            raise ReferenceEvidenceError(f"{name} must be a lowercase SHA-256")
    return result


def _bound_term(
    name: str,
    bound: FiniteBound | None,
    *,
    direction: str,
    unit: str,
    scope: dict[str, object],
) -> tuple[dict[str, object], str | None]:
    context_tokens = int(scope["maximum_context_tokens"])
    empty = {
        "name": name,
        "value": None,
        "bound_direction": direction,
        "unit": unit,
        "receipt_sha256": None,
        "source_locator": None,
        "arithmetic": None,
        "rounding": None,
        "valid_for_context_tokens": context_tokens,
    }
    if bound is None:
        return empty, f"{name}_finite_bound_missing"
    receipt, digest = _load_json(bound.receipt_path, bound.receipt_sha256, f"{name} receipt")
    receipt = _closed(
        receipt,
        {
            "schema_version",
            "kind",
            "metric",
            "value",
            "bound_direction",
            "unit",
            "source_locator",
            "arithmetic",
            "rounding",
            "valid_for_context_tokens",
            "scope",
        },
        f"{name} receipt",
    )
    if receipt["schema_version"] != 1 or receipt["kind"] != "reference_finite_bound_receipt":
        raise ReferenceEvidenceError(f"{name} receipt type is unsupported")
    if (
        receipt["metric"],
        receipt["bound_direction"],
        receipt["unit"],
        receipt["source_locator"],
        receipt["scope"],
    ) != (name, direction, unit, "/value", scope):
        raise ReferenceEvidenceError(f"{name} receipt binding mismatch")
    value = receipt["value"]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReferenceEvidenceError(f"{name} bound must be a non-negative integer")
    if not isinstance(receipt["arithmetic"], str) or not receipt["arithmetic"]:
        raise ReferenceEvidenceError(f"{name} receipt arithmetic is missing")
    allowed_rounding = {
        "ceiling_to_integer_byte",
        "ceiling_to_integer_second",
        "floor_to_integer_byte",
    }
    if receipt["rounding"] not in allowed_rounding:
        raise ReferenceEvidenceError(f"{name} receipt rounding is unsupported")
    validity = _positive_int(receipt["valid_for_context_tokens"], f"{name} context validity")
    term = {
        "name": name,
        "value": value,
        "bound_direction": direction,
        "unit": unit,
        "receipt_sha256": digest,
        "source_locator": "/value",
        "arithmetic": receipt["arithmetic"],
        "rounding": receipt["rounding"],
        "valid_for_context_tokens": validity,
    }
    if digest not in APPROVED_FINITE_BOUND_RECEIPT_SHA256S:
        return term, f"{name}_receipt_not_independently_authorized"
    if validity < context_tokens:
        return term, f"{name}_context_validity_insufficient"
    return term, None


def _dtype_bytes(value: object) -> int | None:
    return {"float16": 2, "bfloat16": 2, "float32": 4}.get(str(value))


def _memory_architecture(
    architecture: dict[str, Any], context_tokens: int
) -> tuple[int | None, str | None, dict[str, int] | None]:
    text = architecture.get("text_config", architecture)
    if not isinstance(text, dict):
        return None, "cache_state_architecture_unknown", None
    layers, num_layers = text.get("layer_types"), text.get("num_hidden_layers")
    if (
        not isinstance(layers, list)
        or any(not isinstance(x, str) for x in layers)
        or not isinstance(num_layers, int)
        or isinstance(num_layers, bool)
        or num_layers <= 0
        or len(layers) != num_layers
        or any(x not in {"full_attention", "linear_attention"} for x in layers)
    ):
        return None, "cache_state_architecture_unknown", None
    try:
        configured = _positive_int(text.get("max_position_embeddings"), "max_position_embeddings")
        kv_heads = _positive_int(text.get("num_key_value_heads"), "num_key_value_heads")
        head_dim = _positive_int(text.get("head_dim"), "head_dim")
        key_heads = _positive_int(text.get("linear_num_key_heads"), "linear_num_key_heads")
        key_dim = _positive_int(text.get("linear_key_head_dim"), "linear_key_head_dim")
        value_heads = _positive_int(text.get("linear_num_value_heads"), "linear_num_value_heads")
        value_dim = _positive_int(text.get("linear_value_head_dim"), "linear_value_head_dim")
        conv_kernel = _positive_int(text.get("linear_conv_kernel_dim"), "linear_conv_kernel_dim")
    except ReferenceEvidenceError:
        return None, "cache_state_architecture_unknown", None
    if configured != context_tokens:
        return None, "configured_context_drift", None
    kv_dtype, state_dtype = (
        _dtype_bytes(text.get("dtype")),
        _dtype_bytes(text.get("mamba_ssm_dtype")),
    )
    if kv_dtype is None or state_dtype is None:
        return None, "cache_state_dtype_unknown", None
    full_layers, linear_layers = layers.count("full_attention"), layers.count("linear_attention")
    if full_layers <= 0 or linear_layers <= 0:
        return None, "cache_state_architecture_unknown", None
    # Batch one is frozen. The recurrent matrix uses the full cross-product of
    # declared key/value channels; this is conservative for packed implementations.
    full_kv = context_tokens * full_layers * 2 * kv_heads * head_dim * kv_dtype
    recurrent = linear_layers * key_heads * key_dim * value_heads * value_dim * state_dtype
    conv = (
        linear_layers
        * (conv_kernel - 1)
        * (key_heads * key_dim + value_heads * value_dim)
        * state_dtype
    )
    inputs = {
        "batch_size": 1,
        "context_tokens": context_tokens,
        "num_hidden_layers": num_layers,
        "full_attention_layers": full_layers,
        "linear_attention_layers": linear_layers,
        "kv_heads": kv_heads,
        "head_dim": head_dim,
        "kv_dtype_bytes": kv_dtype,
        "linear_key_heads": key_heads,
        "linear_key_head_dim": key_dim,
        "linear_value_heads": value_heads,
        "linear_value_head_dim": value_dim,
        "linear_conv_kernel_dim": conv_kernel,
        "linear_state_dtype_bytes": state_dtype,
        "full_attention_kv_bytes": full_kv,
        "linear_recurrent_state_bytes": recurrent,
        "linear_conv_state_bytes": conv,
    }
    return full_kv + recurrent + conv, None, inputs


def _sources(
    *,
    inventory_path: Path,
    inventory_sha256: str,
    runtime_receipt_path: Path,
    runtime_receipt_sha256: str,
    image_build_identity_path: Path,
    image_build_identity_sha256: str,
    evaluation_lock_path: Path,
    evaluation_lock_sha256: str,
    maximum_context_tokens: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, object], list[str]]:
    inventory, inventory_digest = _load_json(
        inventory_path,
        inventory_sha256,
        "weight inventory",
        require_canonical=False,
    )
    _, runtime_digest = _load_json(
        runtime_receipt_path,
        runtime_receipt_sha256,
        "runtime receipt",
        require_canonical=False,
    )
    image, image_digest = _load_json(
        image_build_identity_path,
        image_build_identity_sha256,
        "image build identity",
        require_canonical=False,
    )
    image = _closed(
        image,
        {
            "schema_version",
            "kind",
            "proven",
            "resolved_image_identity",
            "blockers",
        },
        "image build identity",
    )
    image_blockers = image["blockers"]
    if (
        image["schema_version"] != 1
        or image["kind"] != "reference_image_build_identity"
        or not isinstance(image["proven"], bool)
        or not isinstance(image_blockers, list)
        or any(not isinstance(item, str) or not item for item in image_blockers)
        or image_blockers != sorted(set(image_blockers))
    ):
        raise ReferenceEvidenceError("image build identity is invalid")
    resolved_identity = image["resolved_image_identity"]
    if image["proven"]:
        if not isinstance(resolved_identity, str) or not resolved_identity or image_blockers:
            raise ReferenceEvidenceError("proven image build identity is incomplete")
    elif resolved_identity is not None or not image_blockers:
        raise ReferenceEvidenceError("unproven image build identity must name blockers")
    evaluation, evaluation_digest = _load_json(
        evaluation_lock_path,
        evaluation_lock_sha256,
        "evaluation lock",
        require_canonical=False,
    )
    context = evaluation.get("context")
    if not isinstance(context, dict) or context.get("configured_tokens") != maximum_context_tokens:
        raise ReferenceEvidenceError("evaluation context mismatch")
    return (
        inventory,
        evaluation,
        _scope(
            inventory_sha256=inventory_digest,
            runtime_receipt_sha256=runtime_digest,
            image_build_identity_sha256=image_digest,
            evaluation_lock_sha256=evaluation_digest,
            maximum_context_tokens=maximum_context_tokens,
        ),
        [] if image["proven"] else ["image_build_identity_unproven"],
    )


def derive_memory_fit_evidence(
    *,
    inventory_path: Path,
    inventory_sha256: str,
    architecture_path: Path,
    architecture_sha256: str,
    runtime_receipt_path: Path,
    runtime_receipt_sha256: str,
    image_build_identity_path: Path,
    image_build_identity_sha256: str,
    evaluation_lock_path: Path,
    evaluation_lock_sha256: str,
    maximum_context_tokens: int,
    runtime_overhead_bound: FiniteBound | None = None,
    allocator_reserve_bound: FiniteBound | None = None,
    usable_gpu_memory_bound: FiniteBound | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    context_tokens = _positive_int(maximum_context_tokens, "maximum_context_tokens")
    inventory, _, scope, source_blockers = _sources(
        inventory_path=inventory_path,
        inventory_sha256=inventory_sha256,
        runtime_receipt_path=runtime_receipt_path,
        runtime_receipt_sha256=runtime_receipt_sha256,
        image_build_identity_path=image_build_identity_path,
        image_build_identity_sha256=image_build_identity_sha256,
        evaluation_lock_path=evaluation_lock_path,
        evaluation_lock_sha256=evaluation_lock_sha256,
        maximum_context_tokens=context_tokens,
    )
    architecture, architecture_digest = _load_json(
        architecture_path,
        architecture_sha256,
        "architecture metadata",
        require_canonical=False,
    )
    index = inventory.get("index")
    if not isinstance(index, dict):
        raise ReferenceEvidenceError("weight inventory index is missing")
    tensor_bytes = _positive_int(index.get("tensor_bytes"), "tensor_bytes")
    terms: list[dict[str, object]] = [
        {
            "name": "tensor_bytes",
            "value": tensor_bytes,
            "bound_direction": "exact",
            "unit": "bytes",
            "receipt_sha256": scope["weight_inventory_sha256"],
            "source_locator": "/index/tensor_bytes",
            "arithmetic": "identity",
            "rounding": "exact_integer_bytes",
            "valid_for_context_tokens": context_tokens,
        }
    ]
    blockers: list[str] = list(source_blockers)
    for name, bound, direction in (
        ("runtime_overhead_bytes", runtime_overhead_bound, "upper"),
        ("allocator_reserve_bytes", allocator_reserve_bound, "upper"),
        ("usable_gpu_memory_bytes", usable_gpu_memory_bound, "lower"),
    ):
        term, blocker = _bound_term(name, bound, direction=direction, unit="bytes", scope=scope)
        terms.append(term)
        if blocker:
            blockers.append(blocker)
    cache_bytes, cache_blocker, cache_inputs = _memory_architecture(architecture, context_tokens)
    terms.insert(
        2,
        {
            "name": "kv_cache_bytes",
            "value": cache_bytes,
            "bound_direction": "exact_for_declared_hybrid_cache_state",
            "unit": "bytes",
            "receipt_sha256": architecture_digest,
            "source_locator": "/text_config",
            "arithmetic": "full_attention_kv+linear_recurrent_state+linear_conv_state",
            "rounding": "exact_integer_bytes",
            "valid_for_context_tokens": context_tokens,
        },
    )
    if cache_blocker:
        blockers.append(cache_blocker)
    method = {
        "schema_version": 2,
        "kind": "reference_memory_method_contract",
        "method_id": MEMORY_METHOD_ID,
        "method_version": MEMORY_METHOD_VERSION,
        "formula": MEMORY_FORMULA,
        "bindings": {
            **scope,
            "architecture_sha256": architecture_digest,
            "maximum_gpu_memory_bytes": A100_80GB_BYTES,
        },
        "terms": terms,
        "cache_state_inputs": cache_inputs,
        "conservative_rule": "all required bounds need an exact independently approved receipt",
    }
    method_sha = canonical_sha256(method)
    values = {str(x["name"]): x["value"] for x in terms}
    names = ("tensor_bytes", "runtime_overhead_bytes", "kv_cache_bytes", "allocator_reserve_bytes")
    known = sum(int(values[name]) for name in names if values[name] is not None)
    required = (
        sum(int(values[name]) for name in names)
        if not blockers and all(values[name] is not None for name in names)
        else None
    )
    available = values["usable_gpu_memory_bytes"]
    if isinstance(available, int) and available > A100_80GB_BYTES:
        blockers.append("usable_gpu_memory_exceeds_hardware_envelope")
        required = None
    if required is not None and isinstance(available, int) and required > available:
        blockers.append("memory_formula_not_satisfied")
    proven = (
        required is not None
        and isinstance(available, int)
        and not blockers
        and required <= available
    )
    return method, {
        "schema_version": 2,
        "kind": "memory_fit_evidence",
        "method_sha256": method_sha,
        "inventory_sha256": scope["weight_inventory_sha256"],
        "architecture_sha256": architecture_digest,
        "runtime_receipt_sha256": scope["runtime_receipt_sha256"],
        "image_build_identity_sha256": scope["image_build_identity_sha256"],
        "evaluation_lock_sha256": scope["evaluation_lock_sha256"],
        "maximum_context_tokens": context_tokens,
        "tensor_bytes": tensor_bytes,
        "known_required_lower_bound_bytes": known,
        "required_bytes": required,
        "available_bytes": available,
        "proven": proven,
        "blockers": sorted(set(blockers)),
    }


def derive_cold_path_evidence(
    *,
    inventory_path: Path,
    inventory_sha256: str,
    runtime_receipt_path: Path,
    runtime_receipt_sha256: str,
    image_build_identity_path: Path,
    image_build_identity_sha256: str,
    evaluation_lock_path: Path,
    evaluation_lock_sha256: str,
    maximum_context_tokens: int,
    timeout_seconds: int,
    transfer_bound: FiniteBound | None = None,
    verification_bound: FiniteBound | None = None,
    load_bound: FiniteBound | None = None,
    evaluation_bound: FiniteBound | None = None,
    safety_margin_bound: FiniteBound | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    context_tokens, timeout = (
        _positive_int(maximum_context_tokens, "maximum_context_tokens"),
        _positive_int(timeout_seconds, "timeout_seconds"),
    )
    _, _, scope, source_blockers = _sources(
        inventory_path=inventory_path,
        inventory_sha256=inventory_sha256,
        runtime_receipt_path=runtime_receipt_path,
        runtime_receipt_sha256=runtime_receipt_sha256,
        image_build_identity_path=image_build_identity_path,
        image_build_identity_sha256=image_build_identity_sha256,
        evaluation_lock_path=evaluation_lock_path,
        evaluation_lock_sha256=evaluation_lock_sha256,
        maximum_context_tokens=context_tokens,
    )
    terms: list[dict[str, object]] = []
    blockers: list[str] = list(source_blockers)
    for name, bound in (
        ("transfer_seconds", transfer_bound),
        ("verification_seconds", verification_bound),
        ("load_seconds", load_bound),
        ("evaluation_seconds", evaluation_bound),
        ("safety_margin_seconds", safety_margin_bound),
    ):
        term, blocker = _bound_term(name, bound, direction="upper", unit="seconds", scope=scope)
        terms.append(term)
        if blocker:
            blockers.append(blocker)
    method = {
        "schema_version": 2,
        "kind": "reference_cold_path_method_contract",
        "method_id": COLD_PATH_METHOD_ID,
        "method_version": COLD_PATH_METHOD_VERSION,
        "formula": TIME_FORMULA,
        "bindings": {**scope, "timeout_seconds": timeout},
        "terms": terms,
        "conservative_rule": (
            "each stage needs an exact independently approved "
            "finite upper-bound receipt"
        ),
    }
    method_sha = canonical_sha256(method)
    required = (
        sum(int(x["value"]) for x in terms)
        if not blockers and all(x["value"] is not None for x in terms)
        else None
    )
    if required is not None and required > timeout:
        blockers.append("cold_path_formula_not_satisfied")
    return method, {
        "schema_version": 2,
        "kind": "cold_path_time_evidence",
        "method_sha256": method_sha,
        "inventory_sha256": scope["weight_inventory_sha256"],
        "runtime_receipt_sha256": scope["runtime_receipt_sha256"],
        "image_build_identity_sha256": scope["image_build_identity_sha256"],
        "evaluation_lock_sha256": scope["evaluation_lock_sha256"],
        "maximum_context_tokens": context_tokens,
        "timeout_seconds": timeout,
        "required_seconds": required,
        "available_seconds": timeout,
        "proven": required is not None and not blockers and required <= timeout,
        "blockers": sorted(set(blockers)),
    }


def _bound_from_terms(terms: object, name: str, receipt_root: Path) -> FiniteBound | None:
    if not isinstance(terms, list):
        raise ReferenceEvidenceError("method terms must be a list")
    matches = [x for x in terms if isinstance(x, dict) and x.get("name") == name]
    if len(matches) != 1:
        raise ReferenceEvidenceError(f"method must contain one {name} term")
    digest = matches[0].get("receipt_sha256")
    if matches[0].get("value") is None:
        if digest is not None:
            raise ReferenceEvidenceError(f"{name} missing bound is not closed")
        return None
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ReferenceEvidenceError(f"{name} receipt digest is invalid")
    return FiniteBound(receipt_root / f"{digest}.json", digest)


def verify_memory_evidence_reproducible(
    *,
    method_path: Path,
    method_sha256: str,
    evidence_path: Path,
    evidence_sha256: str,
    inventory_path: Path,
    architecture_path: Path,
    expected_architecture_sha256: str,
    runtime_receipt_path: Path,
    image_build_identity_path: Path,
    evaluation_lock_path: Path,
    receipt_root: Path,
) -> bool:
    method, _ = _load_json(method_path, method_sha256, "memory method contract")
    evidence, _ = _load_json(evidence_path, evidence_sha256, "memory evidence")
    if method.get("schema_version") != 2 or evidence.get("schema_version") != 2:
        raise ReferenceEvidenceError("paid evidence reproducibility requires schema version 2")
    bindings, terms = method.get("bindings"), method.get("terms")
    if not isinstance(bindings, dict):
        raise ReferenceEvidenceError("memory method bindings are missing")
    if bindings.get("architecture_sha256") != expected_architecture_sha256:
        raise ReferenceEvidenceError("memory architecture metadata binding mismatch")
    reproduced = derive_memory_fit_evidence(
        inventory_path=inventory_path,
        inventory_sha256=str(bindings.get("weight_inventory_sha256")),
        architecture_path=architecture_path,
        architecture_sha256=str(bindings.get("architecture_sha256")),
        runtime_receipt_path=runtime_receipt_path,
        runtime_receipt_sha256=str(bindings.get("runtime_receipt_sha256")),
        image_build_identity_path=image_build_identity_path,
        image_build_identity_sha256=str(bindings.get("image_build_identity_sha256")),
        evaluation_lock_path=evaluation_lock_path,
        evaluation_lock_sha256=str(bindings.get("evaluation_lock_sha256")),
        maximum_context_tokens=bindings.get("maximum_context_tokens"),
        runtime_overhead_bound=_bound_from_terms(terms, "runtime_overhead_bytes", receipt_root),
        allocator_reserve_bound=_bound_from_terms(terms, "allocator_reserve_bytes", receipt_root),
        usable_gpu_memory_bound=_bound_from_terms(terms, "usable_gpu_memory_bytes", receipt_root),
    )
    if (method, evidence) != reproduced:
        raise ReferenceEvidenceError("memory evidence is not reproducible")
    return True


def verify_cold_path_evidence_reproducible(
    *,
    method_path: Path,
    method_sha256: str,
    evidence_path: Path,
    evidence_sha256: str,
    inventory_path: Path,
    runtime_receipt_path: Path,
    image_build_identity_path: Path,
    evaluation_lock_path: Path,
    receipt_root: Path,
) -> bool:
    method, _ = _load_json(method_path, method_sha256, "cold-path method contract")
    evidence, _ = _load_json(evidence_path, evidence_sha256, "cold-path evidence")
    if method.get("schema_version") != 2 or evidence.get("schema_version") != 2:
        raise ReferenceEvidenceError("paid evidence reproducibility requires schema version 2")
    bindings, terms = method.get("bindings"), method.get("terms")
    if not isinstance(bindings, dict):
        raise ReferenceEvidenceError("cold-path method bindings are missing")
    reproduced = derive_cold_path_evidence(
        inventory_path=inventory_path,
        inventory_sha256=str(bindings.get("weight_inventory_sha256")),
        runtime_receipt_path=runtime_receipt_path,
        runtime_receipt_sha256=str(bindings.get("runtime_receipt_sha256")),
        image_build_identity_path=image_build_identity_path,
        image_build_identity_sha256=str(bindings.get("image_build_identity_sha256")),
        evaluation_lock_path=evaluation_lock_path,
        evaluation_lock_sha256=str(bindings.get("evaluation_lock_sha256")),
        maximum_context_tokens=bindings.get("maximum_context_tokens"),
        timeout_seconds=bindings.get("timeout_seconds"),
        transfer_bound=_bound_from_terms(terms, "transfer_seconds", receipt_root),
        verification_bound=_bound_from_terms(terms, "verification_seconds", receipt_root),
        load_bound=_bound_from_terms(terms, "load_seconds", receipt_root),
        evaluation_bound=_bound_from_terms(terms, "evaluation_seconds", receipt_root),
        safety_margin_bound=_bound_from_terms(terms, "safety_margin_seconds", receipt_root),
    )
    if (method, evidence) != reproduced:
        raise ReferenceEvidenceError("cold-path evidence is not reproducible")
    return True
