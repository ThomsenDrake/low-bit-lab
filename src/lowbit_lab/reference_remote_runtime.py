"""Minimal by-value runtime for the audited reference Modal function.

This module deliberately has no imports from :mod:`lowbit_lab`.  Modal serializes
it by value while its standard-library and pinned image dependencies remain
ordinary imports.  Keep this module narrow: adding local imports expands both the
hydration graph and the remote trust boundary.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

# A built-in exception keeps Modal's payload deterministic across fresh Python
# processes; cloudpickle assigns random tracker IDs to dynamic exception classes.
RemoteRuntimeError = RuntimeError


_FIELDS = (
    "bootstrap_request_bytes_b64",
    "evaluation_lock_bytes_b64",
    "execution_identity",
    "fixtures",
    "image_lock",
    "image_recipe_sha256",
    "kind",
    "provider_image_identity",
    "response_caps",
    "schema_version",
    "serialized_function_sha256",
    "submission_pending_at",
    "timeout_seconds",
)
_STAGES = (
    "runtime_identity",
    "source_transfer",
    "hash_verification",
    "model_load",
    "evaluation",
    "evidence_finalization",
)
_PROXIES = ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy")
_SIGNED = (
    ("huggingface.co", "/api/resolve-cache/models/"),
    ("us.aws.cdn.hf.co", "/xet-bridge-us/"),
)
_REDIRECTS = (301, 302, 303, 307, 308)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SHARD = re.compile(r"model(?:-[0-9]{5}-of-[0-9]{5})?\.safetensors\Z")
_JSON = (
    "config.json",
    "generation_config.json",
    "model.safetensors.index.json",
    "special_tokens_map.json",
    "tokenizer_config.json",
)
_TOKENIZER = ("tokenizer.json", "vocab.json", "merges.txt")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise RemoteRuntimeError(f"{label}_invalid")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise RemoteRuntimeError(f"{label}_invalid") from None
    if base64.b64encode(result).decode() != value:
        raise RemoteRuntimeError(f"{label}_invalid")
    return result


def _json_bytes(value: bytes, label: str) -> dict[str, object]:
    try:
        raw = json.loads(value)
    except (UnicodeError, json.JSONDecodeError):
        raise RemoteRuntimeError(f"{label}_invalid") from None
    if not isinstance(raw, dict) or _canonical(raw) != value:
        raise RemoteRuntimeError(f"{label}_invalid")
    return raw


def _public(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    return value.is_global and not any(
        (
            value.is_private,
            value.is_loopback,
            value.is_link_local,
            value.is_reserved,
            value.is_multicast,
            value.is_unspecified,
        )
    )


def validate_public_url(
    url: object, approved_hosts: frozenset[str], *, redirected: bool
) -> tuple[str, str]:
    """Return host and request selector after the frozen signed-CDN checks."""
    if not isinstance(url, str) or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise RemoteRuntimeError("unsafe_url")
    try:
        parsed, port = urlsplit(url), urlsplit(url).port
    except ValueError:
        raise RemoteRuntimeError("unsafe_url") from None
    host, path = parsed.hostname, parsed.path
    lowered = path.lower()
    if (
        parsed.scheme != "https"
        or not host
        or host not in approved_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not path.startswith("/")
        or "\\" in path
        or re.search(r"%(?![0-9a-fA-F]{2})", path)
        or any(token in lowered for token in ("%2f", "%5c", "%2e"))
        or any(part in (".", "..") for part in path.split("/"))
    ):
        raise RemoteRuntimeError("unsafe_url")
    if parsed.query and (
        not redirected or not any(host == h and path.startswith(p) for h, p in _SIGNED)
    ):
        raise RemoteRuntimeError("unsafe_url")
    return host, path + (("?" + parsed.query) if parsed.query else "")


def _open(url: str, approved_hosts: frozenset[str]):
    """Open one direct HTTPS response, pinning the peer to fresh public DNS."""
    current = url
    for hop in range(6):
        host, selector = validate_public_url(current, approved_hosts, redirected=hop > 0)
        try:
            addresses = tuple(
                sorted(
                    dict.fromkeys(
                        item[4][0]
                        for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                    )
                )
            )
        except OSError:
            raise RemoteRuntimeError("resolution_failed") from None
        if not addresses or any(not _public(item) for item in addresses):
            raise RemoteRuntimeError("unsafe_address")
        connection = http.client.HTTPSConnection(
            host, 443, timeout=30, context=ssl.create_default_context()
        )
        try:
            raw = socket.create_connection((addresses[0], 443), 30)
            connection.sock = connection._context.wrap_socket(raw, server_hostname=host)  # type: ignore[attr-defined]
            connection.request("GET", selector, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            peer = str(connection.sock.getpeername()[0])
        except (OSError, http.client.HTTPException):
            connection.close()
            raise RemoteRuntimeError("network_request_failed") from None
        if not _public(peer) or not any(
            ipaddress.ip_address(peer) == ipaddress.ip_address(item) for item in addresses
        ):
            connection.close()
            raise RemoteRuntimeError("peer_address_drift")
        if response.status in _REDIRECTS:
            location = response.getheader("Location")
            connection.close()
            if not location or hop == 5:
                raise RemoteRuntimeError("redirect_drift")
            current = urljoin(current, location)
            continue
        if response.status != 200 or response.getheader("Location") is not None:
            connection.close()
            raise RemoteRuntimeError("unexpected_http_status")
        return connection, response
    raise RemoteRuntimeError("redirect_drift")


def _artifact_name(artifact: dict[str, object]) -> str:
    raw = urlsplit(str(artifact["url"])).path.rsplit("/", 1)[-1]
    name = unquote(raw)
    fmt = artifact["format"]
    valid = (
        raw == name
        and Path(name).name == name
        and bool(name)
        and (
            (fmt == "safetensors" and _SHARD.fullmatch(name))
            or (fmt == "json" and name in _JSON)
            or (fmt == "tokenizer_data" and name in _TOKENIZER)
            or (fmt == "text" and name == "chat_template.jinja")
        )
    )
    if not valid:
        raise RemoteRuntimeError("unsafe_artifact")
    return name


def _reject_remote_code(value: object) -> None:
    if isinstance(value, dict):
        if "auto_map" in value or value.get("trust_remote_code") not in (None, False):
            raise RemoteRuntimeError("remote_code_forbidden")
        for nested in value.values():
            _reject_remote_code(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_remote_code(nested)


def _contract(
    content: bytes,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, bytes], float]:
    raw = _json_bytes(content, "remote_contract")
    if (
        tuple(sorted(raw)) != tuple(sorted(_FIELDS))
        or raw.get("kind") != "reference_modal_remote_contract"
        or raw.get("schema_version") != 1
    ):
        raise RemoteRuntimeError("remote_contract_schema_drift")
    request_bytes = _decode(raw["bootstrap_request_bytes_b64"], "bootstrap_request")
    lock_bytes = _decode(raw["evaluation_lock_bytes_b64"], "evaluation_lock")
    request, lock = (
        _json_bytes(request_bytes, "bootstrap_request"),
        _json_bytes(lock_bytes, "evaluation_lock"),
    )
    if (
        request.get("configured_context_tokens") != 262144
        or request.get("context_ladder_tokens", [None])[-1] != 262144
    ):
        raise RemoteRuntimeError("configured_context_drift")
    if raw.get("timeout_seconds") != 2700 or raw.get("response_caps") != request.get(
        "response_caps"
    ):
        raise RemoteRuntimeError("remote_contract_boundary_drift")
    lineage = request.get("lineage")
    if not isinstance(lineage, dict) or lineage.get("evaluation_lock_sha256") != _digest(
        lock_bytes
    ):
        raise RemoteRuntimeError("evaluation_lock_drift")
    identity = raw.get("execution_identity")
    identity_fields = (
        "weight_inventory_sha256",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "reviewed_commit_sha256",
        "resource_spec_sha256",
    )
    if not isinstance(identity, dict) or tuple(sorted(identity)) != tuple(sorted(identity_fields)):
        raise RemoteRuntimeError("execution_identity_drift")
    fixtures: dict[str, bytes] = {}
    items = raw.get("fixtures")
    if not isinstance(items, list) or len(items) != 6:
        raise RemoteRuntimeError("fixture_binding_drift")
    for item in items:
        if not isinstance(item, dict) or tuple(sorted(item)) != (
            "bytes_b64",
            "fixture_id",
            "sha256",
        ):
            raise RemoteRuntimeError("fixture_binding_drift")
        body = _decode(item["bytes_b64"], "fixture")
        key = item["fixture_id"]
        if not isinstance(key, str) or item["sha256"] != _digest(body) or key in fixtures:
            raise RemoteRuntimeError("fixture_binding_drift")
        fixtures[key] = body
    declared = lock.get("fixtures")
    declared_ids = (
        tuple(sorted(item.get("fixture_id") for item in declared if isinstance(item, dict)))
        if isinstance(declared, list)
        else ()
    )
    if not isinstance(declared, list) or declared_ids != tuple(sorted(fixtures)):
        raise RemoteRuntimeError("fixture_binding_drift")
    for item in declared:
        if item.get("sha256") != _digest(fixtures[str(item["fixture_id"])]):
            raise RemoteRuntimeError("fixture_binding_drift")
    try:
        submitted = datetime.fromisoformat(str(raw["submission_pending_at"]))
    except ValueError:
        raise RemoteRuntimeError("submission_time_invalid") from None
    if (
        submitted.tzinfo is None
        or not isinstance(raw.get("provider_image_identity"), str)
        or not str(raw["provider_image_identity"]).startswith(("im-", "ap-"))
    ):
        raise RemoteRuntimeError("remote_contract_boundary_drift")
    elapsed = (datetime.now(UTC) - submitted.astimezone(UTC)).total_seconds()
    if elapsed < 0 or elapsed >= 2700:
        raise RemoteRuntimeError("submission_deadline_unavailable")
    return raw, request, lock, fixtures, elapsed


def _empty(stage: str, request: dict[str, object]) -> dict[str, object]:
    if stage == "runtime_identity":
        return {
            "device_free_bytes": 0,
            "device_total_bytes": 0,
            "image_identity_sha256": "0" * 64,
            "runtime_identity_sha256": "0" * 64,
        }
    if stage == "source_transfer":
        return {"artifacts_received": 0, "bytes_received": 0}
    if stage == "hash_verification":
        return {"artifacts_verified": 0, "bytes_verified": 0}
    if stage == "model_load":
        return {
            "device_free_before_bytes": 0,
            "known_required_bytes": int(request["known_memory_lower_bound_bytes"]),
            "loaded": False,
            "peak_allocated_bytes": 0,
            "peak_reserved_bytes": 0,
        }
    if stage == "evaluation":
        return {
            "configured_context_tokens": 262144,
            "full_context_completed": False,
            "levels_completed": 0,
            "max_completed_context_tokens": 0,
            "reference_manifest_bytes": 0,
            "reference_manifest_sha256": None,
            "usefulness_proven": False,
        }
    return {"receipt_bytes": 0}


def _stage(
    ordinal: int,
    request_sha: str,
    started: float,
    deadline: float,
    measurements: dict[str, object],
    code: str | None = None,
) -> dict[str, object]:
    return {
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        "failure_code": code,
        "kind": "reference_bootstrap_stage_receipt",
        "measurements": measurements,
        "ordinal": ordinal,
        "remaining_ms": max(0, int((deadline - time.monotonic()) * 1000)),
        "request_sha256": request_sha,
        "schema_version": 1,
        "stage": _STAGES[ordinal],
        "status": "failed" if code else "completed",
    }


def _receipt(
    request: dict[str, object],
    request_sha: str,
    stages: list[dict[str, object]],
    success: bool,
    useful: bool = False,
) -> bytes:
    completed = tuple(item["stage"] for item in stages if item["status"] == "completed")
    evaluation = next((item for item in stages if item["stage"] == "evaluation"), None)
    maximum = (
        int(evaluation["measurements"]["max_completed_context_tokens"])
        if evaluation is not None
        else 0
    )  # type: ignore[index]
    raw = {
        "configured_context_tokens": 262144,
        "empirical_facts": {
            "cold_path_timing": success,
            "context_usefulness": useful,
            "empirical_fit": "model_load" in completed,
            "provider_image_identity": "runtime_identity" in completed,
            "runtime_allocator_overhead": "model_load" in completed,
            "usable_gpu_memory": "runtime_identity" in completed,
        },
        "full_context_usefulness_proven": useful,
        "kind": "reference_bootstrap_receipt",
        "max_completed_context_tokens": maximum,
        "request_sha256": request_sha,
        "schema_version": 1,
        "stages": stages,
        "status": "succeeded" if success else "failed",
        "terminal_failure": None
        if success
        else {"code": stages[-1]["failure_code"], "stage": stages[-1]["stage"]},
    }
    return _canonical(raw)


def _failure(
    request: dict[str, object],
    request_sha: str,
    stages: list[dict[str, object]],
    ordinal: int,
    started: float,
    deadline: float,
    code: str,
    measurements: dict[str, object] | None = None,
) -> bytes:
    safe = code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "unknown_failure"
    stages.append(
        _stage(
            ordinal,
            request_sha,
            started,
            deadline,
            measurements or _empty(_STAGES[ordinal], request),
            safe,
        )
    )
    return _receipt(request, request_sha, stages, False)


def _generate(model: object, tokenizer: object, prompt: str, cap: int) -> tuple[str, int, float]:
    import torch

    values = tokenizer(prompt, return_tensors="pt", add_special_tokens=True)
    values = {name: value.to("cuda:0") for name, value in values.items()}
    input_tokens = int(values["input_ids"].shape[-1])
    began = time.monotonic()
    with torch.inference_mode():
        output = model.generate(
            **values,
            do_sample=False,
            max_new_tokens=cap,
            temperature=0.0,
            top_p=1.0,
        )
    generated = output[0, input_tokens:]
    return (
        tokenizer.decode(generated, skip_special_tokens=True),
        int(generated.shape[-1]),
        time.monotonic() - began,
    )


def _long_generate(
    model: object,
    tokenizer: object,
    fixture: dict[str, object],
    context: int,
    cap: int,
) -> tuple[str, int, float]:
    import torch

    prefix = tokenizer.encode(str(fixture["needle"]) + "\n", add_special_tokens=False)
    suffix = tokenizer.encode("\n" + str(fixture["prompt"]) + "\n", add_special_tokens=False)
    filler = tokenizer.encode(" x", add_special_tokens=False)
    count = context - cap
    if not prefix or not suffix or len(filler) != 1 or count < len(prefix) + len(suffix):
        raise RemoteRuntimeError("context_ladder_drift")
    tokens = prefix + filler * (count - len(prefix) - len(suffix)) + suffix
    values = torch.tensor([tokens], dtype=torch.long, device="cuda:0")
    began = time.monotonic()
    with torch.inference_mode():
        output = model.generate(
            input_ids=values,
            do_sample=False,
            max_new_tokens=cap,
            temperature=0.0,
            top_p=1.0,
        )
    generated = output[0, count:]
    return (
        tokenizer.decode(generated, skip_special_tokens=True),
        int(generated.shape[-1]),
        time.monotonic() - began,
    )


def _evaluate(
    model: object,
    tokenizer: object,
    lock: dict[str, object],
    fixtures: dict[str, bytes],
    identity: dict[str, object],
    ladder: list[int],
    deadline: float,
) -> tuple[bytes, int, bool]:
    import torch

    generation = lock["generation"]
    token_caps = generation["response_caps_tokens"]
    byte_caps = generation["response_caps_bytes"]
    fixture_defs = {item["fixture_id"]: item for item in lock["fixtures"]}
    measurements: list[dict[str, object]] = []
    maximum, useful = 0, False
    for fixture_id in lock["fixture_order"]:
        definition = fixture_defs[fixture_id]
        family = definition["family"]
        fixture = json.loads(fixtures[fixture_id])
        levels = ladder if family == "long_context_retrieval" else (262144,)
        for level in levels:
            if time.monotonic() >= deadline - 60:
                raise RemoteRuntimeError("projected_timeout")
            cap = int(token_caps[family])
            if family == "long_context_retrieval":
                response, tokens, _ = _long_generate(model, tokenizer, fixture, level, cap)
                score = float(str(fixture["expected"]).casefold() in response.casefold())
                metrics = {name: score for name in definition["metrics"]}
                maximum, useful = level, score == 1.0
            elif family == "coding":
                response, tokens, _ = _generate(model, tokenizer, str(fixture["prompt"]), cap)
                score = float(response.strip() == str(fixture["expected"]))
                metrics = {name: score for name in definition["metrics"]}
            elif family == "tool_call_validity":
                response, tokens, _ = _generate(model, tokenizer, str(fixture["prompt"]), cap)
                try:
                    parsed = json.loads(response)
                except json.JSONDecodeError:
                    parsed = None
                valid = isinstance(parsed, dict) and isinstance(parsed.get("name"), str)
                valid = valid and isinstance(parsed.get("arguments"), dict)
                scores = {
                    "argument_accuracy": float(valid and parsed == fixture.get("expected")),
                    "schema_valid_rate": float(valid),
                }
                metrics = {name: scores[name] for name in definition["metrics"]}
            elif family == "throughput":
                total_tokens, total_time, response = 0, 0.0, ""
                for _ in range(int(fixture["repetitions"])):
                    response, tokens, duration = _generate(
                        model, tokenizer, "Continue with deterministic text.", cap
                    )
                    total_tokens += tokens
                    total_time += duration
                tokens = min(total_tokens, cap)
                metrics = {"decode_tokens_per_second": total_tokens / total_time}
            elif family == "memory":
                torch.cuda.reset_peak_memory_stats("cuda:0")
                response, tokens, _ = _generate(model, tokenizer, "Return one token.", cap)
                torch.cuda.synchronize("cuda:0")
                metrics = {"peak_vram_bytes": int(torch.cuda.max_memory_reserved("cuda:0"))}
            elif family == "soak":
                duration = int(fixture["duration_seconds"])
                began, errors, response, tokens = time.monotonic(), 0, "", 0
                while time.monotonic() - began < duration:
                    if time.monotonic() >= deadline - 60:
                        raise RemoteRuntimeError("projected_timeout")
                    try:
                        response, tokens, _ = _generate(model, tokenizer, "Return one token.", cap)
                    except Exception:
                        errors += 1
                        break
                seconds = time.monotonic() - began
                metrics = {
                    "completed_minutes": seconds / 60,
                    "failure_free_rate": float(errors == 0 and seconds >= duration),
                    "runtime_errors": errors,
                }
            else:
                raise RemoteRuntimeError("evaluation_family_unknown")
            body = response.encode()
            if tokens > cap or len(body) > int(byte_caps[family]):
                raise RemoteRuntimeError("evaluation_response_oversized")
            measurements.append(
                {
                    "context_level_tokens": level,
                    "family": family,
                    "fixture_id": fixture_id,
                    "metrics": dict(sorted(metrics.items())),
                    "response_bytes": len(body),
                    "response_sha256": _digest(body),
                    "response_tokens": tokens,
                    "status": "completed",
                }
            )
    manifest = _canonical(
        {
            "evaluation_lock_sha256": _digest(_canonical(lock)),
            "execution_identity": dict(sorted(identity.items())),
            "executor_identity": {
                "runtime_sha256": lock["scorer"]["runtime"]["sha256"],
                "scorer_sha256": lock["scorer"]["sha256"],
            },
            "kind": "reference_metrics",
            "measurements": measurements,
            "schema_version": 1,
            "status": "completed",
        }
    )
    return manifest, maximum, bool(useful and maximum == 262144)


def _execute(
    raw: dict[str, object],
    request: dict[str, object],
    lock: dict[str, object],
    fixtures: dict[str, bytes],
    elapsed: float,
) -> tuple[bytes, bytes | None]:
    started, deadline = time.monotonic(), time.monotonic() + 2700 - elapsed
    request_sha = _digest(_canonical(request))
    stages: list[dict[str, object]] = []
    root = Path("/tmp/lowbit-lab-reference")
    paths: dict[str, Path] = {}
    try:
        import safetensors
        import torch
        import transformers

        free, total = torch.cuda.mem_get_info("cuda:0")
        runtime_sha = _digest(
            _canonical(
                {
                    "cuda": str(torch.version.cuda),
                    "python": sys.version.split()[0],
                    "safetensors": safetensors.__version__,
                    "torch": torch.__version__,
                    "transformers": transformers.__version__,
                }
            )
        )
        measurement = {
            "device_free_bytes": int(free),
            "device_total_bytes": int(total),
            "image_identity_sha256": _digest(str(raw["provider_image_identity"]).encode()),
            "runtime_identity_sha256": runtime_sha,
        }
        if int(free) < int(request["known_memory_lower_bound_bytes"]):
            return _failure(
                request,
                request_sha,
                stages,
                0,
                started,
                deadline,
                "insufficient_memory",
                measurement,
            ), None
        stages.append(_stage(0, request_sha, started, deadline, measurement))
    except Exception:
        return _failure(
            request, request_sha, stages, 0, started, deadline, "runtime_probe_failed"
        ), None
    try:
        if any(key in os.environ for key in _PROXIES):
            raise RemoteRuntimeError("ambient_proxy")
        artifacts = request["source_artifacts"]
        hosts = frozenset(request["approved_https_hosts"])
        if not isinstance(artifacts, list) or not artifacts or not hosts:
            raise RemoteRuntimeError("artifact_binding_drift")
        if root.exists():
            raise RemoteRuntimeError("artifact_root_drift")
        root.mkdir()
        expected_total = sum(int(item["size_bytes"]) for item in artifacts)
        if shutil.disk_usage(root).free < expected_total:
            raise RemoteRuntimeError("insufficient_disk")
        received_total = 0
        for ordinal, item in enumerate(artifacts):
            if item.get("ordinal") != ordinal or not _SHA.fullmatch(str(item.get("sha256"))):
                raise RemoteRuntimeError("artifact_binding_drift")
            name, expected = _artifact_name(item), int(item["size_bytes"])
            connection, response = _open(str(item["url"]), hosts)
            length = response.getheader("Content-Length")
            if length is not None and int(length) != expected:
                connection.close()
                raise RemoteRuntimeError("transfer_length_mismatch")
            digest, count, path = hashlib.sha256(), 0, root / name
            with path.open("xb") as handle:
                while chunk := response.read(8 * 1024 * 1024):
                    count += len(chunk)
                    received_total += len(chunk)
                    if count > expected or received_total > expected_total:
                        raise RemoteRuntimeError("transfer_oversized")
                    handle.write(chunk)
                    digest.update(chunk)
                    if time.monotonic() >= deadline - 1500:
                        raise RemoteRuntimeError("projected_timeout")
                handle.flush()
                os.fsync(handle.fileno())
            connection.close()
            if count != expected or digest.hexdigest() != item["sha256"]:
                raise RemoteRuntimeError("hash_mismatch")
            paths[name] = path
        stages.append(
            _stage(
                1,
                request_sha,
                started,
                deadline,
                {"artifacts_received": len(paths), "bytes_received": received_total},
            )
        )
        stages.append(
            _stage(
                2,
                request_sha,
                started,
                deadline,
                {"artifacts_verified": len(paths), "bytes_verified": received_total},
            )
        )
    except RemoteRuntimeError as exc:
        return _failure(
            request,
            request_sha,
            stages,
            1,
            started,
            deadline,
            str(exc),
            {
                "artifacts_received": len(paths),
                "bytes_received": sum(path.stat().st_size for path in paths.values()),
            },
        ), None
    try:
        import torch
        from safetensors import safe_open
        from transformers import (
            AutoModelForCausalLM,
            AutoModelForImageTextToText,
            AutoTokenizer,
        )

        config_raw = json.loads(paths["config.json"].read_bytes())
        _reject_remote_code(config_raw)
        for filename in ("tokenizer_config.json", "generation_config.json"):
            if filename in paths:
                _reject_remote_code(json.loads(paths[filename].read_bytes()))
        architectures = config_raw.get("architectures")
        if (
            not isinstance(architectures, list)
            or len(architectures) != 1
            or not isinstance(architectures[0], str)
        ):
            raise RemoteRuntimeError("architecture_mismatch")
        text_config = config_raw.get("text_config")
        text_config = text_config if isinstance(text_config, dict) else config_raw
        if text_config.get("dtype", text_config.get("torch_dtype")) != "bfloat16":
            raise RemoteRuntimeError("dtype_drift")
        if text_config.get("max_position_embeddings") != 262144:
            raise RemoteRuntimeError("configured_context_drift")
        tokenizer_json = "tokenizer.json" in paths
        tokenizer_pair = "vocab.json" in paths and "merges.txt" in paths
        if tokenizer_json == tokenizer_pair or "tokenizer_config.json" not in paths:
            raise RemoteRuntimeError("tokenizer_binding_drift")
        index = json.loads(paths["model.safetensors.index.json"].read_bytes())
        weight_map = index.get("weight_map")
        supplied = tuple(sorted(name for name in paths if _SHARD.fullmatch(name)))
        if not isinstance(weight_map, dict) or not weight_map:
            raise RemoteRuntimeError("weight_index_invalid")
        referenced_values = tuple(weight_map.values())
        if any(not isinstance(name, str) for name in referenced_values):
            raise RemoteRuntimeError("weight_index_invalid")
        referenced = tuple(sorted(dict.fromkeys(referenced_values)))
        if supplied != referenced:
            raise RemoteRuntimeError("weight_index_invalid")
        for name, path in paths.items():
            if _SHARD.fullmatch(name):
                with safe_open(path, framework="pt", device="cpu") as handle:
                    if not tuple(handle.keys()):
                        raise RemoteRuntimeError("invalid_safetensors")
        factory = (
            AutoModelForImageTextToText
            if isinstance(config_raw.get("vision_config"), dict)
            else AutoModelForCausalLM
        )
        tokenizer = AutoTokenizer.from_pretrained(
            root, local_files_only=True, trust_remote_code=False
        )
        free_before, _ = torch.cuda.mem_get_info("cuda:0")
        torch.cuda.reset_peak_memory_stats("cuda:0")
        model = factory.from_pretrained(
            root,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            dtype=torch.bfloat16,
            device_map={"": "cuda:0"},
        )
        if getattr(model.config, "architectures", None) != architectures:
            raise RemoteRuntimeError("architecture_mismatch")
        values = tuple(model.parameters()) + tuple(model.buffers())
        if not values or any(str(item.device) != "cuda:0" for item in values):
            raise RemoteRuntimeError("device_drift")
        if any(str(item.dtype) != "torch.bfloat16" for item in model.parameters()):
            raise RemoteRuntimeError("dtype_drift")
        torch.cuda.synchronize("cuda:0")
        allocated, reserved = (
            int(torch.cuda.max_memory_allocated("cuda:0")),
            int(torch.cuda.max_memory_reserved("cuda:0")),
        )
        measurement = {
            "device_free_before_bytes": int(free_before),
            "known_required_bytes": int(request["known_memory_lower_bound_bytes"]),
            "loaded": True,
            "peak_allocated_bytes": allocated,
            "peak_reserved_bytes": reserved,
        }
        stages.append(_stage(3, request_sha, started, deadline, measurement))
    except Exception:
        return _failure(
            request, request_sha, stages, 3, started, deadline, "model_load_failed"
        ), None
    try:
        manifest, maximum, useful = _evaluate(
            model,
            tokenizer,
            lock,
            fixtures,
            raw["execution_identity"],
            request["context_ladder_tokens"],
            deadline,
        )
        evaluation = {
            "configured_context_tokens": 262144,
            "full_context_completed": maximum == 262144,
            "levels_completed": sum(level <= maximum for level in request["context_ladder_tokens"]),
            "max_completed_context_tokens": maximum,
            "reference_manifest_bytes": len(manifest),
            "reference_manifest_sha256": _digest(manifest),
            "usefulness_proven": useful,
        }
        if maximum != 262144:
            return _failure(
                request,
                request_sha,
                stages,
                4,
                started,
                deadline,
                "context_incomplete",
            ), None
        stages.append(_stage(4, request_sha, started, deadline, evaluation))
        stages.append(_stage(5, request_sha, started, deadline, {"receipt_bytes": 0}))
        receipt = _receipt(request, request_sha, stages, True, useful)
        size = 0
        for _ in range(8):
            stages[-1]["measurements"] = {"receipt_bytes": size}
            receipt = _receipt(request, request_sha, stages, True, useful)
            if len(receipt) == size:
                break
            size = len(receipt)
        if len(receipt) > 65536:
            raise RemoteRuntimeError("receipt_oversized")
        return receipt, manifest
    except RemoteRuntimeError as exc:
        return _failure(request, request_sha, stages, 4, started, deadline, str(exc)), None
    except Exception:
        return _failure(
            request, request_sha, stages, 4, started, deadline, "evaluation_failed"
        ), None


def remote_entry(contract_bytes: bytes) -> dict[str, object]:
    """Modal entrypoint: one bytes payload in, one bounded sanitized mapping out."""
    raw, request, lock, fixtures, elapsed = _contract(contract_bytes)
    expired = False

    def abort(_signum: int, _frame: object) -> None:
        nonlocal expired
        expired = True
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, abort)
    signal.setitimer(signal.ITIMER_REAL, 2700 - elapsed)
    try:
        receipt, manifest = _execute(raw, request, lock, fixtures, elapsed)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    if expired:
        raise TimeoutError
    result = {
        "contract_sha256": _digest(contract_bytes),
        "kind": "reference_modal_remote_result",
        "manifest_b64": None if manifest is None else base64.b64encode(manifest).decode(),
        "receipt_b64": base64.b64encode(receipt).decode(),
        "schema_version": 1,
    }
    return json.loads(_canonical(result))
