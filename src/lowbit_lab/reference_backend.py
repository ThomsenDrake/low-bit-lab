"""Data-only production callbacks for the staged reference executor.

The backend receives only already-validated contract objects and verified local
artifacts. Its fetcher has one direct HTTPS path, and model loading never uses
generic Torch deserialization.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket
import ssl
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from lowbit_lab.evaluation_lock import (
    EvaluationLockError,
    PendingEvaluationLock,
    validate_pending_evaluation_lock,
)
from lowbit_lab.reference_bootstrap import CONFIGURED_CONTEXT_TOKENS, BootstrapRequest
from lowbit_lab.reference_execution import (
    ArtifactWriter,
    EvaluationObservation,
    ExecutionDependencies,
    ExecutionFailure,
    FetchResponse,
    LoadObservation,
    RuntimeObservation,
    StoredArtifact,
)
from lowbit_lab.reference_harness import (
    ReferenceHarnessError,
    ReferenceObservation,
    ReferenceRequest,
    run_reference_harness,
    validate_execution_identity,
)

DTYPE = "bfloat16"
DEVICE = "cuda:0"
_ARCHITECTURE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}")
_SHARD_RE = re.compile(r"(?:model(?:-[0-9]{5}-of-[0-9]{5})?)\.safetensors")
_JSON_FILES = frozenset(
    {
        "config.json",
        "generation_config.json",
        "model.safetensors.index.json",
        "special_tokens_map.json",
        "tokenizer_config.json",
    }
)
_TOKENIZER_FILES = frozenset({"tokenizer.json", "vocab.json", "merges.txt"})
_TEXT_FILES = frozenset({"chat_template.jinja"})
_LOAD_FLAGS = {"local_files_only": True, "trust_remote_code": False}
_CHUNK_BYTES = 8 * 1024 * 1024
_PROXY_KEYS = ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy")


class MonotonicClock:
    def monotonic(self) -> float:
        return time.monotonic()


class PublicResolver:
    def resolve(self, host: str) -> tuple[str, ...]:
        try:
            values = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        except OSError:
            raise ExecutionFailure("resolution_failed") from None
        return tuple(sorted(values, key=lambda address: (":" in address, address)))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str) -> None:
        super().__init__(host, port=443, timeout=30, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class DirectHTTPSFetcher:
    """One direct TLS request pinned to an address freshly approved by U19."""

    def open(
        self, url: str, *, resolved_addresses: tuple[str, ...], proxies_disabled: bool
    ) -> FetchResponse:
        if not proxies_disabled or not resolved_addresses:
            raise ExecutionFailure("network_policy_drift")
        parsed = urlsplit(url)
        connection = _PinnedHTTPSConnection(str(parsed.hostname), resolved_addresses[0])
        try:
            connection.request("GET", parsed.path, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            peer = str(connection.sock.getpeername()[0])  # type: ignore[union-attr]
            length_header = response.getheader("Content-Length")
            length = int(length_header) if length_header is not None else None
            location = response.getheader("Location")
        except (OSError, ValueError, http.client.HTTPException):
            connection.close()
            raise ExecutionFailure("network_request_failed") from None
        if response.status in {301, 302, 303, 307, 308}:
            connection.close()
            return FetchResponse(response.status, peer, length, (), location)

        def chunks():
            try:
                while chunk := response.read(_CHUNK_BYTES):
                    yield chunk
            finally:
                connection.close()

        return FetchResponse(response.status, peer, length, chunks(), location)


class _FileWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._file = path.open("xb")

    def write(self, chunk: bytes) -> None:
        self._file.write(chunk)

    def finish(self) -> object:
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        return self.path


class LocalArtifactStore:
    def __init__(self, root: Path, request: BootstrapRequest) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self._expected = tuple(request.source_artifacts)

    def free_bytes(self) -> int:
        return int(shutil.disk_usage(self.root).free)

    def begin(self, ordinal: int, expected_bytes: int) -> ArtifactWriter:
        try:
            expected = self._expected[ordinal]
        except IndexError:
            raise ExecutionFailure("artifact_binding_drift") from None
        if expected["ordinal"] != ordinal or expected["size_bytes"] != expected_bytes:
            raise ExecutionFailure("artifact_binding_drift")
        name = _artifact_name(str(expected["url"]), str(expected["format"]))
        return _FileWriter(self.root / name)


class CudaRuntimeProbe:
    def __init__(self, image_identity_sha256: str) -> None:
        self.image_identity = image_identity_sha256

    def probe(self) -> RuntimeObservation:
        try:
            import safetensors
            import torch
            import transformers

            free, total = torch.cuda.mem_get_info(DEVICE)
            identity = json.dumps(
                {
                    "cuda": str(torch.version.cuda),
                    "python": sys.version.split()[0],
                    "safetensors": safetensors.__version__,
                    "torch": torch.__version__,
                    "transformers": transformers.__version__,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        except Exception:
            raise ExecutionFailure("runtime_probe_failed") from None
        import hashlib

        return RuntimeObservation(
            int(free), int(total), self.image_identity, hashlib.sha256(identity).hexdigest()
        )


class BackendRuntime(Protocol):
    """Narrow import seam; tests can exercise policy without heavyweight packages."""

    bfloat16: object

    def inspect_safetensors(self, path: Path) -> None: ...

    def load_config(self, root: Path, **kwargs: object) -> object: ...

    def load_tokenizer(self, root: Path, **kwargs: object) -> object: ...

    def load_model(self, root: Path, **kwargs: object) -> object: ...

    def memory_before(self) -> int: ...

    def memory_peaks(self) -> tuple[int, int]: ...

    def evaluate_reference(
        self, bundle: object, request: ReferenceRequest, *, deadline_monotonic: float
    ) -> ReferenceObservation: ...


@dataclass(frozen=True)
class BackendBundle:
    model: object
    tokenizer: object
    architecture: str
    root: Path
    generation: Mapping[str, object]


class TransformersRuntime:
    """Pinned-runtime implementation, imported only inside the remote function."""

    def __init__(self) -> None:
        import torch
        from safetensors import safe_open
        from transformers import (
            AutoConfig,
            AutoModelForCausalLM,
            AutoModelForImageTextToText,
            AutoTokenizer,
        )

        self._torch = torch
        self._safe_open = safe_open
        self._config = AutoConfig
        self._tokenizer = AutoTokenizer
        self._model_factories = {
            "causal_lm": AutoModelForCausalLM,
            "image_text_to_text": AutoModelForImageTextToText,
        }
        self.bfloat16 = torch.bfloat16

    def inspect_safetensors(self, path: Path) -> None:
        with self._safe_open(path, framework="pt", device="cpu") as handle:
            if not tuple(handle.keys()):
                raise ExecutionFailure("invalid_safetensors")

    def load_config(self, root: Path, **kwargs: object) -> object:
        return self._config.from_pretrained(root, **kwargs)

    def load_tokenizer(self, root: Path, **kwargs: object) -> object:
        return self._tokenizer.from_pretrained(root, **kwargs)

    def load_model(self, root: Path, **kwargs: object) -> object:
        model_kind = kwargs.pop("model_kind", None)
        factory = self._model_factories.get(model_kind)
        if factory is None:
            raise ExecutionFailure("architecture_mismatch")
        return factory.from_pretrained(root, **kwargs)

    def memory_before(self) -> int:
        self._torch.cuda.reset_peak_memory_stats(DEVICE)
        free, _ = self._torch.cuda.mem_get_info(DEVICE)
        return int(free)

    def memory_peaks(self) -> tuple[int, int]:
        self._torch.cuda.synchronize(DEVICE)
        return (
            int(self._torch.cuda.max_memory_allocated(DEVICE)),
            int(self._torch.cuda.max_memory_reserved(DEVICE)),
        )

    def evaluate_reference(
        self, bundle: object, request: ReferenceRequest, *, deadline_monotonic: float
    ) -> ReferenceObservation:
        if not isinstance(bundle, BackendBundle):
            raise ExecutionFailure("model_binding_drift")
        self._guard_deadline(deadline_monotonic)
        try:
            fixture = json.loads(request.fixture_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ExecutionFailure("evaluation_fixture_invalid") from None
        if not isinstance(fixture, Mapping):
            raise ExecutionFailure("evaluation_fixture_invalid")
        if request.family == "long_context_retrieval":
            response, tokens, _ = self._generate_long(bundle, fixture, request)
            expected = _fixture_string(fixture, "expected")
            score = float(expected.casefold() in response.casefold())
            if not set(request.metrics) <= {"retrieval_accuracy", "exact_match"}:
                raise ExecutionFailure("evaluation_metrics_invalid")
            metrics = {name: score for name in request.metrics}
        elif request.family == "coding":
            response, tokens, _ = self._generate(
                bundle, _fixture_string(fixture, "prompt"), request
            )
            expected = _fixture_string(fixture, "expected")
            score = float(response.strip() == expected)
            if not set(request.metrics) <= {"exact_match", "pass_rate"}:
                raise ExecutionFailure("evaluation_metrics_invalid")
            metrics = {name: score for name in request.metrics}
        elif request.family == "tool_call_validity":
            response, tokens, _ = self._generate(
                bundle, _fixture_string(fixture, "prompt"), request
            )
            metrics = _tool_metrics(response, fixture, request.metrics)
        elif request.family == "throughput":
            repetitions = _fixture_positive_int(fixture, "repetitions")
            configured = _fixture_positive_int(fixture, "configured_tokens")
            if configured != request.response_cap_tokens:
                raise ExecutionFailure("evaluation_fixture_invalid")
            total_tokens = 0
            total_seconds = 0.0
            response = ""
            for _ in range(repetitions):
                self._guard_deadline(deadline_monotonic)
                response, tokens, elapsed = self._generate(
                    bundle, "Continue with deterministic text.", request
                )
                total_tokens += tokens
                total_seconds += elapsed
            if total_seconds <= 0:
                raise ExecutionFailure("evaluation_metrics_invalid")
            tokens = min(total_tokens, request.response_cap_tokens)
            metrics = {"decode_tokens_per_second": total_tokens / total_seconds}
        elif request.family == "memory":
            if (
                fixture.get("measurement") != "peak_vram_bytes"
                or _fixture_positive_int(fixture, "sample_interval_ms") <= 0
            ):
                raise ExecutionFailure("evaluation_fixture_invalid")
            self.memory_before()
            response, tokens, _ = self._generate(bundle, "Return one token.", request)
            _, peak = self.memory_peaks()
            metrics = {"peak_vram_bytes": peak}
        elif request.family == "soak":
            duration = _fixture_positive_int(fixture, "duration_seconds")
            if fixture.get("measurement") != "failure_free_rate":
                raise ExecutionFailure("evaluation_fixture_invalid")
            started = time.monotonic()
            if started + duration > deadline_monotonic:
                raise ExecutionFailure("projected_timeout")
            errors = 0
            response = ""
            tokens = 0
            while time.monotonic() - started < duration:
                try:
                    response, tokens, _ = self._generate(bundle, "Return one token.", request)
                except Exception:
                    errors += 1
                    break
            elapsed = time.monotonic() - started
            metrics = {
                "completed_minutes": elapsed / 60,
                "failure_free_rate": float(errors == 0 and elapsed >= duration),
                "runtime_errors": errors,
            }
        else:
            raise ExecutionFailure("evaluation_family_unknown")
        self._guard_deadline(deadline_monotonic)
        return ReferenceObservation(
            status="completed", metrics=metrics, response=response.encode(), generated_tokens=tokens
        )

    def _generate(
        self, bundle: BackendBundle, prompt: str, request: ReferenceRequest
    ) -> tuple[str, int, float]:
        tokenizer = bundle.tokenizer
        try:
            inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=True)
            inputs = {name: value.to(DEVICE) for name, value in inputs.items()}
            input_tokens = int(inputs["input_ids"].shape[-1])
        except Exception:
            raise ExecutionFailure("tokenizer_contract_invalid") from None
        started = time.monotonic()
        with self._torch.inference_mode():
            output = bundle.model.generate(
                **inputs,
                **_generation_kwargs(bundle.generation, request.response_cap_tokens),
            )
        elapsed = time.monotonic() - started
        generated = output[0, input_tokens:]
        response = tokenizer.decode(generated, skip_special_tokens=True)
        return response, int(generated.shape[-1]), elapsed

    def _generate_long(
        self, bundle: BackendBundle, fixture: Mapping[str, object], request: ReferenceRequest
    ) -> tuple[str, int, float]:
        tokenizer = bundle.tokenizer
        try:
            prefix = tokenizer.encode(
                _fixture_string(fixture, "needle") + "\n", add_special_tokens=False
            )
            suffix = tokenizer.encode(
                "\n" + _fixture_string(fixture, "prompt") + "\n", add_special_tokens=False
            )
            filler = tokenizer.encode(" x", add_special_tokens=False)
        except Exception:
            raise ExecutionFailure("tokenizer_contract_invalid") from None
        input_tokens = request.context_level_tokens - request.response_cap_tokens
        if not prefix or not suffix or len(filler) != 1 or input_tokens < len(prefix) + len(suffix):
            raise ExecutionFailure("context_ladder_drift")
        ids = prefix + filler * (input_tokens - len(prefix) - len(suffix)) + suffix
        inputs = self._torch.tensor([ids], dtype=self._torch.long, device=DEVICE)
        started = time.monotonic()
        with self._torch.inference_mode():
            output = bundle.model.generate(
                input_ids=inputs,
                **_generation_kwargs(bundle.generation, request.response_cap_tokens),
            )
        elapsed = time.monotonic() - started
        generated = output[0, input_tokens:]
        response = tokenizer.decode(generated, skip_special_tokens=True)
        return response, int(generated.shape[-1]), elapsed

    @staticmethod
    def _guard_deadline(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise ExecutionFailure("deadline_exceeded")


class ProductionReferenceBackend:
    """Safetensors-only loader and ordered context evaluator."""

    def __init__(
        self,
        request: BootstrapRequest,
        evaluation_lock: PendingEvaluationLock,
        fixture_bytes: Mapping[str, bytes],
        execution_identity: Mapping[str, str],
        runtime: BackendRuntime | None = None,
    ) -> None:
        if not isinstance(request, BootstrapRequest):
            raise ExecutionFailure("request_binding_drift")
        try:
            raw = json.loads(request.canonical_json)
        except (TypeError, json.JSONDecodeError):
            raise ExecutionFailure("request_binding_drift") from None
        if raw.get("configured_context_tokens") != CONFIGURED_CONTEXT_TOKENS:
            raise ExecutionFailure("configured_context_drift")
        lineage = raw.get("lineage")
        if (
            not isinstance(lineage, Mapping)
            or lineage.get("evaluation_lock_sha256") != evaluation_lock.sha256
        ):
            raise ExecutionFailure("evaluation_lock_drift")
        try:
            validated_lock = validate_pending_evaluation_lock(
                json.loads(evaluation_lock.canonical_json), fixture_bytes=fixture_bytes
            )
        except (EvaluationLockError, TypeError, json.JSONDecodeError):
            raise ExecutionFailure("evaluation_lock_drift") from None
        if validated_lock != evaluation_lock:
            raise ExecutionFailure("evaluation_lock_drift")
        if (
            tuple(evaluation_lock.context.ladder_tokens) != request.context_ladder_tokens
            or evaluation_lock.context.configured_tokens != CONFIGURED_CONTEXT_TOKENS
        ):
            raise ExecutionFailure("context_ladder_drift")
        self.request = request
        self.lock = evaluation_lock
        try:
            self.execution_identity = validate_execution_identity(execution_identity)
        except ReferenceHarnessError:
            raise ExecutionFailure("execution_identity_drift") from None
        self.runtime = runtime or TransformersRuntime()
        _locked_retrieval_fixture(evaluation_lock, fixture_bytes)
        self.fixture_bytes = dict(fixture_bytes)
        self._expected = tuple(request.source_artifacts)
        self._next_context = 0
        self._bundle: BackendBundle | None = None
        self._long_context: dict[int, ReferenceObservation] = {}
        self._active_deadline = 0.0

    def load(self, artifacts: tuple[StoredArtifact, ...]) -> LoadObservation:
        root, paths = self._bind_local_artifacts(artifacts)
        config_raw = _read_json(paths.get("config.json"), "model_config_invalid")
        architecture, model_kind = _validate_model_config(config_raw)
        _reject_remote_code(config_raw)
        for name in ("tokenizer_config.json", "generation_config.json"):
            if name in paths:
                _reject_remote_code(_read_json(paths[name], "model_config_invalid"))
        _validate_tokenizer_set(paths)
        _validate_weight_index(paths)
        for name, path in paths.items():
            if _SHARD_RE.fullmatch(name):
                try:
                    self.runtime.inspect_safetensors(path)
                except ExecutionFailure:
                    raise
                except Exception:
                    raise ExecutionFailure("invalid_safetensors") from None
        try:
            config = self.runtime.load_config(root, **_LOAD_FLAGS)
            _require_architecture(config, architecture)
            tokenizer = self.runtime.load_tokenizer(root, **_LOAD_FLAGS)
            free_before = self.runtime.memory_before()
            model = self.runtime.load_model(
                root,
                **_LOAD_FLAGS,
                use_safetensors=True,
                dtype=self.runtime.bfloat16,
                device_map={"": DEVICE},
                model_kind=model_kind,
            )
            _require_architecture(getattr(model, "config", None), architecture)
            _validate_placement(model)
            allocated, reserved = self.runtime.memory_peaks()
        except ExecutionFailure:
            raise
        except Exception:
            raise ExecutionFailure("model_load_failed") from None
        if not all(_nonnegative_int(value) for value in (free_before, allocated, reserved)):
            raise ExecutionFailure("memory_metrics_invalid")
        bundle = BackendBundle(
            model=model,
            tokenizer=tokenizer,
            architecture=architecture,
            root=root,
            generation=self.lock.generation,
        )
        self._bundle = bundle
        return LoadObservation(True, free_before, allocated, reserved, bundle)

    def identity(self) -> Mapping[str, str]:
        return {
            "scorer_sha256": str(self.lock.scorer["sha256"]),
            "runtime_sha256": str(self.lock.scorer["runtime"]["sha256"]),
        }

    def evaluate_context(
        self, model: object, context_tokens: int, *, deadline_monotonic: float
    ) -> EvaluationObservation:
        if model is not self._bundle or not isinstance(model, BackendBundle):
            raise ExecutionFailure("model_binding_drift")
        if self._next_context >= len(self.request.context_ladder_tokens):
            raise ExecutionFailure("context_ladder_drift")
        expected = self.request.context_ladder_tokens[self._next_context]
        if context_tokens != expected:
            raise ExecutionFailure("context_ladder_drift")
        _validate_placement(model.model)
        request = self._reference_request("long_context_retrieval", context_tokens)
        try:
            observation = self.runtime.evaluate_reference(
                model, request, deadline_monotonic=deadline_monotonic
            )
        except ExecutionFailure:
            raise
        except Exception:
            raise ExecutionFailure("evaluation_failed") from None
        if not isinstance(observation, ReferenceObservation):
            raise ExecutionFailure("evaluation_metrics_invalid")
        completed = observation.status == "completed"
        useful = observation.metrics.get("retrieval_accuracy") == 1
        self._long_context[context_tokens] = observation
        self._next_context += 1
        manifest: bytes | None = None
        if context_tokens == self.request.context_ladder_tokens[-1] and completed:
            self._active_deadline = deadline_monotonic
            try:
                result = run_reference_harness(
                    self.lock,
                    self.fixture_bytes,
                    self,
                    self.execution_identity,
                    precomputed_long_context=self._long_context,
                )
            except ReferenceHarnessError:
                raise ExecutionFailure("reference_harness_failed") from None
            if result.status != "completed":
                raise ExecutionFailure("reference_harness_incomplete")
            manifest = result.canonical_json.encode()
        return EvaluationObservation(
            completed=completed, usefulness_proven=useful, manifest=manifest
        )

    def evaluate(self, request: ReferenceRequest) -> ReferenceObservation:
        if self._bundle is None or request.family == "long_context_retrieval":
            raise ExecutionFailure("reference_harness_drift")
        if time.monotonic() >= self._active_deadline:
            raise ExecutionFailure("deadline_exceeded")
        try:
            return self.runtime.evaluate_reference(
                self._bundle, request, deadline_monotonic=self._active_deadline
            )
        except ExecutionFailure:
            raise
        except Exception:
            raise ExecutionFailure("evaluation_failed") from None

    def _reference_request(self, family: str, context_tokens: int) -> ReferenceRequest:
        fixture = next(item for item in self.lock.fixtures if item.family == family)
        generation_json = json.dumps(
            self.lock.generation, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return ReferenceRequest(
            family=family,
            fixture_id=fixture.fixture_id,
            fixture_bytes=self.fixture_bytes[fixture.fixture_id],
            seed=fixture.seed,
            metrics=fixture.metrics,
            context_level_tokens=context_tokens,
            generation_json=generation_json,
            response_cap_tokens=self.lock.generation["response_caps_tokens"][family],
            response_cap_bytes=self.lock.generation["response_caps_bytes"][family],
        )

    def _bind_local_artifacts(
        self, artifacts: tuple[StoredArtifact, ...]
    ) -> tuple[Path, dict[str, Path]]:
        if len(artifacts) != len(self._expected):
            raise ExecutionFailure("artifact_binding_drift")
        root: Path | None = None
        paths: dict[str, Path] = {}
        for ordinal, (actual, expected) in enumerate(zip(artifacts, self._expected, strict=True)):
            if (
                actual.ordinal != ordinal
                or actual.ordinal != expected["ordinal"]
                or actual.format != expected["format"]
                or actual.size_bytes != expected["size_bytes"]
                or actual.sha256 != expected["sha256"]
                or not isinstance(actual.handle, Path)
            ):
                raise ExecutionFailure("artifact_binding_drift")
            name = _artifact_name(str(expected["url"]), str(expected["format"]))
            path = actual.handle.resolve()
            if path.name != name or not path.is_file():
                raise ExecutionFailure("artifact_binding_drift")
            if root is None:
                root = path.parent
            elif path.parent != root:
                raise ExecutionFailure("artifact_root_drift")
            if name in paths:
                raise ExecutionFailure("artifact_binding_drift")
            paths[name] = path
        if root is None:
            raise ExecutionFailure("artifact_binding_drift")
        return root, paths


def build_execution_dependencies(
    request: BootstrapRequest,
    evaluation_lock: PendingEvaluationLock,
    fixture_bytes: Mapping[str, bytes],
    execution_identity: Mapping[str, str],
    *,
    artifact_root: Path,
    image_identity_sha256: str,
    runtime: BackendRuntime | None = None,
) -> ExecutionDependencies:
    """Build the sole production dependency graph without contacting a provider."""
    backend = ProductionReferenceBackend(
        request,
        evaluation_lock,
        fixture_bytes,
        execution_identity,
        runtime=runtime,
    )
    return ExecutionDependencies(
        clock=MonotonicClock(),
        resolver=PublicResolver(),
        fetcher=DirectHTTPSFetcher(),
        store=LocalArtifactStore(artifact_root, request),
        runtime_probe=CudaRuntimeProbe(image_identity_sha256),
        loader=backend,
        evaluator=backend,
        environment={name: os.environ.get(name, "") for name in _PROXY_KEYS},
    )


def _artifact_name(url: str, format_name: str) -> str:
    parsed = urlsplit(url)
    raw_name = parsed.path.rsplit("/", 1)[-1]
    name = unquote(raw_name)
    if not name or raw_name != name or Path(name).name != name:
        raise ExecutionFailure("unsafe_artifact")
    valid = (
        (format_name == "safetensors" and _SHARD_RE.fullmatch(name))
        or (format_name == "json" and name in _JSON_FILES)
        or (format_name == "tokenizer_data" and name in _TOKENIZER_FILES)
        or (format_name == "text" and name in _TEXT_FILES)
    )
    if not valid:
        raise ExecutionFailure("unsafe_artifact")
    return name


def _locked_retrieval_fixture(
    lock: PendingEvaluationLock, fixture_bytes: Mapping[str, bytes]
) -> Mapping[str, str]:
    fixture_id = next(
        fixture.fixture_id
        for fixture in lock.fixtures
        if fixture.family == "long_context_retrieval"
    )
    try:
        raw = json.loads(fixture_bytes[fixture_id])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
        raise ExecutionFailure("evaluation_lock_drift") from None
    required = {"expected", "id", "needle", "prompt"}
    if (
        not isinstance(raw, Mapping)
        or set(raw) != required
        or any(not isinstance(raw[name], str) or not raw[name] for name in required)
    ):
        raise ExecutionFailure("evaluation_fixture_invalid")
    return {name: raw[name] for name in sorted(required)}


def _generation_kwargs(generation: Mapping[str, object], max_new_tokens: int) -> dict[str, object]:
    return {
        "do_sample": False,
        "max_new_tokens": max_new_tokens,
        "temperature": float(str(generation["temperature"])),
        "top_p": float(str(generation["top_p"])),
    }


def _fixture_string(fixture: Mapping[str, object], name: str) -> str:
    value = fixture.get(name)
    if not isinstance(value, str) or not value:
        raise ExecutionFailure("evaluation_fixture_invalid")
    return value


def _fixture_positive_int(fixture: Mapping[str, object], name: str) -> int:
    value = fixture.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ExecutionFailure("evaluation_fixture_invalid")
    return value


def _tool_metrics(
    response: str, fixture: Mapping[str, object], metrics: tuple[str, ...]
) -> dict[str, float]:
    try:
        parsed = json.loads(response)
    except json.JSONDecodeError:
        parsed = None
    valid = (
        isinstance(parsed, Mapping)
        and isinstance(parsed.get("name"), str)
        and isinstance(parsed.get("arguments"), Mapping)
    )
    expected = fixture.get("expected")
    scores = {
        "argument_accuracy": float(valid and parsed == expected),
        "schema_valid_rate": float(valid),
    }
    try:
        return {name: scores[name] for name in metrics}
    except KeyError:
        raise ExecutionFailure("evaluation_metrics_invalid") from None


def _read_json(path: Path | None, code: str) -> Mapping[str, Any]:
    if path is None:
        raise ExecutionFailure(code)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise ExecutionFailure(code) from None
    if not isinstance(value, Mapping):
        raise ExecutionFailure(code)
    return value


def _reject_remote_code(value: object) -> None:
    if isinstance(value, Mapping):
        if "auto_map" in value or value.get("trust_remote_code") not in (None, False):
            raise ExecutionFailure("remote_code_forbidden")
        for nested in value.values():
            _reject_remote_code(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_remote_code(nested)


def _validate_model_config(config: Mapping[str, Any]) -> tuple[str, str]:
    architectures = config.get("architectures")
    if (
        not isinstance(architectures, list)
        or len(architectures) != 1
        or not isinstance(architectures[0], str)
        or _ARCHITECTURE_RE.fullmatch(architectures[0]) is None
    ):
        raise ExecutionFailure("architecture_mismatch")
    text_config = config.get("text_config")
    text = text_config if isinstance(text_config, Mapping) else config
    declared_dtype = text.get("dtype", text.get("torch_dtype"))
    if declared_dtype != DTYPE:
        raise ExecutionFailure("dtype_drift")
    if text.get("max_position_embeddings") != CONFIGURED_CONTEXT_TOKENS:
        raise ExecutionFailure("configured_context_drift")
    model_kind = (
        "image_text_to_text" if isinstance(config.get("vision_config"), Mapping) else "causal_lm"
    )
    return architectures[0], model_kind


def _validate_tokenizer_set(paths: Mapping[str, Path]) -> None:
    tokenizer_json = "tokenizer.json" in paths
    pair = {"vocab.json", "merges.txt"}.issubset(paths)
    if tokenizer_json == pair or bool({"vocab.json", "merges.txt"} & paths.keys()) != pair:
        raise ExecutionFailure("tokenizer_binding_drift")
    if "tokenizer_config.json" not in paths:
        raise ExecutionFailure("tokenizer_binding_drift")


def _validate_weight_index(paths: Mapping[str, Path]) -> None:
    index = _read_json(paths.get("model.safetensors.index.json"), "weight_index_invalid")
    weight_map = index.get("weight_map")
    if not isinstance(weight_map, Mapping) or not weight_map:
        raise ExecutionFailure("weight_index_invalid")
    referenced = set(weight_map.values())
    if any(not isinstance(name, str) or _SHARD_RE.fullmatch(name) is None for name in referenced):
        raise ExecutionFailure("weight_index_invalid")
    supplied = {name for name in paths if _SHARD_RE.fullmatch(name)}
    if referenced != supplied:
        raise ExecutionFailure("weight_index_invalid")


def _require_architecture(value: object, expected: str) -> None:
    if getattr(value, "architectures", None) != [expected] or getattr(
        value, "auto_map", None
    ) not in (None, {}):
        raise ExecutionFailure("architecture_mismatch")


def _validate_placement(model: object) -> None:
    try:
        parameters = tuple(model.parameters())
        buffers = tuple(model.buffers())
    except (AttributeError, TypeError):
        raise ExecutionFailure("device_drift") from None
    if not parameters:
        raise ExecutionFailure("device_drift")
    if any(str(getattr(value, "dtype", "")) != "torch.bfloat16" for value in parameters):
        raise ExecutionFailure("dtype_drift")
    if any(str(getattr(value, "device", "")) != DEVICE for value in parameters + buffers):
        raise ExecutionFailure("device_drift")


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
