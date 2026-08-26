from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

import pytest

import lowbit_lab.reference_execution as reference_execution
from lowbit_lab.reference_bootstrap import (
    BootstrapRequest,
    canonical_json,
    canonical_sha256,
    validate_bootstrap_receipt_bytes,
)
from lowbit_lab.reference_execution import (
    ArtifactWriter,
    EvaluationObservation,
    ExecutionDependencies,
    FetchResponse,
    LoadObservation,
    ReferenceDeadlineAbort,
    ReferenceExecution,
    RuntimeObservation,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
PUBLIC_IP = "8.8.8.8"
BODY = b"data"


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FakeResolver:
    addresses: Mapping[str, Sequence[str]] = field(
        default_factory=lambda: {"artifacts.example": (PUBLIC_IP,)}
    )
    calls: list[str] = field(default_factory=list)

    def resolve(self, host: str) -> Sequence[str]:
        self.calls.append(host)
        return self.addresses[host]


@dataclass
class FakeFetcher:
    responses: dict[str, list[FetchResponse]]
    calls: list[tuple[str, tuple[str, ...], bool]] = field(default_factory=list)

    def open(
        self, url: str, *, resolved_addresses: tuple[str, ...], proxies_disabled: bool
    ) -> FetchResponse:
        self.calls.append((url, resolved_addresses, proxies_disabled))
        return self.responses[url].pop(0)


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, chunk: bytes) -> None:
        self.data.extend(chunk)

    def finish(self) -> object:
        return bytes(self.data)


@dataclass
class MemoryStore:
    available: int = 1024
    writers: list[MemoryWriter] = field(default_factory=list)

    def free_bytes(self) -> int:
        return self.available

    def begin(self, ordinal: int, expected_bytes: int) -> ArtifactWriter:
        writer = MemoryWriter()
        self.writers.append(writer)
        return writer


@dataclass
class FakeRuntime:
    free: int = 100
    total: int = 200

    def probe(self) -> RuntimeObservation:
        return RuntimeObservation(self.free, self.total, SHA_A, SHA_B)


@dataclass
class FakeLoader:
    loaded: bool = True
    raises: BaseException | None = None
    calls: int = 0

    def load(self, artifacts: tuple[object, ...]) -> LoadObservation:
        self.calls += 1
        if self.raises:
            raise self.raises
        return LoadObservation(self.loaded, 100, 20, 30, object())


@dataclass
class FakeEvaluator:
    clock: FakeClock
    incomplete_at: int | None = None
    raises_at: int | None = None
    calls: list[int] = field(default_factory=list)

    def evaluate_context(
        self, model: object, context_tokens: int, *, deadline_monotonic: float
    ) -> EvaluationObservation:
        del model, deadline_monotonic
        self.calls.append(context_tokens)
        if context_tokens == self.raises_at:
            raise RuntimeError("sensitive target and local path")
        self.clock.advance(0.001)
        return EvaluationObservation(
            completed=context_tokens != self.incomplete_at,
            usefulness_proven=context_tokens == 262_144,
            manifest=_manifest() if context_tokens == 262_144 else None,
        )


def _manifest(evaluation_lock_sha256: str = SHA_A) -> bytes:
    metrics = {
        "coding": {"exact_match": 1.0},
        "tool_call_validity": {"schema_valid_rate": 1.0},
        "long_context_retrieval": {"retrieval_accuracy": 1.0},
        "throughput": {"decode_tokens_per_second": 1.0},
        "memory": {"peak_vram_bytes": 1},
        "soak": {"completed_minutes": 1.0, "failure_free_rate": 1.0, "runtime_errors": 0},
    }
    measurements = []
    for family in metrics:
        levels = (
            [65_536, 131_072, 196_608, 262_144] if family == "long_context_retrieval" else [262_144]
        )
        measurements.extend(
            {
                "context_level_tokens": level,
                "family": family,
                "fixture_id": f"generic-{family}",
                "metrics": metrics[family],
                "response_bytes": 0,
                "response_sha256": hashlib.sha256(b"").hexdigest(),
                "response_tokens": 0,
                "status": "completed",
            }
            for level in levels
        )
    raw = {
        "evaluation_lock_sha256": evaluation_lock_sha256,
        "execution_identity": {
            "provenance_manifest_sha256": "1" * 64,
            "resource_spec_sha256": "2" * 64,
            "reviewed_commit_sha256": "3" * 40,
            "runtime_receipt_sha256": "4" * 64,
            "weight_inventory_sha256": "5" * 64,
        },
        "executor_identity": {"runtime_sha256": "6" * 64, "scorer_sha256": "7" * 64},
        "kind": "reference_metrics",
        "measurements": measurements,
        "schema_version": 1,
        "status": "completed",
    }
    return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _request(
    *,
    url: str = "https://artifacts.example/weights.safetensors",
    body: bytes = BODY,
    size: int | None = None,
) -> BootstrapRequest:
    artifacts = [
        {
            "format": "safetensors",
            "ordinal": 0,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body) if size is None else size,
            "url": url,
        }
    ]
    raw = {
        "approved_https_hosts": [
            "artifacts.example",
            "cdn.example",
            "huggingface.co",
            "us.aws.cdn.hf.co",
        ],
        "context_ladder_tokens": [65_536, 131_072, 196_608, 262_144],
        "known_memory_lower_bound_bytes": 50,
        "lineage": {"evaluation_lock_sha256": SHA_A},
        "source_artifacts": artifacts,
    }
    encoded = canonical_json(raw)
    return BootstrapRequest(
        canonical_json=encoded,
        sha256=canonical_sha256(raw),
        source_artifacts=tuple(artifacts),
        context_ladder_tokens=tuple(raw["context_ladder_tokens"]),
        image_lock_sha256=SHA_A,
    )


def _response(
    body: Iterable[bytes] = (BODY,),
    *,
    status: int = 200,
    peer: str = PUBLIC_IP,
    length: int | None = len(BODY),
    location: str | None = None,
) -> FetchResponse:
    return FetchResponse(status, peer, length, body, location)


def _dependencies(
    *,
    response: FetchResponse | None = None,
    resolver: FakeResolver | None = None,
    store: MemoryStore | None = None,
    runtime: FakeRuntime | None = None,
    loader: FakeLoader | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[ExecutionDependencies, FakeClock, FakeFetcher, FakeLoader, FakeEvaluator]:
    clock = FakeClock()
    fetcher = FakeFetcher(
        {"https://artifacts.example/weights.safetensors": [response or _response()]}
    )
    actual_loader = loader or FakeLoader()
    evaluator = FakeEvaluator(clock)
    dependencies = ExecutionDependencies(
        clock=clock,
        resolver=resolver or FakeResolver(),
        fetcher=fetcher,
        store=store or MemoryStore(),
        runtime_probe=runtime or FakeRuntime(),
        loader=actual_loader,
        evaluator=evaluator,
        environment={} if environment is None else environment,
    )
    return dependencies, clock, fetcher, actual_loader, evaluator


def _run(
    request: BootstrapRequest | None = None,
    dependencies: ExecutionDependencies | None = None,
) -> dict[str, object]:
    actual_request = request or _request()
    actual_dependencies = dependencies or _dependencies()[0]
    result = ReferenceExecution(
        actual_request, actual_dependencies, deadline_started_monotonic=0
    ).run()
    validated = validate_bootstrap_receipt_bytes(result.receipt, request=actual_request)
    return json.loads(validated.canonical_json)


def _failure(receipt: Mapping[str, object]) -> tuple[str, str]:
    terminal = receipt["terminal_failure"]
    assert isinstance(terminal, dict)
    return str(terminal["stage"]), str(terminal["code"])


def test_fake_end_to_end_visits_each_stage_once_and_returns_bounded_receipt() -> None:
    dependencies, _, fetcher, loader, evaluator = _dependencies()
    receipt = _run(dependencies=dependencies)

    assert receipt["status"] == "succeeded"
    assert [stage["stage"] for stage in receipt["stages"]] == [
        "runtime_identity",
        "source_transfer",
        "hash_verification",
        "model_load",
        "evaluation",
        "evidence_finalization",
    ]
    assert len(fetcher.calls) == loader.calls == 1
    assert fetcher.calls[0][2] is True
    assert evaluator.calls == [65_536, 131_072, 196_608, 262_144]
    assert receipt["configured_context_tokens"] == 262_144
    assert receipt["full_context_usefulness_proven"] is True
    evaluation = receipt["stages"][4]["measurements"]
    assert evaluation["reference_manifest_sha256"] == hashlib.sha256(_manifest()).hexdigest()
    assert evaluation["reference_manifest_bytes"] == len(_manifest())
    receipt_size = len(canonical_json(receipt).encode())
    assert receipt_size <= 65_536
    assert receipt["stages"][-1]["measurements"]["receipt_bytes"] == receipt_size

    direct_dependencies = _dependencies()[0]
    result = ReferenceExecution(_request(), direct_dependencies, deadline_started_monotonic=0).run()
    assert result.manifest == _manifest()
    rebound = validate_bootstrap_receipt_bytes(result.receipt, request=_request())
    rebound_raw = json.loads(rebound.canonical_json)
    assert (
        rebound_raw["stages"][4]["measurements"]["reference_manifest_sha256"]
        == hashlib.sha256(result.manifest).hexdigest()
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://artifacts.example/weights.safetensors",
        "https://user@artifacts.example/weights.safetensors",
        "https://artifacts.example:444/weights.safetensors",
        "https://artifacts.example/weights.safetensors?download=1",
        "https://artifacts.example/weights.safetensors#fragment",
        "https://artifacts.example/weights.safetensors?sig=line\nbreak",
        "https://other.example/weights.safetensors",
    ],
)
def test_unsafe_urls_stop_before_fetch(url: str) -> None:
    request = _request(url=url)
    dependencies, _, fetcher, _, _ = _dependencies()
    receipt = _run(request, dependencies)
    assert _failure(receipt) == ("source_transfer", "unsafe_url")
    assert fetcher.calls == []


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "192.0.2.1", "::1"],
)
def test_nonpublic_resolution_is_rejected(address: str) -> None:
    resolver = FakeResolver({"artifacts.example": (address,)})
    dependencies, _, fetcher, _, _ = _dependencies(resolver=resolver)
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("source_transfer", "unsafe_address")
    assert fetcher.calls == []


def test_connected_peer_must_match_the_fresh_public_resolution() -> None:
    dependencies, _, _, _, _ = _dependencies(response=_response(peer="1.1.1.1"))
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("source_transfer", "peer_address_drift")


def test_redirect_revalidates_host_resolution_and_peer() -> None:
    first = _response((), status=302, length=0, location="https://cdn.example/file")
    second = _response()
    dependencies, _, fetcher, _, _ = _dependencies(response=first)
    fetcher.responses["https://cdn.example/file"] = [second]
    resolver = dependencies.resolver
    assert isinstance(resolver, FakeResolver)
    resolver.addresses = {"artifacts.example": (PUBLIC_IP,), "cdn.example": (PUBLIC_IP,)}

    receipt = _run(dependencies=dependencies)
    assert receipt["status"] == "succeeded"
    assert resolver.calls == ["artifacts.example", "cdn.example"]
    assert len(fetcher.calls) == 2


def test_redirect_to_unapproved_host_stops_without_second_connection() -> None:
    first = _response((), status=302, length=0, location="https://evil.example/file")
    dependencies, _, fetcher, _, _ = _dependencies(response=first)
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("source_transfer", "unsafe_url")
    assert len(fetcher.calls) == 1


@pytest.mark.parametrize(
    "target",
    [
        "https://huggingface.co/api/resolve-cache/models/org/rev/file?sig=value",
        "https://us.aws.cdn.hf.co/xet-bridge-us/rev/file?sig=value",
    ],
)
def test_signed_query_redirect_is_allowed_only_by_frozen_policy(target: str) -> None:
    first = _response((), status=302, length=0, location=target)
    dependencies, _, fetcher, _, _ = _dependencies(response=first)
    fetcher.responses[target] = [_response()]
    resolver = dependencies.resolver
    assert isinstance(resolver, FakeResolver)
    host = str(target.split("/", 3)[2])
    resolver.addresses = {"artifacts.example": (PUBLIC_IP,), host: (PUBLIC_IP,)}

    receipt = _run(dependencies=dependencies)

    assert receipt["status"] == "succeeded"
    assert len(fetcher.calls) == 2
    assert "sig=value" not in canonical_json(receipt)


@pytest.mark.parametrize(
    "target",
    [
        "https://huggingface.co/models/org/file?sig=value",
        "https://us.aws.cdn.hf.co/xet-bridge-usa/file?sig=value",
        "https://huggingface.co/api/resolve-cache/models/../private?sig=value",
        "https://huggingface.co/api/resolve-cache/models/%2e%2e/private?sig=value",
        "https://huggingface.co/api/resolve-cache/models/a%2fb?sig=value",
        "https://huggingface.co/api/resolve-cache/models/a\\b?sig=value",
        "https://huggingface.co/api/resolve-cache/models/a%zz?sig=value",
    ],
)
def test_signed_query_redirect_path_drift_stops_before_second_fetch(target: str) -> None:
    sentinel = "signed" + "-query-secret"
    target = target.replace("sig=value", f"sig={sentinel}")
    first = _response((), status=302, length=0, location=target)
    dependencies, _, fetcher, _, _ = _dependencies(response=first)

    receipt = _run(dependencies=dependencies)

    assert _failure(receipt) == ("source_transfer", "unsafe_url")
    assert len(fetcher.calls) == 1
    assert sentinel not in canonical_json(receipt)


def test_ambient_proxy_stops_before_resolution_or_fetch() -> None:
    dependencies, _, fetcher, _, _ = _dependencies(environment={"HTTPS_PROXY": "x"})
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("source_transfer", "ambient_proxy")
    assert fetcher.calls == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_response((b"da",), length=None), "transfer_length_mismatch"),
        (_response((b"data!",), length=None), "transfer_oversized"),
        (_response(length=5), "transfer_length_mismatch"),
        (_response((b"xxxx",)), "hash_mismatch"),
    ],
)
def test_partial_oversized_length_and_hash_fail_closed(
    response: FetchResponse, expected: str
) -> None:
    dependencies, _, _, _, _ = _dependencies(response=response)
    receipt = _run(dependencies=dependencies)
    stage = "hash_verification" if expected == "hash_mismatch" else "source_transfer"
    assert _failure(receipt) == (stage, expected)


def test_disk_and_runtime_memory_bounds_stop_before_later_stages() -> None:
    disk_deps, _, _, disk_loader, _ = _dependencies(store=MemoryStore(available=3))
    disk_receipt = _run(dependencies=disk_deps)
    assert _failure(disk_receipt) == ("source_transfer", "insufficient_disk")
    assert disk_loader.calls == 0

    memory_deps, _, memory_fetcher, _, _ = _dependencies(runtime=FakeRuntime(free=49))
    memory_receipt = _run(dependencies=memory_deps)
    assert _failure(memory_receipt) == ("runtime_identity", "insufficient_memory")
    assert memory_fetcher.calls == []


def test_load_failure_and_unknown_exception_are_sanitized() -> None:
    failed_deps, _, _, _, _ = _dependencies(loader=FakeLoader(loaded=False))
    assert _failure(_run(dependencies=failed_deps)) == ("model_load", "load_failed")

    unknown_deps, _, _, _, evaluator = _dependencies()
    evaluator.raises_at = 65_536
    receipt = _run(dependencies=unknown_deps)
    assert _failure(receipt) == ("evaluation", "unknown_failure")
    assert "sensitive" not in canonical_json(receipt)
    assert receipt["stages"][-1]["measurements"]["reference_manifest_sha256"] is None


def test_absolute_deadline_abort_is_never_converted_to_a_receipt() -> None:
    dependencies, _, _, _, _ = _dependencies(
        loader=FakeLoader(raises=ReferenceDeadlineAbort("deadline"))
    )
    with pytest.raises(ReferenceDeadlineAbort):
        ReferenceExecution(_request(), dependencies, deadline_started_monotonic=0).run()


def test_malformed_runtime_metrics_fail_without_becoming_evidence() -> None:
    dependencies, _, fetcher, _, _ = _dependencies(runtime=FakeRuntime(free=201, total=200))
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("runtime_identity", "malformed_metrics")
    assert receipt["empirical_facts"]["usable_gpu_memory"] is False
    assert fetcher.calls == []


def test_incomplete_context_never_relabels_configured_context_as_proven() -> None:
    dependencies, _, _, _, evaluator = _dependencies()
    evaluator.incomplete_at = 196_608
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("evaluation", "context_incomplete")
    assert receipt["configured_context_tokens"] == 262_144
    assert receipt["max_completed_context_tokens"] == 131_072
    assert receipt["full_context_usefulness_proven"] is False
    assert receipt["empirical_facts"]["provider_image_identity"] is True
    assert receipt["empirical_facts"]["empirical_fit"] is True


def test_terminal_failure_never_returns_or_binds_a_manifest() -> None:
    request = _request()
    dependencies, clock, _, _, evaluator = _dependencies()

    def malformed(
        model: object, context_tokens: int, *, deadline_monotonic: float
    ) -> EvaluationObservation:
        del model, deadline_monotonic
        evaluator.calls.append(context_tokens)
        clock.advance(0.001)
        return EvaluationObservation(
            True, False, b'{"not":"a manifest"}' if context_tokens == 262_144 else None
        )

    evaluator.evaluate_context = malformed  # type: ignore[method-assign]
    result = ReferenceExecution(request, dependencies, deadline_started_monotonic=0).run()
    receipt = json.loads(
        validate_bootstrap_receipt_bytes(result.receipt, request=request).canonical_json
    )

    assert result.manifest is None
    assert _failure(receipt) == ("evaluation", "manifest_binding_drift")
    assert receipt["stages"][-1]["measurements"]["reference_manifest_sha256"] is None


def test_shared_deadline_and_nonmonotonic_clock_fail_closed() -> None:
    dependencies, clock, fetcher, _, _ = _dependencies()
    clock.now = 1_201
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("runtime_identity", "projected_timeout")
    assert fetcher.calls == []

    backwards_deps, backwards_clock, _, _, _ = _dependencies()
    backwards_clock.now = -1
    backwards = _run(dependencies=backwards_deps)
    assert _failure(backwards) == ("runtime_identity", "non_monotonic_clock")


def test_transfer_projection_uses_observed_bytes_and_preserves_future_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(body=b"x" * 100, size=100)
    dependencies, clock, fetcher, _, _ = _dependencies()

    def slow_chunks() -> Iterable[bytes]:
        clock.advance(100)
        yield b"x" * 4
        raise AssertionError("projection must stop before another byte is read")

    fetcher.responses["https://artifacts.example/weights.safetensors"] = [
        _response(slow_chunks(), length=100)
    ]
    assert reference_execution.MIN_PROJECTION_BYTES == 67_108_864
    monkeypatch.setattr(reference_execution, "MIN_PROJECTION_BYTES", 4)
    receipt = _run(request, dependencies)
    assert _failure(receipt) == ("source_transfer", "projected_timeout")
    assert receipt["stages"][-1]["measurements"]["bytes_received"] == 4


def test_quadratic_context_projection_stops_before_next_level() -> None:
    dependencies, _, _, _, evaluator = _dependencies()

    def slow_evaluate(
        model: object, context_tokens: int, *, deadline_monotonic: float
    ) -> EvaluationObservation:
        del model, deadline_monotonic
        evaluator.calls.append(context_tokens)
        evaluator.clock.advance(100)
        return EvaluationObservation(
            True, False, _manifest() if context_tokens == 262_144 else None
        )

    evaluator.evaluate_context = slow_evaluate  # type: ignore[method-assign]
    receipt = _run(dependencies=dependencies)
    assert _failure(receipt) == ("evaluation", "projected_timeout")
    assert evaluator.calls == [65_536]
