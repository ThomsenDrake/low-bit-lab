"""Provider-neutral fail-closed staged executor for the reference bootstrap."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from lowbit_lab.reference_bootstrap import (
    CONFIGURED_CONTEXT_TOKENS,
    FUTURE_STAGE_RESERVES_SECONDS,
    STAGES,
    BootstrapRequest,
    ReferenceBootstrapError,
    canonical_bytes,
    validate_bootstrap_receipt,
    validate_bootstrap_request_bytes,
    validate_stage_receipt,
)
from lowbit_lab.reference_harness import (
    ReferenceHarnessError,
    validate_reference_manifest_bytes,
)

MIN_PROJECTION_BYTES = 67_108_864
MAX_REDIRECTS = 5
FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
PROXY_KEYS = frozenset(
    {"all_proxy", "http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"}
)


class Clock(Protocol):
    def monotonic(self) -> float: ...


class Resolver(Protocol):
    def resolve(self, host: str) -> Sequence[str]: ...


@dataclass(frozen=True)
class FetchResponse:
    status: int
    peer_address: str
    content_length: int | None
    chunks: Iterable[bytes]
    location: str | None = None


class Fetcher(Protocol):
    def open(
        self, url: str, *, resolved_addresses: tuple[str, ...], proxies_disabled: bool
    ) -> FetchResponse: ...


class ArtifactWriter(Protocol):
    def write(self, chunk: bytes) -> None: ...

    def finish(self) -> object: ...


class ArtifactStore(Protocol):
    def free_bytes(self) -> int: ...

    def begin(self, ordinal: int, expected_bytes: int) -> ArtifactWriter: ...


@dataclass(frozen=True)
class RuntimeObservation:
    device_free_bytes: int
    device_total_bytes: int
    image_identity_sha256: str
    runtime_identity_sha256: str


class RuntimeProbe(Protocol):
    def probe(self) -> RuntimeObservation: ...


@dataclass(frozen=True)
class StoredArtifact:
    ordinal: int
    format: str
    size_bytes: int
    sha256: str
    handle: object


@dataclass(frozen=True)
class LoadObservation:
    loaded: bool
    device_free_before_bytes: int
    peak_allocated_bytes: int
    peak_reserved_bytes: int
    model: object


class Loader(Protocol):
    def load(self, artifacts: tuple[StoredArtifact, ...]) -> LoadObservation: ...


@dataclass(frozen=True)
class EvaluationObservation:
    completed: bool
    usefulness_proven: bool
    manifest: bytes | None = None


class Evaluator(Protocol):
    def evaluate_context(
        self, model: object, context_tokens: int, *, deadline_monotonic: float
    ) -> EvaluationObservation: ...


@dataclass(frozen=True)
class ExecutionDependencies:
    clock: Clock
    resolver: Resolver
    fetcher: Fetcher
    store: ArtifactStore
    runtime_probe: RuntimeProbe
    loader: Loader
    evaluator: Evaluator
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class ExecutionResult:
    receipt: bytes
    manifest: bytes | None


class ExecutionFailure(RuntimeError):
    """A deliberately sanitized terminal failure from an injected backend."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if _safe_code(code) else "unknown_failure"


class ReferenceDeadlineAbort(BaseException):
    """An absolute provider deadline that staged fail-closed handling must never swallow."""


def _safe_code(code: object) -> bool:
    return isinstance(code, str) and FAILURE_CODE_RE.fullmatch(code) is not None


class ReferenceExecution:
    """Run each locked stage once and return only a validated canonical receipt."""

    def __init__(
        self,
        request: BootstrapRequest,
        dependencies: ExecutionDependencies,
        *,
        deadline_started_monotonic: float,
    ) -> None:
        self.request = request
        self.deps = dependencies
        self.started = deadline_started_monotonic
        self.deadline = self.started + 2700
        self.last_now = deadline_started_monotonic
        self.raw = json.loads(request.canonical_json)
        self.stages: list[dict[str, object]] = []
        self.runtime: RuntimeObservation | None = None
        self.artifacts: list[StoredArtifact] = []
        self.transfer_digests: list[str] = []
        self.bytes_received = 0
        self.model: object | None = None
        self.max_context = 0
        self.full_usefulness = False
        self.manifest: bytes | None = None

    def run(self) -> ExecutionResult:
        stage_functions = (
            self._runtime_identity,
            self._source_transfer,
            self._hash_verification,
            self._model_load,
            self._evaluation,
            self._evidence_finalization,
        )
        for ordinal, function in enumerate(stage_functions):
            try:
                measurements = function()
                self._append_stage(ordinal, "completed", None, measurements)
            except Exception as exc:  # fail closed for unexpected backend failures
                code = exc.code if isinstance(exc, ExecutionFailure) else "unknown_failure"
                if ordinal == 4:
                    self.manifest = None
                if isinstance(exc, _StageFailure):
                    code = exc.code
                    measurements = (
                        self._empty_measurements(ordinal)
                        if ordinal == 4 or exc.measurements is None
                        else exc.measurements
                    )
                else:
                    measurements = self._empty_measurements(ordinal)
                self._append_stage(ordinal, "failed", code, measurements, tolerate_clock=True)
                return ExecutionResult(self._final_receipt(False), None)
        return ExecutionResult(self._final_receipt(True), self.manifest)

    def _now(self) -> float:
        now = self.deps.clock.monotonic()
        if not isinstance(now, int | float) or not math.isfinite(now) or now < self.last_now:
            raise _StageFailure("non_monotonic_clock")
        self.last_now = float(now)
        if now > self.deadline:
            raise _StageFailure("deadline_exceeded")
        return float(now)

    def _timing(self, *, tolerate_clock: bool = False) -> tuple[int, int]:
        try:
            now = self._now()
        except _StageFailure:
            if not tolerate_clock:
                raise
            now = min(max(self.last_now, self.started), self.deadline)
        elapsed = max(0, math.ceil((now - self.started) * 1000))
        remaining = max(0, math.floor((self.deadline - now) * 1000))
        return elapsed, remaining

    def _require_seconds(
        self,
        seconds: float,
        code: str = "projected_timeout",
        measurements: Mapping[str, object] | None = None,
    ) -> None:
        now = self._now()
        if math.ceil(seconds * 1000) > math.floor((self.deadline - now) * 1000):
            raise _StageFailure(code, measurements)

    def _append_stage(
        self,
        ordinal: int,
        status: str,
        failure_code: str | None,
        measurements: Mapping[str, object],
        *,
        tolerate_clock: bool = False,
    ) -> None:
        elapsed, remaining = self._timing(tolerate_clock=tolerate_clock)
        raw = {
            "elapsed_ms": elapsed,
            "failure_code": failure_code,
            "kind": "reference_bootstrap_stage_receipt",
            "measurements": dict(measurements),
            "ordinal": ordinal,
            "remaining_ms": remaining,
            "request_sha256": self.request.sha256,
            "schema_version": 1,
            "stage": STAGES[ordinal],
            "status": status,
        }
        try:
            validate_stage_receipt(raw, request=self.request)
        except ReferenceBootstrapError:
            raw["measurements"] = self._empty_measurements(ordinal)
            try:
                validate_stage_receipt(raw, request=self.request)
            except ReferenceBootstrapError:
                raw["status"] = "failed"
                raw["failure_code"] = "malformed_measurements"
                validate_stage_receipt(raw, request=self.request)
        self.stages.append(raw)

    def _runtime_identity(self) -> Mapping[str, object]:
        self._require_seconds(sum(FUTURE_STAGE_RESERVES_SECONDS.values()))
        observation = self.deps.runtime_probe.probe()
        values = (
            observation.device_free_bytes,
            observation.device_total_bytes,
        )
        if (
            any(not _nonnegative_int(value) for value in values)
            or observation.device_free_bytes > observation.device_total_bytes
            or not _sha256(observation.image_identity_sha256)
            or not _sha256(observation.runtime_identity_sha256)
        ):
            raise _StageFailure("malformed_metrics")
        measurements = {
            "device_free_bytes": observation.device_free_bytes,
            "device_total_bytes": observation.device_total_bytes,
            "image_identity_sha256": observation.image_identity_sha256,
            "runtime_identity_sha256": observation.runtime_identity_sha256,
        }
        self.runtime = observation
        if observation.device_free_bytes < self.raw["known_memory_lower_bound_bytes"]:
            raise _StageFailure("insufficient_memory", measurements)
        self._require_seconds(
            sum(FUTURE_STAGE_RESERVES_SECONDS.values()), measurements=measurements
        )
        return measurements

    def _source_transfer(self) -> Mapping[str, object]:
        future = sum(FUTURE_STAGE_RESERVES_SECONDS.values())
        self._require_seconds(future)
        environment = self.deps.environment if self.deps.environment is not None else os.environ
        if any(environment.get(key) for key in PROXY_KEYS):
            raise _StageFailure("ambient_proxy")
        expected_total = sum(item["size_bytes"] for item in self.raw["source_artifacts"])
        free_disk = self.deps.store.free_bytes()
        if not _nonnegative_int(free_disk) or free_disk < expected_total:
            raise _StageFailure("insufficient_disk")
        transferred = 0
        transfer_started = self._now()
        for artifact in self.raw["source_artifacts"]:
            writer = self.deps.store.begin(artifact["ordinal"], artifact["size_bytes"])
            digest = hashlib.sha256()
            received = 0
            response = self._open_final(artifact["url"])
            if (
                response.content_length is not None
                and response.content_length != artifact["size_bytes"]
            ):
                raise _StageFailure("transfer_length_mismatch")
            for chunk in response.chunks:
                if not isinstance(chunk, bytes) or not chunk:
                    raise _StageFailure("malformed_transfer")
                received += len(chunk)
                transferred += len(chunk)
                self.bytes_received = transferred
                if received > artifact["size_bytes"] or transferred > expected_total:
                    raise _StageFailure("transfer_oversized")
                writer.write(chunk)
                digest.update(chunk)
                now = self._now()
                if transferred >= MIN_PROJECTION_BYTES:
                    elapsed = now - transfer_started
                    if elapsed <= 0:
                        raise _StageFailure("transfer_rate_unknown")
                    projected_transfer = elapsed * expected_total / transferred
                    self._require_seconds(max(0, projected_transfer - elapsed) + future)
            if received != artifact["size_bytes"]:
                raise _StageFailure("transfer_length_mismatch")
            handle = writer.finish()
            value = digest.hexdigest()
            self.transfer_digests.append(value)
            self.artifacts.append(
                StoredArtifact(
                    ordinal=artifact["ordinal"],
                    format=artifact["format"],
                    size_bytes=received,
                    sha256=value,
                    handle=handle,
                )
            )
        measurements = {
            "artifacts_received": len(self.artifacts),
            "bytes_received": transferred,
        }
        self._require_seconds(future, measurements=measurements)
        return measurements

    def _open_final(self, initial_url: str) -> FetchResponse:
        current = initial_url
        approved = frozenset(self.raw["approved_https_hosts"])
        for redirect_count in range(MAX_REDIRECTS + 1):
            host = _validate_url(current, approved)
            try:
                resolved = tuple(self.deps.resolver.resolve(host))
            except Exception as exc:
                raise _StageFailure("resolution_failed") from exc
            if not resolved or any(not _public_address(address) for address in resolved):
                raise _StageFailure("unsafe_address")
            response = self.deps.fetcher.open(
                current, resolved_addresses=resolved, proxies_disabled=True
            )
            if not _public_address(response.peer_address) or not any(
                _same_address(response.peer_address, address) for address in resolved
            ):
                raise _StageFailure("peer_address_drift")
            if response.status in {301, 302, 303, 307, 308}:
                if response.location is None or redirect_count == MAX_REDIRECTS:
                    raise _StageFailure("redirect_drift")
                current = urljoin(current, response.location)
                _validate_url(current, approved)
                continue
            if response.status != 200 or response.location is not None:
                raise _StageFailure("unexpected_http_status")
            return response
        raise _StageFailure("redirect_drift")

    def _hash_verification(self) -> Mapping[str, object]:
        self._require_seconds(sum(FUTURE_STAGE_RESERVES_SECONDS.values()))
        expected = [item["sha256"] for item in self.raw["source_artifacts"]]
        if self.transfer_digests != expected:
            raise _StageFailure("hash_mismatch")
        measurements = {
            "artifacts_verified": len(self.artifacts),
            "bytes_verified": sum(item.size_bytes for item in self.artifacts),
        }
        self._require_seconds(
            FUTURE_STAGE_RESERVES_SECONDS["load"]
            + FUTURE_STAGE_RESERVES_SECONDS["evaluation"]
            + FUTURE_STAGE_RESERVES_SECONDS["finalization"],
            measurements=measurements,
        )
        return measurements

    def _model_load(self) -> Mapping[str, object]:
        self._require_seconds(
            FUTURE_STAGE_RESERVES_SECONDS["load"]
            + FUTURE_STAGE_RESERVES_SECONDS["evaluation"]
            + FUTURE_STAGE_RESERVES_SECONDS["finalization"]
        )
        observation = self.deps.loader.load(tuple(self.artifacts))
        lower_bound = self.raw["known_memory_lower_bound_bytes"]
        measurements = {
            "device_free_before_bytes": observation.device_free_before_bytes,
            "known_required_bytes": lower_bound,
            "loaded": observation.loaded,
            "peak_allocated_bytes": observation.peak_allocated_bytes,
            "peak_reserved_bytes": observation.peak_reserved_bytes,
        }
        if (
            not isinstance(observation.loaded, bool)
            or any(
                not _nonnegative_int(value)
                for value in (
                    observation.device_free_before_bytes,
                    observation.peak_allocated_bytes,
                    observation.peak_reserved_bytes,
                )
            )
            or observation.peak_allocated_bytes > observation.peak_reserved_bytes
            or (
                self.runtime
                and (
                    observation.device_free_before_bytes > self.runtime.device_total_bytes
                    or observation.peak_reserved_bytes > self.runtime.device_total_bytes
                )
            )
        ):
            raise _StageFailure("malformed_metrics")
        if observation.device_free_before_bytes < lower_bound:
            raise _StageFailure("insufficient_memory", measurements)
        if not observation.loaded:
            raise _StageFailure("load_failed", measurements)
        self.model = observation.model
        self._require_seconds(
            FUTURE_STAGE_RESERVES_SECONDS["evaluation"]
            + FUTURE_STAGE_RESERVES_SECONDS["finalization"],
            measurements=measurements,
        )
        return measurements

    def _evaluation(self) -> Mapping[str, object]:
        self._require_seconds(
            FUTURE_STAGE_RESERVES_SECONDS["evaluation"]
            + FUTURE_STAGE_RESERVES_SECONDS["finalization"]
        )
        observations: list[tuple[int, float]] = []
        usefulness = False
        for tokens in self.request.context_ladder_tokens:
            started = self._now()
            result = self.deps.evaluator.evaluate_context(
                self.model,
                tokens,
                deadline_monotonic=self.deadline - FUTURE_STAGE_RESERVES_SECONDS["finalization"],
            )
            ended = self._now()
            duration = ended - started
            if (
                not isinstance(result.completed, bool)
                or not isinstance(result.usefulness_proven, bool)
                or (result.manifest is not None and not isinstance(result.manifest, bytes))
                or duration < 0
            ):
                raise _StageFailure("malformed_metrics")
            is_final = tokens == self.request.context_ladder_tokens[-1]
            if (result.manifest is not None) != is_final:
                raise _StageFailure("manifest_binding_drift")
            if not result.completed:
                raise _StageFailure("context_incomplete", self._evaluation_measurements())
            self.max_context = tokens
            usefulness = result.usefulness_proven
            if result.manifest is not None:
                try:
                    lineage = self.raw["lineage"]
                    manifest = validate_reference_manifest_bytes(
                        result.manifest,
                        evaluation_lock_sha256=lineage["evaluation_lock_sha256"],
                        context_ladder_tokens=self.request.context_ladder_tokens,
                    )
                    if manifest.status != "completed":
                        raise ReferenceHarnessError("reference manifest is incomplete")
                except (KeyError, ReferenceHarnessError):
                    raise _StageFailure("manifest_binding_drift") from None
                self.manifest = result.manifest
            observations.append((tokens, duration))
            remaining_tokens = self.request.context_ladder_tokens[len(observations) :]
            if remaining_tokens:
                if duration <= 0:
                    raise _StageFailure("evaluation_rate_unknown")
                projected = sum(
                    max(
                        observed_duration
                        * max(
                            next_tokens / observed_tokens,
                            (next_tokens / observed_tokens) ** 2,
                        )
                        for observed_tokens, observed_duration in observations
                    )
                    for next_tokens in remaining_tokens
                )
                self._require_seconds(projected + FUTURE_STAGE_RESERVES_SECONDS["finalization"])
        self.full_usefulness = usefulness and self.max_context == CONFIGURED_CONTEXT_TOKENS
        if self.manifest is None:
            raise _StageFailure("manifest_missing", self._evaluation_measurements())
        measurements = self._evaluation_measurements()
        self._require_seconds(
            FUTURE_STAGE_RESERVES_SECONDS["finalization"], measurements=measurements
        )
        return measurements

    def _evaluation_measurements(self) -> Mapping[str, object]:
        full = self.max_context == CONFIGURED_CONTEXT_TOKENS
        return {
            "configured_context_tokens": CONFIGURED_CONTEXT_TOKENS,
            "full_context_completed": full,
            "levels_completed": sum(
                tokens <= self.max_context for tokens in self.request.context_ladder_tokens
            ),
            "max_completed_context_tokens": self.max_context,
            "reference_manifest_bytes": len(self.manifest or b""),
            "reference_manifest_sha256": (
                hashlib.sha256(self.manifest).hexdigest() if self.manifest is not None else None
            ),
            "usefulness_proven": self.full_usefulness if full else False,
        }

    def _evidence_finalization(self) -> Mapping[str, object]:
        self._require_seconds(FUTURE_STAGE_RESERVES_SECONDS["finalization"])
        return {"receipt_bytes": 0}

    def _empty_measurements(self, ordinal: int) -> Mapping[str, object]:
        empty = (
            {
                "device_free_bytes": 0,
                "device_total_bytes": 0,
                "image_identity_sha256": "0" * 64,
                "runtime_identity_sha256": "0" * 64,
            },
            {
                "artifacts_received": len(self.artifacts),
                "bytes_received": self.bytes_received,
            },
            {"artifacts_verified": 0, "bytes_verified": 0},
            {
                "device_free_before_bytes": 0,
                "known_required_bytes": self.raw["known_memory_lower_bound_bytes"],
                "loaded": False,
                "peak_allocated_bytes": 0,
                "peak_reserved_bytes": 0,
            },
            self._evaluation_measurements(),
            {"receipt_bytes": 0},
        )
        return empty[ordinal]

    def _receipt_mapping(
        self, success: bool, stages: list[dict[str, object]] | None = None
    ) -> dict[str, object]:
        stage_list = self.stages if stages is None else stages
        completed = {str(stage["stage"]) for stage in stage_list if stage["status"] == "completed"}
        facts = {
            "cold_path_timing": success,
            "context_usefulness": self.full_usefulness,
            "empirical_fit": "model_load" in completed,
            "provider_image_identity": "runtime_identity" in completed,
            "runtime_allocator_overhead": "model_load" in completed,
            "usable_gpu_memory": "runtime_identity" in completed,
        }
        terminal = None
        if not success:
            failed = stage_list[-1]
            terminal = {"code": failed["failure_code"], "stage": failed["stage"]}
        return {
            "configured_context_tokens": CONFIGURED_CONTEXT_TOKENS,
            "empirical_facts": facts,
            "full_context_usefulness_proven": self.full_usefulness,
            "kind": "reference_bootstrap_receipt",
            "max_completed_context_tokens": self.max_context,
            "request_sha256": self.request.sha256,
            "schema_version": 1,
            "stages": stage_list,
            "status": "succeeded" if success else "failed",
            "terminal_failure": terminal,
        }

    def _final_receipt(self, success: bool) -> bytes:
        if success:
            size = 0
            for _ in range(8):
                self.stages[-1]["measurements"] = {"receipt_bytes": size}
                new_size = len(canonical_bytes(self._receipt_mapping(True)))
                if new_size == size:
                    break
                size = new_size
            else:
                success = False
                self.stages[-1]["status"] = "failed"
                self.stages[-1]["failure_code"] = "receipt_size_unstable"
            if success and size > 65_536:
                success = False
                self.stages[-1]["status"] = "failed"
                self.stages[-1]["failure_code"] = "receipt_oversized"
        raw = self._receipt_mapping(success)
        try:
            validated = validate_bootstrap_receipt(raw, request=self.request)
            return validated.canonical_json.encode("utf-8")
        except ReferenceBootstrapError:
            # A malformed success cannot be reinterpreted as evidence.
            if not success:
                raise
            self.stages[-1]["status"] = "failed"
            self.stages[-1]["failure_code"] = "receipt_validation_failed"
            raw = self._receipt_mapping(False)
            return validate_bootstrap_receipt(raw, request=self.request).canonical_json.encode(
                "utf-8"
            )


class _StageFailure(RuntimeError):
    def __init__(self, code: str, measurements: Mapping[str, object] | None = None) -> None:
        super().__init__(code)
        self.code = code if _safe_code(code) else "unknown_failure"
        self.measurements = measurements


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value != "0" * 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _public_address(value: object) -> bool:
    try:
        address = ipaddress.ip_address(value)  # type: ignore[arg-type]
    except ValueError:
        return False
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _same_address(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _validate_url(url: object, approved_hosts: frozenset[str]) -> str:
    if not isinstance(url, str):
        raise _StageFailure("unsafe_url")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise _StageFailure("unsafe_url") from exc
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or host not in approved_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise _StageFailure("unsafe_url")
    return host


def execute_reference_request(
    request: BootstrapRequest,
    dependencies: ExecutionDependencies,
    *,
    deadline_started_monotonic: float,
) -> ExecutionResult:
    """Validated boundary used by fake and provider adapters."""
    validated_request = validate_bootstrap_request_bytes(request.canonical_json.encode("utf-8"))
    if validated_request != request:
        raise ReferenceBootstrapError("bootstrap request object drift")
    return ReferenceExecution(
        validated_request,
        dependencies,
        deadline_started_monotonic=deadline_started_monotonic,
    ).run()
