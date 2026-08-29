from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lowbit_lab import reference_remote_runtime as runtime

ORIGIN_HOSTS = frozenset({"huggingface.co", "us.aws.cdn.hf.co"})


class _FakeCuda:
    @staticmethod
    def reset_peak_memory_stats(_device: str) -> None:
        pass

    @staticmethod
    def synchronize(_device: str) -> None:
        pass

    @staticmethod
    def max_memory_reserved(_device: str) -> int:
        return 123_456


def _install_https(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[tuple[int, str | None]],
    *,
    peer: str = "8.8.8.8",
) -> list[tuple[str, str]]:
    requests: list[tuple[str, str]] = []

    class Socket:
        @staticmethod
        def getpeername() -> tuple[str, int]:
            return peer, 443

    class Context:
        @staticmethod
        def wrap_socket(_raw: object, *, server_hostname: str) -> Socket:
            assert server_hostname in ORIGIN_HOSTS
            return Socket()

    class Response:
        def __init__(self, status: int, location: str | None) -> None:
            self.status = status
            self._location = location

        def getheader(self, name: str) -> str | None:
            return self._location if name == "Location" else None

    class Connection:
        def __init__(self, host: str, *_args: object, context: Context, **_kwargs: object) -> None:
            self.host = host
            self._context = context
            self.sock: Socket | None = None

        def request(self, _method: str, selector: str, **_kwargs: object) -> None:
            requests.append((self.host, selector))

        @staticmethod
        def getresponse() -> Response:
            status, location = responses.pop(0)
            return Response(status, location)

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runtime.ssl, "create_default_context", Context)
    monkeypatch.setattr(runtime.http.client, "HTTPSConnection", Connection)
    return requests


def _evaluation_case(
    family: str,
    fixture: dict[str, object],
    metrics: tuple[str, ...],
    *,
    token_cap: int = 8,
    byte_cap: int = 256,
) -> tuple[dict[str, object], dict[str, bytes]]:
    fixture_id = f"{family}-fixture"
    lock = {
        "fixture_order": [fixture_id],
        "fixtures": [{"family": family, "fixture_id": fixture_id, "metrics": list(metrics)}],
        "generation": {
            "response_caps_bytes": {family: byte_cap},
            "response_caps_tokens": {family: token_cap},
        },
        "scorer": {
            "runtime": {"sha256": "1" * 64},
            "sha256": "2" * 64,
        },
    }
    return lock, {fixture_id: runtime._canonical(fixture)}


@pytest.fixture(autouse=True)
def _fake_torch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(cuda=_FakeCuda()))


def test_origin_is_query_free_and_signed_query_is_redirect_only() -> None:
    assert runtime.validate_public_url(
        "https://huggingface.co/org/repo/resolve/" + "a" * 40 + "/model.safetensors",
        ORIGIN_HOSTS,
        redirected=False,
    ) == (
        "huggingface.co",
        "/org/repo/resolve/" + "a" * 40 + "/model.safetensors",
    )
    assert (
        runtime.validate_public_url(
            "https://us.aws.cdn.hf.co/xet-bridge-us/object?X-Amz-Signature=transient",
            ORIGIN_HOSTS,
            redirected=True,
        )[0]
        == "us.aws.cdn.hf.co"
    )
    with pytest.raises(runtime.RemoteRuntimeError, match="unsafe_url"):
        runtime.validate_public_url(
            "https://us.aws.cdn.hf.co/xet-bridge-us/object?X-Amz-Signature=transient",
            ORIGIN_HOSTS,
            redirected=False,
        )


@pytest.mark.parametrize(
    "url",
    (
        "http://huggingface.co/a",
        "https://user@huggingface.co/a",
        "https://huggingface.co:444/a",
        "https://huggingface.co/a#fragment",
        "https://huggingface.co/a?caller=value",
        "https://huggingface.co/a/%2e%2e/b",
        "https://127.0.0.1/a",
    ),
)
def test_url_policy_rejects_broadened_boundaries(url: str) -> None:
    with pytest.raises(runtime.RemoteRuntimeError, match="unsafe_url"):
        runtime.validate_public_url(url, ORIGIN_HOSTS, redirected=False)


def test_private_resolution_is_rejected_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))],
    )
    monkeypatch.setattr(
        runtime.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not connect")),
    )
    with pytest.raises(runtime.RemoteRuntimeError, match="unsafe_address"):
        runtime._open("https://huggingface.co/public/file", ORIGIN_HOSTS)


def test_redirect_chain_stops_after_five_hops(monkeypatch: pytest.MonkeyPatch) -> None:
    class Peer:
        @staticmethod
        def getpeername() -> tuple[str, int]:
            return ("8.8.8.8", 443)

    class Context:
        @staticmethod
        def wrap_socket(raw: object, *, server_hostname: str) -> Peer:
            assert raw is not None
            assert server_hostname == "huggingface.co"
            return Peer()

    class Response:
        status = 302

        @staticmethod
        def getheader(name: str) -> str | None:
            return "/api/resolve-cache/models/public/object" if name == "Location" else None

    class Connection:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._context = Context()
            self.sock: Peer | None = None

        def request(self, *args: object, **kwargs: object) -> None:
            pass

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(runtime.socket, "create_connection", lambda *args, **kwargs: object())
    monkeypatch.setattr(runtime.http.client, "HTTPSConnection", Connection)

    with pytest.raises(runtime.RemoteRuntimeError, match="redirect_drift"):
        runtime._open("https://huggingface.co/public/file", ORIGIN_HOSTS)


def test_open_returns_only_a_closed_https_success(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _install_https(monkeypatch, [(200, None)])

    _connection, response = runtime._open("https://huggingface.co/public/file", ORIGIN_HOSTS)

    assert response.status == 200
    assert requests == [("huggingface.co", "/public/file")]


@pytest.mark.parametrize(
    ("responses", "peer", "error"),
    (
        ([(200, None)], "1.1.1.1", "peer_address_drift"),
        ([(404, None)], "8.8.8.8", "unexpected_http_status"),
        ([(302, None)], "8.8.8.8", "redirect_drift"),
    ),
)
def test_open_fails_closed_on_peer_status_or_missing_redirect(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[tuple[int, str | None]],
    peer: str,
    error: str,
) -> None:
    _install_https(monkeypatch, responses, peer=peer)

    with pytest.raises(runtime.RemoteRuntimeError, match=error):
        runtime._open("https://huggingface.co/public/file", ORIGIN_HOSTS)


def test_open_allows_signed_query_only_after_approved_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = "https://us.aws.cdn.hf.co/xet-bridge-us/object?X-Amz-Signature=transient"
    requests = _install_https(monkeypatch, [(302, signed), (200, None)])

    _connection, response = runtime._open("https://huggingface.co/public/file", ORIGIN_HOSTS)

    assert response.status == 200
    assert requests == [
        ("huggingface.co", "/public/file"),
        ("us.aws.cdn.hf.co", "/xet-bridge-us/object?X-Amz-Signature=transient"),
    ]


@pytest.mark.parametrize(
    ("family", "fixture", "metric_names", "response", "tokens", "duration", "expected"),
    (
        (
            "coding",
            {"prompt": "code", "expected": "OK"},
            ("exact_match",),
            "OK",
            1,
            0.25,
            {"exact_match": 1.0},
        ),
        (
            "tool_call_validity",
            {"prompt": "tool", "expected": {"name": "lookup", "arguments": {}}},
            ("argument_accuracy", "schema_valid_rate"),
            '{"name":"lookup","arguments":{}}',
            4,
            0.25,
            {"argument_accuracy": 1.0, "schema_valid_rate": 1.0},
        ),
        (
            "long_context_retrieval",
            {"needle": "hidden", "prompt": "find", "expected": "answer"},
            ("retrieval_accuracy",),
            "the answer is present",
            3,
            0.25,
            {"retrieval_accuracy": 1.0},
        ),
        (
            "throughput",
            {"repetitions": 2},
            ("decode_tokens_per_second",),
            "fast",
            2,
            0.5,
            {"decode_tokens_per_second": 4.0},
        ),
        (
            "memory",
            {},
            ("peak_vram_bytes",),
            "m",
            1,
            0.25,
            {"peak_vram_bytes": 123_456},
        ),
        (
            "soak",
            {"duration_seconds": 0},
            ("completed_minutes", "failure_free_rate", "runtime_errors"),
            "",
            0,
            0.0,
            {"failure_free_rate": 1.0, "runtime_errors": 0},
        ),
    ),
)
def test_evaluation_families_emit_bounded_valid_metrics(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
    fixture: dict[str, object],
    metric_names: tuple[str, ...],
    response: str,
    tokens: int,
    duration: float,
    expected: dict[str, float | int],
) -> None:
    lock, fixtures = _evaluation_case(family, fixture, metric_names)
    monkeypatch.setattr(runtime, "_generate", lambda *_args: (response, tokens, duration))
    monkeypatch.setattr(runtime, "_long_generate", lambda *_args: (response, tokens, duration))

    manifest_bytes, maximum, useful = runtime._evaluate(
        object(), object(), lock, fixtures, {"reviewed_commit_sha256": "3" * 64}, [262144], 10**12
    )

    manifest = json.loads(manifest_bytes)
    measurement = manifest["measurements"][0]
    assert measurement["family"] == family
    assert set(measurement["metrics"]) == set(metric_names)
    for name, value in expected.items():
        assert measurement["metrics"][name] == pytest.approx(value)
    assert measurement["response_tokens"] <= 8
    assert measurement["response_bytes"] <= 256
    assert measurement["response_sha256"] == runtime._digest(response.encode())
    assert manifest["evaluation_lock_sha256"] == runtime._digest(runtime._canonical(lock))
    assert manifest["execution_identity"] == {"reviewed_commit_sha256": "3" * 64}
    assert manifest["executor_identity"] == {
        "runtime_sha256": "1" * 64,
        "scorer_sha256": "2" * 64,
    }
    assert maximum == (262144 if family == "long_context_retrieval" else 0)
    assert useful is (family == "long_context_retrieval")


@pytest.mark.parametrize(
    ("token_cap", "byte_cap", "response", "tokens"),
    ((1, 256, "ok", 2), (8, 1, "too large", 1)),
)
def test_evaluation_rejects_token_or_byte_cap_overflow(
    monkeypatch: pytest.MonkeyPatch,
    token_cap: int,
    byte_cap: int,
    response: str,
    tokens: int,
) -> None:
    lock, fixtures = _evaluation_case(
        "coding",
        {"prompt": "code", "expected": "ok"},
        ("exact_match",),
        token_cap=token_cap,
        byte_cap=byte_cap,
    )
    monkeypatch.setattr(runtime, "_generate", lambda *_args: (response, tokens, 0.1))

    with pytest.raises(runtime.RemoteRuntimeError, match="evaluation_response_oversized"):
        runtime._evaluate(object(), object(), lock, fixtures, {}, [262144], 10**12)


def test_evaluation_stops_before_projected_deadline() -> None:
    lock, fixtures = _evaluation_case(
        "coding", {"prompt": "code", "expected": "ok"}, ("exact_match",)
    )

    with pytest.raises(runtime.RemoteRuntimeError, match="projected_timeout"):
        runtime._evaluate(object(), object(), lock, fixtures, {}, [262144], 0.0)


def test_soak_generation_failure_is_recorded_without_claiming_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, fixtures = _evaluation_case(
        "soak",
        {"duration_seconds": 1},
        ("completed_minutes", "failure_free_rate", "runtime_errors"),
    )
    ticks = iter(index / 10 for index in range(20))
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        runtime, "_generate", lambda *_args: (_ for _ in ()).throw(RuntimeError("fake"))
    )

    manifest_bytes, maximum, useful = runtime._evaluate(
        object(), object(), lock, fixtures, {}, [262144], 1000.0
    )

    metrics = json.loads(manifest_bytes)["measurements"][0]["metrics"]
    assert metrics["runtime_errors"] == 1
    assert metrics["failure_free_rate"] == 0.0
    assert metrics["completed_minutes"] < 1 / 60
    assert maximum == 0
    assert useful is False


def test_262144_is_configured_but_not_proven_when_final_retrieval_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, fixtures = _evaluation_case(
        "long_context_retrieval",
        {"needle": "hidden", "prompt": "find", "expected": "answer"},
        ("retrieval_accuracy",),
    )
    monkeypatch.setattr(
        runtime,
        "_long_generate",
        lambda _model, _tokenizer, _fixture, context, _cap: (
            ("answer" if context < 262144 else "miss"),
            1,
            0.1,
        ),
    )

    manifest_bytes, maximum, useful = runtime._evaluate(
        object(), object(), lock, fixtures, {}, [131072, 262144], 10**12
    )

    measurements = json.loads(manifest_bytes)["measurements"]
    assert [item["context_level_tokens"] for item in measurements] == [131072, 262144]
    assert [item["metrics"]["retrieval_accuracy"] for item in measurements] == [1.0, 0.0]
    assert maximum == 262144
    assert useful is False


def test_remote_runtime_has_no_local_package_import_or_dynamic_source_execution() -> None:
    source = Path(runtime.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert all(not name.startswith("lowbit_lab") for name in imports)
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"eval", "exec", "compile"}
        for node in ast.walk(tree)
    )
