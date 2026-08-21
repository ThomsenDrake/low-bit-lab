from __future__ import annotations

import hashlib
import json
import ssl
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from lowbit_lab.provenance import (
    MAX_AGGREGATE_BYTES,
    MAX_FILE_BYTES,
    AnonymousHTTPSClient,
    JSONResponse,
    MetadataPolicyError,
    ProvenanceError,
    ResponseMetadata,
    _AllowlistedRedirects,
    load_metadata_policy,
    parse_metadata_policy,
    verify_metadata_repository,
)

HOST = "metadata.example.invalid"
REVISION = "1" * 40


def _policy(**overrides: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "schema_version": 1,
        "repository": {
            "identifier": "org/example-model",
            "revision": REVISION,
            "license": "Apache-2.0",
            "architectures": ["ExampleForCausalLM"],
        },
        "network": {
            "allowed_hosts": [HOST],
            "metadata_url": f"https://{HOST}/api/repositories/org/example-model/revision/{REVISION}",
            "connect_timeout_seconds": 3,
            "metadata_format": "normalized_v1",
            "read_timeout_seconds": 5,
        },
        "limits": {
            "per_file_bytes": MAX_FILE_BYTES,
            "aggregate_bytes": MAX_AGGREGATE_BYTES,
        },
        "cache_root": "artifacts/local/provenance",
    }
    raw.update(overrides)
    return raw


def _files(tokenizer: str = "tokenizer.json") -> dict[str, bytes]:
    values = {
        "LICENSE": b"Apache License 2.0\n",
        "README.md": b"# Example\n",
        "config.json": json.dumps(
            {"architectures": ["ExampleForCausalLM"], "max_position_embeddings": 262_144}
        ).encode(),
        "model.safetensors.index.json": json.dumps(
            {"metadata": {"total_size": 123}, "weight_map": {"a": "model-00001.safetensors"}}
        ).encode(),
        "tokenizer_config.json": json.dumps({"model_max_length": 262_144}).encode(),
    }
    if tokenizer == "tokenizer.json":
        values["tokenizer.json"] = b'{"version":"1.0","model":{"type":"BPE"}}'
    else:
        values["vocab.json"] = b'{"a":0}'
        values["merges.txt"] = b"#version: 0.2\n"
    return values


def _metadata(files: dict[str, bytes], **repository: object) -> dict[str, object]:
    identity = {
        "identifier": "org/example-model",
        "revision": REVISION,
        "license": "Apache-2.0",
        "architectures": ["ExampleForCausalLM"],
    }
    identity.update(repository)
    return {
        "schema_version": 1,
        "repository": identity,
        "files": [
            {
                "path": path,
                "size_bytes": len(data),
                "download_url": f"https://{HOST}/resolve/{REVISION}/{path}",
                "git": {"object_id": hashlib.sha1(data).hexdigest()},
                "lfs": None,
            }
            for path, data in files.items()
        ],
    }


@dataclass
class FakeResponse:
    metadata: ResponseMetadata
    body: bytes
    chunk_size: int = 7
    fail_after: int | None = None
    body_started: bool = False

    def iter_bytes(self) -> Iterator[bytes]:
        self.body_started = True
        delivered = 0
        for offset in range(0, len(self.body), self.chunk_size):
            chunk = self.body[offset : offset + self.chunk_size]
            if self.fail_after is not None and delivered + len(chunk) > self.fail_after:
                return
            delivered += len(chunk)
            yield chunk

    def close(self) -> None:
        return None


class FakeTransport:
    anonymous = True
    uses_environment_proxies = False
    uses_netrc = False
    uses_cookies = False
    uses_sdk_credentials = False
    verifies_tls = True
    verifies_hostname = True

    def __init__(
        self,
        files: dict[str, bytes],
        *,
        metadata: dict[str, object] | None = None,
        response_overrides: dict[str, dict[str, object]] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.files = files
        self.repository_metadata = metadata or _metadata(files)
        self.response_overrides = response_overrides or {}
        self.error = error
        self.opened: list[str] = []
        self.responses: dict[str, FakeResponse] = {}

    def get_json(self, url: str, *, max_bytes: int, timeout_seconds: int) -> JSONResponse:
        if self.error:
            raise self.error
        body = json.dumps(self.repository_metadata).encode()
        return JSONResponse(
            metadata=ResponseMetadata(
                requested_url=url,
                final_url=url,
                status=200,
                content_length=len(body),
                etag=None,
                last_modified=None,
            ),
            value=self.repository_metadata,
        )

    def open(self, url: str, *, timeout_seconds: int) -> FakeResponse:
        if self.error:
            raise self.error
        path = url.rsplit("/", 1)[-1]
        body = self.files.get(path, b"")
        override = self.response_overrides.get(path, {})
        response = FakeResponse(
            metadata=ResponseMetadata(
                requested_url=url,
                final_url=str(override.get("final_url", url)),
                status=int(override.get("status", 200 if path in self.files else 404)),
                content_length=override.get("content_length", len(body)),
                etag=override.get("etag", f'"{hashlib.sha1(body).hexdigest()}"'),
                last_modified=None,
            ),
            body=body,
            fail_after=override.get("fail_after"),
        )
        self.opened.append(path)
        self.responses[path] = response
        return response


def _verify(
    tmp_path: Path, files: dict[str, bytes], **transport_kwargs: object
) -> dict[str, object]:
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    return verify_metadata_repository(
        policy, root=tmp_path, transport=FakeTransport(files, **transport_kwargs)
    )


def test_happy_path_records_distinct_source_http_and_local_identities(tmp_path: Path) -> None:
    result = _verify(tmp_path, _files())

    assert result["repository"]["revision"] == REVISION
    assert result["tokenizer"]["representation"] == "tokenizer.json"
    assert result["context"] == {
        "configured_tokens": 262_144,
        "runtime_initialized": False,
        "usefulness_proven": False,
    }
    assert result["weights_required"] is False
    assert result["uploads_enabled"] is False
    assert result["remote_submission_enabled"] is False
    entry = next(item for item in result["files"] if item["path"] == "tokenizer.json")
    assert set(entry) >= {"source", "http", "local_content"}
    assert entry["source"]["git_object_id"] != entry["local_content"]["sha256"]
    assert (
        Path(tmp_path, entry["local_content"]["cache_path"]).read_bytes()
        == _files()["tokenizer.json"]
    )


def test_huggingface_api_adapter_builds_root_inventory_without_target_code(
    tmp_path: Path,
) -> None:
    files = _files()
    raw = _policy()
    raw["network"]["metadata_format"] = "huggingface_model_api_v1"
    api_metadata = {
        "id": "org/example-model",
        "sha": REVISION,
        "cardData": {"license": "Apache-2.0"},
        "config": {"architectures": ["ExampleForCausalLM"]},
        "siblings": [
            {
                "rfilename": path,
                "size": len(data),
                "blobId": hashlib.sha1(data).hexdigest(),
                "lfs": None,
            }
            for path, data in files.items()
        ]
        + [
            {
                "rfilename": "model-00001-of-00002.safetensors",
                "size": 123456,
                "blobId": "f" * 40,
                "lfs": {"sha256": "e" * 64, "size": 123456},
            }
        ],
    }
    policy = parse_metadata_policy(raw, root=tmp_path)
    result = verify_metadata_repository(
        policy,
        root=tmp_path,
        transport=FakeTransport(files, metadata=api_metadata),
    )

    assert result["repository"]["revision"] == REVISION
    assert result["tokenizer"]["root_only"] is True
    assert all(
        entry["path"] != "model-00001-of-00002.safetensors" for entry in result["files"]
    )


def test_nested_text_config_records_configured_context_only(tmp_path: Path) -> None:
    files = _files()
    files["config.json"] = json.dumps(
        {
            "architectures": ["ExampleForCausalLM"],
            "text_config": {"max_position_embeddings": 262_144},
        }
    ).encode()
    result = _verify(tmp_path, files)
    assert result["context"] == {
        "configured_tokens": 262_144,
        "runtime_initialized": False,
        "usefulness_proven": False,
    }


def test_model_index_accepts_an_integral_json_float_size(tmp_path: Path) -> None:
    files = _files()
    index = json.loads(files["model.safetensors.index.json"])
    index["metadata"]["total_size"] = 123.0
    files["model.safetensors.index.json"] = json.dumps(index).encode()

    assert _verify(tmp_path, files)["weights_required"] is False


@pytest.mark.parametrize("total_size", [False, 0, 1.5, "123"])
def test_model_index_rejects_non_positive_or_non_integral_sizes(
    tmp_path: Path, total_size: object
) -> None:
    files = _files()
    index = json.loads(files["model.safetensors.index.json"])
    index["metadata"]["total_size"] = total_size
    files["model.safetensors.index.json"] = json.dumps(index).encode()

    with pytest.raises(ProvenanceError, match="total_size"):
        _verify(tmp_path, files)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("identifier", "org/drift", "identifier drift"),
        ("revision", "2" * 40, "revision drift"),
        ("license", "MIT", "license drift"),
        ("architectures", ["OtherModel"], "architecture drift"),
    ],
)
def test_repository_identity_drift_fails_before_body_transfer(
    tmp_path: Path, field: str, value: object, match: str
) -> None:
    files = _files()
    transport = FakeTransport(files, metadata=_metadata(files, **{field: value}))
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    with pytest.raises(ProvenanceError, match=match):
        verify_metadata_repository(policy, root=tmp_path, transport=transport)
    assert transport.opened == []


@pytest.mark.parametrize(
    "path",
    [
        "model.safetensors",
        "model.gguf",
        "weights.zip",
        "code.py",
        "unknown.dat",
        "quantized/tokenizer.json",
        "tokenizer.json/../tokenizer.json",
    ],
)
def test_disallowed_unknown_executable_and_non_root_objects_fail_before_body(
    tmp_path: Path, path: str
) -> None:
    files = _files() | {path: b"forbidden"}
    transport = FakeTransport(files)
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    with pytest.raises(ProvenanceError, match="not allowlisted|root-level"):
        verify_metadata_repository(policy, root=tmp_path, transport=transport)
    assert transport.opened == []


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda values: values.pop("LICENSE"), "missing required"),
        (lambda values: values.pop("tokenizer.json"), "tokenizer"),
        (
            lambda values: (values.pop("tokenizer.json"), values.update({"vocab.json": b"{}"})),
            "tokenizer",
        ),
        (lambda values: values.update({"LICENSE": b""}), "empty"),
    ],
)
def test_required_empty_and_incomplete_conditional_files_fail(
    tmp_path: Path, mutation: object, match: str
) -> None:
    files = _files()
    mutation(files)
    with pytest.raises(ProvenanceError, match=match):
        _verify(tmp_path, files)


def test_vocab_and_merges_are_a_complete_root_tokenizer(tmp_path: Path) -> None:
    result = _verify(tmp_path, _files("pair"))
    assert result["tokenizer"]["representation"] == "vocab.json+merges.txt"


def test_optional_404_is_recorded_without_accepting_a_body(tmp_path: Path) -> None:
    files = _files()
    metadata = _metadata(files)
    metadata["files"].append(
        {
            "path": "generation_config.json",
            "size_bytes": 2,
            "download_url": f"https://{HOST}/resolve/{REVISION}/generation_config.json",
            "git": {"object_id": "a" * 40},
            "lfs": None,
        }
    )
    result = _verify(
        tmp_path,
        files,
        metadata=metadata,
        response_overrides={"generation_config.json": {"status": 404, "content_length": 0}},
    )
    assert result["optional_absent"] == [
        "abliteration_metadata.json",
        "chat_template.jinja",
        "generation_config.json",
        "hard_negative_residue.json",
        "preprocessor_config.json",
        "video_preprocessor_config.json",
    ]


def test_duplicate_inventory_path_fails_before_body(tmp_path: Path) -> None:
    files = _files()
    metadata = _metadata(files)
    metadata["files"].append(dict(metadata["files"][0]))
    transport = FakeTransport(files, metadata=metadata)
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    with pytest.raises(ProvenanceError, match="duplicate"):
        verify_metadata_repository(policy, root=tmp_path, transport=transport)
    assert transport.opened == []


def test_oversized_and_aggregate_inventory_fail_before_body(tmp_path: Path) -> None:
    files = _files()
    metadata = _metadata(files)
    metadata["files"][0]["size_bytes"] = MAX_FILE_BYTES + 1
    transport = FakeTransport(files, metadata=metadata)
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    with pytest.raises(ProvenanceError, match="per-file"):
        verify_metadata_repository(policy, root=tmp_path, transport=transport)
    assert transport.opened == []

    metadata = _metadata(files)
    for item in metadata["files"]:
        item["size_bytes"] = 6 * 1024 * 1024
    transport = FakeTransport(files, metadata=metadata)
    with pytest.raises(ProvenanceError, match="aggregate"):
        verify_metadata_repository(policy, root=tmp_path, transport=transport)
    assert transport.opened == []


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"final_url": "https://escape.invalid/file"}, "host"),
        ({"final_url": f"http://{HOST}/file"}, "HTTPS"),
        ({"content_length": 999}, "size"),
        ({"fail_after": 2}, "partial"),
    ],
)
def test_redirect_downgrade_size_and_partial_response_fail_closed(
    tmp_path: Path, override: dict[str, object], match: str
) -> None:
    files = _files()
    with pytest.raises(ProvenanceError, match=match):
        _verify(tmp_path, files, response_overrides={"LICENSE": override})


def test_certificate_failure_is_sanitized_and_no_cache_is_promoted(tmp_path: Path) -> None:
    policy = parse_metadata_policy(_policy(), root=tmp_path)
    with pytest.raises(ProvenanceError, match="TLS verification failed") as raised:
        verify_metadata_repository(
            policy,
            root=tmp_path,
            transport=FakeTransport(_files(), error=ssl.SSLCertVerificationError("private path")),
        )
    assert "private path" not in str(raised.value)
    assert not (tmp_path / "artifacts/local/provenance").exists()


def test_content_address_reuse_and_identity_drift_detection(tmp_path: Path) -> None:
    files = _files()
    first = _verify(tmp_path, files)
    second = _verify(tmp_path, files)
    assert all(item["local_content"]["reused"] is True for item in second["files"])

    changed = dict(files)
    changed["README.md"] = b"changed"
    metadata = _metadata(changed)
    original_readme = next(
        item for item in _metadata(files)["files"] if item["path"] == "README.md"
    )
    changed_readme = next(item for item in metadata["files"] if item["path"] == "README.md")
    changed_readme["git"] = original_readme["git"]
    with pytest.raises(ProvenanceError, match="source identity drift"):
        _verify(tmp_path, changed, metadata=metadata)
    assert first["manifest_sha256"] == second["manifest_sha256"]


def test_cache_ambiguity_is_rejected_instead_of_overwritten(tmp_path: Path) -> None:
    result = _verify(tmp_path, _files())
    path = tmp_path / result["files"][0]["local_content"]["cache_path"]
    path.write_bytes(b"corrupt")
    with pytest.raises(ProvenanceError, match="cache ambiguity"):
        _verify(tmp_path, _files())


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw.update({"unknown": True}),
        lambda raw: raw["network"].update({"allowed_hosts": [HOST, HOST]}),
        lambda raw: raw["limits"].update({"per_file_bytes": MAX_FILE_BYTES + 1}),
        lambda raw: raw["limits"].update({"aggregate_bytes": MAX_AGGREGATE_BYTES + 1}),
        lambda raw: raw["repository"].update({"revision": "main"}),
        lambda raw: raw.update({"cache_root": "artifacts/provenance"}),
    ],
)
def test_policy_is_closed_immutable_and_bounded(tmp_path: Path, mutation: object) -> None:
    raw = _policy()
    mutation(raw)
    with pytest.raises(MetadataPolicyError):
        parse_metadata_policy(raw, root=tmp_path)


def test_policy_load_is_confined_to_ignored_local_area(tmp_path: Path) -> None:
    local = tmp_path / "configs/local/policy.json"
    local.parent.mkdir(parents=True)
    local.write_text(json.dumps(_policy()), encoding="utf-8")
    assert load_metadata_policy(local, root=tmp_path).identifier == "org/example-model"
    outside = tmp_path / "configs/policy.json"
    outside.write_text(json.dumps(_policy()), encoding="utf-8")
    with pytest.raises(MetadataPolicyError, match="configs/local"):
        load_metadata_policy(outside, root=tmp_path)


def test_anonymous_client_disables_every_ambient_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("HF_TOKEN", "secret")
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "secret")
    monkeypatch.setenv("NETRC", "private-netrc")
    client = AnonymousHTTPSClient()
    assert client.anonymous is True
    assert client.uses_environment_proxies is False
    assert client.uses_netrc is False
    assert client.uses_cookies is False
    assert client.uses_sdk_credentials is False
    assert client.verifies_tls is True
    assert client.verifies_hostname is True
    assert client.default_headers == {"Accept": "application/json", "User-Agent": "low-bit-lab/1"}


def test_redirect_handler_allows_only_approved_https_hosts() -> None:
    handler = _AllowlistedRedirects((HOST,))
    request = urllib.request.Request(f"https://{HOST}/source")

    redirected = handler.redirect_request(
        request, None, 307, "Temporary Redirect", {}, f"https://{HOST}/approved"
    )
    assert redirected.full_url == f"https://{HOST}/approved"

    for url in ("https://escape.invalid/file", f"http://{HOST}/file"):
        with pytest.raises(ProvenanceError, match="approved HTTPS hosts"):
            handler.redirect_request(request, None, 307, "Temporary Redirect", {}, url)
