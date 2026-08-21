from __future__ import annotations

import hashlib
import json
import math
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

MAX_FILE_BYTES = 24 * 1024 * 1024
MAX_AGGREGATE_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024

REQUIRED_FILES = frozenset(
    {
        "LICENSE",
        "README.md",
        "config.json",
        "model.safetensors.index.json",
        "tokenizer_config.json",
    }
)
TOKENIZER_JSON = "tokenizer.json"
TOKENIZER_PAIR = frozenset({"vocab.json", "merges.txt"})
OPTIONAL_FILES = frozenset(
    {
        "generation_config.json",
        "chat_template.jinja",
        "preprocessor_config.json",
        "video_preprocessor_config.json",
        "abliteration_metadata.json",
        "hard_negative_residue.json",
    }
)
ALLOWED_FILES = REQUIRED_FILES | TOKENIZER_PAIR | {TOKENIZER_JSON} | OPTIONAL_FILES

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40,64}")


class MetadataPolicyError(ValueError):
    pass


class ProvenanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class MetadataPolicy:
    identifier: str
    revision: str
    license: str
    architectures: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    metadata_url: str
    metadata_format: str
    connect_timeout_seconds: int
    read_timeout_seconds: int
    per_file_bytes: int
    aggregate_bytes: int
    cache_root: Path
    sha256: str


@dataclass(frozen=True)
class ResponseMetadata:
    requested_url: str
    final_url: str
    status: int
    content_length: object
    etag: object
    last_modified: object


@dataclass(frozen=True)
class JSONResponse:
    metadata: ResponseMetadata
    value: object


class StreamingResponse(Protocol):
    metadata: ResponseMetadata

    def iter_bytes(self) -> Iterator[bytes]: ...

    def close(self) -> None: ...


class MetadataTransport(Protocol):
    anonymous: bool
    uses_environment_proxies: bool
    uses_netrc: bool
    uses_cookies: bool
    uses_sdk_credentials: bool
    verifies_tls: bool
    verifies_hostname: bool

    def get_json(self, url: str, *, max_bytes: int, timeout_seconds: int) -> JSONResponse: ...

    def open(self, url: str, *, timeout_seconds: int) -> StreamingResponse: ...


def _closed_mapping(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MetadataPolicyError(f"{label} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    if unknown:
        raise MetadataPolicyError(f"{label} has unknown keys: {sorted(unknown)}")
    if missing:
        raise MetadataPolicyError(f"{label} is missing keys: {sorted(missing)}")
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > maximum:
        raise MetadataPolicyError(f"{label} must be an integer from 1 through {maximum}")
    return value


def _https_url(url: object, hosts: tuple[str, ...], label: str) -> str:
    if not isinstance(url, str):
        raise MetadataPolicyError(f"{label} must be a URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise MetadataPolicyError(f"{label} must use HTTPS")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise MetadataPolicyError(f"{label} cannot contain credentials or a fragment")
    if parsed.hostname.lower() not in hosts:
        raise MetadataPolicyError(f"{label} host is not allowlisted")
    if parsed.port not in (None, 443):
        raise MetadataPolicyError(f"{label} must use the standard HTTPS port")
    return url


def parse_metadata_policy(raw: object, *, root: Path) -> MetadataPolicy:
    top = _closed_mapping(
        raw,
        {"schema_version", "repository", "network", "limits", "cache_root"},
        "metadata policy",
    )
    if top["schema_version"] != 1:
        raise MetadataPolicyError("schema_version must be 1")
    repository = _closed_mapping(
        top["repository"], {"identifier", "revision", "license", "architectures"}, "repository"
    )
    identifier = repository["identifier"]
    revision = repository["revision"]
    license_name = repository["license"]
    architectures = repository["architectures"]
    if not isinstance(identifier, str) or not identifier or identifier.strip() != identifier:
        raise MetadataPolicyError("repository.identifier must be a non-empty exact identifier")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise MetadataPolicyError("repository.revision must be an immutable lowercase hex revision")
    if not isinstance(license_name, str) or not license_name.strip():
        raise MetadataPolicyError("repository.license must be non-empty")
    if (
        not isinstance(architectures, list)
        or not architectures
        or any(not isinstance(value, str) or not value for value in architectures)
        or len(set(architectures)) != len(architectures)
    ):
        raise MetadataPolicyError("repository.architectures must be unique non-empty strings")

    network = _closed_mapping(
        top["network"],
        {
            "allowed_hosts",
            "metadata_url",
            "metadata_format",
            "connect_timeout_seconds",
            "read_timeout_seconds",
        },
        "network",
    )
    allowed_hosts = network["allowed_hosts"]
    if (
        not isinstance(allowed_hosts, list)
        or not allowed_hosts
        or any(not isinstance(host, str) for host in allowed_hosts)
        or any(host != host.lower() or host.strip() != host for host in allowed_hosts)
        or len(set(allowed_hosts)) != len(allowed_hosts)
    ):
        raise MetadataPolicyError(
            "network.allowed_hosts must contain unique exact lowercase hosts"
        )
    hosts = tuple(allowed_hosts)
    metadata_url = _https_url(network["metadata_url"], hosts, "network.metadata_url")
    metadata_format = network["metadata_format"]
    if metadata_format not in {"normalized_v1", "huggingface_model_api_v1"}:
        raise MetadataPolicyError("network.metadata_format is unsupported")
    connect_timeout = _positive_int(network["connect_timeout_seconds"], "connect timeout", 30)
    read_timeout = _positive_int(network["read_timeout_seconds"], "read timeout", 60)

    limits = _closed_mapping(top["limits"], {"per_file_bytes", "aggregate_bytes"}, "limits")
    per_file = _positive_int(limits["per_file_bytes"], "per-file cap", MAX_FILE_BYTES)
    aggregate = _positive_int(limits["aggregate_bytes"], "aggregate cap", MAX_AGGREGATE_BYTES)
    if per_file > aggregate:
        raise MetadataPolicyError("per-file cap cannot exceed aggregate cap")

    cache_value = top["cache_root"]
    if not isinstance(cache_value, str) or PurePosixPath(cache_value).is_absolute():
        raise MetadataPolicyError("cache_root must be repository-relative")
    if cache_value != "artifacts/local/provenance":
        raise MetadataPolicyError("cache_root must be artifacts/local/provenance")
    root = root.resolve()
    cache_root = (root / Path(cache_value)).resolve()
    if not cache_root.is_relative_to(root):
        raise MetadataPolicyError("cache_root escapes the repository")

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return MetadataPolicy(
        identifier=identifier,
        revision=revision,
        license=license_name,
        architectures=tuple(architectures),
        allowed_hosts=hosts,
        metadata_url=metadata_url,
        metadata_format=metadata_format,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        per_file_bytes=per_file,
        aggregate_bytes=aggregate,
        cache_root=cache_root,
        sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    )


def load_metadata_policy(path: Path, *, root: Path) -> MetadataPolicy:
    root = root.resolve()
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    local_root = (root / "configs/local").resolve()
    if not candidate.is_relative_to(local_root) or not candidate.is_file():
        raise MetadataPolicyError("metadata policy must be a file under configs/local")
    try:
        raw = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MetadataPolicyError("metadata policy is unreadable or invalid JSON") from exc
    return parse_metadata_policy(raw, root=root)


class _URLResponse:
    def __init__(self, response: Any, requested_url: str) -> None:
        self._response = response
        self.metadata = ResponseMetadata(
            requested_url=requested_url,
            final_url=response.geturl(),
            status=response.status,
            content_length=response.headers.get("Content-Length"),
            etag=response.headers.get("ETag"),
            last_modified=response.headers.get("Last-Modified"),
        )

    def iter_bytes(self) -> Iterator[bytes]:
        while chunk := self._response.read(64 * 1024):
            yield chunk

    def close(self) -> None:
        self._response.close()


class _AllowlistedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: tuple[str, ...]) -> None:
        self._allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request:
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in self._allowed_hosts:
            raise ProvenanceError("HTTP redirect leaves the approved HTTPS hosts")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            raise ProvenanceError("HTTP redirect is not supported")
        return redirected


class AnonymousHTTPSClient:
    anonymous = True
    uses_environment_proxies = False
    uses_netrc = False
    uses_cookies = False
    uses_sdk_credentials = False
    verifies_tls = True
    verifies_hostname = True
    default_headers = {"Accept": "application/json", "User-Agent": "low-bit-lab/1"}

    def __init__(self, allowed_hosts: tuple[str, ...] = ()) -> None:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        # An explicit empty proxy map bypasses HTTP(S)_PROXY. No auth, cookie,
        # netrc, or provider-SDK handler is installed in this dedicated opener.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _AllowlistedRedirects(allowed_hosts),
        )

    def open(self, url: str, *, timeout_seconds: int) -> StreamingResponse:
        request = urllib.request.Request(url, headers=self.default_headers, method="GET")
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            # HTTPError remains a readable response object. Preserve 404 so the
            # closed optional-file contract can record absence, but never read a
            # redirect/error response body.
            if 300 <= exc.code < 400:
                exc.close()
                raise ProvenanceError("HTTP redirect was not allowlisted") from exc
            response = exc
        return _URLResponse(response, url)

    def get_json(self, url: str, *, max_bytes: int, timeout_seconds: int) -> JSONResponse:
        response = self.open(url, timeout_seconds=timeout_seconds)
        try:
            if response.metadata.status != 200:
                raise ProvenanceError(
                    f"repository metadata returned HTTP {response.metadata.status}"
                )
            if response.metadata.content_length is not None:
                declared = _response_length(response.metadata.content_length)
                if declared > max_bytes:
                    raise ProvenanceError("repository metadata exceeds its byte cap")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ProvenanceError("repository metadata exceeds its byte cap")
            if response.metadata.content_length is not None:
                length = _response_length(response.metadata.content_length)
                if length != len(body):
                    raise ProvenanceError("repository metadata response is partial")
            try:
                value = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProvenanceError("repository metadata is invalid JSON") from exc
            return JSONResponse(response.metadata, value)
        finally:
            response.close()


def _assert_secure_transport(transport: MetadataTransport) -> None:
    expected = {
        "anonymous": True,
        "uses_environment_proxies": False,
        "uses_netrc": False,
        "uses_cookies": False,
        "uses_sdk_credentials": False,
        "verifies_tls": True,
        "verifies_hostname": True,
    }
    for field, value in expected.items():
        if getattr(transport, field, None) is not value:
            raise ProvenanceError(f"transport security profile rejects {field}")


def _validate_response_url(metadata: ResponseMetadata, hosts: tuple[str, ...]) -> None:
    for label, url in (("requested", metadata.requested_url), ("final", metadata.final_url)):
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            raise ProvenanceError(f"{label} response URL must use HTTPS")
        if parsed.hostname is None or parsed.hostname.lower() not in hosts:
            raise ProvenanceError(f"{label} response URL host is not allowlisted")
        if (
            parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ProvenanceError(f"{label} response URL is not an exact allowed HTTPS origin")


def _response_length(value: object) -> int:
    if isinstance(value, bool):
        raise ProvenanceError("response content length is invalid")
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ProvenanceError("response content length is missing or invalid") from exc
    if result < 0:
        raise ProvenanceError("response content length is invalid")
    return result


def _inventory(
    raw: object, policy: MetadataPolicy
) -> tuple[Mapping[str, object], dict[str, Mapping[str, object]]]:
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "repository", "files"}:
        raise ProvenanceError("repository metadata must use the closed schema")
    if raw["schema_version"] != 1:
        raise ProvenanceError("repository metadata schema_version must be 1")
    repository = raw["repository"]
    if not isinstance(repository, Mapping) or set(repository) != {
        "identifier",
        "revision",
        "license",
        "architectures",
    }:
        raise ProvenanceError("repository metadata is missing required identity fields")
    drift_fields = (
        ("identifier", policy.identifier, "identifier drift"),
        ("revision", policy.revision, "revision drift"),
        ("license", policy.license, "license drift"),
        ("architectures", list(policy.architectures), "architecture drift"),
    )
    for field, expected, message in drift_fields:
        if repository[field] != expected:
            raise ProvenanceError(message)
    files = raw["files"]
    if not isinstance(files, list):
        raise ProvenanceError("repository files must be a list")
    inventory: dict[str, Mapping[str, object]] = {}
    total = 0
    for raw_item in files:
        if not isinstance(raw_item, Mapping) or set(raw_item) != {
            "path",
            "size_bytes",
            "download_url",
            "git",
            "lfs",
        }:
            raise ProvenanceError("repository file is missing required metadata fields")
        path = raw_item["path"]
        if (
            not isinstance(path, str)
            or PurePosixPath(path).name != path
            or "/" in path
            or "\\" in path
        ):
            raise ProvenanceError("repository files must be root-level")
        if path not in ALLOWED_FILES:
            raise ProvenanceError(f"repository object is not allowlisted: {path}")
        if path in inventory:
            raise ProvenanceError(f"duplicate repository path: {path}")
        size = raw_item["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ProvenanceError(f"repository file is empty or has invalid size: {path}")
        if size > policy.per_file_bytes:
            raise ProvenanceError(f"repository file exceeds per-file cap: {path}")
        total += size
        if total > policy.aggregate_bytes:
            raise ProvenanceError("repository files exceed aggregate cap")
        _https_url_for_verification(raw_item["download_url"], policy.allowed_hosts, path)
        _validate_source_identity(raw_item, path)
        inventory[path] = raw_item
    missing = REQUIRED_FILES - inventory.keys()
    if missing:
        raise ProvenanceError(f"missing required repository files: {sorted(missing)}")
    tokenizer_json = TOKENIZER_JSON in inventory
    tokenizer_pair = TOKENIZER_PAIR.issubset(inventory)
    if not tokenizer_json and not tokenizer_pair:
        raise ProvenanceError("missing complete root tokenizer representation")
    if bool(TOKENIZER_PAIR & inventory.keys()) and not tokenizer_pair:
        raise ProvenanceError("incomplete root tokenizer vocab.json+merges.txt pair")
    return repository, inventory


def _normalize_repository_metadata(raw: object, policy: MetadataPolicy) -> object:
    if policy.metadata_format == "normalized_v1":
        return raw
    if not isinstance(raw, Mapping):
        raise ProvenanceError("provider metadata must be an object")
    card_data = raw.get("cardData")
    config = raw.get("config")
    siblings = raw.get("siblings")
    if not isinstance(card_data, Mapping) or not isinstance(config, Mapping):
        raise ProvenanceError("provider metadata is missing identity fields")
    if not isinstance(siblings, list):
        raise ProvenanceError("provider metadata is missing file inventory")
    host = urlsplit(policy.metadata_url).hostname
    if host is None:
        raise ProvenanceError("provider metadata host is invalid")
    repository_path = quote(policy.identifier, safe="/")
    revision_path = quote(policy.revision, safe="")
    files: list[dict[str, object]] = []
    for item in siblings:
        if not isinstance(item, Mapping):
            raise ProvenanceError("provider file metadata must be an object")
        path = item.get("rfilename")
        if not isinstance(path, str):
            raise ProvenanceError("provider file path is invalid")
        if path not in ALLOWED_FILES:
            continue
        blob_id = item.get("blobId")
        size = item.get("size")
        lfs_raw = item.get("lfs")
        lfs: dict[str, object] | None = None
        if lfs_raw is not None:
            if not isinstance(lfs_raw, Mapping):
                raise ProvenanceError("provider LFS metadata is invalid")
            oid = lfs_raw.get("sha256")
            if isinstance(oid, str) and not oid.startswith("sha256:"):
                oid = f"sha256:{oid}"
            lfs = {"oid": oid, "size_bytes": lfs_raw.get("size")}
        files.append(
            {
                "path": path,
                "size_bytes": size,
                "download_url": (
                    f"https://{host}/{repository_path}/resolve/{revision_path}/"
                    f"{quote(str(path), safe='')}"
                ),
                "git": {"object_id": blob_id},
                "lfs": lfs,
            }
        )
    return {
        "schema_version": 1,
        "repository": {
            "identifier": raw.get("id"),
            "revision": raw.get("sha"),
            "license": card_data.get("license"),
            "architectures": config.get("architectures"),
        },
        "files": files,
    }


def _https_url_for_verification(value: object, hosts: tuple[str, ...], path: str) -> str:
    try:
        return _https_url(value, hosts, f"download URL for {path}")
    except MetadataPolicyError as exc:
        raise ProvenanceError(str(exc)) from exc


def _validate_source_identity(item: Mapping[str, object], path: str) -> None:
    git = item["git"]
    lfs = item["lfs"]
    if not isinstance(git, Mapping) or set(git) != {"object_id"}:
        raise ProvenanceError(f"missing Git identity for {path}")
    object_id = git["object_id"]
    if not isinstance(object_id, str) or not (
        SHA1_RE.fullmatch(object_id) or SHA256_RE.fullmatch(object_id)
    ):
        raise ProvenanceError(f"invalid Git identity for {path}")
    if lfs is not None:
        if not isinstance(lfs, Mapping) or set(lfs) != {"oid", "size_bytes"}:
            raise ProvenanceError(f"invalid LFS identity for {path}")
        oid = lfs["oid"]
        lfs_size = lfs["size_bytes"]
        if not isinstance(oid, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", oid):
            raise ProvenanceError(f"invalid LFS object identity for {path}")
        if lfs_size != item["size_bytes"]:
            raise ProvenanceError(f"LFS size mismatch for {path}")


def _source_key(policy: MetadataPolicy, item: Mapping[str, object]) -> str:
    git = item["git"]
    assert isinstance(git, Mapping)
    lfs = item["lfs"]
    lfs_value = None
    if isinstance(lfs, Mapping):
        lfs_value = {"oid": lfs["oid"], "size_bytes": lfs["size_bytes"]}
    identity = {
        "repository": policy.identifier,
        "revision": policy.revision,
        "path": item["path"],
        "git_object_id": git["object_id"],
        "lfs": lfs_value,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _load_identity_index(cache_root: Path) -> dict[str, str]:
    index = cache_root / "source-identities.json"
    if not index.exists():
        return {}
    try:
        raw = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("cache identity index is ambiguous") from exc
    if (
        not isinstance(raw, dict)
        or any(not SHA256_RE.fullmatch(key) for key in raw)
        or any(
            not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in raw.values()
        )
    ):
        raise ProvenanceError("cache identity index is ambiguous")
    return raw


def _write_identity_index(cache_root: Path, index: dict[str, str]) -> None:
    destination = cache_root / "source-identities.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def _cache_file(
    *,
    response: StreamingResponse,
    expected_size: int,
    item: Mapping[str, object],
    policy: MetadataPolicy,
    root: Path,
    identity_index: dict[str, str],
) -> dict[str, object]:
    metadata = response.metadata
    _validate_response_url(metadata, policy.allowed_hosts)
    if metadata.status != 200:
        raise ProvenanceError(f"repository file returned HTTP {metadata.status}: {item['path']}")
    if _response_length(metadata.content_length) != expected_size:
        raise ProvenanceError(f"response size does not match metadata: {item['path']}")
    policy.cache_root.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    written = 0
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix="partial-", dir=policy.cache_root, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            for chunk in response.iter_bytes():
                if not isinstance(chunk, bytes) or not chunk:
                    raise ProvenanceError(f"invalid response body chunk: {item['path']}")
                written += len(chunk)
                if written > expected_size or written > policy.per_file_bytes:
                    raise ProvenanceError(f"response exceeds declared size: {item['path']}")
                digest.update(chunk)
                temporary.write(chunk)
        if written != expected_size:
            raise ProvenanceError(f"partial response for {item['path']}")
        sha256 = digest.hexdigest()
        identity_key = _source_key(policy, item)
        prior = identity_index.get(identity_key)
        if prior is not None and prior != sha256:
            raise ProvenanceError(f"source identity drift for {item['path']}")
        destination = policy.cache_root / "sha256" / sha256
        destination.parent.mkdir(parents=True, exist_ok=True)
        reused = destination.exists()
        if reused:
            with destination.open("rb") as handle:
                actual = hashlib.file_digest(handle, "sha256").hexdigest()
            if destination.stat().st_size != expected_size or actual != sha256:
                raise ProvenanceError(f"cache ambiguity for {item['path']}")
        else:
            os.replace(temporary_path, destination)
            temporary_path = None
        identity_index[identity_key] = sha256
        return {
            "sha256": sha256,
            "size_bytes": written,
            "cache_path": destination.relative_to(root).as_posix(),
            "reused": reused,
        }
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_cached_json(entry: Mapping[str, object], root: Path, label: str) -> Mapping[str, object]:
    local = entry["local_content"]
    assert isinstance(local, Mapping)
    path = root / str(local["cache_path"])
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"{label} is not valid inert JSON metadata") from exc
    if not isinstance(raw, Mapping):
        raise ProvenanceError(f"{label} must be a JSON object")
    if _requires_remote_code(raw):
        raise ProvenanceError(f"{label} requires remote executable code")
    return raw


def _requires_remote_code(value: object) -> bool:
    if isinstance(value, Mapping):
        if value.get("trust_remote_code") is True or value.get("auto_map"):
            return True
        return any(_requires_remote_code(item) for item in value.values())
    if isinstance(value, list):
        return any(_requires_remote_code(item) for item in value)
    return False


def _validate_inert_metadata(
    entries: list[dict[str, object]], root: Path, policy: MetadataPolicy
) -> int:
    by_path = {entry["path"]: entry for entry in entries}
    config = _read_cached_json(by_path["config.json"], root, "config.json")
    if config.get("architectures") != list(policy.architectures):
        raise ProvenanceError("config.json architecture drift")
    context = config.get("max_position_embeddings")
    if context is None and isinstance(config.get("text_config"), Mapping):
        context = config["text_config"].get("max_position_embeddings")
    if not isinstance(context, int) or isinstance(context, bool) or context <= 0:
        raise ProvenanceError("config.json is missing required max_position_embeddings")
    tokenizer_config = _read_cached_json(
        by_path["tokenizer_config.json"], root, "tokenizer_config.json"
    )
    tokenizer_context = tokenizer_config.get("model_max_length")
    if not isinstance(tokenizer_context, int) or isinstance(tokenizer_context, bool):
        raise ProvenanceError("tokenizer_config.json is missing required model_max_length")
    if tokenizer_context != context:
        raise ProvenanceError("configured context drift between config and tokenizer")
    index = _read_cached_json(
        by_path["model.safetensors.index.json"], root, "model.safetensors.index.json"
    )
    if not isinstance(index.get("weight_map"), Mapping) or not index["weight_map"]:
        raise ProvenanceError("model index is missing required weight_map metadata")
    index_metadata = index.get("metadata")
    total_size = index_metadata.get("total_size") if isinstance(index_metadata, Mapping) else None
    if (
        isinstance(total_size, bool)
        or not isinstance(total_size, int | float)
        or not math.isfinite(total_size)
        or total_size <= 0
        or not float(total_size).is_integer()
    ):
        raise ProvenanceError("model index is missing required total_size metadata")
    if TOKENIZER_JSON in by_path:
        _read_cached_json(by_path[TOKENIZER_JSON], root, TOKENIZER_JSON)
    else:
        vocab = _read_cached_json(by_path["vocab.json"], root, "vocab.json")
        if not vocab:
            raise ProvenanceError("vocab.json is empty")
    return context


def verify_metadata_repository(
    policy: MetadataPolicy,
    *,
    root: Path,
    transport: MetadataTransport | None = None,
) -> dict[str, object]:
    root = root.resolve()
    if policy.cache_root != (root / "artifacts/local/provenance").resolve():
        raise ProvenanceError("policy cache root does not belong to this repository")
    client = transport or AnonymousHTTPSClient(policy.allowed_hosts)
    _assert_secure_transport(client)
    try:
        metadata_response = client.get_json(
            policy.metadata_url,
            max_bytes=MAX_METADATA_BYTES,
            timeout_seconds=policy.connect_timeout_seconds,
        )
    except ssl.SSLCertVerificationError as exc:
        raise ProvenanceError("TLS verification failed") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProvenanceError("metadata transport failed") from exc
    _validate_response_url(metadata_response.metadata, policy.allowed_hosts)
    if metadata_response.metadata.status != 200:
        raise ProvenanceError(
            f"repository metadata returned HTTP {metadata_response.metadata.status}"
        )
    normalized_metadata = _normalize_repository_metadata(metadata_response.value, policy)
    repository, inventory = _inventory(normalized_metadata, policy)
    identity_index = _load_identity_index(policy.cache_root)
    entries: list[dict[str, object]] = []
    optional_absent = sorted(OPTIONAL_FILES - inventory.keys())
    for path in sorted(inventory):
        item = inventory[path]
        try:
            response = client.open(
                str(item["download_url"]), timeout_seconds=policy.read_timeout_seconds
            )
        except ssl.SSLCertVerificationError as exc:
            raise ProvenanceError("TLS verification failed") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProvenanceError(f"metadata file transport failed: {path}") from exc
        try:
            _validate_response_url(response.metadata, policy.allowed_hosts)
            if response.metadata.status == 404 and path in OPTIONAL_FILES:
                optional_absent.append(path)
                continue
            local = _cache_file(
                response=response,
                expected_size=int(item["size_bytes"]),
                item=item,
                policy=policy,
                root=root,
                identity_index=identity_index,
            )
        finally:
            response.close()
        git = item["git"]
        assert isinstance(git, Mapping)
        lfs = item["lfs"]
        source = {
            "git_object_id": git["object_id"],
            "lfs_oid": lfs["oid"] if isinstance(lfs, Mapping) else None,
            "lfs_size_bytes": lfs["size_bytes"] if isinstance(lfs, Mapping) else None,
        }
        entries.append(
            {
                "path": path,
                "source": source,
                "http": {
                    "requested_url": response.metadata.requested_url,
                    "final_url": response.metadata.final_url,
                    "content_length": int(item["size_bytes"]),
                    "etag": response.metadata.etag,
                    "last_modified": response.metadata.last_modified,
                },
                "local_content": local,
            }
        )
    context = _validate_inert_metadata(entries, root, policy)
    optional_absent = sorted(set(optional_absent))
    _write_identity_index(policy.cache_root, identity_index)
    tokenizer_representation = (
        TOKENIZER_JSON if TOKENIZER_JSON in inventory else "vocab.json+merges.txt"
    )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "policy_sha256": policy.sha256,
        "repository": {
            "identifier": repository["identifier"],
            "revision": repository["revision"],
            "license": repository["license"],
            "architectures": repository["architectures"],
        },
        "files": entries,
        "optional_absent": optional_absent,
        "tokenizer": {"root_only": True, "representation": tokenizer_representation},
        "context": {
            "configured_tokens": context,
            "runtime_initialized": False,
            "usefulness_proven": False,
        },
        "weights_required": False,
        "uploads_enabled": False,
        "remote_submission_enabled": False,
        "scheduling_enabled": False,
        "destructive_cleanup_enabled": False,
        "requested_cloud_cost_usd": 0,
        "actual_cloud_cost_usd": 0,
    }
    identity_manifest = json.loads(json.dumps(manifest))
    for entry in identity_manifest["files"]:
        entry["local_content"].pop("reused", None)
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(identity_manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return manifest
