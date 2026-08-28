"""Construct and consume the one closed U8 capability from ignored local evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from lowbit_lab.config import SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_MERGE_COMMIT,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_IMMUTABLE_ORIGIN_HOSTS,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_RECOVERY_AUTHORITY_SHA256,
    REFERENCE_SETTLED_SMOKE_USD,
    REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
    REFERENCE_SIGNED_CDN_MERGE_COMMIT,
    REFERENCE_SIGNED_REDIRECT_POLICY,
    REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256,
)
from lowbit_lab.db import SCHEMA_VERSION, ResultsDatabase, confine_results_db
from lowbit_lab.evaluation_lock import validate_pending_evaluation_lock
from lowbit_lab.jsonio import emit
from lowbit_lab.modal_job import (
    ReferenceJobConfig,
    load_reference_job_config,
    plan_reference_bootstrap_preview,
)
from lowbit_lab.provenance import parse_weight_inventory
from lowbit_lab.provider_evidence import (
    DEFAULT_BILLING_AUTHORITY,
    DEFAULT_BILLING_RECEIPT,
    DEFAULT_BILLING_REPORT,
    REPORT_FIELDS,
    validate_provider_capability_receipt,
)
from lowbit_lab.provider_evidence import (
    DEFAULT_OUTPUT as PROVIDER_CAPABILITY_PATH,
)
from lowbit_lab.reference_authority import (
    RECOVERY_AUTHORITY_PATH,
    WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
    ReferenceAuthorityError,
    build_reference_recovery_authority,
    build_workspace_scope_reconciliation_authority,
    validate_reference_recovery_authority,
    validate_workspace_scope_reconciliation_authority,
)
from lowbit_lab.reference_bootstrap import (
    EMPIRICAL_FACTS,
    FUTURE_STAGE_RESERVES_SECONDS,
    STAGES,
    canonical_bytes,
    canonical_sha256,
    validate_bootstrap_request_bytes,
    validate_image_lock_bytes,
)
from lowbit_lab.reference_contract import (
    REFERENCE_APP_NAME,
    REFERENCE_REPLACEMENT_AUDIT_REASON,
    REFERENCE_RESOURCES,
)
from lowbit_lab.reference_gates import ReferenceGateError, verify_provider_billing_authority
from lowbit_lab.reference_provider_auth import (
    OFFICIAL_MODAL_SERVER_URL,
    auth_receipt_path,
    provider_environment_overrides_present,
    sanitized_modal_environment,
)
from lowbit_lab.reference_replacement_settlement import (
    APP_KIND as REPLACEMENT_APP_KIND,
)
from lowbit_lab.reference_replacement_settlement import (
    RECEIPT_KIND as REPLACEMENT_SETTLEMENT_KIND,
)
from lowbit_lab.reference_replacement_settlement import (
    REPORT_KIND as REPLACEMENT_REPORT_KIND,
)
from lowbit_lab.reference_settlement import (
    AUTH_METHOD_SHA256,
    AUTH_RECEIPT_MAXIMUM_AGE_SECONDS,
    CANONICAL_EMPTY_REPORT,
)
from lowbit_lab.reference_settlement import (
    RECEIPT_KIND as WORKSPACE_ZERO_RECEIPT_KIND,
)
from lowbit_lab.reference_transport import observe_topology
from lowbit_lab.runtime import (
    load_runtime_lock,
    runtime_metadata,
    verify_current_installed_environment,
)
from lowbit_lab.safe_files import SafeFileError, atomic_write

CONFIG_PATH = Path("configs/local/reference.yaml")
REQUEST_PATH = Path("reports/local/u8-bootstrap-request.json")
IMAGE_LOCK_PATH = Path("configs/local/reference-image-lock.json")
PUBLICATION_MANIFEST_PATH = Path("configs/local/publication.yaml")
DATABASE_PATH = Path("results/local/reference.sqlite")
AUTH_BINDING_PATH = Path("configs/local/reference-workspace-auth-binding.json")
AUTH_RECEIPT_PATH = Path("reports/local/reference-workspace-auth-receipt.json")
WORKSPACE_ZERO_REPORT_PATH = Path("reports/local/reference-preidentity-zero-report.json")
WORKSPACE_ZERO_RECEIPT_PATH = Path("reports/local/reference-preidentity-zero-receipt.json")
REPLACEMENT_APP_EVIDENCE_PATH = Path("reports/local/reference-replacement-app-evidence.json")
REPLACEMENT_REPORT_PATH = Path("reports/local/reference-replacement-billing-report.json")
REPLACEMENT_RECEIPT_PATH = Path("reports/local/reference-replacement-settlement-receipt.json")
AUTH_MAXIMUM_AGE_SECONDS = AUTH_RECEIPT_MAXIMUM_AGE_SECONDS
MAX_LOCAL_EVIDENCE_BYTES = 64 * 1024
MAX_FILTERED_BILLING_REPORT_BYTES = 1_000_000
if TYPE_CHECKING:
    from lowbit_lab.reference_modal_adapter import ReferenceModalCapability
_SOURCE_FILES = {
    "chat_template.jinja": "text",
    "config.json": "json",
    "generation_config.json": "json",
    "merges.txt": "tokenizer_data",
    "model.safetensors.index.json": "json",
    "special_tokens_map.json": "json",
    "tokenizer.json": "tokenizer_data",
    "tokenizer_config.json": "json",
    "vocab.json": "tokenizer_data",
}


class ReferenceOrchestratorError(RuntimeError):
    """A sanitized failure before or at the already-audited paid boundary."""


class ReferenceProviderStateUnknown(ReferenceOrchestratorError):
    """Modal may have been contacted; only authoritative evidence can settle the state."""


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_json_bytes(path: Path, label: str) -> tuple[Mapping[str, object], bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError(f"{label} is unavailable") from exc
    if not isinstance(value, Mapping):
        raise ReferenceOrchestratorError(f"{label} schema drift")
    return value, content


def _read_json(path: Path, label: str) -> Mapping[str, object]:
    return _read_json_bytes(path, label)[0]


def _read_bounded(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            content = handle.read(maximum_bytes + 1)
    except OSError as exc:
        raise ReferenceOrchestratorError(f"{label} is unavailable") from exc
    if len(content) > maximum_bytes:
        raise ReferenceOrchestratorError(f"{label} exceeds its byte limit")
    return content


def _write_atomic(root: Path, path: Path, content: bytes) -> None:
    try:
        atomic_write(root.resolve(strict=True), path, content, replace=True)
    except SafeFileError as exc:
        raise ReferenceOrchestratorError("orchestration evidence path is unsafe") from exc


def _utc(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReferenceOrchestratorError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ReferenceOrchestratorError(f"{label} must be UTC")
    return parsed.astimezone(UTC)


def _root_json(root: Path, relative: Path, label: str) -> Mapping[str, Any]:
    if relative.is_absolute() or ".." in relative.parts:
        raise ReferenceOrchestratorError(f"{label} path is invalid")
    return _read_json(root.resolve() / relative, label)


def _configured_workspace_scope(root: Path) -> str:
    try:
        raw = yaml.safe_load((root.resolve() / CONFIG_PATH).read_text(encoding="utf-8"))
        scope = raw["provider"]["workspace_scope_sha256"]
    except (OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        raise ReferenceOrchestratorError("configured workspace scope is unavailable") from exc
    if not isinstance(scope, str) or SHA256_RE.fullmatch(scope) is None:
        raise ReferenceOrchestratorError("configured workspace scope is invalid")
    return scope


def _require_merged_clean_main(root: Path) -> str:
    """Require the local checkout to be exact, clean, reviewed public main."""
    commands = (
        ["git", "status", "--porcelain=v1"],
        ["git", "branch", "--show-current"],
        ["git", "rev-parse", "HEAD"],
        ["git", "rev-parse", "origin/main"],
    )
    outputs: list[str] = []
    try:
        for command in commands:
            completed = subprocess.run(
                command,
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
            )
            if completed.returncode != 0:
                raise ReferenceOrchestratorError("reviewed main lineage is unavailable")
            outputs.append(completed.stdout.strip())
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReferenceOrchestratorError("reviewed main lineage is unavailable") from exc
    dirty, branch, head, origin_main = outputs
    if (
        dirty
        or branch != "main"
        or re.fullmatch(r"[0-9a-f]{40}", head) is None
        or head != origin_main
    ):
        raise ReferenceOrchestratorError("live actions require clean merged origin/main")
    return head


def _run_modal_cli(
    arguments: list[str],
    *,
    runner: Any | None = None,
) -> bytes:
    """Run only the read-only Modal CLI surfaces and return uncaptured bytes."""
    command = [sys.executable, "-I", "-B", "-c", _VALIDATED_MODAL_CLI_SCRIPT, *arguments]
    environment = sanitized_modal_environment()
    try:
        if runner is not None:
            completed = runner(
                command,
                check=False,
                capture_output=True,
                env=environment,
                shell=False,
                timeout=60,
            )
            stdout = completed.stdout
            returncode = completed.returncode
        else:
            with tempfile.TemporaryFile() as output:
                process = subprocess.Popen(
                    command,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    shell=False,
                )
                try:
                    returncode = process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                output.seek(0)
                stdout = output.read(1_000_001)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReferenceOrchestratorError("Modal read-only CLI is unavailable") from exc
    if returncode != 0:
        raise ReferenceOrchestratorError("Modal read-only CLI failed")
    if not isinstance(stdout, bytes) or len(stdout) > 1_000_000:
        raise ReferenceOrchestratorError("Modal read-only CLI output is invalid")
    return stdout


_VALIDATED_MODAL_CLI_SCRIPT = (
    "from modal.config import DEFAULT_SERVER_URL,_check_config,config;"
    "_check_config();"
    "ok=(DEFAULT_SERVER_URL==" + repr(OFFICIAL_MODAL_SERVER_URL) + " and "
    "config.get('server_url',use_env=False)==DEFAULT_SERVER_URL and "
    "config.get('override_headers',use_env=False) in (None,{}));"
    "ok or (_ for _ in ()).throw(RuntimeError('unsupported provider transport'));"
    "from modal.__main__ import main;main()"
)
_ACTIVE_WORKSPACE_DIGEST_SCRIPT = (
    "import asyncio,hashlib;"
    "from modal.config import DEFAULT_SERVER_URL,_check_config,_lookup_workspace,_profile,config;"
    "_check_config();"
    "server=config.get('server_url',profile=_profile,use_env=False);"
    "headers=config.get('override_headers',profile=_profile,use_env=False);"
    "ok=(DEFAULT_SERVER_URL==" + repr(OFFICIAL_MODAL_SERVER_URL) + " and "
    "server==DEFAULT_SERVER_URL and headers in (None,{}));"
    "ok or (_ for _ in ()).throw(RuntimeError('unsupported provider transport'));"
    "token_id=config.get('token_id',profile=_profile,use_env=False);"
    "token_secret=config.get('token_secret',profile=_profile,use_env=False);"
    "response=asyncio.run(_lookup_workspace(server,token_id,token_secret));"
    "print(hashlib.sha256(response.username.encode('utf-8')).hexdigest())"
)


def _run_active_workspace_digest(*, runner: Any | None = None) -> bytes:
    """Authenticate only the active profile and emit only its workspace digest."""
    command = [sys.executable, "-I", "-B", "-c", _ACTIVE_WORKSPACE_DIGEST_SCRIPT]
    environment = sanitized_modal_environment()
    try:
        completed = (runner or subprocess.run)(
            command,
            check=False,
            capture_output=True,
            env=environment,
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReferenceOrchestratorError("Modal workspace identity is unavailable") from exc
    if completed.returncode != 0:
        raise ReferenceOrchestratorError("Modal workspace identity is unavailable")
    if not isinstance(completed.stdout, bytes):
        raise ReferenceOrchestratorError("Modal workspace identity is invalid")
    return completed.stdout


def _current_workspace_digest(*, runner: Any | None = None) -> str:
    raw = _run_active_workspace_digest(runner=runner)
    try:
        digest = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ReferenceOrchestratorError("Modal workspace identity is invalid") from exc
    encoded = digest.encode("ascii")
    if SHA256_RE.fullmatch(digest) is None or raw not in {
        encoded,
        encoded + b"\n",
        encoded + b"\r\n",
    }:
        raise ReferenceOrchestratorError("Modal workspace identity is invalid")
    return digest


def bind_workspace_auth(root: Path, *, runner: Any | None = None) -> Mapping[str, object]:
    """Bind the current provider-local profile without persisting its display value."""
    if provider_environment_overrides_present():
        raise ReferenceOrchestratorError("ambient provider environment override is forbidden")
    root = root.resolve()
    scope = _configured_workspace_scope(root)
    reconciliation = validate_workspace_scope_reconciliation_authority(root)
    workspace_identity_sha256 = _current_workspace_digest(runner=runner)
    if (
        reconciliation["original_workspace_scope_sha256"] != scope
        or reconciliation["authenticated_workspace_identity_sha256"] != workspace_identity_sha256
    ):
        raise ReferenceOrchestratorError("authenticated Modal workspace reconciliation mismatch")
    binding = {
        "authenticated_workspace_identity_sha256": workspace_identity_sha256,
        "kind": "reference_modal_workspace_auth_binding",
        "original_workspace_scope_sha256": scope,
        "provider": "modal",
        "reconciliation_authority_sha256": (REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256),
        "schema_version": 2,
    }
    encoded = canonical_bytes(binding)
    path = root / AUTH_BINDING_PATH
    if path.exists():
        if path.read_bytes() != encoded:
            raise ReferenceOrchestratorError("workspace auth binding is immutable")
    else:
        try:
            atomic_write(root, AUTH_BINDING_PATH, encoded, replace=False)
        except SafeFileError as exc:
            raise ReferenceOrchestratorError("workspace auth binding raced") from exc
    return {
        "authenticated_workspace_identity_sha256": workspace_identity_sha256,
        "binding_sha256": _sha(encoded),
        "original_workspace_scope_sha256": scope,
        "reconciliation_authority_sha256": (REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256),
    }


def verify_workspace_auth(
    root: Path,
    *,
    runner: Any | None = None,
    write_latest: bool = True,
) -> Mapping[str, object]:
    """Verify the current local profile against the private digest binding."""
    if provider_environment_overrides_present():
        raise ReferenceOrchestratorError("ambient provider environment override is forbidden")
    root = root.resolve()
    binding = _root_json(root, AUTH_BINDING_PATH, "workspace auth binding")
    expected = {
        "authenticated_workspace_identity_sha256",
        "kind",
        "original_workspace_scope_sha256",
        "provider",
        "reconciliation_authority_sha256",
        "schema_version",
    }
    if (
        set(binding) != expected
        or binding.get("schema_version") != 2
        or binding.get("kind") != "reference_modal_workspace_auth_binding"
        or binding.get("provider") != "modal"
    ):
        raise ReferenceOrchestratorError("workspace auth binding schema drift")
    scope = _configured_workspace_scope(root)
    reconciliation = validate_workspace_scope_reconciliation_authority(root)
    current_identity = _current_workspace_digest(runner=runner)
    if (
        binding.get("original_workspace_scope_sha256") != scope
        or binding.get("authenticated_workspace_identity_sha256") != current_identity
        or binding.get("reconciliation_authority_sha256")
        != REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
        or reconciliation["original_workspace_scope_sha256"] != scope
        or reconciliation["authenticated_workspace_identity_sha256"] != current_identity
    ):
        raise ReferenceOrchestratorError("authenticated Modal workspace reconciliation mismatch")
    authenticated_at = datetime.now(UTC).isoformat()
    receipt = {
        "authenticated_at": authenticated_at,
        "authenticated_workspace_identity_sha256": current_identity,
        "binding_sha256": _sha(canonical_bytes(binding)),
        "kind": "reference_modal_workspace_auth_receipt",
        "method_sha256": AUTH_METHOD_SHA256,
        "provider": "modal",
        "original_workspace_scope_sha256": scope,
        "reconciliation_authority_sha256": (REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256),
        "schema_version": 2,
        "verification_nonce_sha256": _sha(os.urandom(32)),
    }
    encoded = canonical_bytes(receipt)
    receipt_sha256 = _sha(encoded)
    try:
        immutable_path = auth_receipt_path(receipt_sha256)
        absolute_immutable_path = root / immutable_path
        if absolute_immutable_path.exists():
            if absolute_immutable_path.read_bytes() != encoded:
                raise ReferenceOrchestratorError("workspace auth receipt digest collision")
        else:
            atomic_write(root, immutable_path, encoded, replace=False)
        if write_latest:
            atomic_write(root, AUTH_RECEIPT_PATH, encoded, replace=True)
    except SafeFileError as exc:
        raise ReferenceOrchestratorError("workspace auth receipt path is unsafe") from exc
    return {**receipt, "receipt_sha256": receipt_sha256}


def _validate_fresh_auth_receipt(
    root: Path,
    *,
    expected_original_workspace_scope_sha256: str,
    expected_authenticated_workspace_identity_sha256: str,
) -> None:
    receipt = _root_json(root, AUTH_RECEIPT_PATH, "workspace auth receipt")
    if (
        set(receipt)
        != {
            "authenticated_at",
            "authenticated_workspace_identity_sha256",
            "binding_sha256",
            "kind",
            "method_sha256",
            "provider",
            "original_workspace_scope_sha256",
            "reconciliation_authority_sha256",
            "schema_version",
            "verification_nonce_sha256",
        }
        or receipt.get("schema_version") != 2
        or receipt.get("kind") != "reference_modal_workspace_auth_receipt"
        or receipt.get("provider") != "modal"
    ):
        raise ReferenceOrchestratorError("workspace auth receipt schema drift")
    authenticated = _utc(str(receipt["authenticated_at"]), "authenticated_at")
    age = (datetime.now(UTC) - authenticated).total_seconds()
    if age < 0 or age > AUTH_MAXIMUM_AGE_SECONDS:
        raise ReferenceOrchestratorError("workspace auth receipt is stale")
    if (
        receipt.get("original_workspace_scope_sha256") != expected_original_workspace_scope_sha256
        or receipt.get("authenticated_workspace_identity_sha256")
        != expected_authenticated_workspace_identity_sha256
        or receipt.get("reconciliation_authority_sha256")
        != REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
        or receipt.get("method_sha256") != AUTH_METHOD_SHA256
    ):
        raise ReferenceOrchestratorError("workspace auth receipt reconciliation mismatch")


def _original_preidentity_row(database: ResultsDatabase) -> Mapping[str, Any]:
    with database.connect_readonly() as connection:
        rows = connection.execute(
            """SELECT br.reservation_id, br.reference_execution_scope_sha256,
                billing_authority_sha256, authoritative_report_identity_sha256,
                billing_completeness_delay_seconds, heartbeat_at, updated_at,
                ras.consumed_at
            FROM budget_reservations AS br
            JOIN reference_authority_slots AS ras
              ON ras.execution_scope_sha256 = br.reference_execution_scope_sha256
            WHERE br.status = 'audit_blocked'
              AND br.failure_reason = 'provider boundary uncertainty: AuthError'
              AND br.provider_job_id IS NULL AND br.app_identity IS NULL
              AND br.submitted_at IS NULL AND br.settlement_pending_at IS NULL"""
        ).fetchall()
    if len(rows) != 1:
        raise ReferenceOrchestratorError("unique pre-identity reservation is unavailable")
    return dict(rows[0])


def materialize_workspace_reconciliation_authority(
    root: Path, *, runner: Any | None = None
) -> Mapping[str, str]:
    """Create the exact ignored one-time mapping from live, read-only lineage."""
    root = root.resolve()
    _require_merged_clean_main(root)
    if provider_environment_overrides_present():
        raise ReferenceOrchestratorError("ambient provider environment override is forbidden")
    if validate_reference_recovery_authority(root) != REFERENCE_RECOVERY_AUTHORITY_SHA256:
        raise ReferenceOrchestratorError("recovery authority lineage drift")
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    row = _original_preidentity_row(database)
    authority = build_workspace_scope_reconciliation_authority(
        original_workspace_scope_sha256=_configured_workspace_scope(root),
        authenticated_workspace_identity_sha256=_current_workspace_digest(runner=runner),
        original_reservation_id=str(row["reservation_id"]),
        original_execution_scope_sha256=str(row["reference_execution_scope_sha256"]),
        billing_authority_sha256=str(row["billing_authority_sha256"]),
    )
    encoded = canonical_bytes(authority) + b"\n"
    if canonical_sha256(authority) != REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256:
        raise ReferenceOrchestratorError("workspace reconciliation authority lineage drift")
    output = root / WORKSPACE_RECONCILIATION_AUTHORITY_PATH
    try:
        if output.exists():
            if output.read_bytes() != encoded:
                raise ReferenceOrchestratorError("workspace reconciliation authority is immutable")
        else:
            atomic_write(root, WORKSPACE_RECONCILIATION_AUTHORITY_PATH, encoded, replace=False)
        validated = validate_workspace_scope_reconciliation_authority(root)
    except (OSError, SafeFileError, ReferenceAuthorityError) as exc:
        raise ReferenceOrchestratorError(
            "workspace reconciliation authority is invalid"
        ) from exc
    return {
        "authenticated_workspace_identity_sha256": str(
            validated["authenticated_workspace_identity_sha256"]
        ),
        "original_workspace_scope_sha256": str(validated["original_workspace_scope_sha256"]),
        "reconciliation_authority_sha256": (REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256),
    }


def capture_workspace_zero_billing(
    root: Path,
    *,
    query_start: str,
    query_end: str,
    runner: Any | None = None,
) -> Mapping[str, object]:
    """Capture one explicit, complete, unfiltered, canonical empty workspace report."""
    root = root.resolve()
    _require_merged_clean_main(root)
    start = _utc(query_start, "query start")
    end = _utc(query_end, "query end")
    if (
        start >= end
        or any((start.minute, start.second, start.microsecond))
        or any((end.minute, end.second, end.microsecond))
    ):
        raise ReferenceOrchestratorError("billing interval must contain complete UTC hours")
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    row = _original_preidentity_row(database)
    latest_boundary = max(
        _utc(str(row["heartbeat_at"]), "stored heartbeat_at"),
        _utc(str(row["updated_at"]), "stored updated_at"),
    )
    completeness_delay = int(row["billing_completeness_delay_seconds"])
    if (
        start > _utc(str(row["consumed_at"]), "original consumed_at")
        or end < latest_boundary + timedelta(seconds=int(REFERENCE_RESOURCES["timeout_seconds"]))
        or datetime.now(UTC) < end + timedelta(seconds=completeness_delay)
    ):
        raise ReferenceOrchestratorError(
            "billing interval does not cover a complete settled window"
        )
    try:
        authority_bytes = (root / DEFAULT_BILLING_AUTHORITY).read_bytes()
        authority = json.loads(authority_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError("billing authority is unavailable") from exc
    if (
        not isinstance(authority, Mapping)
        or _sha(authority_bytes) != row["billing_authority_sha256"]
        or authority.get("authoritative_report_identity_sha256")
        != row["authoritative_report_identity_sha256"]
        or authority.get("billing_completeness_delay_seconds") != completeness_delay
    ):
        raise ReferenceOrchestratorError("billing authority lineage drift")
    auth = verify_workspace_auth(root, runner=runner, write_latest=False)
    raw_report = _run_modal_cli(
        [
            "billing",
            "report",
            "--start",
            start.isoformat().replace("+00:00", "Z"),
            "--end",
            end.isoformat().replace("+00:00", "Z"),
            "--resolution",
            "h",
            "--show-resources",
            "--json",
        ],
        runner=runner,
    )
    if raw_report != CANONICAL_EMPTY_REPORT:
        raise ReferenceOrchestratorError(
            "workspace billing report is not the exact canonical zero snapshot"
        )
    # Recheck the selected local profile after the provider response.
    after = verify_workspace_auth(root, runner=runner, write_latest=False)
    if (
        after["authenticated_workspace_identity_sha256"]
        != auth["authenticated_workspace_identity_sha256"]
        or after["original_workspace_scope_sha256"] != auth["original_workspace_scope_sha256"]
    ):
        raise ReferenceOrchestratorError("Modal workspace changed during billing capture")
    acquired_at = datetime.now(UTC).isoformat()
    report = raw_report
    receipt = {
        "actual_cost_usd": "0",
        "acquired_at": acquired_at,
        "all_environments": True,
        "all_resources": True,
        "authenticated_workspace_identity_sha256": auth["authenticated_workspace_identity_sha256"],
        "auth_binding_sha256": auth["binding_sha256"],
        "pre_auth_receipt_sha256": auth["receipt_sha256"],
        "post_auth_receipt_sha256": after["receipt_sha256"],
        "authoritative_report_identity_sha256": row["authoritative_report_identity_sha256"],
        "billing_authority_sha256": row["billing_authority_sha256"],
        "billing_method_sha256": authority["attribution_method_sha256"],
        "completeness_delay_seconds": completeness_delay,
        "currency": "USD",
        "failure_code": "auth_before_provider_identity",
        "filters": [],
        "kind": WORKSPACE_ZERO_RECEIPT_KIND,
        "original_execution_scope_sha256": row["reference_execution_scope_sha256"],
        "original_workspace_scope_sha256": auth["original_workspace_scope_sha256"],
        "pagination_complete": True,
        "provider": "modal",
        "query_end": end.isoformat(),
        "query_start": start.isoformat(),
        "recovery_authority_sha256": REFERENCE_RECOVERY_AUTHORITY_SHA256,
        "report_sha256": _sha(report),
        "report_size_bytes": len(report),
        "reservation_id": row["reservation_id"],
        "row_count": 0,
        "schema_version": 2,
        "workspace_reconciliation_authority_sha256": (
            REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
        ),
    }
    receipt_bytes = canonical_bytes(receipt)
    try:
        atomic_write(root, WORKSPACE_ZERO_REPORT_PATH, report, replace=True)
        atomic_write(root, WORKSPACE_ZERO_RECEIPT_PATH, receipt_bytes, replace=True)
    except SafeFileError as exc:
        raise ReferenceOrchestratorError("workspace-zero evidence path is unsafe") from exc
    return {
        "provider_contacted": False,
        "provider_read_only_contacted": True,
        "receipt_sha256": _sha(receipt_bytes),
        "report_sha256": _sha(report),
        "authenticated_workspace_identity_sha256": auth["authenticated_workspace_identity_sha256"],
        "original_workspace_scope_sha256": auth["original_workspace_scope_sha256"],
    }


def settle_workspace_zero(root: Path) -> Mapping[str, object]:
    """Settle from local byte snapshots only; this path has no adapter import."""
    root = root.resolve()
    _require_merged_clean_main(root)
    try:
        validate_reference_recovery_authority(root)
        validate_workspace_scope_reconciliation_authority(root)
    except ReferenceAuthorityError as exc:
        raise ReferenceOrchestratorError("workspace settlement authority is invalid") from exc
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    database.initialize()
    row = _original_preidentity_row(database)
    receipt_bytes = (root / WORKSPACE_ZERO_RECEIPT_PATH).read_bytes()
    report_bytes = (root / WORKSPACE_ZERO_REPORT_PATH).read_bytes()
    try:
        receipt = json.loads(receipt_bytes)
        pre_auth_receipt_bytes = (
            root / auth_receipt_path(str(receipt["pre_auth_receipt_sha256"]))
        ).read_bytes()
        post_auth_receipt_bytes = (
            root / auth_receipt_path(str(receipt["post_auth_receipt_sha256"]))
        ).read_bytes()
        _utc(str(receipt["query_start"]), "query start")
        _utc(str(receipt["query_end"]), "query end")
        _utc(str(receipt["acquired_at"]), "acquired_at")
        authority_path = root / DEFAULT_BILLING_AUTHORITY
        authority_bytes = authority_path.read_bytes()
        authority = json.loads(authority_bytes)
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError("workspace-zero evidence is unavailable") from exc
    if (
        not isinstance(authority, Mapping)
        or _sha(authority_bytes) != row["billing_authority_sha256"]
    ):
        raise ReferenceOrchestratorError("billing authority lineage drift")
    entitlement_sha256 = database.settle_reference_preidentity_zero(
        receipt_bytes,
        report_bytes,
        pre_auth_receipt_bytes=pre_auth_receipt_bytes,
        post_auth_receipt_bytes=post_auth_receipt_bytes,
        billing_authority_bytes=authority_bytes,
        authority_root=root,
        occurred_at=datetime.now(UTC).isoformat(),
    )
    return {
        "actual_cost_usd": "0",
        "entitlement_sha256": entitlement_sha256,
        "original_reservation_id": row["reservation_id"],
        "provider_contacted": False,
        "settlement_receipt_sha256": _sha(receipt_bytes),
    }


def _replacement_audit_row(database: ResultsDatabase) -> Mapping[str, Any]:
    with database.connect_readonly() as connection:
        rows = connection.execute(
            """SELECT br.reservation_id, br.reference_execution_scope_sha256,
                br.billing_authority_sha256, br.authoritative_report_identity_sha256,
                br.billing_completeness_delay_seconds, br.heartbeat_at,
                rre.entitlement_sha256, rre.consumed_at,
                rps.auth_binding_sha256, rws.original_workspace_scope_sha256,
                rws.authenticated_workspace_identity_sha256,
                rac.packet_sha256 AS standing_packet_sha256
            FROM budget_reservations AS br
            JOIN reference_replacement_entitlements AS rre
              ON rre.replacement_reservation_id = br.reservation_id
            JOIN reference_preidentity_settlements AS rps
              ON rps.settlement_sha256 = rre.settlement_sha256
            JOIN reference_workspace_scope_reconciliations AS rws
              ON rws.authority_sha256 = rre.workspace_reconciliation_authority_sha256
            JOIN reference_approval_challenges AS rac ON rac.run_id = br.run_id
            WHERE br.status = 'audit_blocked'
              AND br.failure_reason = ?
              AND br.provider_job_id IS NULL AND br.app_identity IS NULL
              AND br.submitted_at IS NULL AND br.settlement_pending_at IS NULL
              AND rre.state = 'consumed' LIMIT 2""",
            (REFERENCE_REPLACEMENT_AUDIT_REASON,),
        ).fetchall()
    if len(rows) != 1:
        raise ReferenceOrchestratorError("unique replacement audit reservation is unavailable")
    return dict(rows[0])


def _provider_json(raw: bytes, label: str) -> list[Mapping[str, object]]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError(f"{label} is not valid JSON") from exc
    if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
        raise ReferenceOrchestratorError(f"{label} schema drift")
    return value


def _validated_provider_capability(
    root: Path, request_bytes: bytes
) -> Mapping[str, object]:
    """Reproduce provider evidence bound to one canonical bootstrap request."""
    validated_request = validate_bootstrap_request_bytes(request_bytes)
    request = json.loads(validated_request.canonical_json)
    return validate_provider_capability_receipt(
        root / PROVIDER_CAPABILITY_PATH,
        expected_sha256=str(request["provider_capability"]["receipt_sha256"]),
        image_recipe_sha256=str(request["image_lock"]["recipe_sha256"]),
        billing_authority_path=root / DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=root / DEFAULT_BILLING_RECEIPT,
        billing_report_path=root / DEFAULT_BILLING_REPORT,
    )


def capture_replacement_billing(
    root: Path,
    *,
    query_start: str,
    query_end: str,
    runner: Any | None = None,
) -> Mapping[str, object]:
    """Capture sanitized app-attributed billing without executing provider work."""
    root = root.resolve()
    _require_merged_clean_main(root)
    if provider_environment_overrides_present():
        raise ReferenceOrchestratorError("ambient provider environment override is forbidden")
    start = _utc(query_start, "query start")
    end = _utc(query_end, "query end")
    if (
        start >= end
        or any((start.minute, start.second, start.microsecond))
        or any((end.minute, end.second, end.microsecond))
    ):
        raise ReferenceOrchestratorError("billing interval must contain complete UTC hours")
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    row = _replacement_audit_row(database)
    consumed = _utc(str(row["consumed_at"]), "replacement consumed_at")
    latest = _utc(str(row["heartbeat_at"]), "replacement heartbeat_at")
    delay = int(row["billing_completeness_delay_seconds"])
    if (
        start > consumed
        or end < latest + timedelta(seconds=int(REFERENCE_RESOURCES["timeout_seconds"]))
        or datetime.now(UTC) < end + timedelta(seconds=delay)
    ):
        raise ReferenceOrchestratorError("replacement billing interval is incomplete")
    config = load_reference_job_config(root / CONFIG_PATH, root=root)
    request_bytes = (root / REQUEST_PATH).read_bytes()
    provider = _validated_provider_capability(root, request_bytes)
    expected_packet_sha256 = canonical_sha256(
        {
            "bootstrap_authority_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "config_sha256": config.sha256,
            "request_sha256": _sha(request_bytes),
            "signed_cdn_authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
            "standing_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        }
    )
    if expected_packet_sha256 != row["standing_packet_sha256"]:
        raise ReferenceOrchestratorError("replacement request packet lineage drift")
    environment = str(provider["provider_environment"])
    environment_scope_sha256 = str(config.provider["environment_scope_sha256"])
    try:
        authority = verify_provider_billing_authority(
            root / DEFAULT_BILLING_AUTHORITY,
            expected_sha256=str(row["billing_authority_sha256"]),
            expected_environment_scope_sha256=environment_scope_sha256,
        )
    except ReferenceGateError as exc:
        raise ReferenceOrchestratorError("billing authority lineage drift") from exc
    if (
        authority["authoritative_report_identity_sha256"]
        != row["authoritative_report_identity_sha256"]
        or authority["billing_completeness_delay_seconds"] != delay
    ):
        raise ReferenceOrchestratorError("billing authority lineage drift")
    pre_auth = verify_workspace_auth(root, runner=runner, write_latest=False)
    app_raw = _run_modal_cli(
        ["app", "list", "--env", environment, "--json"], runner=runner
    )
    app_rows = _provider_json(app_raw, "provider app list")
    candidates = [
        item
        for item in app_rows
        if set(item) == {"app_id", "created_at", "description", "state", "stopped_at", "tasks"}
        and item["description"] == REFERENCE_APP_NAME
        and item["state"] == "stopped"
        and item["tasks"] == "0"
        and consumed
        <= _utc(str(item["created_at"]), "app created_at")
        <= consumed + timedelta(seconds=int(REFERENCE_RESOURCES["timeout_seconds"]))
    ]
    if len(candidates) != 1:
        raise ReferenceOrchestratorError("unique stopped replacement app is unavailable")
    app = candidates[0]
    created = _utc(str(app["created_at"]), "app created_at")
    stopped = _utc(str(app["stopped_at"]), "app stopped_at")
    if stopped < created or stopped > consumed + timedelta(
        seconds=int(REFERENCE_RESOURCES["timeout_seconds"])
    ):
        raise ReferenceOrchestratorError("replacement app timing drift")
    billing_raw = _run_modal_cli(
        [
            "billing",
            "report",
            "--start",
            start.isoformat().replace("+00:00", "Z"),
            "--end",
            end.isoformat().replace("+00:00", "Z"),
            "--resolution",
            "h",
            "--show-resources",
            "--json",
        ],
        runner=runner,
    )
    billing_rows = _provider_json(billing_raw, "provider billing report")
    filtered: list[dict[str, object]] = []
    total = Decimal("0")
    for item in billing_rows:
        if (
            item.get("description") == REFERENCE_APP_NAME
            and item.get("object_id") != app["app_id"]
        ):
            raise ReferenceOrchestratorError("replacement billing app identity is ambiguous")
        if item.get("object_id") != app["app_id"]:
            continue
        if set(item) != REPORT_FIELDS or (
            item["description"] != REFERENCE_APP_NAME
            or item["environment"] != environment
        ):
            raise ReferenceOrchestratorError("replacement billing attribution drift")
        if (
            type(item["cost"]) is not str
            or not item["cost"]
            or type(item["resource"]) is not str
            or not item["resource"]
        ):
            raise ReferenceOrchestratorError("replacement billing row type drift")
        try:
            cost = Decimal(item["cost"])
        except InvalidOperation as exc:
            raise ReferenceOrchestratorError("replacement billing cost is invalid") from exc
        if not cost.is_finite() or cost < 0 or cost.as_tuple().exponent < -10:
            raise ReferenceOrchestratorError("replacement billing cost is invalid")
        interval = _utc(str(item["interval_start"]), "billing interval")
        if interval < start or interval >= end:
            raise ReferenceOrchestratorError("replacement billing interval drift")
        total += cost
        filtered.append(
            {
                "cost": item["cost"],
                "interval_start": interval.isoformat(),
                "object_id": app["app_id"],
                "resource": item["resource"],
            }
        )
    post_auth = verify_workspace_auth(root, runner=runner, write_latest=False)
    if (
        pre_auth["authenticated_workspace_identity_sha256"]
        != post_auth["authenticated_workspace_identity_sha256"]
        or pre_auth["authenticated_workspace_identity_sha256"]
        != row["authenticated_workspace_identity_sha256"]
        or pre_auth["binding_sha256"] != row["auth_binding_sha256"]
        or post_auth["binding_sha256"] != row["auth_binding_sha256"]
    ):
        raise ReferenceOrchestratorError("Modal workspace changed during replacement capture")
    app_evidence = canonical_bytes(
        {
            "app_id": app["app_id"],
            "created_at": created.isoformat(),
            "kind": REPLACEMENT_APP_KIND,
            "schema_version": 1,
            "state": "stopped",
            "stopped_at": stopped.isoformat(),
            "running_tasks": 0,
        }
    )
    report = canonical_bytes(
        {"kind": REPLACEMENT_REPORT_KIND, "rows": filtered, "schema_version": 1}
    )
    acquired_at = datetime.now(UTC).isoformat()
    receipt = canonical_bytes(
        {
            "acquired_at": acquired_at,
            "actual_cost_usd": str(total),
            "app_evidence_sha256": _sha(app_evidence),
            "authenticated_workspace_identity_sha256": row[
                "authenticated_workspace_identity_sha256"
            ],
            "auth_binding_sha256": row["auth_binding_sha256"],
            "authoritative_report_identity_sha256": row[
                "authoritative_report_identity_sha256"
            ],
            "billing_authority_sha256": row["billing_authority_sha256"],
            "billing_method_sha256": authority["attribution_method_sha256"],
            "completeness_delay_seconds": delay,
            "entitlement_sha256": row["entitlement_sha256"],
            "environment_scope_sha256": environment_scope_sha256,
            "execution_scope_sha256": row["reference_execution_scope_sha256"],
            "filtered_report_sha256": _sha(report),
            "filtered_report_size_bytes": len(report),
            "kind": REPLACEMENT_SETTLEMENT_KIND,
            "post_auth_receipt_sha256": post_auth["receipt_sha256"],
            "pre_auth_receipt_sha256": pre_auth["receipt_sha256"],
            "provider": "modal",
            "query_end": end.isoformat(),
            "query_start": start.isoformat(),
            "reservation_id": row["reservation_id"],
            "schema_version": 1,
        }
    )
    for path, content in (
        (REPLACEMENT_APP_EVIDENCE_PATH, app_evidence),
        (REPLACEMENT_REPORT_PATH, report),
        (REPLACEMENT_RECEIPT_PATH, receipt),
    ):
        _write_atomic(root, path, content)
    return {
        "actual_cost_usd": str(total),
        "app_identity_sha256": _sha(str(app["app_id"]).encode()),
        "provider_read_only_contacted": True,
        "receipt_sha256": _sha(receipt),
    }


def settle_replacement_billing(root: Path) -> Mapping[str, object]:
    """Settle the replacement from local sanitized snapshots only."""
    root = root.resolve()
    _require_merged_clean_main(root)
    receipt_bytes = _read_bounded(
        root / REPLACEMENT_RECEIPT_PATH,
        maximum_bytes=MAX_LOCAL_EVIDENCE_BYTES,
        label="replacement settlement receipt",
    )
    try:
        receipt = json.loads(receipt_bytes)
        pre_auth_sha256 = str(receipt["pre_auth_receipt_sha256"])
        post_auth_sha256 = str(receipt["post_auth_receipt_sha256"])
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReferenceOrchestratorError("replacement settlement receipt is invalid") from exc
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    settlement_sha256 = database.settle_reference_replacement_billing(
        receipt_bytes,
        _read_bounded(
            root / REPLACEMENT_APP_EVIDENCE_PATH,
            maximum_bytes=MAX_LOCAL_EVIDENCE_BYTES,
            label="replacement app evidence",
        ),
        _read_bounded(
            root / REPLACEMENT_REPORT_PATH,
            maximum_bytes=MAX_FILTERED_BILLING_REPORT_BYTES,
            label="replacement filtered billing report",
        ),
        pre_auth_receipt_bytes=_read_bounded(
            root / auth_receipt_path(pre_auth_sha256),
            maximum_bytes=MAX_LOCAL_EVIDENCE_BYTES,
            label="replacement pre-auth receipt",
        ),
        post_auth_receipt_bytes=_read_bounded(
            root / auth_receipt_path(post_auth_sha256),
            maximum_bytes=MAX_LOCAL_EVIDENCE_BYTES,
            label="replacement post-auth receipt",
        ),
        billing_authority_bytes=_read_bounded(
            root / DEFAULT_BILLING_AUTHORITY,
            maximum_bytes=MAX_LOCAL_EVIDENCE_BYTES,
            label="replacement billing authority",
        ),
        occurred_at=datetime.now(UTC).isoformat(),
    )
    return {
        "actual_cost_usd": str(receipt["actual_cost_usd"]),
        "provider_contacted": False,
        "settlement_receipt_sha256": settlement_sha256,
    }


def materialize_recovery_authority(root: Path) -> Mapping[str, str]:
    """Create the ignored canonical recovery authority without provider contact."""
    root = root.resolve()
    legacy_content = canonical_bytes(build_reference_recovery_authority())
    content = legacy_content + b"\n"
    output = root / RECOVERY_AUTHORITY_PATH
    try:
        if output.exists():
            existing = output.read_bytes()
            if existing == legacy_content:
                atomic_write(root, RECOVERY_AUTHORITY_PATH, content, replace=True)
            elif existing != content:
                raise ReferenceOrchestratorError("recovery authority is immutable")
        else:
            atomic_write(root, RECOVERY_AUTHORITY_PATH, content, replace=False)
        validated = validate_reference_recovery_authority(root)
    except (SafeFileError, ReferenceAuthorityError) as exc:
        raise ReferenceOrchestratorError("recovery authority path is unsafe") from exc
    if validated != REFERENCE_RECOVERY_AUTHORITY_SHA256:
        raise ReferenceOrchestratorError("recovery authority lineage drift")
    return {"recovery_authority_sha256": validated}


def reference_status(root: Path) -> Mapping[str, object]:
    """Report only authority state and sanitized cost; never prepare or submit."""
    database = ResultsDatabase(confine_results_db(root.resolve(), DATABASE_PATH))
    with database.connect_readonly() as connection:
        version_row = connection.execute("SELECT max(version) FROM schema_info").fetchone()
        if version_row is None or version_row[0] != SCHEMA_VERSION:
            return {
                "configured_context_tokens": 262144,
                "provider_contacted": False,
                "proven_useful_context_tokens": None,
                "schema_upgrade_required": True,
            }
        original = connection.execute(
            """SELECT ras.consumed_at, br.reservation_id, br.status,
                br.provider_actual_cost_usd, br.settlement_mode
            FROM reference_authority_slots AS ras
            JOIN budget_reservations AS br
              ON br.reference_execution_scope_sha256 = ras.execution_scope_sha256
            ORDER BY br.created_at LIMIT 1"""
        ).fetchone()
        entitlements = connection.execute(
            """SELECT rre.entitlement_sha256, rre.state, br.reservation_id,
                br.status AS reservation_status, br.provider_actual_cost_usd,
                br.app_identity
            FROM reference_replacement_entitlements AS rre
            LEFT JOIN budget_reservations AS br
              ON br.reservation_id = rre.replacement_reservation_id LIMIT 2"""
        ).fetchall()
    if len(entitlements) > 1:
        raise ReferenceOrchestratorError("multiple replacement entitlements are invalid")
    entitlement = None if not entitlements else entitlements[0]
    return {
        "configured_context_tokens": 262144,
        "original": None
        if original is None
        else {
            "actual_cost_usd": original["provider_actual_cost_usd"],
            "reservation_id": original["reservation_id"],
            "settlement_mode": original["settlement_mode"],
            "slot_consumed": original["consumed_at"] is not None,
            "status": original["status"],
        },
        "provider_contacted": bool(
            entitlement is not None and entitlement["reservation_id"] is not None
        ),
        "proven_useful_context_tokens": None,
        "replacement": None
        if entitlement is None
        else {
            "entitlement_sha256": entitlement["entitlement_sha256"],
            "actual_cost_usd": entitlement["provider_actual_cost_usd"],
            "app_identity_bound": entitlement["app_identity"] is not None,
            "reservation_id": entitlement["reservation_id"],
            "reservation_status": entitlement["reservation_status"],
            "state": entitlement["state"],
        },
    }


def _replacement_binding(
    database: ResultsDatabase, *, execution_scope_sha256: str
) -> Mapping[str, str]:
    with database.connect_readonly() as connection:
        rows = connection.execute(
            """SELECT rre.entitlement_sha256, rre.state,
                rre.original_execution_scope_sha256,
                rps.original_workspace_scope_sha256,
                rps.authenticated_workspace_identity_sha256,
                rps.workspace_reconciliation_authority_sha256,
                rps.auth_binding_sha256
            FROM reference_replacement_entitlements AS rre
            JOIN reference_preidentity_settlements AS rps
              ON rps.settlement_sha256 = rre.settlement_sha256
            LIMIT 2"""
        ).fetchall()
    if len(rows) != 1:
        raise ReferenceOrchestratorError("reference replacement entitlement is unavailable")
    entitlement = rows[0]
    if (
        entitlement["state"] != "available"
        or entitlement["original_execution_scope_sha256"] != execution_scope_sha256
    ):
        raise ReferenceOrchestratorError("reference replacement entitlement is unavailable")
    return {
        "entitlement_sha256": str(entitlement["entitlement_sha256"]),
        "original_workspace_scope_sha256": str(entitlement["original_workspace_scope_sha256"]),
        "authenticated_workspace_identity_sha256": str(
            entitlement["authenticated_workspace_identity_sha256"]
        ),
        "workspace_reconciliation_authority_sha256": str(
            entitlement["workspace_reconciliation_authority_sha256"]
        ),
        "auth_binding_sha256": str(entitlement["auth_binding_sha256"]),
    }


def _manifest_identity(provenance: Mapping[str, object]) -> str:
    identity_manifest = deepcopy(dict(provenance))
    declared = identity_manifest.pop("manifest_sha256", None)
    files = identity_manifest.get("files")
    if not isinstance(files, list):
        raise ReferenceOrchestratorError("provenance manifest identity is incomplete")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("local_content"), dict):
            raise ReferenceOrchestratorError("provenance manifest identity is incomplete")
        item["local_content"].pop("reused", None)
    reproduced = _sha(json.dumps(identity_manifest, sort_keys=True, separators=(",", ":")).encode())
    if declared != reproduced:
        raise ReferenceOrchestratorError("provenance manifest identity drift")
    return reproduced


def _validate_frozen_inputs(
    frozen: Mapping[str, object],
    inventory: object,
    evaluation: object,
    evaluation_lock_file_sha256: str,
    runtime_receipt_sha256: str,
) -> None:
    if (
        inventory.source_revision != frozen["source_revision"]
        or inventory.index_tensor_bytes != frozen["weight_inventory_tensor_bytes"]
        # The config key binds exact persisted bytes, not canonical semantics.
        or evaluation_lock_file_sha256 != frozen["evaluation_lock_sha256"]
        or evaluation.context.configured_tokens != frozen["evaluation_max_context_tokens"]
        or runtime_receipt_sha256 != frozen["runtime_receipt_sha256"]
    ):
        raise ReferenceOrchestratorError("frozen source, evaluation, or runtime identity drift")


def refresh_local_config(root: Path) -> ReferenceJobConfig:
    """Bind ignored target configuration to the current clean reviewed tree."""
    root = root.resolve()
    runtime = runtime_metadata(root)
    if runtime["git_dirty"] or runtime["git_commit"] == "uncommitted":
        raise ReferenceOrchestratorError("reviewed tree must be clean and committed")
    path = root / CONFIG_PATH
    current = load_reference_job_config(path, root=root)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReferenceOrchestratorError("reference config is unavailable") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("inputs"), dict):
        raise ReferenceOrchestratorError("reference config schema drift")
    provenance = _read_json(
        root / str(current.authority_files["provenance_manifest_path"]), "provenance manifest"
    )
    provenance_sha = _manifest_identity(provenance)
    files = provenance.get("files")
    if not isinstance(files, list):
        raise ReferenceOrchestratorError("provenance manifest is incomplete")
    by_name = {item.get("path"): item for item in files if isinstance(item, Mapping)}
    try:
        index_entry = by_name["model.safetensors.index.json"]
        tokenizer_entry = by_name["tokenizer.json"]
        index_bytes = (root / index_entry["local_content"]["cache_path"]).read_bytes()
        tokenizer_sha = str(tokenizer_entry["local_content"]["sha256"])
    except (KeyError, OSError, TypeError) as exc:
        raise ReferenceOrchestratorError("provenance cache binding is incomplete") from exc
    runtime_lock = load_runtime_lock(
        root / str(current.authority_files["runtime_lock_path"]), root=root
    )
    evaluation_raw, evaluation_bytes = _read_json_bytes(
        root / str(current.authority_files["evaluation_lock_path"]), "evaluation lock"
    )
    fixture_root = root / str(current.authority_files["evaluation_fixture_root"])
    fixture_bytes = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation_raw["fixtures"]
    }
    evaluation = validate_pending_evaluation_lock(evaluation_raw, fixture_bytes=fixture_bytes)
    evaluation_lock_canonical_sha256 = evaluation.sha256
    source_metadata = _read_json(
        root / str(current.authority_files["source_shard_metadata_path"]),
        "source shard metadata",
    )
    inventory_raw = _read_json(
        root / str(current.authority_files["weight_inventory_path"]), "weight inventory"
    )
    inventory = parse_weight_inventory(
        inventory_raw,
        source_index_bytes=index_bytes,
        source_shards={
            name: (int(item["size_bytes"]), str(item["lfs_sha256"]))
            for name, item in source_metadata.items()
            if isinstance(item, Mapping)
        },
        expected_bindings={
            "provenance_manifest_sha256": provenance_sha,
            "tokenizer_sha256": tokenizer_sha,
            "runtime_lock_sha256": runtime_lock.sha256,
            # Inventory provenance binds the validated canonical lock identity.
            "evaluation_lock_sha256": evaluation_lock_canonical_sha256,
            "source_index_sha256": _sha(index_bytes),
        },
    )
    receipt_path = root / str(current.authority_files["runtime_receipt_path"])
    receipt, receipt_bytes = _read_json_bytes(receipt_path, "runtime receipt")
    verify_current_installed_environment(receipt, root=root, lock=runtime_lock)
    _validate_frozen_inputs(
        current.inputs,
        inventory,
        evaluation,
        _sha(evaluation_bytes),
        _sha(receipt_bytes),
    )
    commit = str(runtime["git_commit"])
    raw["experiment_id"] = f"phase1-u8-{commit[:12]}"
    raw["inputs"]["reviewed_commit_sha256"] = commit
    raw["inputs"]["control_plane_sha256"] = runtime["control_plane_sha256"]
    raw["inputs"]["weight_inventory_sha256"] = inventory.sha256
    raw["inputs"]["provenance_manifest_sha256"] = provenance_sha
    raw["approval_artifact_path"] = None
    encoded = yaml.safe_dump(raw, sort_keys=False, allow_unicode=False).encode("utf-8")
    _write_atomic(root, path, encoded)
    return load_reference_job_config(path, root=root)


def _source_artifacts(root: Path, config: ReferenceJobConfig) -> list[dict[str, object]]:
    provenance = _read_json(
        root / str(config.authority_files["provenance_manifest_path"]), "provenance manifest"
    )
    inventory = _read_json(
        root / str(config.authority_files["weight_inventory_path"]), "weight inventory"
    )
    files = provenance.get("files")
    shards = inventory.get("shards")
    if not isinstance(files, list) or not isinstance(shards, list) or not shards:
        raise ReferenceOrchestratorError("source artifact inventory is incomplete")
    reproduced_manifest_sha = _manifest_identity(provenance)
    declared_manifest_sha = provenance.get("manifest_sha256")
    repository = provenance.get("repository")
    source = inventory.get("source")
    if not isinstance(repository, Mapping) or not isinstance(source, Mapping):
        raise ReferenceOrchestratorError("source identity is incomplete")
    identifier = repository.get("identifier")
    revision = repository.get("revision")
    if (
        not isinstance(identifier, str)
        or identifier.count("/") != 1
        or any(part in {"", ".", ".."} for part in identifier.split("/"))
        or "\\" in identifier
        or revision != config.inputs["source_revision"]
        or source.get("identifier") != identifier
        or source.get("revision") != revision
        or declared_manifest_sha != config.inputs["provenance_manifest_sha256"]
        or reproduced_manifest_sha != declared_manifest_sha
    ):
        raise ReferenceOrchestratorError("source identity does not match immutable provenance")
    expected_prefix = f"/{identifier}/resolve/{revision}/"
    by_name = {item.get("path"): item for item in files if isinstance(item, Mapping)}
    index = by_name.get("model.safetensors.index.json")
    if not isinstance(index, Mapping) or not isinstance(index.get("http"), Mapping):
        raise ReferenceOrchestratorError("source index origin is unavailable")
    index_url = str(index["http"].get("requested_url"))
    parsed_index = urlsplit(index_url)
    if (
        parsed_index.query
        or parsed_index.fragment
        or not parsed_index.path.endswith("/model.safetensors.index.json")
        or (
            parsed_index.scheme != "https"
            or parsed_index.hostname not in REFERENCE_IMMUTABLE_ORIGIN_HOSTS
            or parsed_index.username is not None
            or parsed_index.password is not None
            or parsed_index.port not in (None, 443)
            or parsed_index.path != expected_prefix + "model.safetensors.index.json"
        )
    ):
        raise ReferenceOrchestratorError("source index origin is not immutable and query-free")
    base_path = parsed_index.path.rsplit("/", 1)[0] + "/"
    raw_artifacts: list[tuple[str, str, int, str]] = []
    for shard in sorted(shards, key=lambda item: str(item.get("path"))):
        if not isinstance(shard, Mapping):
            raise ReferenceOrchestratorError("weight shard inventory schema drift")
        name = str(shard.get("path"))
        if "/" in name or "\\" in name or not name.endswith(".safetensors"):
            raise ReferenceOrchestratorError("weight shard name is unsafe")
        url = urlunsplit((parsed_index.scheme, parsed_index.netloc, base_path + name, "", ""))
        raw_artifacts.append(
            ("safetensors", str(shard.get("content_sha256")), int(shard.get("size_bytes")), url)
        )
    for name in sorted(_SOURCE_FILES):
        item = by_name.get(name)
        if item is None and name == "special_tokens_map.json":
            continue
        if not isinstance(item, Mapping):
            raise ReferenceOrchestratorError("required source metadata is unavailable")
        local = item.get("local_content")
        http = item.get("http")
        if not isinstance(local, Mapping) or not isinstance(http, Mapping):
            raise ReferenceOrchestratorError("source metadata binding is incomplete")
        requested_url = str(http.get("requested_url"))
        parsed = urlsplit(requested_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in REFERENCE_IMMUTABLE_ORIGIN_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
            or parsed.path != expected_prefix + name
        ):
            raise ReferenceOrchestratorError("source metadata origin is not provenance-bound")
        raw_artifacts.append(
            (
                _SOURCE_FILES[name],
                str(local.get("sha256")),
                int(local.get("size_bytes")),
                requested_url,
            )
        )
    return [
        {"format": kind, "ordinal": ordinal, "sha256": digest, "size_bytes": size, "url": url}
        for ordinal, (kind, digest, size, url) in enumerate(raw_artifacts)
    ]


def build_bootstrap_request(root: Path, config: ReferenceJobConfig) -> bytes:
    """Build canonical target-neutral wire bytes; target details remain inside the bytes."""
    root = root.resolve()
    image_path = root / IMAGE_LOCK_PATH
    image = validate_image_lock_bytes(image_path.read_bytes())
    runtime_lock = load_runtime_lock(
        root / str(config.authority_files["runtime_lock_path"]), root=root
    )
    evaluation_bytes = (root / str(config.authority_files["evaluation_lock_path"])).read_bytes()
    evaluation_raw = json.loads(evaluation_bytes)
    fixture_root = root / str(config.authority_files["evaluation_fixture_root"])
    fixture_bytes = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation_raw["fixtures"]
    }
    evaluation = validate_pending_evaluation_lock(evaluation_raw, fixture_bytes=fixture_bytes)
    evaluation_lock_canonical_sha256 = evaluation.sha256
    provider_path = root / PROVIDER_CAPABILITY_PATH
    provider_sha = _sha(provider_path.read_bytes())
    provider = validate_provider_capability_receipt(
        provider_path,
        expected_sha256=provider_sha,
        image_recipe_sha256=image.recipe_sha256,
        billing_authority_path=root / DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=root / DEFAULT_BILLING_RECEIPT,
        billing_report_path=root / DEFAULT_BILLING_REPORT,
    )
    memory = _read_json(
        root / str(config.gates["memory_fit_evidence_path"]), "memory lower-bound evidence"
    )
    artifacts = _source_artifacts(root, config)
    hosts = sorted(
        {str(urlsplit(str(item["url"])).hostname) for item in artifacts}
        | {host for host, _ in REFERENCE_SIGNED_REDIRECT_POLICY}
    )
    resources = dict(REFERENCE_RESOURCES)
    resources["max_concurrent_containers"] = 1
    source_hashes = {
        key: value
        for key, value in config.inputs.items()
        if key not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
        and value is not None
    }
    request = {
        "action": "u8_reference_once",
        "approved_https_hosts": hosts,
        "authority": {
            "bootstrap_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "merge_commit": REFERENCE_BOOTSTRAP_MERGE_COMMIT,
            "parent_sha256": REFERENCE_AUTHORITY_SHA256,
            "signed_cdn_merge_commit": REFERENCE_SIGNED_CDN_MERGE_COMMIT,
            "signed_cdn_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
        },
        "budget": {
            "cumulative_cap_usd": str(REFERENCE_CUMULATIVE_CAP_USD),
            "incremental_reserved_usd": str(REFERENCE_INCREMENTAL_CAP_USD),
            "no_overlapping_reservations": True,
            "provider_hard_dollar_cap": False,
            "settled_before_usd": str(REFERENCE_SETTLED_SMOKE_USD),
        },
        "configured_context_tokens": 262144,
        "context_ladder_tokens": [8192, 32768, 131072, 262144],
        "deadline_policy": {
            "absolute_deadline_starts_at": "submission_pending",
            "future_stage_reserves_seconds": FUTURE_STAGE_RESERVES_SECONDS,
            "minimum_transfer_projection_bytes": 67108864,
            "projection_rounding": "against_admission",
            "timeout_seconds": 2700,
            "unused_time_flows_forward": True,
        },
        "image_lock": {"recipe_sha256": image.recipe_sha256, "sha256": image.sha256},
        "kind": "reference_bootstrap_request",
        "known_memory_lower_bound_bytes": memory.get("known_required_lower_bound_bytes"),
        "lineage": {
            "control_plane_sha256": config.inputs["control_plane_sha256"],
            # The wire lineage key binds canonical evaluation-lock bytes.
            "evaluation_lock_sha256": evaluation_lock_canonical_sha256,
            "inventory_sha256": config.inputs["weight_inventory_sha256"],
            "reviewed_commit": config.inputs["reviewed_commit_sha256"],
            "runtime_lock_sha256": runtime_lock.sha256,
            "runtime_receipt_sha256": config.inputs["runtime_receipt_sha256"],
            "source_hashes_sha256": canonical_sha256(source_hashes),
            "source_revision": config.inputs["source_revision"],
        },
        "provider_capability": {
            "image_recipe_sha256": image.recipe_sha256,
            "proven": True,
            "receipt_sha256": provider_sha,
            "remote_contact_performed": False,
            "sdk_version": provider["sdk_version"],
        },
        "readiness": {
            "deterministic": "bootstrap_ready",
            "empirical": {fact: "pending" for fact in EMPIRICAL_FACTS},
        },
        "resources": resources,
        "response_caps": {
            "max_failure_code_chars": 64,
            "max_measurements_per_stage": 16,
            "max_receipt_bytes": 65536,
            "max_stages": len(STAGES),
        },
        "restrictions": {
            "application_retries": 0,
            "destructive_cleanup": False,
            "executable_artifacts": False,
            "fallback_gpu": False,
            "local_data_mount": False,
            "local_source_mount": False,
            "persistent_volumes": False,
            "provider_retries": 0,
            "remote_code": False,
            "scheduling": False,
            "secrets": False,
            "user_payloads": False,
            "weights_source": "remote_immutable_public_only",
        },
        "schema_version": 1,
        "source_artifacts": artifacts,
        "source_artifacts_sha256": canonical_sha256(artifacts),
    }
    encoded = canonical_bytes(request)
    validate_bootstrap_request_bytes(encoded)
    return encoded


def validate_reproduced_request(
    root: Path, config: ReferenceJobConfig, request_bytes: bytes
) -> None:
    """Require the paid consumer to reproduce every source entry from local authority."""
    if build_bootstrap_request(root, config) != request_bytes:
        raise ReferenceOrchestratorError("bootstrap request does not match local provenance")


def _capability(root: Path, config: ReferenceJobConfig, request: bytes) -> ReferenceModalCapability:
    from lowbit_lab.reference_modal_adapter import ReferenceModalCapability

    evaluation_path = Path(str(config.authority_files["evaluation_lock_path"]))
    evaluation_lock_file_bytes = (root / evaluation_path).read_bytes()
    evaluation = json.loads(evaluation_lock_file_bytes)
    evaluation_lock_canonical_bytes = canonical_bytes(evaluation)
    fixture_root = root / str(config.authority_files["evaluation_fixture_root"])
    fixtures = {
        str(item["fixture_id"]): (fixture_root / f"{item['fixture_id']}.json").read_bytes()
        for item in evaluation["fixtures"]
    }
    image = json.loads((root / IMAGE_LOCK_PATH).read_text(encoding="utf-8"))
    provider = _validated_provider_capability(root, request)
    identity = {
        "weight_inventory_sha256": str(config.inputs["weight_inventory_sha256"]),
        "provenance_manifest_sha256": str(config.inputs["provenance_manifest_sha256"]),
        "runtime_receipt_sha256": str(config.inputs["runtime_receipt_sha256"]),
        "reviewed_commit_sha256": str(config.inputs["reviewed_commit_sha256"]),
        "resource_spec_sha256": _sha(canonical_bytes(config.resources)),
    }
    return ReferenceModalCapability(
        db_path=root / DATABASE_PATH,
        root=root,
        config_path=CONFIG_PATH,
        request_path=REQUEST_PATH,
        image_lock_path=IMAGE_LOCK_PATH,
        provider_capability_path=PROVIDER_CAPABILITY_PATH,
        billing_authority_path=DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=DEFAULT_BILLING_RECEIPT,
        billing_report_path=DEFAULT_BILLING_REPORT,
        publication_manifest_path=PUBLICATION_MANIFEST_PATH,
        reservation_id="",
        owner_id="",
        authority_root=root,
        provider_environment=str(provider["provider_environment"]),
        bootstrap_request_bytes=request,
        evaluation_lock_bytes=evaluation_lock_canonical_bytes,
        fixture_bytes=fixtures,
        execution_identity=identity,
        image_lock=image,
    )


def prepare(root: Path) -> tuple[ReferenceJobConfig, bytes, ReferenceModalCapability]:
    root = root.resolve()
    config = refresh_local_config(root)
    request = build_bootstrap_request(root, config)
    _write_atomic(root, root / REQUEST_PATH, request)
    request_sha = _sha(request)
    image_sha = _sha((root / IMAGE_LOCK_PATH).read_bytes())
    provider_sha = _sha((root / PROVIDER_CAPABILITY_PATH).read_bytes())
    preview = plan_reference_bootstrap_preview(
        config,
        root=root,
        request_path=REQUEST_PATH,
        request_sha256=request_sha,
        image_lock_path=IMAGE_LOCK_PATH,
        image_lock_sha256=image_sha,
        provider_capability_path=PROVIDER_CAPABILITY_PATH,
        provider_capability_sha256=provider_sha,
        billing_authority_path=DEFAULT_BILLING_AUTHORITY,
        billing_receipt_path=DEFAULT_BILLING_RECEIPT,
        billing_report_path=DEFAULT_BILLING_REPORT,
        publication_manifest_path=PUBLICATION_MANIFEST_PATH,
    )
    if preview["bootstrap_ready"] is not True or preview["blockers"]:
        raise ReferenceOrchestratorError("deterministic bootstrap gates are not ready")
    return config, request, _capability(root, config, request)


def prepare_replacement(
    root: Path,
) -> tuple[ReferenceJobConfig, bytes, ReferenceModalCapability, Mapping[str, str]]:
    """Prepare the deterministic graph and require an available, same-scope child slot."""
    root = root.resolve()
    config, request, capability = prepare(root)
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    binding = _replacement_binding(
        database, execution_scope_sha256=config.reference_execution_scope_sha256
    )
    _validate_fresh_auth_receipt(
        root,
        expected_original_workspace_scope_sha256=binding["original_workspace_scope_sha256"],
        expected_authenticated_workspace_identity_sha256=binding[
            "authenticated_workspace_identity_sha256"
        ],
    )
    return config, request, capability, binding


def _watchdog_ready() -> None:
    if os.name == "nt" or not all(
        hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer")
    ):
        raise ReferenceOrchestratorError("paid execution requires the WSL/Linux watchdog")


def execute(
    root: Path, *, confirm_request_sha256: str, replacement: bool = False
) -> Mapping[str, object]:
    """Reserve once and cross the existing adapter boundary after fresh local checks."""
    root = root.resolve()
    _require_merged_clean_main(root)
    _watchdog_ready()
    if provider_environment_overrides_present():
        raise ReferenceOrchestratorError("ambient provider environment override is forbidden")
    config, request, unreserved = prepare(root)
    request_sha = _sha(request)
    if confirm_request_sha256 != request_sha:
        raise ReferenceOrchestratorError("request confirmation does not match fresh bytes")
    observe_topology(root / REQUEST_PATH)
    from lowbit_lab.reference_modal_adapter import (
        prepare_local_modal_graph,
        submit_reference,
        validate_reference_preflight,
    )

    validate_reference_preflight(unreserved)
    # Freeze, cap, and bind Modal's exact hydration bytes before creating the
    # USD 4 local reservation. This builds only lazy local SDK objects.
    prepared_graph = prepare_local_modal_graph(unreserved)
    # Runtime lineage reproduction can exceed the topology receipt's freshness window on DrvFS.
    # Re-observe after that slow gate so reservation never relies on a stale route receipt.
    observe_topology(root / REQUEST_PATH)
    database = ResultsDatabase(confine_results_db(root, DATABASE_PATH))
    database.initialize()
    replacement_binding: Mapping[str, str] | None = None
    if replacement:
        replacement_binding = _replacement_binding(
            database, execution_scope_sha256=config.reference_execution_scope_sha256
        )
        verify_workspace_auth(root)
        _validate_fresh_auth_receipt(
            root,
            expected_original_workspace_scope_sha256=replacement_binding[
                "original_workspace_scope_sha256"
            ],
            expected_authenticated_workspace_identity_sha256=replacement_binding[
                "authenticated_workspace_identity_sha256"
            ],
        )
    now = datetime.now(UTC)
    expires = now + timedelta(hours=1)
    reservation_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    packet_sha = canonical_sha256(
        {
            "bootstrap_authority_sha256": REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
            "config_sha256": config.sha256,
            "request_sha256": request_sha,
            "signed_cdn_authority_sha256": REFERENCE_SIGNED_CDN_AUTHORITY_SHA256,
            "standing_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        }
    )
    approval_digest = canonical_sha256(
        {
            "action": "u8_reference_replacement_once" if replacement else "u8_reference_once",
            "challenge_sha256": config.challenge_sha256,
            "packet_sha256": packet_sha,
            "standing_authority_sha256": REFERENCE_AUTHORITY_SHA256,
        }
    )
    reserve_arguments: dict[str, object] = dict(
        reservation_id=reservation_id,
        attempt_id=attempt_id,
        run_id=run_id,
        experiment_id=config.experiment_id,
        config_sha256=config.sha256,
        config_json=config.canonical_json,
        source_hashes={
            key: value
            for key, value in config.inputs.items()
            if key not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
            and value is not None
        },
        runtime={"receipt_sha256": config.inputs["runtime_receipt_sha256"]},
        hardware={},
        requested_cost_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        phase_cap_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        total_cap_usd=str(REFERENCE_CUMULATIVE_CAP_USD),
        single_job_cap_usd=str(REFERENCE_INCREMENTAL_CAP_USD),
        idempotency_key=str(uuid.uuid4()),
        owner_id=owner_id,
        lease_expires_at=expires.isoformat(),
        started_at=now.isoformat(),
        challenge_sha256=config.challenge_sha256,
        approval_digest=approval_digest,
        standing_authority_sha256=REFERENCE_AUTHORITY_SHA256,
        bootstrap_authority_sha256=REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
        authority_root=root,
        standing_packet_sha256=packet_sha,
        approval_expires_at=expires.isoformat(),
        attempt_config_path=CONFIG_PATH.as_posix(),
        attempt_raw_config_sha256=_sha((root / CONFIG_PATH).read_bytes()),
    )
    if replacement_binding is not None:
        reserve_arguments.update(
            replacement_entitlement_sha256=replacement_binding["entitlement_sha256"],
            recovery_authority_sha256=REFERENCE_RECOVERY_AUTHORITY_SHA256,
            recovery_authority_path=RECOVERY_AUTHORITY_PATH,
        )
    database.reserve_reference_run(**reserve_arguments)
    capability = replace(
        unreserved,
        reservation_id=reservation_id,
        owner_id=owner_id,
        replacement_entitlement_sha256=(
            None if replacement_binding is None else replacement_binding["entitlement_sha256"]
        ),
        recovery_authority_sha256=(
            None if replacement_binding is None else REFERENCE_RECOVERY_AUTHORITY_SHA256
        ),
        replacement_original_workspace_scope_sha256=(
            None
            if replacement_binding is None
            else replacement_binding["original_workspace_scope_sha256"]
        ),
        replacement_authenticated_workspace_identity_sha256=(
            None
            if replacement_binding is None
            else replacement_binding["authenticated_workspace_identity_sha256"]
        ),
        workspace_reconciliation_authority_sha256=(
            None
            if replacement_binding is None
            else replacement_binding["workspace_reconciliation_authority_sha256"]
        ),
        replacement_auth_binding_sha256=(
            None if replacement_binding is None else replacement_binding["auth_binding_sha256"]
        ),
    )
    try:
        return submit_reference(capability, prepared_graph)
    except Exception:
        try:
            reservation = database.get_reservation(reservation_id)
        except Exception:
            raise ReferenceProviderStateUnknown("reference provider state requires audit") from None
        if reservation.get("status") == "reserved":
            raise ReferenceOrchestratorError("reference stopped before Modal contact") from None
        raise ReferenceProviderStateUnknown("reference provider state requires audit") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gate the one U8 reference action")
    parser.add_argument("--root", type=Path, default=Path("."))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("status")
    sub.add_parser("auth-bind")
    sub.add_parser("recovery-authority")
    sub.add_parser("reconciliation-authority")
    sub.add_parser("auth-verify")
    capture = sub.add_parser("billing-capture")
    capture.add_argument("--query-start", required=True)
    capture.add_argument("--query-end", required=True)
    replacement_capture = sub.add_parser("billing-capture-replacement")
    replacement_capture.add_argument("--query-start", required=True)
    replacement_capture.add_argument("--query-end", required=True)
    sub.add_parser("settle-preidentity-zero")
    sub.add_parser("settle-replacement")
    sub.add_parser("prepare-replacement")
    live = sub.add_parser("execute")
    live.add_argument("--confirm-request-sha256", required=True)
    replacement = sub.add_parser("execute-replacement")
    replacement.add_argument("--confirm-request-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    command = None
    provider_read_only_contacted = False
    try:
        args = _parser().parse_args(argv)
        command = args.command
        if command == "prepare":
            config, request, _ = prepare(args.root)
            emit(
                {
                    "configured_context_tokens": 262144,
                    "execution_scope_sha256": config.reference_execution_scope_sha256,
                    "ok": True,
                    "provider_contacted": False,
                    "proven_useful_context_tokens": None,
                    "request_sha256": _sha(request),
                }
            )
            return 0
        if command == "status":
            emit({"ok": True, **reference_status(args.root)})
            return 0
        if command == "auth-bind":
            emit(
                {
                    "ok": True,
                    "provider_contacted": False,
                    **bind_workspace_auth(args.root),
                }
            )
            return 0
        if command == "recovery-authority":
            emit(
                {
                    "ok": True,
                    "provider_contacted": False,
                    **materialize_recovery_authority(args.root),
                }
            )
            return 0
        if command == "reconciliation-authority":
            emit(
                {
                    "ok": True,
                    "provider_contacted": False,
                    **materialize_workspace_reconciliation_authority(args.root),
                }
            )
            return 0
        if command == "auth-verify":
            emit(
                {
                    "ok": True,
                    "provider_contacted": False,
                    **verify_workspace_auth(args.root),
                }
            )
            return 0
        if command == "billing-capture":
            emit(
                {
                    "ok": True,
                    **capture_workspace_zero_billing(
                        args.root,
                        query_start=args.query_start,
                        query_end=args.query_end,
                    ),
                }
            )
            return 0
        if command == "billing-capture-replacement":
            def track_read_only_provider_call(*args: object, **kwargs: object) -> object:
                nonlocal provider_read_only_contacted
                provider_read_only_contacted = True
                return subprocess.run(*args, **kwargs)

            emit(
                {
                    "ok": True,
                    **capture_replacement_billing(
                        args.root,
                        query_start=args.query_start,
                        query_end=args.query_end,
                        runner=track_read_only_provider_call,
                    ),
                }
            )
            return 0
        if command == "settle-preidentity-zero":
            emit({"ok": True, **settle_workspace_zero(args.root)})
            return 0
        if command == "settle-replacement":
            emit({"ok": True, **settle_replacement_billing(args.root)})
            return 0
        if command == "prepare-replacement":
            config, request, _, binding = prepare_replacement(args.root)
            emit(
                {
                    "configured_context_tokens": 262144,
                    "entitlement_sha256": binding["entitlement_sha256"],
                    "execution_scope_sha256": config.reference_execution_scope_sha256,
                    "ok": True,
                    "provider_contacted": False,
                    "proven_useful_context_tokens": None,
                    "request_sha256": _sha(request),
                }
            )
            return 0
        result = execute(
            args.root,
            confirm_request_sha256=args.confirm_request_sha256,
            replacement=command == "execute-replacement",
        )
        emit({"ok": True, "provider_contacted": True, "result": result})
        return 0
    except Exception as exc:
        failure: dict[str, object] = {
            "command": command,
            "error": type(exc).__name__,
            "ok": False,
            "provider_contacted": (
                "unknown" if isinstance(exc, ReferenceProviderStateUnknown) else False
            ),
        }
        if command == "billing-capture-replacement":
            failure["provider_read_only_contacted"] = provider_read_only_contacted
        emit(failure, stream=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
