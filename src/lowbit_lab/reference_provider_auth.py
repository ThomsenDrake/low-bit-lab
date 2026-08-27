"""Fail-closed checks for ambient Modal authentication overrides."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

OFFICIAL_MODAL_SERVER_URL = "https://api.modal.com,https://api.modal2.com"
MODAL_AUTH_OVERRIDE_KEYS = (
    "MODAL_TOKEN_ID",
    "MODAL_TOKEN_SECRET",
    "MODAL_PROFILE",
    "MODAL_CONFIG_PATH",
    "MODAL_ENVIRONMENT",
    "MODAL_SERVER_URL",
    "MODAL_OVERRIDE_HEADERS",
)
PROVIDER_TRANSPORT_OVERRIDE_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    "SSLKEYLOGFILE",
)
PYTHON_IMPORT_OVERRIDE_KEYS = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
)
PROVIDER_ENVIRONMENT_OVERRIDE_KEYS = (
    *PROVIDER_TRANSPORT_OVERRIDE_KEYS,
    *PYTHON_IMPORT_OVERRIDE_KEYS,
)


def _is_modal_override(key: str) -> bool:
    return key.startswith("MODAL_")


def modal_auth_overrides_present(environment: Mapping[str, str] | None = None) -> bool:
    """Report only whether an override key exists; never inspect or expose its value."""
    selected = os.environ if environment is None else environment
    return any(_is_modal_override(key) for key in selected)


def provider_environment_overrides_present(
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Report key presence only; values are never read, copied, or logged."""
    selected = os.environ if environment is None else environment
    return modal_auth_overrides_present(selected) or any(
        key in selected for key in PROVIDER_ENVIRONMENT_OVERRIDE_KEYS
    )


def sanitized_modal_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a child-process environment with every Modal auth override removed."""
    selected = os.environ if environment is None else environment
    return {
        key: value
        for key, value in selected.items()
        if not _is_modal_override(key) and key not in PROVIDER_ENVIRONMENT_OVERRIDE_KEYS
    }


def auth_receipt_path(receipt_sha256: str) -> Path:
    """Return the content-addressed local path for a validated lowercase digest."""
    if len(receipt_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in receipt_sha256
    ):
        raise ValueError("workspace auth receipt digest is invalid")
    return Path("reports/local/reference-workspace-auth-receipts") / f"{receipt_sha256}.json"
